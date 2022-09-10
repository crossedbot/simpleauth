package controller

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crossedbot/common/golang/config"
	"github.com/crossedbot/simplejwt/jwk"
	middleware "github.com/crossedbot/simplemiddleware"
	"github.com/sec51/twofactor"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/crossedbot/simpleauth/pkg/database"
	"github.com/crossedbot/simpleauth/pkg/grants"
	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	// Defaults
	DefaultTotpIssuer   = "simpleauth"
	DefaultTotpDigits   = 6
	DefaultPrivateKey   = "~/.simpleauth/simpleauth.key"
	DefaultCertificate  = "~/.simpleauth/simpleauth.cert"
	DefaultDatabaseAddr = "mongodb://127.0.0.1:27017"
)

var (
	// Errors
	ErrorUserNotFound     = errors.New("User not found")
	ErrorUserExists       = errors.New("The username, email or phone number already exists")
	ErrorBadCredentials   = errors.New("The username or password is incorrect")
	ErrorUsernameRequired = errors.New("Username/Email is required")
	ErrorPasswordRequired = errors.New("Password is required")
	ErrorTotpNotFound     = errors.New("TOTP not set for user")
)

// Controller represents an interface to an authentication service.
type Controller interface {
	// SetDatabase sets the user database for the authentication service at
	// the given address.
	SetDatabase(addr string) error

	// SetAuthPrivateKey sets the JWT private key for generating access
	// tokens.
	SetAuthPrivateKey(io.Reader) error

	// SetAuthCert sets the authentication service JSON web key for
	// validating access tokens.
	SetAuthCert(io.Reader) error

	// SetTotpIssuer sets the TOTP issuer for the authentication service.
	SetTotpIssuer(issuer string)

	// Login returns a new AccessToken for the given login request.
	// Effectively, logging in the user for as long the token remains valid.
	Login(models.Login) (models.AccessToken, error)

	// SignUp adds the given user to the authentication service and returns
	// a new Accesstoken.
	SignUp(models.User) (models.AccessToken, error)

	// SetTotp sets the TOTP for the given user ID. Implementations, should
	// only enable/disable TOTP for the given user.
	SetTotp(id string, totp models.Totp) (models.Totp, error)

	// ValidateOtp returns a new AccessToken if the given OTP was valid for
	// the user ID.
	ValidateOtp(id, otp string) (models.AccessToken, error)

	// GetOtpQr returns an image of the QR code for the given user ID.
	GetOtpQr(id string) ([]byte, error)

	// RefreshToken returns a new AccessToken for the given user ID.
	// Effectively, refreshing the authenticated access.
	RefreshToken(id string) (models.AccessToken, error)

	// GetJwks returns the JSON web key of the authentication service.
	GetJwks() (jwk.Jwks, error)
}

// controller implements the authentication service interface.
type controller struct {
	ctx        context.Context
	client     *mongo.Client   // MongoDB client
	privateKey []byte          // JSON web token private key
	publicKey  []byte          // JSON web token public key
	cert       jwk.Certificate // JSON-Web key certificate
	issuer     string          // TOTP issuer
}

// Config represents the configuration of an authentication service controller.
type Config struct {
	DatabaseAddr string `toml:"database_addr"`
	PrivateKey   string `toml:"private_key"`
	Certificate  string `toml:"certificate"`
	TotpIssuer   string `toml:"totp_issuer"`
}

var control Controller
var controllerOnce sync.Once

// V1 is version 1 of an authentication service controller.
var V1 = func() Controller {
	// XXX Probably should change the name of this. I am unlikely to keep
	// previous versions of the service around.

	controllerOnce.Do(func() {
		// XXX this should really be split up into functions
		var cfg Config
		if err := config.Load(&cfg); err != nil {
			panic(err)
		}
		if cfg.TotpIssuer == "" {
			cfg.TotpIssuer = DefaultTotpIssuer
		}
		ctx := context.Background()
		db, err := database.New(ctx, cfg.DatabaseAddr)
		if err != nil {
			panic(fmt.Sprintf(
				"Controller: failed to connect to database at "+
					"address ('%s')",
				cfg.DatabaseAddr,
			))
		}
		privateKey, err := ioutil.ReadFile(cfg.PrivateKey)
		if err != nil {
			panic(fmt.Sprintf(
				"Controller: private key not found ('%s')",
				cfg.PrivateKey,
			))
		}
		cert := jwk.Certificate{}
		certFd, err := os.Open(cfg.Certificate)
		if err != nil {
			panic(fmt.Sprintf(
				"Controller: certificate not found ('%s')",
				cfg.Certificate,
			))
		}
		cert, err = jwk.NewCertificate(certFd)
		if err != nil {
			panic(fmt.Sprintf(
				"Controller: failed to parse certificate; %s",
				err,
			))
		}
		publicKey, err := cert.PublicKey()
		if err != nil {
			panic(fmt.Sprintf(
				"Controller: failed to parse certificate's "+
					"public key; %s",
				err,
			))
		}
		middleware.SetAuthPublicKey(publicKey)
		control = New(
			ctx,
			db,
			privateKey,
			publicKey,
			cert,
			cfg.TotpIssuer,
		)
	})
	return control
}

// New returns a new Controller.
func New(
	ctx context.Context,
	client *mongo.Client,
	privateKey []byte,
	publicKey []byte,
	cert jwk.Certificate,
	totpIssuer string,
) Controller {
	return &controller{
		ctx,
		client,
		privateKey,
		publicKey,
		cert,
		totpIssuer,
	}
}

func (c *controller) SetDatabase(addr string) error {
	db, err := database.New(c.ctx, addr)
	if err != nil {
		return err
	}
	c.client = db
	return nil
}

func (c *controller) SetAuthPrivateKey(privKey io.Reader) error {
	b, err := ioutil.ReadAll(privKey)
	if err != nil {
		return err
	}
	c.privateKey = b
	return nil
}

func (c *controller) SetAuthCert(cert io.Reader) error {
	newCert, err := jwk.NewCertificate(cert)
	if err != nil {
		return err
	}
	c.publicKey, err = newCert.PublicKey()
	if err != nil {
		return err
	}
	middleware.SetAuthPublicKey(c.publicKey)
	c.cert = newCert
	return nil
}

func (c *controller) SetTotpIssuer(issuer string) {
	c.issuer = issuer
}

func (c *controller) Login(login models.Login) (models.AccessToken, error) {
	login.Name = strings.ToLower(login.Name)
	users := c.Users()
	filter := bson.D{bson.E{
		Key: "$or",
		Value: bson.A{
			bson.M{"email": login.Name},
			bson.M{"username": login.Name},
		},
	}}
	var foundUser models.User
	err := users.FindOne(c.ctx, filter).Decode(&foundUser)
	if err != nil {
		return models.AccessToken{}, ErrorUserNotFound
	}
	if err := VerifyPassword(foundUser.Password, login.Password); err != nil {
		return models.AccessToken{}, ErrorBadCredentials
	}
	tkn := ""
	refreshTkn := ""
	options := &TokenOptions{}
	if foundUser.TotpEnabled {
		// If TOTP is enabled then we only need a short-lived access
		// token to complete the OTP transaction.
		options.Grant = grants.GrantOTPValidate
		options.TTL = TransactionTokenExpiration
		options.SkipRefresh = true
	}
	tkn, refreshTkn, err = GenerateTokens(foundUser, c.publicKey,
		c.privateKey, options)
	if err != nil {
		return models.AccessToken{}, err
	}
	if err := c.UpdateTokens(tkn, refreshTkn, foundUser.UserId); err != nil {
		return models.AccessToken{}, err
	}
	return models.AccessToken{
		Token:        tkn,
		RefreshToken: refreshTkn,
		OtpRequired:  foundUser.TotpEnabled,
	}, nil
}

func (c *controller) SignUp(user models.User) (models.AccessToken, error) {
	user.Username = strings.ToLower(user.Username)
	user.Email = strings.ToLower(user.Email)
	if err := user.Valid(); err != nil {
		return models.AccessToken{}, err
	}
	params := bson.A{bson.M{"username": user.Username}}
	if user.Email != "" {
		params = append(params, bson.M{"email": user.Email})
	}
	filter := bson.D{bson.E{Key: "$or", Value: params}}
	userCount, err := c.Users().CountDocuments(c.ctx, filter)
	if err != nil {
		return models.AccessToken{}, err
	}
	if user.Phone != "" {
		count, err := c.Users().CountDocuments(
			c.ctx,
			bson.M{"phone": user.Phone},
		)
		if err != nil {
			return models.AccessToken{}, err
		}
		userCount += count
	}
	if userCount > 0 {
		return models.AccessToken{}, ErrorUserExists
	}
	hashedPass, err := HashPassword(user.Password)
	if err != nil {
		return models.AccessToken{}, err
	}
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.UserType = strings.ToUpper(user.UserType)
	user.Password = hashedPass
	user.CreatedAt = now
	user.UpdatedAt = now
	user.ID = primitive.NewObjectID()
	user.UserId = user.ID.Hex()
	tkn, refreshTkn, err := GenerateTokens(user, c.publicKey, c.privateKey,
		nil)
	if err != nil {
		return models.AccessToken{}, err
	}
	user.Token = tkn
	user.RefreshToken = refreshTkn
	result, err := c.Users().InsertOne(c.ctx, user)
	if err != nil {
		return models.AccessToken{}, err
	}
	id, ok := result.InsertedID.(primitive.ObjectID)
	if ok {
		c.SetTotp(id.String(), models.Totp{Enabled: user.TotpEnabled})
	}
	return models.AccessToken{
		Token:        tkn,
		RefreshToken: refreshTkn,
		OtpRequired:  user.TotpEnabled,
	}, err
}

func (c *controller) SetTotp(id string, totp models.Totp) (models.Totp, error) {
	users := c.Users()
	var foundUser models.User
	err := users.FindOne(c.ctx, bson.M{"user_id": id}).Decode(&foundUser)
	if err != nil {
		return models.Totp{}, ErrorUserNotFound
	}
	if totp.Enabled && foundUser.Totp == "" {
		account := foundUser.Email
		if account == "" {
			account = foundUser.Username
		}
		// set TOTP if it doesn't exist and is enabled
		newTotp, err := twofactor.NewTOTP(
			foundUser.Email,
			c.issuer,
			crypto.SHA1,
			DefaultTotpDigits,
		)
		if err != nil {
			return models.Totp{}, err
		}
		totp.Otp, err = newTotp.OTP()
		if err != nil {
			return models.Totp{}, err
		}
		totp.Qr, err = newTotp.QR()
		if err != nil {
			return models.Totp{}, err
		}
		foundUser.Totp, err = EncodeTotp(newTotp)
		if err != nil {
			return models.Totp{}, err
		}
	}
	if err := c.UpdateTotp(totp.Enabled, foundUser.Totp, id); err != nil {
		return models.Totp{}, err
	}
	return totp, nil
}

func (c *controller) ValidateOtp(id, otp string) (models.AccessToken, error) {
	users := c.Users()
	var foundUser models.User
	err := users.FindOne(c.ctx, bson.M{"user_id": id}).Decode(&foundUser)
	if err != nil {
		return models.AccessToken{}, ErrorUserNotFound
	}
	totp, err := DecodeTotp(foundUser.Totp, c.issuer)
	if err != nil {
		return models.AccessToken{}, err
	}
	if err := totp.Validate(otp); err != nil {
		return models.AccessToken{}, err
	}
	tkn, refreshTkn, err := GenerateTokens(foundUser, c.publicKey,
		c.privateKey, nil)
	if err != nil {
		return models.AccessToken{}, err
	}
	err = c.UpdateTokens(tkn, refreshTkn, foundUser.UserId)
	if err != nil {
		return models.AccessToken{}, err
	}
	return models.AccessToken{
		Token:        tkn,
		RefreshToken: refreshTkn,
		OtpRequired:  foundUser.TotpEnabled,
	}, nil
}

func (c *controller) GetOtpQr(id string) ([]byte, error) {
	users := c.Users()
	var foundUser models.User
	err := users.FindOne(c.ctx, bson.M{"user_id": id}).Decode(&foundUser)
	if err != nil {
		return nil, ErrorUserNotFound
	}
	if foundUser.Totp != "" {
		totp, err := DecodeTotp(foundUser.Totp, c.issuer)
		if err != nil {
			return nil, err
		}
		return totp.QR()
	}
	return nil, ErrorTotpNotFound
}

func (c *controller) RefreshToken(id string) (models.AccessToken, error) {
	users := c.Users()
	var foundUser models.User
	err := users.FindOne(c.ctx, bson.M{"user_id": id}).Decode(&foundUser)
	if err != nil {
		return models.AccessToken{}, ErrorUserNotFound
	}
	tkn, refreshTkn, err := GenerateTokens(foundUser, c.publicKey,
		c.privateKey, nil)
	if err != nil {
		return models.AccessToken{}, err
	}
	if err := c.UpdateTokens(tkn, refreshTkn, foundUser.UserId); err != nil {
		return models.AccessToken{}, err
	}
	return models.AccessToken{
		Token:        tkn,
		RefreshToken: refreshTkn,
		OtpRequired:  foundUser.TotpEnabled,
	}, nil
}

func (c *controller) GetJwks() (jwk.Jwks, error) {
	webKey, err := c.cert.ToJwk()
	return jwk.Jwks{Keys: []jwk.Jwk{webKey}}, err
}

// Users returns the "users" collection of the "auth" database.
func (c *controller) Users() *mongo.Collection {
	return c.client.Database("auth").Collection("users")
}

// UpdateTokens sets the token and refresh token for the given user ID.
func (c *controller) UpdateTokens(token, refreshToken, userId string) error {
	users := c.Users()
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	update := primitive.D{
		bson.E{Key: "token", Value: token},
		bson.E{Key: "refresh_token", Value: refreshToken},
		bson.E{Key: "updated_at", Value: now},
	}
	upsert := true
	_, err := users.UpdateOne(
		c.ctx,
		bson.M{"user_id": userId},
		bson.D{bson.E{Key: "$set", Value: update}},
		&options.UpdateOptions{Upsert: &upsert},
	)
	return err
}

// UpdateTotp sets the TOTP for the given user ID.
func (c *controller) UpdateTotp(enabled bool, totp, userId string) error {
	users := c.Users()
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	update := primitive.D{
		bson.E{Key: "totp_enabled", Value: enabled},
		bson.E{Key: "totp", Value: totp},
		bson.E{Key: "updated_at", Value: now},
	}
	upsert := true
	_, err := users.UpdateOne(
		c.ctx,
		bson.M{"user_id": userId},
		bson.D{bson.E{Key: "$set", Value: update}},
		&options.UpdateOptions{Upsert: &upsert},
	)
	return err
}

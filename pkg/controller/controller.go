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

	"github.com/crossedbot/common/golang/logger"
	"github.com/sec51/twofactor"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/crossedbot/simpleauth/pkg/database"
	"github.com/crossedbot/simpleauth/pkg/jwk"
	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	DefaultTotpIssuer   = "simpleauth"
	DefaultTotpDigits   = 6
	DefaultPrivateKey   = "~/.simpleauth/simpleauth.key"
	DefaultCertificate  = "~/.simpleauth/simpleauth.cert"
	DefaultDatabaseAddr = "mongodb://127.0.0.1:27017"
)

var (
	ErrorUserNotFound     = errors.New("User not found")
	ErrorUserExists       = errors.New("The username, email or phone number already exists")
	ErrorBadCredentials   = errors.New("The username or password is incorrect")
	ErrorUsernameRequired = errors.New("Username/Email is required")
	ErrorPasswordRequired = errors.New("Password is required")
)

type Controller interface {
	// Control functions
	SetDatabase(addr string) error
	SetAuthPrivateKey(io.Reader) error
	SetAuthCert(io.Reader) error
	SetTotpIssuer(issuer string)

	// Handler functions
	Login(models.Login) (models.AccessToken, error)
	SignUp(models.User) (models.AccessToken, error)
	SetTotp(id string, totp models.Totp) (models.Totp, error)
	ValidateOtp(id, otp string) (models.AccessToken, error)
	GetOtpQr(id string) ([]byte, error)
	RefreshToken(id string) (models.AccessToken, error)
	GetJwks() (jwk.Jwks, error)
}

type controller struct {
	ctx        context.Context
	client     *mongo.Client
	privateKey []byte
	cert       jwk.Certificate
	issuer     string
}

var control Controller
var controllerOnce sync.Once
var V1 = func() Controller {
	controllerOnce.Do(func() {
		ctx := context.Background()
		db, err := database.New(ctx, DefaultDatabaseAddr)
		if err != nil {
			logger.Warning(
				fmt.Sprintf(
					"Controller: failed to connect to database at default address ('%s')",
					DefaultDatabaseAddr,
				),
			)
		}
		key, err := ioutil.ReadFile(DefaultPrivateKey)
		if err != nil {
			logger.Warning(
				fmt.Sprintf(
					"Controller: default private key ('%s') not found",
					DefaultPrivateKey,
				),
			)
		}
		cert := jwk.Certificate{}
		certFd, err := os.Open(DefaultCertificate)
		if err != nil {
			logger.Warning(
				fmt.Sprintf(
					"Controller: default certificate ('%s') not found",
					DefaultCertificate,
				),
			)
		} else {
			cert, err = jwk.NewCertificate(certFd)
			if err != nil {
				panic(fmt.Sprintf("Controller: failed to parse certificate; %s", err))
			}
			publicKey, err := cert.PublicKey()
			if err != nil {
				panic(fmt.Sprintf("Controller: failed to parse certificate's public key; %s", err))
			}
			setAuthPublicKey(publicKey)
		}
		control = New(ctx, db, key, cert, DefaultTotpIssuer)
	})
	return control
}

func New(ctx context.Context, client *mongo.Client, privateKey []byte, cert jwk.Certificate, totpIssuer string) Controller {
	return &controller{ctx, client, privateKey, cert, totpIssuer}
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
	publicKey, err := newCert.PublicKey()
	if err != nil {
		return err
	}
	setAuthPublicKey(publicKey)
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
	if !foundUser.TotpEnabled {
		// Only login if TOTP has not been enabled
		tkn, refreshTkn, err = GenerateTokens(foundUser, publicAuthKey, c.privateKey)
		if err != nil {
			return models.AccessToken{}, err
		}
		if err := c.UpdateTokens(tkn, refreshTkn, foundUser.UserId); err != nil {
			return models.AccessToken{}, err
		}
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
	tkn, refreshTkn, err := GenerateTokens(user, publicAuthKey, c.privateKey)
	if err != nil {
		return models.AccessToken{}, err
	}
	user.Token = tkn
	user.RefreshToken = refreshTkn
	_, err = c.Users().InsertOne(c.ctx, user)
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
	tkn, refreshTkn, err := GenerateTokens(foundUser, publicAuthKey, c.privateKey)
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
	// XXX is this fine? and should we respond a NotFound?
	return nil, nil
}

func (c *controller) RefreshToken(id string) (models.AccessToken, error) {
	users := c.Users()
	var foundUser models.User
	err := users.FindOne(c.ctx, bson.M{"user_id": id}).Decode(&foundUser)
	if err != nil {
		return models.AccessToken{}, ErrorUserNotFound
	}
	tkn, refreshTkn, err := GenerateTokens(foundUser, publicAuthKey, c.privateKey)
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

func (c *controller) Users() *mongo.Collection {
	return c.client.Database("auth").Collection("users")
}

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

func (c *controller) UpdateTotp(enabled bool, totp, userId string) error {
	users := c.Users()
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	update := primitive.D{
		bson.E{Key: "Totp_enabled", Value: enabled},
		bson.E{Key: "Totp", Value: totp},
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

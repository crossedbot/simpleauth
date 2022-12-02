package controller

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/crossedbot/common/golang/config"
	"github.com/crossedbot/simplejwt/jwk"
	middleware "github.com/crossedbot/simplemiddleware"
	"github.com/sec51/twofactor"

	"github.com/crossedbot/simpleauth/pkg/database"
	"github.com/crossedbot/simpleauth/pkg/grants"
	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	// Defaults
	DefaultTotpIssuer      = "simpleauth"
	DefaultTotpDigits      = 6
	DefaultPrivateKey      = "~/.simpleauth/simpleauth.key"
	DefaultCertificate     = "~/.simpleauth/simpleauth.cert"
	DefaultDatabasePath    = "mongodb://127.0.0.1:27017"
	DefaultDatabaseDialect = database.DialectMongoDb
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
	SetDatabase(dialect, path string) error

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
	db         database.Database // Users database
	privateKey []byte            // JSON web token private key
	publicKey  []byte            // JSON web token public key
	cert       jwk.Certificate   // JSON-Web key certificate
	issuer     string            // TOTP issuer
}

// Config represents the configuration of an authentication service controller.
type Config struct {
	DatabasePath    string `toml:"database_path"`
	DatabaseDialect string `toml:"database_dialect"`

	PrivateKey  string   `toml:"private_key"`
	Certificate string   `toml:"certificate"`
	TotpIssuer  string   `toml:"totp_issuer"`
	AuthGrants  []string `toml:"auth_grants"`
}

var control Controller
var controllerOnce sync.Once

// Ctrl is an instance of an authentication service controller.
var Ctrl = func() Controller {
	controllerOnce.Do(func() {
		var cfg Config
		if err := config.Load(&cfg); err != nil {
			panic(err)
		}
		if cfg.TotpIssuer == "" {
			cfg.TotpIssuer = DefaultTotpIssuer
		}
		ctx := context.Background()
		db, err := database.New(ctx, cfg.DatabaseDialect, cfg.DatabasePath)
		if err != nil {
			panic(fmt.Sprintf(
				"Controller: failed to connect to database at "+
					"address ('%s')",
				cfg.DatabasePath,
			))
		}
		privateKey, publicKey, cert, err := readKeysFromConfig(cfg)
		if err != nil {
			panic(fmt.Sprintf("Controller: %s", err))
		}
		if len(cfg.AuthGrants) > 0 {
			err := grants.SetCustomGrants(cfg.AuthGrants)
			if err != nil {
				panic(fmt.Sprintf("Controller: %s", err))
			}
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
	db database.Database,
	privateKey []byte,
	publicKey []byte,
	cert jwk.Certificate,
	totpIssuer string,
) Controller {
	return &controller{ctx, db, privateKey, publicKey, cert, totpIssuer}
}

func (c *controller) SetDatabase(dialect, path string) error {
	db, err := database.New(c.ctx, dialect, path)
	if err != nil {
		return err
	}
	c.db = db
	return nil
}

func (c *controller) SetAuthPrivateKey(privKey io.Reader) error {
	b, err := io.ReadAll(privKey)
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
	foundUser, err := c.db.GetUserByName(login.Name)
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
	if err := c.db.UpdateTokens(tkn, refreshTkn, foundUser.UserId); err != nil {
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
	hashedPass, err := HashPassword(user.Password)
	if err != nil {
		return models.AccessToken{}, err
	}
	now, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.UserType = strings.ToUpper(user.UserType)
	user.Password = hashedPass
	user.CreatedAt = now
	user.UpdatedAt = now
	tkn, refreshTkn, err := GenerateTokens(user, c.publicKey, c.privateKey,
		nil)
	if err != nil {
		return models.AccessToken{}, err
	}
	user.Token = tkn
	user.RefreshToken = refreshTkn
	user, err = c.db.SaveUser(user)
	if err != nil {
		return models.AccessToken{}, err
	}
	c.SetTotp(user.UserId, models.Totp{Enabled: user.TotpEnabled})
	return models.AccessToken{
		Token:        tkn,
		RefreshToken: refreshTkn,
		OtpRequired:  user.TotpEnabled,
	}, err
}

func (c *controller) SetTotp(id string, totp models.Totp) (models.Totp, error) {
	foundUser, err := c.db.GetUser(id)
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
			account,
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
	if err := c.db.UpdateTotp(totp.Enabled, foundUser.Totp, id); err != nil {
		return models.Totp{}, err
	}
	return totp, nil
}

func (c *controller) ValidateOtp(id, otp string) (models.AccessToken, error) {
	foundUser, err := c.db.GetUser(id)
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
	if err := c.db.UpdateTokens(tkn, refreshTkn, foundUser.UserId); err != nil {
		return models.AccessToken{}, err
	}
	return models.AccessToken{
		Token:        tkn,
		RefreshToken: refreshTkn,
		OtpRequired:  foundUser.TotpEnabled,
	}, nil
}

func (c *controller) GetOtpQr(id string) ([]byte, error) {
	foundUser, err := c.db.GetUser(id)
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
	foundUser, err := c.db.GetUser(id)
	if err != nil {
		return models.AccessToken{}, ErrorUserNotFound
	}
	tkn, refreshTkn, err := GenerateTokens(foundUser, c.publicKey,
		c.privateKey, nil)
	if err != nil {
		return models.AccessToken{}, err
	}
	if err := c.db.UpdateTokens(tkn, refreshTkn, foundUser.UserId); err != nil {
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

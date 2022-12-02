package controller

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	commoncrypto "github.com/crossedbot/common/golang/crypto"
	"github.com/crossedbot/simplejwt"
	"github.com/crossedbot/simplejwt/algorithms"
	"github.com/crossedbot/simplejwt/jwk"
	middleware "github.com/crossedbot/simplemiddleware"
	"github.com/sec51/twofactor"
	"golang.org/x/crypto/bcrypt"

	"github.com/crossedbot/simpleauth/pkg/grants"
	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	// Access Token TTLs
	AccessTokenExpiration      = 1 * time.Hour
	RefreshTokenExpiration     = 24 * time.Hour
	TransactionTokenExpiration = 5 * time.Minute
)

// HashPassword returns the bcrypt hash of the given password using the default
// cost of 10.
func HashPassword(pass string) (string, error) {
	// I should probably add a note here that hashing the password alone is
	// fine, for the library handles salting and all that itself. If things
	// change I'll modify this appropriately.
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword returns nil if the given bcrypt hash matches the password.
// Otherwise, an error is returned.
func VerifyPassword(hashedPass, pass string) error {
	var msg error
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(pass))
	if err != nil {
		msg = errors.New("login or password is incorrect")
	}
	return msg
}

// TokenOptions represents a container for options for generating an access
// token.
type TokenOptions struct {
	Grant       grants.Grant  // Access grant of the token
	TTL         time.Duration // Time-To-Live of the token
	RefreshTTL  time.Duration // Time-To-Live of the refresh token
	SkipRefresh bool          // Whether to skip generating a refresh token
}

// GenerateTokens returns a new access token, and an accompanying refresh token
// for the given user, and encryption key pair. By default, the generated access
// token will be given a grant of grants.GrantAuthenticated and a TTL of
// AccessTokenExpiration. This can be changed in the given token options.
// Skipping the refresh token, will return an empty string in its place.
func GenerateTokens(user models.User, pubKey, privKey []byte, options *TokenOptions) (string, string, error) {
	grant := grants.GrantAuthenticated
	if grants.IsCustomGrantsSet() {
		grant |= grants.GetCustomGrant()
	}
	if options != nil && options.Grant != grants.GrantUnknown {
		grant = options.Grant
	}
	ttl := AccessTokenExpiration
	if options != nil && options.TTL > time.Duration(0) {
		ttl = options.TTL
	}
	refreshTtl := RefreshTokenExpiration
	if options != nil && options.RefreshTTL > time.Duration(0) {
		refreshTtl = options.RefreshTTL
	}
	claims := simplejwt.CustomClaims{
		"email":                user.Email,
		"username":             user.Username,
		middleware.ClaimUserId: user.UserId,
		"user_type":            user.UserType,
		"exp":                  time.Now().Local().Add(ttl).Unix(),
		middleware.ClaimGrant:  grant.Clean().Short(),
	}
	jwt := simplejwt.New(claims, algorithms.AlgorithmRS256)
	jwt.Header["kid"] = jwk.EncodeToString(commoncrypto.KeyId(pubKey))
	tkn, err := jwt.Sign(privKey)
	if err != nil {
		return "", "", err
	}
	refreshTkn := ""
	if options == nil || !options.SkipRefresh {
		exp := time.Now().Local().Add(refreshTtl).Unix()
		refreshClaims := simplejwt.CustomClaims{
			middleware.ClaimUserId: user.UserId,
			"exp":                  exp,
			middleware.ClaimGrant:  grants.GrantUsersRefresh.String(),
		}
		refreshTkn, err = simplejwt.New(refreshClaims,
			algorithms.AlgorithmRS256).Sign(privKey)
		if err != nil {
			return "", "", err
		}
	}
	return tkn, refreshTkn, nil
}

// DecodeTotp returns the timed-based OTP for the given based64 encoded message
// and the OTP issuer.
func DecodeTotp(enc, issuer string) (*twofactor.Totp, error) {
	dec, err := base64.URLEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	return twofactor.TOTPFromBytes(dec, issuer)
}

// EncodeTotp returns a base64 encoded message for the given timed-based OTP.
func EncodeTotp(totp *twofactor.Totp) (string, error) {
	b, err := totp.ToBytes()
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// readKeysFromConfig returns the private and public key, and JWK certificate
// for the given configuration.
func readKeysFromConfig(cfg Config) ([]byte, []byte, jwk.Certificate, error) {
	privateKey, err := os.ReadFile(cfg.PrivateKey)
	if err != nil {
		return nil, nil, jwk.Certificate{}, fmt.Errorf(
			"Private key not found ('%s')",
			cfg.PrivateKey,
		)
	}
	cert := jwk.Certificate{}
	certFd, err := os.Open(cfg.Certificate)
	if err != nil {
		return nil, nil, jwk.Certificate{}, fmt.Errorf(
			"Certificate not found ('%s')",
			cfg.Certificate,
		)
	}
	cert, err = jwk.NewCertificate(certFd)
	if err != nil {
		return nil, nil, jwk.Certificate{}, fmt.Errorf(
			"Failed to parse certificate; %s",
			err,
		)
	}
	publicKey, err := cert.PublicKey()
	if err != nil {
		return nil, nil, jwk.Certificate{}, fmt.Errorf(
			"Failed to parse certificate's public key; %s",
			err,
		)
	}
	return privateKey, publicKey, cert, nil
}

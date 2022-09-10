package controller

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	commoncrypto "github.com/crossedbot/common/golang/crypto"
	"github.com/crossedbot/simplejwt"
	"github.com/crossedbot/simplejwt/algorithms"
	"github.com/crossedbot/simplejwt/jwk"
	middleware "github.com/crossedbot/simplemiddleware"
	"github.com/sec51/twofactor"
	"golang.org/x/crypto/bcrypt"

	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	AccessTokenExpiration      = 1 * time.Hour
	RefreshTokenExpiration     = 24 * time.Hour
	TransactionTokenExpiration = 5 * time.Minute
)

var (
	ErrRequestGrant = errors.New("Request does not match grant")
)

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

func VerifyPassword(hashedPass, pass string) error {
	var msg error
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(pass))
	if err != nil {
		msg = errors.New("login or password is incorrect")
	}
	return msg
}

type TokenOptions struct {
	Grant       Grant
	TTL         time.Duration
	RefreshTTL  time.Duration
	SkipRefresh bool
}

func GenerateTokens(user models.User, pubKey, privKey []byte, options *TokenOptions) (string, string, error) {
	grant := GrantAuthenticated
	if options != nil && options.Grant != GrantUnknown {
		grant = options.Grant.Clean()
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
		"first":                user.FirstName,
		"last":                 user.LastName,
		middleware.ClaimUserId: user.UserId,
		"user_type":            user.UserType,
		"exp":                  time.Now().Local().Add(ttl).Unix(),
		middleware.ClaimGrant:  grant.String(),
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
			middleware.ClaimGrant:  GrantUsersRefresh.String(),
		}
		refreshTkn, err = simplejwt.New(refreshClaims,
			algorithms.AlgorithmRS256).Sign(privKey)
		if err != nil {
			return "", "", err
		}
	}
	return tkn, refreshTkn, nil
}

func DecodeTotp(enc, issuer string) (*twofactor.Totp, error) {
	dec, err := base64.URLEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	return twofactor.TOTPFromBytes(dec, issuer)
}

func EncodeTotp(totp *twofactor.Totp) (string, error) {
	b, err := totp.ToBytes()
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func ContainsGrant(grant Grant, r *http.Request) error {
	reqGrantStr, ok := r.Context().Value(middleware.ClaimGrant).(string)
	if !ok {
		return middleware.ErrGrantDataType
	}
	reqGrant, err := ToGrant(reqGrantStr)
	if err != nil {
		return err
	}
	if (reqGrant & grant) != grant {
		return ErrRequestGrant
	}
	return nil
}

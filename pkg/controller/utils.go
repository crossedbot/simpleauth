package controller

import (
	"encoding/base64"
	"errors"
	"time"

	commoncrypto "github.com/crossedbot/common/golang/crypto"
	"github.com/crossedbot/simplejwt"
	"github.com/crossedbot/simplejwt/algorithms"
	"github.com/sec51/twofactor"
	"golang.org/x/crypto/bcrypt"

	"github.com/crossedbot/simpleauth/pkg/jwk"
	"github.com/crossedbot/simpleauth/pkg/models"
)

const (
	AccessTokenExpiration  = 1  // hours
	RefreshTokenExpiration = 24 // hours
)

func HashPassword(pass string) (string, error) {
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

func GenerateTokens(user models.User, publicKey, privateKey []byte) (string, string, error) {
	claims := simplejwt.CustomClaims{
		"email":     user.Email,
		"first":     user.FirstName,
		"last":      user.LastName,
		ClaimUserID: user.UserId,
		"user_type": user.UserType,
		"exp": time.Now().Local().Add(
			time.Hour * time.Duration(AccessTokenExpiration),
		).Unix(),
	}
	jwt := simplejwt.New(claims, algorithms.AlgorithmRS256)
	jwt.Header["kid"] = jwk.EncodeToString(commoncrypto.KeyId(publicKey))
	tkn, err := jwt.Sign(privateKey)
	if err != nil {
		return "", "", err
	}
	refreshClaims := simplejwt.CustomClaims{
		ClaimUserID: user.UserId,
		"exp": time.Now().Local().Add(
			time.Hour * time.Duration(RefreshTokenExpiration),
		).Unix(),
	}
	refreshTkn, err := simplejwt.New(refreshClaims, algorithms.AlgorithmRS256).Sign(privateKey)
	if err != nil {
		return "", "", err
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

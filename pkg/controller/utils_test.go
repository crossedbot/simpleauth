package controller

import (
	"context"
	"crypto"
	"encoding/base64"
	"net/http"
	"testing"

	jwt "github.com/crossedbot/simplejwt"
	middleware "github.com/crossedbot/simplemiddleware"
	"github.com/sec51/twofactor"
	"github.com/stretchr/testify/require"

	"github.com/crossedbot/simpleauth/pkg/models"
)

func TestHashPassword(t *testing.T) {
	pass := "helloworld"
	hash, err := HashPassword(pass)
	require.Nil(t, err)
	require.NotEqual(t, pass, hash)
}

func TestVerifyPassword(t *testing.T) {
	pass := "helloworld"
	hash, err := HashPassword(pass)
	require.Nil(t, err)
	require.NotEqual(t, pass, hash)
	err = VerifyPassword(hash, pass)
	require.Nil(t, err)
}

func TestGenerateTokens(t *testing.T) {
	user := models.User{
		Email:     "hello@world.com",
		FirstName: "hello",
		LastName:  "world",
		UserId:    "abc123",
		UserType:  models.BaseUserType.String(),
	}
	tkn, rTkn, err := GenerateTokens(user, []byte(testPublicKey),
		[]byte(testPrivateKey), nil)
	require.Nil(t, err)
	parsedTkn, err := jwt.Parse(tkn)
	require.Nil(t, err)
	err = parsedTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	parsedRTkn, err := jwt.Parse(rTkn)
	require.Nil(t, err)
	err = parsedRTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
}

func TestDecodeTotp(t *testing.T) {
	account := "hello@world.com"
	issuer := "simpleauth"
	hash := crypto.SHA1
	totp, err := twofactor.NewTOTP(account, issuer, hash, DefaultTotpDigits)
	require.Nil(t, err)
	b, err := totp.ToBytes()
	require.Nil(t, err)
	expected := base64.URLEncoding.EncodeToString(b)
	totp2, err := DecodeTotp(expected, issuer)
	require.Nil(t, err)
	b2, err := totp2.ToBytes()
	require.Nil(t, err)
	actual := base64.URLEncoding.EncodeToString(b2)
	require.Equal(t, expected, actual)
}

func TestEncodeTotp(t *testing.T) {
	account := "hello@world.com"
	issuer := "simpleauth"
	hash := crypto.SHA1
	totp, err := twofactor.NewTOTP(account, issuer, hash, DefaultTotpDigits)
	require.Nil(t, err)
	expected, err := totp.ToBytes()
	require.Nil(t, err)
	enc, err := EncodeTotp(totp)
	require.Nil(t, err)
	dec, err := base64.URLEncoding.DecodeString(enc)
	require.Nil(t, err)
	totp2, err := twofactor.TOTPFromBytes(dec, issuer)
	require.Nil(t, err)
	actual, err := totp2.ToBytes()
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestContainsGrant(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "hello.world/test", nil)
	require.Nil(t, err)
	ctx := req.Context()
	ctx = context.WithValue(ctx, middleware.ClaimGrantType, GrantTypeAuthenticated.String())
	req = req.WithContext(ctx)
	require.Nil(t, ContainsGrant(GrantTypeOTP, req))
	require.Nil(t, ContainsGrant(GrantTypeOTPValidate, req))
	require.Nil(t, ContainsGrant(GrantTypeUsersRefresh, req))

	ctx = req.Context()
	ctx = context.WithValue(ctx, middleware.ClaimGrantType, GrantTypeUsersRefresh.String())
	req = req.WithContext(ctx)
	require.NotNil(t, ContainsGrant(GrantTypeOTP, req))
	require.NotNil(t, ContainsGrant(GrantTypeOTPValidate, req))
	require.Nil(t, ContainsGrant(GrantTypeUsersRefresh, req))
}

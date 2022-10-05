package controller

import (
	"crypto"
	"encoding/base64"
	"testing"
	"time"

	jwt "github.com/crossedbot/simplejwt"
	middleware "github.com/crossedbot/simplemiddleware"
	"github.com/sec51/twofactor"
	"github.com/stretchr/testify/require"

	"github.com/crossedbot/simpleauth/pkg/grants"
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
		Email:    "hello@world.com",
		UserId:   "abc123",
		UserType: models.BaseUserType.String(),
	}

	// Basic usage
	options := &TokenOptions{}
	tkn, rTkn, err := GenerateTokens(user, []byte(testPublicKey),
		[]byte(testPrivateKey), options)
	require.Nil(t, err)
	parsedTkn, err := jwt.Parse(tkn)
	require.Nil(t, err)
	err = parsedTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	parsedRTkn, err := jwt.Parse(rTkn)
	require.Nil(t, err)
	err = parsedRTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	require.Equal(t, user.UserId,
		parsedTkn.Claims.Get(middleware.ClaimUserId))
	require.Equal(t, grants.GrantAuthenticated.Short(),
		parsedTkn.Claims.Get(middleware.ClaimGrant))
	require.Equal(t, user.UserId,
		parsedRTkn.Claims.Get(middleware.ClaimUserId))
	require.Equal(t, grants.GrantUsersRefresh.Short(),
		parsedRTkn.Claims.Get(middleware.ClaimGrant))

	// Options usage
	options.Grant = grants.GrantOTPValidate
	options.TTL = TransactionTokenExpiration
	options.RefreshTTL = 1 * time.Minute
	options.SkipRefresh = false
	tkn, rTkn, err = GenerateTokens(user, []byte(testPublicKey),
		[]byte(testPrivateKey), options)
	require.Nil(t, err)
	parsedTkn, err = jwt.Parse(tkn)
	require.Nil(t, err)
	err = parsedTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	parsedRTkn, err = jwt.Parse(rTkn)
	require.Nil(t, err)
	err = parsedRTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	require.Equal(t, user.UserId,
		parsedTkn.Claims.Get(middleware.ClaimUserId))
	require.Equal(t, grants.GrantOTPValidate.Short(),
		parsedTkn.Claims.Get(middleware.ClaimGrant))
	require.Equal(t, user.UserId,
		parsedRTkn.Claims.Get(middleware.ClaimUserId))
	require.Equal(t, grants.GrantUsersRefresh.Short(),
		parsedRTkn.Claims.Get(middleware.ClaimGrant))

	// Skipping a refresh token
	options.SkipRefresh = true
	tkn, rTkn, err = GenerateTokens(user, []byte(testPublicKey),
		[]byte(testPrivateKey), options)
	require.Nil(t, err)
	require.Equal(t, "", rTkn)
	err = parsedTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	require.Equal(t, user.UserId,
		parsedTkn.Claims.Get(middleware.ClaimUserId))
	require.Equal(t, grants.GrantOTPValidate.Short(),
		parsedTkn.Claims.Get(middleware.ClaimGrant))

	// Custom grants
	err = grants.SetCustomGrants([]string{"this", "that", "those"})
	require.Nil(t, err)
	options = &TokenOptions{}
	tkn, rTkn, err = GenerateTokens(user, []byte(testPublicKey),
		[]byte(testPrivateKey), options)
	require.Nil(t, err)
	parsedTkn, err = jwt.Parse(tkn)
	require.Nil(t, err)
	err = parsedTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	parsedRTkn, err = jwt.Parse(rTkn)
	require.Nil(t, err)
	err = parsedRTkn.Valid([]byte(testPublicKey))
	require.Nil(t, err)
	require.Equal(t, user.UserId,
		parsedTkn.Claims.Get(middleware.ClaimUserId))
	expectedGrantsStr := grants.Grant(grants.GrantAuthenticated | 0x070000)
	require.Equal(t, expectedGrantsStr.Short(),
		parsedTkn.Claims.Get(middleware.ClaimGrant))
	require.Equal(t, user.UserId,
		parsedRTkn.Claims.Get(middleware.ClaimUserId))
	require.Equal(t, grants.GrantUsersRefresh.Short(),
		parsedRTkn.Claims.Get(middleware.ClaimGrant))
	grants.SetCustomGrants([]string{})
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

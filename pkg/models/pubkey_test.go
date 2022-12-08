package models

import (
	"testing"

	"github.com/crossedbot/simplejwt/algorithms"
	"github.com/stretchr/testify/require"

	"github.com/crossedbot/simpleauth/pkg/auth"
)

func TestBase64URLEncode(t *testing.T) {
	b := []byte("Hello World!")
	expected := "SGVsbG8gV29ybGQh"
	require.Equal(t, expected, Base64URLEncode(b))
}

func TestBase64URLDecode(t *testing.T) {
	enc := "SGVsbG8gV29ybGQh"
	expected := []byte("Hello World!")
	actual, err := Base64URLDecode(enc)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestEncode(t *testing.T) {
	b := []byte("This is a long string that should have padding")
	expected := "VGhpcyBpcyBhIGxvbmcgc3RyaW5nIHRoYXQgc2hvdWxkIGhhdmUgcGFkZGluZw"
	require.Equal(t, expected, Encode(b))
}

func TestDecode(t *testing.T) {
	enc := "VGhpcyBpcyBhIGxvbmcgc3RyaW5nIHRoYXQgc2hvdWxkIGhhdmUgcGFkZGluZw"
	expected := []byte("This is a long string that should have padding")
	actual, err := Decode(enc)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestEncodeJSON(t *testing.T) {
	data := struct {
		A string
		B int
	}{
		A: "hello",
		B: 123,
	}
	expected := "eyJBIjoiaGVsbG8iLCJCIjoxMjN9"
	actual, err := EncodeJSON(data)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestDecodeJSON(t *testing.T) {
	type T struct {
		A string
		B int
	}
	enc := "eyJBIjoiaGVsbG8iLCJCIjoxMjN9"
	expected := T{
		A: "hello",
		B: 123,
	}
	actual := T{}
	err := DecodeJSON(enc, &actual)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestSignedPublicKeySigningAlgorithm(t *testing.T) {
	signedKey := SignedPublicKey{
		KTy: auth.KTyRSA.String(),
		Alg: auth.AlgSHA256.String(),
	}
	expected := algorithms.AlgorithmRS256
	actual, err := signedKey.SigningAlgorithm()
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestSignedPublicKeySigningString(t *testing.T) {
	signedKey := SignedPublicKey{
		Id:        "abc123",
		KTy:       "RSA",
		Alg:       "SHA256",
		User:      "user",
		PublicKey: "notakey",
		Signature: "missingsig",
	}
	expected := "eyJpZCI6ImFiYzEyMyIsImFsZyI6IlNIQTI1NiIsImt0eSI6IlJTQSIsInVzZXIiOiJ1c2VyIiwicHVibGljX2tleSI6Im5vdGFrZXkifQ"
	actual, err := signedKey.SigningString()
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestSignedPublicKeyValid(t *testing.T) {
	signedKey := SignedPublicKey{
		Id:        "abc123",
		KTy:       "HMAC",
		Alg:       "SHA256",
		User:      "user",
		PublicKey: "notakey",
		Signature: "",
	}
	key := []byte("supersecret")
	ss, err := signedKey.SigningString()
	require.Nil(t, err)
	sig, err := algorithms.AlgorithmHS256.Sign(ss, key)
	require.Nil(t, err)
	signedKey.Signature = Encode(sig)
	require.Nil(t, signedKey.Valid(key))
	require.NotNil(t, signedKey.Valid([]byte("notkey")))
}

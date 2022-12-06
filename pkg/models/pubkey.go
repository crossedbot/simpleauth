package models

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/crossedbot/simplejwt/algorithms"

	"github.com/crossedbot/simpleauth/pkg/auth"
)

func Base64URLEncode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

func Base64URLDecode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

func Encode(v []byte) string {
	return strings.TrimRight(Base64URLEncode(v), "=")
}

func Decode(s string) ([]byte, error) {
	if l := len(s) % 4; l > 0 {
		padding := strings.Repeat("=", 4-l)
		s = fmt.Sprintf("%s%s", s, padding)
	}
	return Base64URLDecode(s)
}

func EncodeJSON(data interface{}) (string, error) {
	v, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return Encode(v), nil
}

func DecodeJSON(s string, v interface{}) error {
	b, err := Decode(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// SignedPublicKey respresents a public key authentication request.
type SignedPublicKey struct {
	Id        string `json:"id"`
	Alg       string `json:"alg"`
	KTy       string `json:"kty"`
	User      string `json:"user"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// SigningAlgorithm returns the signing algorithm of the signed public key.
func (key *SignedPublicKey) SigningAlgorithm() (algorithms.SigningAlgorithm, error) {
	alg := auth.ToAlg(key.Alg)
	kty := auth.ToKTy(key.KTy)
	return auth.GetSigningAlgorithm(kty, alg)
}

// SigningString returns the encoded signing string of the signed public key.
func (key *SignedPublicKey) SigningString() (string, error) {
	t := struct {
		Id        string `json:"id"`
		Alg       string `json:"alg"`
		KTy       string `json:"kty"`
		User      string `json:"user"`
		PublicKey string `json:"public_key"`
	}{
		Id:        key.Id,
		Alg:       key.Alg,
		KTy:       key.KTy,
		User:      key.User,
		PublicKey: key.PublicKey,
	}
	return EncodeJSON(t)
}

// Valid verifies the signed public key's signature using the given secret.
func (key *SignedPublicKey) Valid(secret []byte) error {
	sa, err := key.SigningAlgorithm()
	if err != nil {
		return err
	}
	ss, err := key.SigningString()
	if err != nil {
		return err
	}
	sig, err := Decode(key.Signature)
	if err != nil {
		return err
	}
	return sa.Valid(ss, sig, secret)
}

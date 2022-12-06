package auth

import (
	"testing"

	"github.com/crossedbot/simplejwt/algorithms"
	"github.com/stretchr/testify/require"
)

func TestToKTy(t *testing.T) {
	tests := []struct {
		Name     string
		Expected KTy
	}{
		{
			Name:     "unknown",
			Expected: KTyUnknown,
		}, {
			Name:     "ECDSA",
			Expected: KTyECDSA,
		}, {
			Name:     "HmAc",
			Expected: KTyHMAC,
		}, {
			Name:     "RSA",
			Expected: KTyRSA,
		}, {
			Name:     "RSAPSS",
			Expected: KTyRSAPSS,
		}, {
			Name:     "ed25519",
			Expected: KTyEd25519,
		},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, ToKTy(test.Name))
	}
}

func TestKTyString(t *testing.T) {
	tests := []struct {
		KTy      KTy
		Expected string
	}{
		{
			KTy:      KTyUnknown,
			Expected: "UNKNOWN",
		}, {
			KTy:      KTyECDSA,
			Expected: "ECDSA",
		}, {
			KTy:      KTyHMAC,
			Expected: "HMAC",
		}, {
			KTy:      KTyRSA,
			Expected: "RSA",
		}, {
			KTy:      KTyRSAPSS,
			Expected: "RSAPSS",
		}, {
			KTy:      KTyEd25519,
			Expected: "ED25519",
		},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, test.KTy.String())
	}
}

func TestToAlg(t *testing.T) {
	tests := []struct {
		Name     string
		Expected Alg
	}{
		{
			Name:     "unknown",
			Expected: AlgUnknown,
		}, {
			Name:     "ShA256",
			Expected: AlgSHA256,
		}, {
			Name:     "sha384",
			Expected: AlgSHA384,
		}, {
			Name:     "SHA512",
			Expected: AlgSHA512,
		},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, ToAlg(test.Name))
	}
}

func TestAlgString(t *testing.T) {
	tests := []struct {
		Alg      Alg
		Expected string
	}{
		{
			Alg:      AlgUnknown,
			Expected: "UNKNOWN",
		}, {
			Alg:      AlgSHA256,
			Expected: "SHA256",
		}, {
			Alg:      AlgSHA384,
			Expected: "SHA384",
		}, {
			Alg:      AlgSHA512,
			Expected: "SHA512",
		},
	}
	for _, test := range tests {
		require.Equal(t, test.Expected, test.Alg.String())
	}
}

func TestGetSigningAlgorithm(t *testing.T) {
	tests := []struct {
		KTy      KTy
		Alg      Alg
		Expected algorithms.SigningAlgorithm
		Error    bool
	}{
		{
			KTy:      KTyECDSA,
			Alg:      AlgSHA384,
			Expected: algorithms.AlgorithmEC384,
			Error:    false,
		}, {
			KTy:      KTyHMAC,
			Alg:      AlgSHA256,
			Expected: algorithms.AlgorithmHS256,
			Error:    false,
		}, {
			KTy:      KTyRSA,
			Alg:      AlgSHA512,
			Expected: algorithms.AlgorithmRS512,
			Error:    false,
		}, {
			KTy:      KTyEd25519,
			Alg:      AlgSHA256,
			Expected: nil,
			Error:    true,
		},
	}
	for _, test := range tests {
		actual, err := GetSigningAlgorithm(test.KTy, test.Alg)
		require.Equal(t, test.Error, err != nil)
		require.Equal(t, test.Expected, actual)
	}
}

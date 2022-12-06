package auth

import (
	"fmt"

	"github.com/crossedbot/simplejwt/algorithms"
)

type KTy int

const (
	KTyUnknown KTy = 0
	KTyECDSA   KTy = 1
	KTyHMAC    KTy = 2
	KTyRSA     KTy = 3
	KTyRSAPSS  KTy = 4
	KTyEd25519 KTy = 5
)

var (
	KTyNames = map[KTy]string{
		KTyUnknown: "UNKNOWN",
		KTyECDSA:   "ECDSA",
		KTyHMAC:    "HMAC",
		KTyRSA:     "RSA",
		KTyRSAPSS:  "RSAPSS",
		KTyEd25519: "ED25519",
	}
	KTyValues = map[string]KTy{
		"UNKNOWN": KTyUnknown,
		"ECDSA":   KTyECDSA,
		"HMAC":    KTyHMAC,
		"RSA":     KTyRSA,
		"RSAPSS":  KTyRSAPSS,
		"ED25519": KTyEd25519,
	}
)

func ToKTy(s string) KTy {
	kty, ok := KTyValues[s]
	if !ok {
		return KTyUnknown
	}
	return kty
}

func (kty KTy) String() string {
	if int(kty) < len(KTyNames) {
		return KTyNames[kty]
	}
	return KTyNames[KTyUnknown]
}

type Alg int

const (
	AlgUnknown Alg = 0
	AlgSHA256  Alg = 1
	AlgSHA384  Alg = 2
	AlgSHA512  Alg = 3
)

var (
	AlgNames = map[Alg]string{
		AlgUnknown: "UNKNOWN",
		AlgSHA256:  "SHA256",
		AlgSHA384:  "SHA384",
		AlgSHA512:  "SHA512",
	}
	AlgValues = map[string]Alg{
		"UNKNOWN": AlgUnknown,
		"SHA256":  AlgSHA256,
		"SHA384":  AlgSHA384,
		"SHA512":  AlgSHA512,
	}
)

func ToAlg(s string) Alg {
	alg, ok := AlgValues[s]
	if !ok {
		return AlgUnknown
	}
	return alg
}

func (alg Alg) String() string {
	if int(alg) < len(AlgNames) {
		return AlgNames[alg]
	}
	return AlgNames[AlgUnknown]
}

var KeyAlgorithms = map[KTy]map[Alg]algorithms.SigningAlgorithm{
	KTyECDSA: {
		AlgSHA256: algorithms.AlgorithmEC256,
		AlgSHA384: algorithms.AlgorithmEC384,
		AlgSHA512: algorithms.AlgorithmEC512,
	},
	/*
		KTyEd25519: {
			AlgSHA256: algorithms.AlgorithmEd256,
			AlgSHA384: algorithms.AlgorithmEd384,
			AlgSHA512: algorithms.AlgorithmEd512,
		},
	*/
	KTyHMAC: {
		AlgSHA256: algorithms.AlgorithmHS256,
		AlgSHA384: algorithms.AlgorithmHS384,
		AlgSHA512: algorithms.AlgorithmHS512,
	},
	KTyRSA: {
		AlgSHA256: algorithms.AlgorithmRS256,
		AlgSHA384: algorithms.AlgorithmRS384,
		AlgSHA512: algorithms.AlgorithmRS512,
	},
}

func GetSigningAlgorithm(kty KTy, alg Alg) (algorithms.SigningAlgorithm, error) {
	sa := KeyAlgorithms[kty][alg]
	if sa == nil {
		return nil, fmt.Errorf(
			"No signing algorithm matches key type '%s', and "+
				"algorithm '%s'",
			kty.String(), alg.String(),
		)
	}
	return sa, nil
}

package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/crossedbot/simpleauth/internal/pkg/jwk"
	"github.com/stretchr/testify/require"

	"github.com/crossedbot/simplejwt/algorithms"
)

func TestSetDatabase(t *testing.T) {
	ctx := context.Background()
	ctr := &controller{ctx, nil, nil, jwk.Certificate{}, ""}
	require.Nil(t, ctr.client)
	ctr.SetDatabase("mongodb://127.0.0.1:27017")
	require.NotNil(t, ctr.client)
}

func TestSetAuthPrivateKey(t *testing.T) {
	ctx := context.Background()
	ctr := &controller{ctx, nil, nil, jwk.Certificate{}, ""}
	expected := []byte("Hello World")
	ctr.SetAuthPrivateKey(bytes.NewBuffer(expected))
	require.Equal(t, expected, ctr.privateKey)
}

func TestSetAuthCert(t *testing.T) {
	publicKey, err := algorithms.AlgorithmRS256.PublicKey([]byte(testPublicKey))
	require.Nil(t, err)
	privateKey, err := algorithms.AlgorithmRS256.PrivateKey([]byte(testPrivateKey))
	require.Nil(t, err)
	subject := pkix.Name{Organization: []string{"SimpleAuth"}}
	ipAddrs := []string{"127.0.0.1", "::1"}
	dnsNames := []string{"localhost"}
	template, err := jwk.NewTemplate(subject, ipAddrs, dnsNames)
	require.Nil(t, err)
	der, err := x509.CreateCertificate(
		rand.Reader,
		template, template,
		publicKey, privateKey,
	)
	require.Nil(t, err)
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ctx := context.Background()
	ctr := &controller{ctx, nil, nil, jwk.Certificate{}, ""}
	ctr.SetAuthCert(bytes.NewBuffer(certPem))
	expected, err := jwk.NewCertificate(bytes.NewBuffer(certPem))
	require.Equal(t, expected, ctr.cert)
}

func TestSetTotpIssuer(t *testing.T) {
	ctx := context.Background()
	ctr := &controller{ctx, nil, nil, jwk.Certificate{}, ""}
	expected := "Hello World"
	ctr.SetTotpIssuer(expected)
	require.Equal(t, expected, ctr.issuer)
}

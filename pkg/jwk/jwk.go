package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"time"

	commoncrypto "github.com/crossedbot/common/golang/crypto"
)

// Jwk represents a JSON Web Key
type Jwk struct {
	Alg string   `json:"alg"` // Version of cryptographic algorithm
	KTy string   `json:"kty"` // Cryptographic algorithm
	KID string   `json:"kid"` // Key ID
	Use string   `json:"use"` // Use of key
	N   string   `json:"n"`   // The modulas of the RSA key
	E   string   `json:"e"`   // The exponent of the RSA key
	X5C []string `json:"x5c"` // The x.509 certificate chain
	X5T string   `json:"x5t"` // Thumbprint of x.509 cert (SHA-1)
}

// Jwks represent a list of JSON Web Keys
type Jwks struct {
	Keys []Jwk `json:"keys"`
}

// Certificate represents a JWK certificate
type Certificate struct {
	publicKey   *rsa.PublicKey
	certificate *x509.Certificate
}

// NewCertificate returns a new Certificate from the given PEM encoded cert
func NewCertificate(cert io.Reader) (Certificate, error) {
	b, err := ioutil.ReadAll(cert)
	if err != nil {
		return Certificate{}, err
	}
	block, _ := pem.Decode(b)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, err
	}
	pubKey, ok := parsed.PublicKey.(*rsa.PublicKey)
	if !ok {
		return Certificate{}, errors.New("failed to assert public key")
	}
	return Certificate{pubKey, parsed}, nil
}

// ToJwk returns the JSON Web Key (JWK) of the certificate
func (cert Certificate) ToJwk() (Jwk, error) {
	kid, err := cert.KeyID()
	if err != nil {
		return Jwk{}, err
	}
	x5c, err := cert.X5C()
	if err != nil {
		return Jwk{}, err
	}
	x5t, err := cert.X5T()
	if err != nil {
		return Jwk{}, err
	}
	return Jwk{
		Alg: "RSA256",
		KTy: "RSA",
		KID: kid,
		Use: "sig",
		N:   cert.N(),
		E:   cert.E(),
		X5C: x5c,
		X5T: x5t,
	}, nil
}

// ToPem returns the Certificate in PEM format
func (cert Certificate) ToPem() (string, error) {
	der := cert.certificate.Raw
	certPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	return string(certPEMBlock), nil
}

// KeyID returns the key identity of the Certificate's RSA public key
func (cert Certificate) KeyID() (string, error) {
	pemBlock, err := cert.PublicKey()
	if err != nil {
		return "", err
	}
	return EncodeToString(commoncrypto.KeyId(pemBlock)), nil
}

// E returns the encoded modulas part of the RSA public key
func (cert Certificate) N() string {
	return EncodeToString(cert.publicKey.N.Bytes())
}

// E returns the encoded exponent part of the RSA public key
func (cert Certificate) E() string {
	e := make([]byte, 4)
	binary.LittleEndian.PutUint32(e, uint32(cert.publicKey.E))
	return EncodeToString(e)
}

// X5C return the x.509 certificate chain in PEM form
func (cert Certificate) X5C() ([]string, error) {
	certPem, err := cert.ToPem()
	if err != nil {
		return []string{}, err
	}
	certPem = strings.TrimSpace(certPem)
	certPem = strings.TrimPrefix(certPem, "-----BEGIN CERTIFICATE-----")
	certPem = strings.TrimSuffix(certPem, "-----END CERTIFICATE-----")
	certPem = strings.TrimSpace(certPem)
	return []string{certPem}, nil
}

// X5T returns the encoded SHA-1 sum of the Certificate
func (cert Certificate) X5T() (string, error) {
	h := sha1.New()
	h.Write(cert.certificate.Raw)
	sum := h.Sum(nil)
	return EncodeToString(sum[:]), nil
}

// PublicKey returns the Certificate's RSA public key in PEM format
func (cert Certificate) PublicKey() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(cert.publicKey)
	if err != nil {
		return nil, err
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return pemBlock, nil
}

// NewSerialNumber returns a new serial number to be used in creating a
// Certificate
func NewSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// NewTemplate returns a new Certificate using default values
func NewTemplate(subject pkix.Name, ipAddrs, dnsNames []string) (*x509.Certificate, error) {
	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	keyUsage := x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDigitalSignature |
		x509.KeyUsageCertSign
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, s := range ipAddrs {
		if ip := net.ParseIP(s); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	for _, name := range dnsNames {
		template.DNSNames = append(template.DNSNames, name)
	}
	return &template, nil
}

// EncodeToString encodes a string to be used in a JWK
func EncodeToString(b []byte) string {
	enc := base64.URLEncoding.EncodeToString(b)
	enc = strings.TrimRight(enc, "=")
	enc = strings.ReplaceAll(enc, "+", "-")
	enc = strings.ReplaceAll(enc, "/", "_")
	return enc
}

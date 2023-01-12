package certificate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	ecPrivateKeyBlockType  = "EC PRIVATE KEY"
	rsaPrivateKeyBlockType = "RSA PRIVATE KEY"
)

type Manager struct {
	// certificate is the device certificate after registration
	certificate *x509.Certificate
	// key is the certificate private key
	key crypto.PrivateKey
	// csrKey is the key used to create the CSR.
	csrKey         crypto.PrivateKey
	privateKeyType string
	rootCA         *x509.CertPool
	// registrationCertificate is the certificate used to register
	registrationCertificate *x509.Certificate
	// registrationPrivateKey is the private key of the registration certificate
	registrationPrivateKey crypto.PrivateKey
}

func New(caRootBlock [][]byte, registrationCertificate, registrationPrivateKey []byte) (*Manager, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("cannot copy system certificate pool: %w", err)
	}
	for _, data := range caRootBlock {
		pool.AppendCertsFromPEM(data)
	}

	c := &Manager{
		rootCA: pool,
	}

	regCert, regPrivateKey, keyType, err := c.decode(registrationCertificate, registrationPrivateKey)
	if err != nil {
		return nil, err
	}

	c.registrationCertificate = regCert
	c.registrationPrivateKey = regPrivateKey
	c.privateKeyType = keyType

	return c, nil
}

// Certificates set a new certificate and a private key.
func (c *Manager) SetCertificate(cert, privateKey []byte) error {
	newCert, key, keyType, err := c.decode(cert, privateKey)
	if err != nil {
		return err
	}

	if keyType != c.registrationPrivateKey {
		return fmt.Errorf("registration key type %q does not match the key provided %q", c.privateKeyType, keyType)
	}

	c.certificate = newCert
	c.key = key

	return nil
}

func (c *Manager) RollbackCertificate() {
	c.certificate = nil
	c.key = nil
}

// Signature returns the client certificate signature.
func (c *Manager) Signature() []byte {
	return c.certificate.Signature[:]
}

func (c *Manager) IsRegistrationCertificate() bool {
	return strings.HasPrefix(c.certificate.Subject.CommonName, "registration")
}

// GetCertificates returns the CA certificate, client certificate and private key.
func (c *Manager) GetCertificates() (*x509.CertPool, *x509.Certificate, crypto.PrivateKey) {
	if c.certificate == nil || c.key == nil {
		return c.rootCA, c.registrationCertificate, c.registrationPrivateKey
	}
	return c.rootCA, c.certificate, c.key
}

func (c *Manager) GenerateCSR(deviceID string) ([]byte, []byte, error) {
	var csrTemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s.home.net", deviceID),
			// Operator will add metadata on this subject, like namespace
		},
	}

	key, err := c.generateKey(c.privateKeyType)
	if err != nil {
		return nil, nil, err
	}

	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrCertificate,
	})

	return csrPEM, c.marshalKeyToPem(key).Bytes(), nil
}

func (c *Manager) CommonName() string {
	return c.certificate.Subject.CommonName
}

func (c *Manager) WriteCertificate(certPath, keyPath string) error {
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: c.certificate.Raw})
	certOut.Close()

	err = ioutil.WriteFile(keyPath, c.marshalKeyToPem(c.key).Bytes(), 0600)
	if err != nil {
		return err
	}

	return nil
}

func (c *Manager) TLSConfig() (*tls.Config, error) {
	caRoot, cert, key := c.GetCertificates()

	config := tls.Config{
		RootCAs:    caRoot,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	privKeyPEM := new(bytes.Buffer)
	switch t := key.(type) {
	case *ecdsa.PrivateKey:
		res, _ := x509.MarshalECPrivateKey(t)
		_ = pem.Encode(privKeyPEM, &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: res,
		})
	case *rsa.PrivateKey:
		_ = pem.Encode(privKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		})
	}

	//
	cc, err := tls.X509KeyPair(certPEM.Bytes(), privKeyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("cannot create x509 key pair: %w", err)
	}

	config.Certificates = []tls.Certificate{cc}

	return &config, nil
}

func (c *Manager) marshalKeyToPem(key crypto.PrivateKey) *bytes.Buffer {
	privKeyPEM := new(bytes.Buffer)
	switch t := key.(type) {
	case *ecdsa.PrivateKey:
		res, _ := x509.MarshalECPrivateKey(t)
		_ = pem.Encode(privKeyPEM, &pem.Block{
			Type:  ecPrivateKeyBlockType,
			Bytes: res,
		})
	case *rsa.PrivateKey:
		_ = pem.Encode(privKeyPEM, &pem.Block{
			Type:  rsaPrivateKeyBlockType,
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		})
	}

	return privKeyPEM
}

func (c *Manager) generateKey(keyType string) (crypto.PrivateKey, error) {
	switch keyType {
	case ecPrivateKeyBlockType:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case rsaPrivateKeyBlockType:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unknown algorithm to create the key")
	}
}

func (c *Manager) decode(cert, key []byte) (*x509.Certificate, crypto.PrivateKey, string, error) {
	certPem, _ := pem.Decode(cert)
	if certPem == nil {
		return nil, nil, "", fmt.Errorf("cannot decode certificate from pem")
	}

	newCert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot parse certificate: %w", err)
	}

	// decode key
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, nil, "", fmt.Errorf("cannot private key")
	}

	var privateKey crypto.Signer

	switch block.Type {
	case ecPrivateKeyBlockType:
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case rsaPrivateKeyBlockType:
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unknown block type")
	}

	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot decode private key: %w", err)
	}
	return newCert, privateKey, block.Type, nil
}

package harness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"time"
)

// Certificate is a test-only TLS certificate an Operator might supply for
// the Agent API, as the PEM a Backend would hold, with a client that trusts
// it.
type Certificate struct {
	// CertificatePEM is the certificate chain: the leaf, then the CA that
	// signed it.
	CertificatePEM string
	// KeyPEM is the leaf's private key as PKCS #8 PEM. It is a Secret value:
	// it must never appear in TrustedCourier's output.
	KeyPEM string
	// Pool trusts the CA.
	Pool *x509.CertPool
}

// IssueCertificate issues a certificate for hosts (IP addresses or DNS
// names), signed by a throwaway CA, valid for validFor from now. The key is
// recorded as a Secret value that must not appear in TrustedCourier's
// output.
func (in *Installation) IssueCertificate(validFor time.Duration, hosts ...string) *Certificate {
	in.t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		in.t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TrustedCourier test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		in.t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		in.t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		in.t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TrustedCourier test Agent API"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		in.t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		in.t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	c := &Certificate{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		Pool:   pool,
	}
	in.mu.Lock()
	in.secretValues = append(in.secretValues, c.KeyPEM)
	in.mu.Unlock()
	return c
}

// Client returns an HTTP client that trusts the certificate's CA and speaks
// HTTP/2 when offered.
func (c *Certificate) Client() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: c.Pool},
			ForceAttemptHTTP2: true,
		},
	}
}

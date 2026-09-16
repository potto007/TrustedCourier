// Package certmanager is the certificate manager: it loads the Agent API's
// TLS certificate and key from a Backend, where they live as Courier Keys
// (ADR-0001, ADR-0006), and serves them to the TLS listener.
//
// v1 loads an Operator-supplied certificate. Nothing is loaded until the
// Backend answers, so the listener binds at once but no handshake completes
// until the certificate is loaded.
package certmanager

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/potto007/TrustedCourier/internal/secret"
)

// Fetch fetches the certificate and key PEM from their Backend. Whatever it
// returns, error or not, the Manager releases.
type Fetch func(ctx context.Context) (certificate, key *secret.Secret, err error)

// Retry cadence for a certificate that cannot be loaded.
const (
	minRetry = 250 * time.Millisecond
	maxRetry = 5 * time.Second
)

// errNotLoaded is what a TLS handshake gets while no certificate is loaded.
var errNotLoaded = errors.New("TrustedCourier's TLS certificate is not loaded yet")

// Manager holds the certificate the TLS listener serves.
type Manager struct {
	log  *slog.Logger
	cert atomic.Pointer[tls.Certificate]

	mu sync.Mutex
	// detail is why the certificate is not loaded, while it is not.
	detail string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New returns a Manager with no certificate loaded.
func New(log *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{log: log, ctx: ctx, cancel: cancel}
}

// Start fetches and parses the certificate in the background, retrying until
// it loads or Close is called.
func (m *Manager) Start(fetch Fetch) {
	m.mu.Lock()
	m.detail = "loading"
	m.mu.Unlock()
	m.wg.Go(func() { m.load(m.ctx, fetch) })
}

// TLSConfig returns the config the Agent API listener serves TLS with. HTTP/2
// is offered by ALPN. A handshake fails while no certificate is loaded, or
// once the loaded one has expired.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := m.cert.Load()
			if c == nil {
				return nil, errNotLoaded
			}
			if err := expired(c.Leaf, time.Now()); err != nil {
				return nil, err
			}
			return c, nil
		},
	}
}

// Status reports whether a usable certificate is loaded, and why not when
// it is not.
func (m *Manager) Status() (loaded bool, detail string) {
	if c := m.cert.Load(); c != nil {
		if err := expired(c.Leaf, time.Now()); err != nil {
			return false, err.Error()
		}
		return true, ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return false, m.detail
}

// Close stops loading. Call it once the listener has stopped.
func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
}

func (m *Manager) load(ctx context.Context, fetch Fetch) {
	retry := minRetry
	for {
		cert, err := fetchAndParse(ctx, fetch)
		if err == nil {
			m.cert.Store(cert)
			m.mu.Lock()
			m.detail = ""
			m.mu.Unlock()
			m.log.Info("TLS certificate loaded", "subject", cert.Leaf.Subject.String(), "not_after", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
			return
		}
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		m.detail = err.Error()
		m.mu.Unlock()
		m.log.Warn("TLS certificate not loaded; the Agent API completes no TLS handshake until it is", "error", err, "retry_in", retry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(retry*2, maxRetry)
	}
}

func fetchAndParse(ctx context.Context, fetch Fetch) (*tls.Certificate, error) {
	certificate, key, err := fetch(ctx)
	if certificate != nil {
		defer certificate.Release()
	}
	if key != nil {
		defer key.Release()
	}
	if err != nil {
		return nil, err
	}
	return parse(certificate, key)
}

// parse builds the certificate crypto/tls serves from the PEM in certificate
// and key. The PEM and DER copies of the key that parsing needs are wiped
// before it returns; the parsed private key itself stays on the heap, as
// crypto/tls signs with it there.
func parse(certificate, key *secret.Secret) (*tls.Certificate, error) {
	var certPEM bytes.Buffer
	if _, err := certificate.WriteTo(&certPEM); err != nil {
		return nil, fmt.Errorf("read the TLS certificate: %w", err)
	}
	chain, err := parseChain(certPEM.Bytes())
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, errors.New("the TLS certificate is not a valid X.509 certificate")
	}
	if err := expired(leaf, time.Now()); err != nil {
		return nil, err
	}
	private, err := parseKey(key)
	if err != nil {
		return nil, err
	}
	public, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !public.Equal(private.Public()) {
		return nil, errors.New("the TLS key does not match the TLS certificate")
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: private, Leaf: leaf}, nil
}

// parseChain returns the DER certificates in data, leaf first.
func parseChain(data []byte) ([][]byte, error) {
	if !isPEM(data) {
		return nil, errors.New("the TLS certificate is not PEM, or has data before the first PEM block")
	}
	var chain [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the TLS certificate has a PEM %q block, want only CERTIFICATE blocks", block.Type)
		}
		chain = append(chain, block.Bytes)
	}
	switch {
	case len(chain) == 0:
		return nil, errors.New("the TLS certificate is not PEM")
	case len(bytes.TrimSpace(data)) > 0:
		return nil, errors.New("the TLS certificate has data after the PEM blocks")
	}
	return chain, nil
}

// parseKey parses the private key PEM in key: PKCS #8, PKCS #1 (RSA), or SEC
// 1 (EC). Its heap copies are wiped before it returns.
func parseKey(key *secret.Secret) (crypto.Signer, error) {
	var keyPEM bytes.Buffer
	if _, err := key.WriteTo(&keyPEM); err != nil {
		return nil, fmt.Errorf("read the TLS key: %w", err)
	}
	data := keyPEM.Bytes()
	defer clear(data)
	if !isPEM(data) {
		return nil, errors.New("the TLS key is not PEM, or has data before the PEM block")
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the TLS key is not PEM")
	}
	defer clear(block.Bytes)
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("the TLS key has data after the PEM block")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("the TLS key is a PEM %q block, want PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY", block.Type)
	}
	if err != nil {
		return nil, errors.New("the TLS key is not a valid private key")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the TLS key is a %T, which cannot sign TLS handshakes", parsed)
	}
	return signer, nil
}

// expired reports why leaf is not valid at now, or nil.
func expired(leaf *x509.Certificate, now time.Time) error {
	switch {
	case now.After(leaf.NotAfter):
		return fmt.Errorf("the TLS certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(leaf.NotBefore):
		return fmt.Errorf("the TLS certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

func isPEM(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN "))
}

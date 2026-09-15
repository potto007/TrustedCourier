// Package certmanager is the Certificate Manager: it loads the Agent API's
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/potto007/TrustedCourier/internal/secret"
)

// Fetch fetches the certificate and key PEM from their Backend. The caller
// releases both.
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
// is offered by ALPN. A handshake fails while no certificate is loaded.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := m.cert.Load(); c != nil {
				return c, nil
			}
			return nil, errNotLoaded
		},
	}
}

// Status reports whether a certificate is loaded, and why not when it is
// not.
func (m *Manager) Status() (loaded bool, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cert.Load() != nil, m.detail
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
			m.mu.Lock()
			m.cert.Store(cert)
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
	if err != nil {
		return nil, err
	}
	defer certificate.Release()
	defer key.Release()
	return parse(certificate, key)
}

// parse builds the certificate crypto/tls serves from the PEM in certificate
// and key. The heap copies parsing needs are wiped before it returns; the
// parsed private key itself stays on the heap, as crypto/tls signs with it.
func parse(certificate, key *secret.Secret) (*tls.Certificate, error) {
	var certPEM, keyPEM bytes.Buffer
	if _, err := certificate.WriteTo(&certPEM); err != nil {
		return nil, fmt.Errorf("read the TLS certificate: %w", err)
	}
	if _, err := key.WriteTo(&keyPEM); err != nil {
		return nil, fmt.Errorf("read the TLS key: %w", err)
	}
	defer clear(keyPEM.Bytes())
	if !isPEM(certPEM.Bytes()) {
		return nil, errors.New("the TLS certificate is not PEM")
	}
	if !isPEM(keyPEM.Bytes()) {
		return nil, errors.New("the TLS key is not PEM")
	}
	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, describe(err)
	}
	if cert.Leaf == nil {
		// tls.X509KeyPair parses the leaf since Go 1.23; keep the guard.
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("the TLS certificate is not valid: %w", err)
		}
	}
	now := time.Now()
	switch {
	case now.After(cert.Leaf.NotAfter):
		return nil, fmt.Errorf("the TLS certificate expired at %s", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(cert.Leaf.NotBefore):
		return nil, fmt.Errorf("the TLS certificate is not valid until %s", cert.Leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	return &cert, nil
}

func isPEM(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN "))
}

// describe rewords tls.X509KeyPair's error in the config's terms. It never
// echoes key material: crypto/tls does not put any in its errors.
func describe(err error) error {
	if strings.Contains(err.Error(), "does not match") {
		return errors.New("the TLS key does not match the TLS certificate")
	}
	return fmt.Errorf("the TLS certificate and key are not usable: %w", err)
}

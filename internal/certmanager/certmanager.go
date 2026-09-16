// Package certmanager is the certificate manager: it loads the Agent API's
// TLS certificate and key from a Backend, where they live as Courier Keys
// (ADR-0001, ADR-0006), and serves them to the TLS listener. With ACME it
// also obtains the pair, stores it in the Backend, and renews it before it
// expires.
//
// Nothing is loaded until the Backend answers, so the listener binds at once
// but no handshake completes until the certificate is loaded.
package certmanager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/potto007/TrustedCourier/internal/acmecert"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/pemkey"
	"github.com/potto007/TrustedCourier/internal/secret"
	"github.com/potto007/TrustedCourier/sdk/plugin"
	"golang.org/x/crypto/acme"
)

// Fetch fetches the certificate and key PEM from their Backend. Whatever it
// returns, error or not, the Manager releases.
type Fetch func(ctx context.Context) (certificate, key *secret.Secret, err error)

// Retry cadence for a certificate that cannot be loaded from its Backend.
const (
	minRetry = 250 * time.Millisecond
	maxRetry = 5 * time.Second
)

// Retry cadence for a certificate that cannot be obtained from the ACME
// directory. Slow, since a CA rate-limits failed validations.
const (
	acmeMinRetry = 30 * time.Second
	acmeMaxRetry = time.Hour
)

// HTTP01Path is where HTTP-01 validations look for a challenge response.
const HTTP01Path = "/.well-known/acme-challenge/"

// errNotLoaded is what a TLS handshake gets while no certificate is loaded.
var errNotLoaded = errors.New("TrustedCourier's TLS certificate is not loaded yet")

// errNoChallenge is what a TLS-ALPN-01 validation gets for a domain no
// challenge is pending for.
var errNoChallenge = errors.New("no TLS-ALPN-01 challenge is pending for this name")

// Manager holds the certificate the TLS listener serves.
type Manager struct {
	log  *slog.Logger
	cert atomic.Pointer[tls.Certificate]

	mu sync.Mutex
	// detail is why the certificate is not loaded, while it is not.
	detail string
	// renewAt is when ACME renews the loaded certificate; zero without ACME.
	renewAt time.Time
	// renewalErr is why the last ACME renewal failed while a certificate
	// stays loaded, or empty.
	renewalErr string
	// alpn holds pending TLS-ALPN-01 challenge certificates by domain, and
	// http01 pending HTTP-01 responses by token.
	alpn   map[string]*tls.Certificate
	http01 map[string]string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Status is the certificate's state as the Operator sees it.
type Status struct {
	// Loaded says a usable certificate is served.
	Loaded bool
	// Detail is why no certificate is loaded, while none is.
	Detail string
	// NotAfter is when the loaded certificate expires.
	NotAfter time.Time
	// RenewAt is when ACME renews the loaded certificate. Zero without ACME.
	RenewAt time.Time
	// RenewalError is why the last ACME renewal failed while the certificate
	// stays loaded, or empty.
	RenewalError string
}

// New returns a Manager with no certificate loaded.
func New(log *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		log:    log,
		alpn:   map[string]*tls.Certificate{},
		http01: map[string]string{},
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start fetches and parses an Operator-supplied certificate in the
// background, retrying until it loads or Close is called.
func (m *Manager) Start(fetch Fetch) {
	m.setDetail("loading")
	m.wg.Go(func() { m.load(m.ctx, fetch) })
}

// ACME says where the certificate manager obtains the certificate and where
// it stores the pair.
type ACME struct {
	Issuer *acmecert.Issuer
	Keys   acmecert.KeyStore
	// Domains are the DNS names the certificate must cover.
	Domains          []string
	Certificate, Key config.CourierKey
}

// StartACME serves the pair stored in the Backend when it is usable, obtains
// one when it is not, and renews it at two thirds of its lifetime, all in
// the background until Close is called.
func (m *Manager) StartACME(a ACME) {
	m.setDetail("loading")
	m.wg.Go(func() { m.runACME(m.ctx, a) })
}

// TLSConfig returns the config the Agent API listener serves TLS with. HTTP/2
// is offered by ALPN, and TLS-ALPN-01 validations get their challenge
// certificate. A handshake fails while no certificate is loaded, or once the
// loaded one has expired.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
				m.mu.Lock()
				defer m.mu.Unlock()
				if c, ok := m.alpn[strings.ToLower(hello.ServerName)]; ok {
					return c, nil
				}
				return nil, errNoChallenge
			}
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

// HTTP01Handler serves pending HTTP-01 challenge responses under HTTP01Path
// and nothing else.
func (m *Manager) HTTP01Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.URL.Path, HTTP01Path)
		if !ok || token == "" || r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		m.mu.Lock()
		keyAuth, ok := m.http01[token]
		m.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(keyAuth))
	})
}

// PresentTLSALPN serves cert to TLS-ALPN-01 validations naming domain.
func (m *Manager) PresentTLSALPN(domain string, cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alpn[strings.ToLower(domain)] = cert
}

// RemoveTLSALPN stops serving the challenge certificate for domain.
func (m *Manager) RemoveTLSALPN(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.alpn, strings.ToLower(domain))
}

// PresentHTTP serves keyAuth at the HTTP-01 path for token.
func (m *Manager) PresentHTTP(token, keyAuth string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.http01[token] = keyAuth
}

// RemoveHTTP stops serving the HTTP-01 response for token.
func (m *Manager) RemoveHTTP(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.http01, token)
}

// Status reports whether a usable certificate is loaded, and why not when
// it is not.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.cert.Load(); c != nil {
		s := Status{Loaded: true, NotAfter: c.Leaf.NotAfter, RenewAt: m.renewAt, RenewalError: m.renewalErr}
		if err := expired(c.Leaf, time.Now()); err != nil {
			s.Loaded, s.Detail = false, err.Error()
		}
		return s
	}
	return Status{Detail: m.detail}
}

// Close stops loading and renewing. Call it once the listener has stopped.
func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
}

func (m *Manager) setDetail(detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detail = detail
}

// serve puts cert into service. The certificate and its renewal state are
// published together, so Status never pairs one with the other's past.
func (m *Manager) serve(cert *tls.Certificate, renewAt time.Time) {
	m.mu.Lock()
	m.cert.Store(cert)
	m.detail, m.renewalErr, m.renewAt = "", "", renewAt
	m.mu.Unlock()
	attrs := []any{"subject", cert.Leaf.Subject.String(), "not_after", cert.Leaf.NotAfter.UTC().Format(time.RFC3339)}
	if !renewAt.IsZero() {
		attrs = append(attrs, "renews_at", renewAt.UTC().Format(time.RFC3339))
	}
	m.log.Info("TLS certificate loaded", attrs...)
}

func (m *Manager) load(ctx context.Context, fetch Fetch) {
	retry := minRetry
	for {
		cert, err := fetchAndParse(ctx, fetch)
		if err == nil {
			m.serve(cert, time.Time{})
			return
		}
		if ctx.Err() != nil {
			return
		}
		m.setDetail(err.Error())
		m.log.Warn("TLS certificate not loaded; the Agent API completes no TLS handshake until it is", "error", err, "retry_in", retry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(retry*2, maxRetry)
	}
}

func (m *Manager) runACME(ctx context.Context, a ACME) {
	// The Backend may hold a pair from an earlier run. Wait for it to
	// answer before ordering, so a restart never re-issues.
	retry := minRetry
	for {
		cert, err := m.loadStored(ctx, a)
		if err == nil {
			if cert != nil {
				m.serve(cert, renewAt(cert.Leaf))
			}
			break
		}
		if ctx.Err() != nil {
			return
		}
		m.setDetail(err.Error())
		m.log.Warn("TLS certificate not loaded; the Agent API completes no TLS handshake until it is", "error", err, "retry_in", retry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(retry*2, maxRetry)
	}

	backoff := acmeMinRetry
	// earliest is the soonest the next order may be placed after an
	// issuance: a third of the lifetime, so a backdated or clock-skewed
	// certificate whose renewal time is already past never puts orders back
	// to back against the CA's rate limits.
	var earliest time.Time
	// pending is an issued pair the Backend has not stored yet; it is
	// stored on the next attempt rather than ordered again.
	var pending *acmecert.Issued
	for ctx.Err() == nil {
		current := m.cert.Load()
		if current != nil && pending == nil {
			due := renewAt(current.Leaf)
			if due.Before(earliest) {
				due = earliest
			}
			if time.Now().Before(due) {
				timer := time.NewTimer(time.Until(due))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				continue
			}
		}
		var err error
		if pending == nil {
			pending, err = m.obtain(ctx, a)
		}
		var cert *tls.Certificate
		if err == nil {
			cert, err = m.store(ctx, a, pending)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if current == nil {
				m.setDetail(err.Error())
				m.log.Warn("TLS certificate not obtained; the Agent API completes no TLS handshake until it is", "error", err, "retry_in", backoff)
			} else {
				m.mu.Lock()
				m.renewalErr = err.Error()
				m.mu.Unlock()
				m.log.Warn("TLS certificate not renewed; the loaded one is served until it expires", "error", err, "not_after", current.Leaf.NotAfter.UTC().Format(time.RFC3339), "retry_in", backoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, acmeMaxRetry)
			continue
		}
		clear(pending.Key)
		pending = nil
		backoff = acmeMinRetry
		earliest = time.Now().Add(lifetime(cert.Leaf) / 3)
		m.serve(cert, renewAt(cert.Leaf))
	}
}

// loadStored returns the pair the Backend holds when it is usable for a's
// domains, nil when the Backend holds none or an unusable one, and an error
// when the Backend did not answer.
func (m *Manager) loadStored(ctx context.Context, a ACME) (*tls.Certificate, error) {
	certificate, err := a.Keys.CourierKey(ctx, a.Certificate)
	if err != nil {
		if errors.Is(err, plugin.ErrNotFound) {
			m.log.Info("the Backend holds no TLS certificate yet; obtaining one", "backend", a.Certificate.Backend)
			return nil, nil
		}
		return nil, fmt.Errorf("fetch the TLS certificate: %w", err)
	}
	defer certificate.Release()
	key, err := a.Keys.CourierKey(ctx, a.Key)
	if err != nil {
		if errors.Is(err, plugin.ErrNotFound) {
			m.log.Warn("the Backend holds a TLS certificate but no key; obtaining a new pair", "backend", a.Key.Backend)
			return nil, nil
		}
		return nil, fmt.Errorf("fetch the TLS key: %w", err)
	}
	defer key.Release()
	cert, err := parse(certificate, key)
	if err == nil {
		for _, d := range a.Domains {
			if !slices.Contains(cert.Leaf.DNSNames, d) {
				err = fmt.Errorf("the stored TLS certificate does not name %s", d)
				break
			}
		}
	}
	if err != nil {
		m.log.Warn("the stored TLS certificate is unusable; obtaining a new one", "error", err)
		return nil, nil
	}
	return cert, nil
}

// obtain obtains a certificate from the ACME directory and checks it is one
// the manager can serve. Nothing is ordered while the Backend cannot store
// the result. The caller wipes the returned key.
func (m *Manager) obtain(ctx context.Context, a ACME) (*acmecert.Issued, error) {
	if err := a.Issuer.CheckWritable(a.Certificate, a.Key); err != nil {
		return nil, fmt.Errorf("%w; ACME needs a Backend that stores Courier Keys, or supply agent_api.tls.certificate and key yourself", err)
	}
	issued, err := a.Issuer.Obtain(ctx, m)
	if err != nil {
		return nil, err
	}
	if _, err := parsePEM(issued.Chain, issued.Key); err != nil {
		clear(issued.Key)
		return nil, fmt.Errorf("the obtained certificate is unusable: %w", err)
	}
	m.log.Info("TLS certificate obtained", "subject", issued.Leaf.Subject.String(), "not_after", issued.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return issued, nil
}

// store writes the issued pair to the Backend and returns it parsed. The
// key goes first: a certificate without its key is re-obtained on the next
// start, while a key without its certificate is simply unused. A pair whose
// second write fails is retried by the caller, not ordered again.
func (m *Manager) store(ctx context.Context, a ACME, issued *acmecert.Issued) (*tls.Certificate, error) {
	if err := a.Keys.WriteCourierKey(ctx, a.Key, issued.Key); err != nil {
		return nil, fmt.Errorf("store the TLS key: %w", err)
	}
	if err := a.Keys.WriteCourierKey(ctx, a.Certificate, issued.Chain); err != nil {
		return nil, fmt.Errorf("store the TLS certificate: %w", err)
	}
	cert, err := parsePEM(issued.Chain, issued.Key)
	if err != nil {
		return nil, fmt.Errorf("the obtained certificate is unusable: %w", err)
	}
	m.log.Info("TLS certificate stored", "backend", a.Certificate.Backend)
	return cert, nil
}

// lifetime is how long leaf is valid, at least a second, so fractions of it
// never overflow or reach zero.
func lifetime(leaf *x509.Certificate) time.Duration {
	const longest = 100 * 365 * 24 * time.Hour
	return min(max(leaf.NotAfter.Sub(leaf.NotBefore), time.Second), longest)
}

// renewAt is when leaf is renewed: at two thirds of its lifetime.
func renewAt(leaf *x509.Certificate) time.Time {
	return leaf.NotBefore.Add(lifetime(leaf) / 3 * 2)
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
	var certPEM, keyPEM bytes.Buffer
	if _, err := certificate.WriteTo(&certPEM); err != nil {
		return nil, fmt.Errorf("read the TLS certificate: %w", err)
	}
	if _, err := key.WriteTo(&keyPEM); err != nil {
		return nil, fmt.Errorf("read the TLS key: %w", err)
	}
	defer clear(keyPEM.Bytes())
	return parsePEM(certPEM.Bytes(), keyPEM.Bytes())
}

// parsePEM is parse on PEM bytes, which stay the caller's to wipe.
func parsePEM(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	chain, err := pemkey.ParseChain(certPEM, "the TLS certificate")
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
	private, err := pemkey.ParseSigner(keyPEM, "the TLS key")
	if err != nil {
		return nil, err
	}
	if err := pemkey.KeyMatches(leaf.PublicKey, private); err != nil {
		return nil, errors.New("the TLS key does not match the TLS certificate")
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: private, Leaf: leaf}, nil
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

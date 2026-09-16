// Package acmecert obtains certificates from an ACME directory (ADR-0006)
// with the TLS-ALPN-01 or HTTP-01 challenge. The account key is a Courier
// Key in a Backend (ADR-0001); the certificate manager owns what is issued.
//
// The ACME client is golang.org/x/crypto/acme, which signs and hashes with
// the standard library only, so FIPS mode covers it.
package acmecert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/pemkey"
	"github.com/potto007/TrustedCourier/internal/secret"
	"github.com/potto007/TrustedCourier/sdk/plugin"
	"golang.org/x/crypto/acme"
)

// KeyStore reads and writes Courier Keys in their Backends.
type KeyStore interface {
	// CourierKey fetches the Courier Key at key, or an error wrapping
	// plugin.ErrNotFound when the Backend holds nothing there. The caller
	// must Release it.
	CourierKey(ctx context.Context, key config.CourierKey) (*secret.Secret, error)
	// WriteCourierKey stores value at key. value is the caller's to wipe.
	WriteCourierKey(ctx context.Context, key config.CourierKey, value []byte) error
	// CanWriteCourierKey reports nil when key's Backend stores Courier
	// Keys, and why not otherwise.
	CanWriteCourierKey(key config.CourierKey) error
}

// Solver serves challenge responses to the CA's validation.
type Solver interface {
	// PresentTLSALPN serves cert to TLS-ALPN-01 validations naming domain
	// until RemoveTLSALPN.
	PresentTLSALPN(domain string, cert *tls.Certificate)
	RemoveTLSALPN(domain string)
	// PresentHTTP serves keyAuth at the HTTP-01 path for token until
	// RemoveHTTP.
	PresentHTTP(token, keyAuth string)
	RemoveHTTP(token string)
}

// userAgent identifies TrustedCourier to the CA.
const userAgent = "TrustedCourier"

// Timeouts.
const (
	// obtainTimeout bounds one attempt at obtaining a certificate, all
	// validations included.
	obtainTimeout = 5 * time.Minute
	// requestTimeout bounds one HTTP request to the directory.
	requestTimeout = 30 * time.Second
)

// Issuer obtains certificates as an ACME config directs.
type Issuer struct {
	cfg  config.ACME
	keys KeyStore
	log  *slog.Logger
}

// New returns an Issuer for cfg, keeping its keys in keys.
func New(cfg config.ACME, keys KeyStore, log *slog.Logger) *Issuer {
	return &Issuer{cfg: cfg, keys: keys, log: log}
}

// Issued is a certificate an Issuer obtained.
type Issued struct {
	// Chain is the certificate chain as PEM, leaf first.
	Chain []byte
	// Key is the leaf's private key as PKCS #8 PEM. It is a Courier Key:
	// wipe it once stored.
	Key []byte
	// Leaf is the parsed leaf.
	Leaf *x509.Certificate
}

// CheckWritable reports whether every Courier Key the Issuer stores can be
// written, before any order is placed.
func (i *Issuer) CheckWritable(certificate, key config.CourierKey) error {
	for _, k := range []config.CourierKey{certificate, key, i.cfg.AccountKey} {
		if err := i.keys.CanWriteCourierKey(k); err != nil {
			return err
		}
	}
	return nil
}

// Obtain obtains a certificate for the configured domains, registering the
// account on first use. solver answers the validations.
func (i *Issuer) Obtain(ctx context.Context, solver Solver) (*Issued, error) {
	ctx, cancel := context.WithTimeout(ctx, obtainTimeout)
	defer cancel()
	client, err := i.client(ctx)
	if err != nil {
		return nil, err
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(i.cfg.Domains...))
	if err != nil {
		return nil, fmt.Errorf("order a certificate from %s: %w", i.cfg.Directory, err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := i.authorize(ctx, client, solver, authzURL); err != nil {
			return nil, err
		}
	}
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("wait for the order to be ready: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: i.cfg.Domains[0]},
		DNSNames: i.cfg.Domains,
	}, leafKey)
	if err != nil {
		return nil, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		// A CA that answers finalize without a Location header (Pebble does)
		// leaves the client nothing to poll, so poll the order itself.
		if chain, err = i.fetchIssued(ctx, client, order.URI, err); err != nil {
			return nil, fmt.Errorf("finalize the order: %w", err)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("the CA returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("the CA returned an invalid certificate: %w", err)
	}
	if err := pemkey.KeyMatches(leaf.PublicKey, leafKey); err != nil {
		return nil, errors.New("the CA returned a certificate for another key")
	}
	for _, d := range i.cfg.Domains {
		if !slices.Contains(leaf.DNSNames, d) {
			return nil, fmt.Errorf("the CA returned a certificate that does not name %s", d)
		}
	}
	keyPEM, err := pemkey.MarshalSigner(leafKey)
	if err != nil {
		return nil, err
	}
	return &Issued{Chain: pemkey.MarshalChain(chain), Key: keyPEM, Leaf: leaf}, nil
}

// fetchIssued polls the order at orderURL after a finalize whose response
// the client could not follow, and fetches the certificate once the order is
// valid. finalizeErr is returned when the order cannot be polled.
func (i *Issuer) fetchIssued(ctx context.Context, client *acme.Client, orderURL string, finalizeErr error) ([][]byte, error) {
	if orderURL == "" {
		return nil, finalizeErr
	}
	order, err := client.WaitOrder(ctx, orderURL)
	if err != nil {
		var orderErr *acme.OrderError
		if errors.As(err, &orderErr) {
			return nil, err
		}
		return nil, finalizeErr
	}
	if order.Status != acme.StatusValid || order.CertURL == "" {
		return nil, finalizeErr
	}
	return client.FetchCert(ctx, order.CertURL, true)
}

// authorize completes the authorization at authzURL with the configured
// challenge type.
func (i *Issuer) authorize(ctx context.Context, client *acme.Client, solver Solver, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("fetch an authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	domain := authz.Identifier.Value
	idx := slices.IndexFunc(authz.Challenges, func(c *acme.Challenge) bool { return c.Type == i.cfg.Challenge })
	if idx < 0 {
		return fmt.Errorf("%s offers no %s challenge for %s", i.cfg.Directory, i.cfg.Challenge, domain)
	}
	chal := authz.Challenges[idx]
	switch i.cfg.Challenge {
	case config.ChallengeTLSALPN01:
		cert, err := client.TLSALPN01ChallengeCert(chal.Token, domain)
		if err != nil {
			return err
		}
		solver.PresentTLSALPN(domain, &cert)
		defer solver.RemoveTLSALPN(domain)
	case config.ChallengeHTTP01:
		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		solver.PresentHTTP(chal.Token, keyAuth)
		defer solver.RemoveHTTP(chal.Token)
	}
	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept the %s challenge for %s: %w", i.cfg.Challenge, domain, err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("validate %s by %s: %w", domain, i.cfg.Challenge, err)
	}
	return nil
}

// client returns an ACME client for the account key, registering the
// account when the key is new.
func (i *Issuer) client(ctx context.Context) (*acme.Client, error) {
	key, created, err := i.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: i.cfg.RootCAs}
	client := &acme.Client{
		Key:          key,
		DirectoryURL: i.cfg.Directory,
		HTTPClient:   &http.Client{Transport: transport, Timeout: requestTimeout},
		UserAgent:    userAgent,
	}
	if _, err := client.Discover(ctx); err != nil {
		return nil, fmt.Errorf("reach the ACME directory %s: %w", i.cfg.Directory, err)
	}
	if !created {
		_, err := client.GetReg(ctx, "")
		if err == nil {
			return client, nil
		}
		if !errors.Is(err, acme.ErrNoAccount) {
			return nil, fmt.Errorf("look up the ACME account at %s: %w", i.cfg.Directory, err)
		}
	}
	account := &acme.Account{}
	if i.cfg.Contact != "" {
		account.Contact = []string{i.cfg.Contact}
	}
	if i.cfg.EAB != nil {
		mac, err := i.hmacKey(ctx)
		if err != nil {
			return nil, err
		}
		defer clear(mac)
		account.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: i.cfg.EAB.KeyID, Key: mac}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register the ACME account at %s: %w", i.cfg.Directory, err)
	}
	i.log.Info("ACME account registered", "directory", i.cfg.Directory)
	return client, nil
}

// accountKey loads the account key from its Backend, or generates and
// stores one when the Backend holds none. created reports the latter.
func (i *Issuer) accountKey(ctx context.Context) (key crypto.Signer, created bool, err error) {
	stored, err := i.keys.CourierKey(ctx, i.cfg.AccountKey)
	if err == nil {
		defer stored.Release()
		var buf bytes.Buffer
		if _, err := stored.WriteTo(&buf); err != nil {
			return nil, false, fmt.Errorf("read the ACME account key: %w", err)
		}
		data := buf.Bytes()
		defer clear(data)
		key, err := pemkey.ParseSigner(data, "the ACME account key")
		if err != nil {
			return nil, false, err
		}
		return key, false, nil
	}
	if !errors.Is(err, plugin.ErrNotFound) {
		return nil, false, fmt.Errorf("fetch the ACME account key: %w", err)
	}
	generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, err
	}
	pemData, err := pemkey.MarshalSigner(generated)
	if err != nil {
		return nil, false, err
	}
	defer clear(pemData)
	if err := i.keys.WriteCourierKey(ctx, i.cfg.AccountKey, pemData); err != nil {
		return nil, false, fmt.Errorf("store the ACME account key: %w", err)
	}
	i.log.Info("ACME account key generated and stored", "backend", i.cfg.AccountKey.Backend)
	return generated, true, nil
}

// hmacKey fetches and decodes the External Account Binding MAC key. The
// caller wipes it.
func (i *Issuer) hmacKey(ctx context.Context) ([]byte, error) {
	stored, err := i.keys.CourierKey(ctx, i.cfg.EAB.HMACKey)
	if err != nil {
		return nil, fmt.Errorf("fetch the ACME External Account Binding key: %w", err)
	}
	defer stored.Release()
	var buf bytes.Buffer
	if _, err := stored.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("read the ACME External Account Binding key: %w", err)
	}
	defer clear(buf.Bytes())
	encoded := bytes.TrimRight(bytes.TrimSpace(buf.Bytes()), "=")
	mac := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawURLEncoding.Decode(mac, encoded)
	if err != nil {
		clear(mac)
		return nil, errors.New("the ACME External Account Binding key is not base64url")
	}
	return mac[:n], nil
}

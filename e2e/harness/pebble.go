package harness

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

// Pebble is an in-process Pebble ACME test CA, as an Operator's ACME
// directory. It validates challenges against the ports it was started with,
// on whatever address the identifier resolves to.
type Pebble struct {
	// DirectoryURL is the ACME directory, served over TLS.
	DirectoryURL string
	// CABundle is a PEM file that trusts DirectoryURL's certificate, for
	// agent_api.tls.acme.ca_bundle.
	CABundle string
	// Roots trusts the certificates Pebble issues.
	Roots *x509.CertPool

	srv *httptest.Server
	log *lockedBuffer
}

// PebbleOptions configure a Pebble.
type PebbleOptions struct {
	// HTTPPort and TLSPort are where HTTP-01 and TLS-ALPN-01 challenges are
	// validated. Zero leaves Pebble's defaults, 5002 and 5001.
	HTTPPort, TLSPort int
	// Validity is how long issued certificates are valid. Zero leaves
	// Pebble's default of 90 days.
	Validity time.Duration
	// EAB, when set, requires External Account Binding with one of these
	// key IDs and base64url MAC keys.
	EAB map[string]string
}

var pebbleEnvOnce sync.Once

// StartPebble starts a Pebble that stops when the test ends.
func (in *Installation) StartPebble(opts PebbleOptions) *Pebble {
	in.t.Helper()
	// Pebble reads its knobs from the environment: no random delay before
	// validating, and no random bad-nonce responses, so a test's timing is
	// its own.
	pebbleEnvOnce.Do(func() {
		_ = os.Setenv("PEBBLE_VA_NOSLEEP", "1")
		_ = os.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	})
	if opts.HTTPPort == 0 {
		opts.HTTPPort = 5002
	}
	if opts.TLSPort == 0 {
		opts.TLSPort = 5001
	}
	buf := &lockedBuffer{}
	logger := log.New(buf, "pebble ", log.Lmicroseconds)
	profiles := map[string]ca.Profile{"default": {Description: "test profile"}}
	if opts.Validity > 0 {
		profiles["default"] = ca.Profile{Description: "test profile", ValidityPeriod: uint64(opts.Validity / time.Second)}
	}
	store := db.NewMemoryStore()
	certAuthority := ca.New(logger, store, "", "ecdsa", 0, 1, profiles)
	validator := va.New(logger, opts.HTTPPort, opts.TLSPort, false, "", store)
	for id, key := range opts.EAB {
		if err := store.AddExternalAccountKeyByID(id, key); err != nil {
			in.t.Fatal(err)
		}
	}
	frontEnd := wfe.New(logger, store, validator, certAuthority, []string{"pebble.letsencrypt.org"}, false, len(opts.EAB) > 0, 0, 0)
	srv := httptest.NewUnstartedServer(frontEnd.Handler())
	srv.StartTLS()
	in.t.Cleanup(srv.Close)

	bundle := filepath.Join(in.dir, "pebble-directory-ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		in.t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certAuthority.GetRootCert(0).Cert)
	return &Pebble{
		DirectoryURL: srv.URL + wfe.DirectoryPath,
		CABundle:     bundle,
		Roots:        roots,
		srv:          srv,
		log:          buf,
	}
}

// Log returns everything Pebble logged so far.
func (p *Pebble) Log() string { return p.log.String() }

// Client returns an HTTP client that trusts certificates Pebble issued for
// serverName, whatever address it dials, and speaks HTTP/2 when offered.
func (p *Pebble) Client(serverName string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: p.Roots, ServerName: serverName},
			ForceAttemptHTTP2: true,
		},
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

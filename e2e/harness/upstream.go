package harness

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// UpstreamRedirectLocation is where the fake Upstream's /redirect points.
const UpstreamRedirectLocation = "https://elsewhere.example/landing?from=upstream"

// Upstream is a fake Upstream: a local TLS server that records every request
// it receives. GET /redirect answers 302 to UpstreamRedirectLocation, GET
// /events streams two server-sent events and holds back the second until
// ReleaseEvents, and every other request gets 200 with a body naming the
// method and path it saw.
type Upstream struct {
	// URL is the base URL, such as https://127.0.0.1:41234.
	URL string
	// CABundle is the path of a PEM file holding the certificate that signs
	// the Upstream's own.
	CABundle string

	srv         *httptest.Server
	release     chan struct{}
	releaseOnce sync.Once

	mu       sync.Mutex
	requests []UpstreamRequest
}

// UpstreamRequest is one request the fake Upstream received.
type UpstreamRequest struct {
	Method     string
	Host       string
	Path       string // escaped, as sent
	RawQuery   string
	Header     http.Header
	Body       string
	ProtoMajor int
}

// StartUpstream starts a fake Upstream, speaking HTTP/2 as well as HTTP/1.1
// when http2 is set, that stops when the test ends.
func (in *Installation) StartUpstream(http2 bool) *Upstream {
	in.t.Helper()
	u := &Upstream{release: make(chan struct{})}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(u.serve))
	u.srv.EnableHTTP2 = http2
	u.srv.StartTLS()
	in.t.Cleanup(u.srv.Close)
	// Runs before Close, so a held stream cannot stall it.
	in.t.Cleanup(u.ReleaseEvents)

	u.URL = u.srv.URL
	ca, err := os.CreateTemp(in.dir, "upstream-ca-*.pem")
	if err != nil {
		in.t.Fatal(err)
	}
	defer func() { _ = ca.Close() }()
	if err := pem.Encode(ca, &pem.Block{Type: "CERTIFICATE", Bytes: u.srv.Certificate().Raw}); err != nil {
		in.t.Fatal(err)
	}
	u.CABundle = filepath.Clean(ca.Name())
	return u
}

// Requests returns every request received so far.
func (u *Upstream) Requests() []UpstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.requests)
}

// ReleaseEvents lets every /events stream send its second event.
func (u *Upstream) ReleaseEvents() { u.releaseOnce.Do(func() { close(u.release) }) }

func (u *Upstream) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.requests = append(u.requests, UpstreamRequest{
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.EscapedPath(),
		RawQuery:   r.URL.RawQuery,
		Header:     r.Header.Clone(),
		Body:       string(body),
		ProtoMajor: r.ProtoMajor,
	})
	u.mu.Unlock()

	switch r.URL.Path {
	case "/redirect":
		http.Redirect(w, r, UpstreamRedirectLocation, http.StatusFound)
	case "/events":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: first\n\n")
		http.NewResponseController(w).Flush()
		select {
		case <-u.release:
		case <-r.Context().Done():
			return
		case <-time.After(15 * time.Second):
		}
		_, _ = io.WriteString(w, "data: second\n\n")
	default:
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream", "fake")
		_, _ = fmt.Fprintf(w, "upstream saw %s %s", r.Method, r.URL.EscapedPath())
	}
}

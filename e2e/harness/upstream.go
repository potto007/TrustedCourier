package harness

import (
	"bytes"
	"compress/gzip"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UpstreamRedirectLocation is where the fake Upstream's /redirect points.
const UpstreamRedirectLocation = "https://elsewhere.example/landing?from=upstream"

// Upstream is a fake Upstream: a local TLS server that records every request
// it receives. GET /redirect answers 302 to UpstreamRedirectLocation, GET
// /events streams two server-sent events and holds back the second until
// ReleaseEvents, GET /echo and /echo-events echo a credential back (see
// echo), and every other request gets 200 with a body naming the method and
// path it saw.
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
	ReceivedAt time.Time
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

// echoed is what /echo and /echo-events send back, as an Upstream echoes a
// rejected credential: the text query parameter, then the value of the
// request header the header query parameter names, then the decoded value of
// the query parameter the query parameter names, then the value, as sent, of
// the query parameter the rawquery parameter names.
func echoed(r *http.Request) string {
	q := r.URL.Query()
	v := q.Get("text") + r.Header.Get(q.Get("header"))
	if name := q.Get("query"); name != "" {
		v += q.Get(name)
	}
	if name := q.Get("rawquery"); name != "" {
		for pair := range strings.SplitSeq(r.URL.RawQuery, "&") {
			if key, value, _ := strings.Cut(pair, "="); key == name {
				v += value
				break
			}
		}
	}
	return v
}

// echo answers with the echoed value as the body and the X-Echo header, with
// the status the status query parameter gives (200 by default) and an exact
// Content-Length. With early, it first sends 103 Early Hints carrying X-Echo.
// With encoding=gzip it compresses the body if the request accepts gzip; with
// encoding=br it labels the body br without compressing it.
func (u *Upstream) echo(w http.ResponseWriter, r *http.Request) {
	v, q := echoed(r), r.URL.Query()
	if q.Has("early") {
		w.Header().Set("X-Echo", v)
		w.WriteHeader(http.StatusEarlyHints)
	}
	status := http.StatusOK
	if s, err := strconv.Atoi(q.Get("status")); err == nil {
		status = s
	}
	if q.Has("name") {
		// The echoed value's last word, lowercased, as a header name.
		words := strings.Fields(v)
		w.Header()[strings.ToLower(words[len(words)-1])] = []string{"1"}
	}
	body := []byte(v)
	acceptsGzip := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
	switch enc := q.Get("encoding"); {
	case enc == "gzip" && acceptsGzip:
		body = gzipped(body)
		w.Header().Set("Content-Encoding", "gzip")
	case enc == "gzip-twice" && acceptsGzip:
		// Two header lines, each naming one of two layers.
		body = gzipped(gzipped(body))
		w.Header()["Content-Encoding"] = []string{"gzip", "gzip"}
	case enc == "br":
		w.Header().Set("Content-Encoding", "br")
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Echo", v)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func gzipped(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}

// echoEvents streams "data: first" and then an event carrying the echoed
// value, split in half: it flushes the first half and holds back the second
// until ReleaseEvents. It sends the echoed value again as the X-Echo trailer.
func (u *Upstream) echoEvents(w http.ResponseWriter, r *http.Request) {
	v := echoed(r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Trailer", "X-Echo")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "data: first\n\ndata: key "+v[:len(v)/2])
	http.NewResponseController(w).Flush()
	select {
	case <-u.release:
	case <-r.Context().Done():
		return
	case <-time.After(15 * time.Second):
	}
	_, _ = io.WriteString(w, v[len(v)/2:]+"\n\n")
	w.Header().Set("X-Echo", v)
}

func (u *Upstream) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.requests = append(u.requests, UpstreamRequest{
		ReceivedAt: time.Now().UTC(),
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
	case "/pause-end":
		// One event, silence for the pause query parameter, then the end of
		// the stream with an X-Done trailer.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Trailer", "X-Done")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: first\n\n")
		http.NewResponseController(w).Flush()
		pause, _ := time.ParseDuration(r.URL.Query().Get("pause"))
		select {
		case <-time.After(pause):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("X-Done", "yes")
	case "/cut":
		// Promises 100 bytes, sends 7, and drops the connection.
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	case "/echo":
		u.echo(w, r)
	case "/echo-events":
		u.echoEvents(w, r)
	default:
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream", "fake")
		_, _ = fmt.Fprintf(w, "upstream saw %s %s", r.Method, r.URL.EscapedPath())
	}
}

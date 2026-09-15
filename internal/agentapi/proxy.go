package agentapi

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/audit"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/redact"
	"github.com/potto007/TrustedCourier/internal/secret"
)

// route is one Upstream of one Secret Name, served at
// /proxy/{secret_name}/{upstream}/.
type route struct {
	template  config.InjectionTemplate
	upstream  config.Upstream
	transport http.RoundTripper
}

type routeKey struct{ secretName, upstream string }

// newRoutes builds a route for every Upstream of every Secret Name, each with
// its own transport so an Upstream's CA bundle verifies only that Upstream.
func newRoutes(cfg *config.Config) map[routeKey]*route {
	routes := make(map[routeKey]*route)
	for name, s := range cfg.Secrets {
		for upName, up := range s.Upstreams {
			routes[routeKey{name, upName}] = &route{
				template:  *s.InjectionTemplate,
				upstream:  up,
				transport: newTransport(up),
			}
		}
	}
	return routes
}

func newTransport(up config.Upstream) *http.Transport {
	return &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		// Verification is never optional: there is no setting to skip it.
		TLSClientConfig:     &tls.Config{RootCAs: up.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
		// The proxy decodes gzip itself, after checking every
		// Content-Encoding the Upstream sent (see decodeBody).
		DisableCompression:    true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// slots are the credential slots every Injection Template defines.
type slots struct {
	// headers are the header templates, by canonical header name.
	headers map[string][]config.HeaderTemplate
	// queries are the query parameter names, sorted.
	queries []string
	// basicAuth are the basic auth templates, read from Authorization.
	basicAuth []config.BasicAuthTemplate
}

// slot is where an Agent Token was presented: a header or a query parameter.
type slot struct{ header, query string }

func newSlots(cfg *config.Config) slots {
	out := slots{headers: make(map[string][]config.HeaderTemplate)}
	for _, name := range slices.Sorted(maps.Keys(cfg.Secrets)) {
		t := cfg.Secrets[name].InjectionTemplate
		switch {
		case t == nil:
		case t.Header != nil && !slices.Contains(out.headers[t.Header.Name], *t.Header):
			out.headers[t.Header.Name] = append(out.headers[t.Header.Name], *t.Header)
		case t.Query != nil && !slices.Contains(out.queries, t.Query.Name):
			out.queries = append(out.queries, t.Query.Name)
		case t.BasicAuth != nil && !slices.Contains(out.basicAuth, *t.BasicAuth):
			out.basicAuth = append(out.basicAuth, *t.BasicAuth)
		}
	}
	slices.Sort(out.queries)
	return out
}

func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	tok, from, ok := s.authenticateProxy(w, r)
	if !ok {
		return
	}
	name, upName := r.PathValue("secret_name"), r.PathValue("upstream")
	log := s.log.With("delivery", config.DeliveryProxy, "agent_token_id", tok.ID, "secret_name", name, "upstream", upName)
	rt := s.routes[routeKey{name, upName}]
	rec := &audit.Record{AgentTokenID: tok.ID, SecretName: name, Delivery: config.DeliveryProxy, Upstream: upName}
	if rt != nil {
		rec.UpstreamHost = rt.upstream.Host
	}
	defer s.record(r, log, rec)
	refuse := func(reason string) {
		log.Info("Delivery denied", "reason", reason)
		rec.Decision, rec.Reason = audit.Denied, reason
	}

	// WebSockets are out of scope (ADR-0002), and an upgraded connection
	// would carry bytes TrustedCourier never inspects. The server declines
	// an h2c offer, as curl --http2 sends, by answering in HTTP/1.1, so the
	// offer is dropped rather than forwarded.
	if strings.EqualFold(r.Header.Get("Upgrade"), "h2c") {
		r.Header.Del("Upgrade")
		r.Header.Del("Http2-Settings")
	}
	if r.Header.Get("Upgrade") != "" {
		refuse("protocol upgrade")
		writeError(w, http.StatusBadRequest, "Proxy Delivery does not support protocol upgrades")
		return
	}
	rest, ok := forwardedPath(r.URL.EscapedPath())
	if !ok {
		refuse("the path contains a dot segment")
		writeError(w, http.StatusBadRequest, "the path must not contain dot segments")
		return
	}

	reason, allowed := s.access.Authorize(tok, name, config.DeliveryProxy)
	if allowed && rt == nil {
		reason, allowed = "unknown Upstream", false
	}
	if !allowed {
		refuse(string(reason))
		writeError(w, http.StatusForbidden, deniedMessage)
		return
	}
	rec.Decision = audit.Allowed

	value, ok := s.resolve(w, r, log, rec, name)
	if !ok {
		return
	}
	cred, err := render(rt.template, value)
	value.Release()
	if err != nil {
		log.Error("Delivery failed: the Secret cannot go in the Injection Template's header", "error", err)
		rec.Failure = "the Secret cannot go in the Injection Template's header"
		writeError(w, http.StatusBadGateway, "the Secret could not be delivered")
		return
	}

	target := &url.URL{Scheme: rt.upstream.Scheme, Host: rt.upstream.Host}
	escaped := rt.upstream.BasePath + rest
	if escaped == "" {
		escaped = "/"
	}
	// rest came from a valid escaped path, so it unescapes.
	target.Path, _ = url.PathUnescape(escaped)
	target.RawPath = escaped

	// A proxied response may stream for as long as the Upstream keeps
	// sending, but may not stall: the request holds the Secret's header copy
	// until it ends. When neither the Upstream's response nor the Agent's
	// request body moves for proxyIdleTimeout, the Delivery is cancelled, and
	// a write to an Agent that stops reading fails after proxyWriteStall.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var idle atomic.Bool
	timer := time.AfterFunc(proxyIdleTimeout, func() {
		idle.Store(true)
		cancel()
	})
	defer timer.Stop()
	rc := http.NewResponseController(w)
	// progressWriter bounds each write instead of the server's write timeout,
	// since on HTTP/2 an armed deadline resets the stream when it passes,
	// even while no write is pending.
	_ = rc.SetWriteDeadline(time.Time{})
	rw := newRedactingWriter(w, cred.needles)
	pw := &progressWriter{ResponseWriter: rw, rc: rc, timer: timer}
	defer func() {
		// Once the response has started, ReverseProxy ends a Delivery it
		// cannot finish by aborting the response with this panic.
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				switch {
				case idle.Load():
					log.Error("Delivery cut off: the Upstream sent nothing in time", "timeout", proxyIdleTimeout)
					rec.Failure = "the Upstream sent nothing in time"
				case r.Context().Err() != nil && s.stopping.Load():
					log.Warn("Delivery cut off by server shutdown")
					rec.Failure = "cut off by server shutdown"
				case r.Context().Err() != nil:
					log.Info("Delivery abandoned by the Agent")
					rec.Failure = "abandoned by the Agent"
				case pw.writeErr() != nil:
					log.Error("Delivery cut off: the response could not be written to the Agent", "error", pw.writeErr())
					rec.Failure = "the response could not be written to the Agent"
				default:
					log.Error("Delivery cut off: the Upstream's response broke off")
					rec.Failure = "the Upstream's response broke off"
				}
			}
			panic(p)
		}
	}()

	(&httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// ReverseProxy has already dropped query parameters it cannot
			// parse from pr.Out, so the query comes from there.
			out := *target
			out.RawQuery = pr.Out.URL.RawQuery
			pr.Out.URL = &out
			pr.Out.Host = ""
			if pr.Out.Body != nil && pr.Out.Body != http.NoBody {
				pr.Out.Body = &progressReader{ReadCloser: pr.Out.Body, timer: timer}
			}
			pr.Out.Header.Del(AgentTokenHeader)
			if from.header != "" {
				pr.Out.Header.Del(from.header)
			}
			if from.query != "" {
				out.RawQuery = withoutParam(out.RawQuery, from.query)
			}
			if cred.header != "" {
				pr.Out.Header.Set(cred.header, cred.headerValue)
			}
			if cred.query != "" {
				q := withoutParam(out.RawQuery, cred.query)
				if q != "" {
					q += "&"
				}
				out.RawQuery = q + cred.query + "=" + cred.queryValue
			}
			// Redaction must see the whole response as plain bytes: the
			// proxy asks for gzip and decodes it, and a range could carry
			// the Secret in pieces.
			pr.Out.Header.Set("Accept-Encoding", "gzip")
			pr.Out.Header.Del("Range")
			pr.Out.Header.Del("If-Range")
		},
		Transport: rt.transport,
		// Redirects reach the Agent as they are: the transport never follows
		// them, so the Secret is never sent to another host.
		ModifyResponse: func(res *http.Response) error {
			rec.UpstreamStatus = res.StatusCode
			if err := decodeBody(res); err != nil {
				return err
			}
			log.Info("Delivery allowed", "upstream_status", res.StatusCode)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, errUnreadableEncoding) {
				log.Error("Delivery failed: Redaction cannot read the Upstream's response", "error", err)
				rec.Failure = "Redaction cannot read the Upstream's response"
				writeError(w, http.StatusBadGateway, "the Upstream's response could not be delivered")
				return
			}
			if idle.Load() {
				log.Error("Delivery failed: the Upstream sent nothing in time", "timeout", proxyIdleTimeout)
				rec.Failure = "the Upstream sent nothing in time"
				writeError(w, http.StatusGatewayTimeout, "the Upstream did not respond in time")
				return
			}
			if r.Context().Err() != nil && s.stopping.Load() {
				log.Warn("Delivery cut off by server shutdown", "error", err)
				rec.Failure = "cut off by server shutdown"
				return
			}
			if r.Context().Err() != nil {
				log.Info("Delivery abandoned by the Agent", "error", err)
				rec.Failure = "abandoned by the Agent"
				return
			}
			log.Error("Delivery failed: Upstream not reached", "error", err)
			rec.Failure = "the Upstream could not be reached"
			writeError(w, http.StatusBadGateway, "the Upstream could not be reached")
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}).ServeHTTP(pw, r.WithContext(ctx))
	// The held-back bytes, the trailers, and the end of the response go out
	// after the last guarded write, so bound them too. The deadline stays
	// set until the server has sent them.
	_ = rc.SetWriteDeadline(time.Now().Add(proxyWriteStall))
	// Not deferred: when the body copy fails, ReverseProxy aborts the
	// response with a panic, and the held-back bytes must not follow.
	rw.finish()
}

const (
	// proxyIdleTimeout bounds how long an Upstream may send nothing, before
	// or during its response.
	proxyIdleTimeout = 5 * time.Minute
	// proxyWriteStall bounds how long an Agent may stop reading a proxied
	// response, as the server's write timeout does for Reveal Delivery.
	proxyWriteStall = 30 * time.Second
)

// progressWriter pushes the idle timer forward whenever the Upstream's
// response makes progress, and bounds each write and flush to the Agent by
// proxyWriteStall. The deadline is cleared between writes: on HTTP/2 an armed
// deadline resets the stream when it passes, even with no write pending.
type progressWriter struct {
	http.ResponseWriter
	rc    *http.ResponseController
	timer *time.Timer

	mu  sync.Mutex
	err error // the last failed write's or flush's error
}

// guard sets the write deadline for one write and returns what clears it.
func (p *progressWriter) guard() func() {
	_ = p.rc.SetWriteDeadline(time.Now().Add(proxyWriteStall))
	return func() { _ = p.rc.SetWriteDeadline(time.Time{}) }
}

func (p *progressWriter) record(err error) {
	if err != nil {
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
	}
}

func (p *progressWriter) writeErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *progressWriter) WriteHeader(code int) {
	p.timer.Reset(proxyIdleTimeout)
	defer p.guard()()
	p.ResponseWriter.WriteHeader(code)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.timer.Reset(proxyIdleTimeout)
	defer p.guard()()
	n, err := p.ResponseWriter.Write(b)
	p.record(err)
	return n, err
}

// FlushError flushes the underlying writer, bounded like a write. It sends
// only what Redaction has already released.
func (p *progressWriter) FlushError() error {
	defer p.guard()()
	err := p.rc.Flush()
	p.record(err)
	return err
}

// progressReader pushes the idle timer forward whenever the Agent's request
// body makes progress, so a long upload is not taken for a silent Upstream.
type progressReader struct {
	io.ReadCloser
	timer *time.Timer
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	if n > 0 {
		p.timer.Reset(proxyIdleTimeout)
	}
	return n, err
}

// Unwrap lets http.ResponseController flush the underlying writer.
func (p *progressWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// redactingWriter performs Redaction on a proxied response: it masks the
// Secret in the headers of every response, 1xx included, in the body, and in
// the trailers.
type redactingWriter struct {
	http.ResponseWriter
	// needles are every form of the Secret the request carried.
	needles     []string
	body        *redact.Writer
	wroteHeader bool
}

func newRedactingWriter(w http.ResponseWriter, needles []string) *redactingWriter {
	return &redactingWriter{ResponseWriter: w, needles: needles, body: redact.NewWriter(w, needles...)}
}

// namesSecret reports whether a header name contains any form of the Secret,
// in any case.
func (w *redactingWriter) namesSecret(name string) bool {
	name = strings.ToLower(name)
	return slices.ContainsFunc(w.needles, func(n string) bool {
		return n != "" && strings.Contains(name, strings.ToLower(n))
	})
}

// redactHeader masks the Secret in every header value and drops any header
// whose name contains it, since a masked name is not a valid one. Names are
// matched in any case: Go canonicalizes them, and HTTP/2 lowercases them on
// the wire. So are the names Trailer announces.
func (w *redactingWriter) redactHeader() {
	h := w.Header()
	for name, values := range h {
		if w.namesSecret(name) {
			delete(h, name)
			continue
		}
		for i, v := range values {
			values[i] = redact.String(v, w.needles...)
		}
	}
	if announced := h.Values("Trailer"); len(announced) > 0 {
		var kept []string
		for _, v := range announced {
			for name := range strings.SplitSeq(v, ",") {
				if name = strings.TrimSpace(name); name != "" && !w.namesSecret(name) {
					kept = append(kept, name)
				}
			}
		}
		h.Del("Trailer")
		if len(kept) > 0 {
			h.Set("Trailer", strings.Join(kept, ", "))
		}
	}
}

func (w *redactingWriter) WriteHeader(code int) {
	w.redactHeader()
	if code >= http.StatusOK {
		w.wroteHeader = true
		// A 1xx response clears the header map noStore filled, so the final
		// response gets these again, in place of the Upstream's own.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *redactingWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

// finish writes the body's held-back bytes, which the response ended before
// they could become the Secret, and masks the trailers.
func (w *redactingWriter) finish() {
	_ = w.body.Close()
	w.redactHeader()
}

// Unwrap lets http.ResponseController reach the underlying writer. A flush
// sends only what Redaction has already released.
func (w *redactingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

var errUnreadableEncoding = errors.New("the response has a Content-Encoding Redaction cannot read")

// decodeBody makes a response's body plain bytes for Redaction. A body
// encoded once with gzip is decoded; one with any other encoding, or with
// more than one, is refused, since the Secret could hide inside it.
func decodeBody(res *http.Response) error {
	if res.Request.Method == http.MethodHead || res.StatusCode == http.StatusNoContent || res.StatusCode == http.StatusNotModified {
		return nil
	}
	var encodings []string
	for _, v := range res.Header.Values("Content-Encoding") {
		for enc := range strings.SplitSeq(v, ",") {
			if enc = strings.TrimSpace(enc); enc != "" && !strings.EqualFold(enc, "identity") {
				encodings = append(encodings, enc)
			}
		}
	}
	switch {
	case len(encodings) == 0:
		return nil
	case len(encodings) == 1 && strings.EqualFold(encodings[0], "gzip"):
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Body = &gzipBody{body: res.Body}
		return nil
	default:
		return fmt.Errorf("%w: %s", errUnreadableEncoding, strings.Join(encodings, ", "))
	}
}

// gzipBody decodes a gzip body, starting on the first Read so the response's
// headers need not wait for its body.
type gzipBody struct {
	body io.ReadCloser
	zr   *gzip.Reader
	err  error
}

func (g *gzipBody) Read(p []byte) (int, error) {
	if g.zr == nil && g.err == nil {
		g.zr, g.err = gzip.NewReader(g.body)
	}
	if g.err != nil {
		return 0, g.err
	}
	return g.zr.Read(p)
}

func (g *gzipBody) Close() error { return g.body.Close() }

// forwardedPath returns the escaped path after /proxy/{secret_name}/{upstream},
// with its leading slash. It refuses dot segments, including percent-encoded
// ones and ones hidden behind an encoded slash, since they could climb out of
// the Upstream's base path.
func forwardedPath(escaped string) (string, bool) {
	parts := strings.SplitN(escaped, "/", 5) // "", "proxy", name, upstream, rest
	if len(parts) < 5 {
		return "", true
	}
	rest := parts[4]
	for seg := range strings.SplitSeq(rest, "/") {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			return "", false
		}
		for part := range strings.FieldsFuncSeq(decoded, func(r rune) bool { return r == '/' || r == '\\' }) {
			// Servlet containers read "..;params" as "..".
			if name, _, _ := strings.Cut(part, ";"); name == "." || name == ".." {
				return "", false
			}
		}
	}
	return "/" + rest, true
}

// credential is a Secret rendered by an Injection Template for one request.
type credential struct {
	// header and headerValue are set for a header template.
	header, headerValue string
	// query and queryValue, escaped, are set for a query template.
	query, queryValue string
	// needles are every form of the Secret the request carries, for
	// Redaction. Each reads the rendered strings in place where it can.
	needles []string
}

// render renders the Injection Template around value. net/http takes header
// values and URLs only as strings, so this is where Proxy Delivery copies the
// Secret out of locked memory (ADR-0013).
func render(t config.InjectionTemplate, value *secret.Secret) (credential, error) {
	var b strings.Builder
	if t.BasicAuth != nil {
		return renderBasicAuth(t.BasicAuth, value)
	}
	if t.Query != nil {
		b.Grow(value.Len())
		if _, err := value.WriteTo(&b); err != nil {
			return credential{}, err
		}
		raw := b.String()
		// QueryEscape returns raw itself when nothing needs escaping.
		escaped := url.QueryEscape(raw)
		return credential{query: t.Query.Name, queryValue: escaped, needles: []string{raw, escaped}}, nil
	}
	h := t.Header
	b.Grow(len(h.Prefix) + value.Len() + len(h.Suffix))
	b.WriteString(h.Prefix)
	if _, err := value.WriteTo(headerValueWriter{&b}); err != nil {
		return credential{}, err
	}
	b.WriteString(h.Suffix)
	v := b.String()
	// The Secret is the part of the header between the template's text.
	return credential{header: h.Name, headerValue: v, needles: []string{v[len(h.Prefix) : len(v)-len(h.Suffix)]}}, nil
}

var errUsernameColon = errors.New("the Secret contains ':', which a basic auth username cannot carry")

// renderBasicAuth renders a basic auth template around value. The request
// carries the Secret only base64-encoded, but Redaction needs its plain form
// too, so both are needles.
func renderBasicAuth(t *config.BasicAuthTemplate, value *secret.Secret) (credential, error) {
	var b strings.Builder
	b.Grow(len(t.Username) + 1 + value.Len() + len(t.Password))
	b.WriteString(t.Username)
	if !t.SecretIsUsername {
		b.WriteByte(':')
	}
	if _, err := value.WriteTo(&b); err != nil {
		return credential{}, err
	}
	if t.SecretIsUsername {
		b.WriteByte(':')
	}
	b.WriteString(t.Password)
	pair := b.String()
	var raw string
	if t.SecretIsUsername {
		raw = pair[:len(pair)-len(t.Password)-1]
		if strings.Contains(raw, ":") {
			return credential{}, errUsernameColon
		}
	} else {
		raw = pair[len(t.Username)+1:]
	}
	const scheme = "Basic "
	plain := []byte(pair)
	header := scheme + base64.StdEncoding.EncodeToString(plain)
	clear(plain)
	return credential{header: "Authorization", headerValue: header, needles: []string{raw, header[len(scheme):]}}, nil
}

// withoutParam returns the query rawQuery without its name parameters. The
// other parameters keep their bytes and order.
func withoutParam(rawQuery, name string) string {
	var kept []string
	for pair := range strings.SplitSeq(rawQuery, "&") {
		key, _, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		if key != name {
			kept = append(kept, pair)
		}
	}
	return strings.Join(kept, "&")
}

var errHeaderControl = errors.New("the Secret contains a control character, which a header cannot carry")

type headerValueWriter struct{ b *strings.Builder }

func (w headerValueWriter) Write(p []byte) (int, error) {
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return 0, errHeaderControl
		}
	}
	return w.b.Write(p)
}

// authenticateProxy finds the Agent Token in a credential slot or in
// AgentTokenHeader and authenticates it, returning the header it came from.
//
// Every slot any header Injection Template defines is read on every route, so
// a 401 never depends on the Secret Name: otherwise a guesser could tell
// which Secret Names exist from which slots were read. A slot counts only when
// it holds something shaped like an Agent Token, so an SDK's placeholder API
// key next to AgentTokenHeader is not a second token.
func (s *Server) authenticateProxy(w http.ResponseWriter, r *http.Request) (access.AgentToken, slot, bool) {
	var presented []string
	var from []slot
	for _, name := range slices.Sorted(maps.Keys(s.slots.headers)) {
		for _, v := range r.Header.Values(name) {
			for _, t := range s.slots.headers[name] {
				if tok, ok := extract(v, t); ok && strings.HasPrefix(tok, access.AgentTokenPrefix) {
					presented, from = append(presented, tok), append(from, slot{header: name})
					break
				}
			}
		}
	}
	for _, v := range r.Header.Values("Authorization") {
		for _, t := range s.slots.basicAuth {
			if tok, ok := extractBasicAuth(v, t); ok && strings.HasPrefix(tok, access.AgentTokenPrefix) {
				presented, from = append(presented, tok), append(from, slot{header: "Authorization"})
				break
			}
		}
	}
	if len(s.slots.queries) > 0 {
		query := r.URL.Query()
		for _, name := range s.slots.queries {
			for _, v := range query[name] {
				if strings.HasPrefix(v, access.AgentTokenPrefix) {
					presented, from = append(presented, v), append(from, slot{query: name})
				}
			}
		}
	}
	for _, v := range r.Header.Values(AgentTokenHeader) {
		presented, from = append(presented, v), append(from, slot{header: AgentTokenHeader})
	}
	tok, ok := s.verifyAgentToken(w, r, presented)
	if !ok {
		return access.AgentToken{}, slot{}, false
	}
	return tok, from[0], true
}

// extract returns what sits where the Secret would in value under t. The
// template's literal text matches case-insensitively, as auth schemes do.
func extract(value string, t config.HeaderTemplate) (string, bool) {
	if len(value) < len(t.Prefix)+len(t.Suffix) ||
		!strings.EqualFold(value[:len(t.Prefix)], t.Prefix) ||
		!strings.EqualFold(value[len(value)-len(t.Suffix):], t.Suffix) {
		return "", false
	}
	return value[len(t.Prefix) : len(value)-len(t.Suffix)], true
}

// extractBasicAuth returns what sits where the Secret would in a basic auth
// Authorization value under t. The literal field must match exactly.
func extractBasicAuth(value string, t config.BasicAuthTemplate) (string, bool) {
	scheme, encoded, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	switch {
	case !ok:
		return "", false
	case t.SecretIsUsername:
		return username, password == t.Password
	default:
		return password, username == t.Username
	}
}

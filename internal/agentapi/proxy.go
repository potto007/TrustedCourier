package agentapi

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/secret"
)

// route is one Upstream of one Secret Name, served at
// /proxy/{secret_name}/{upstream}/.
type route struct {
	template  config.HeaderTemplate
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
				template:  s.InjectionTemplate.Header,
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
		TLSClientConfig:       &tls.Config{RootCAs: up.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// newSlots collects the credential slots every header Injection Template
// defines, by canonical header name.
func newSlots(cfg *config.Config) map[string][]config.HeaderTemplate {
	slots := make(map[string][]config.HeaderTemplate)
	for _, name := range slices.Sorted(maps.Keys(cfg.Secrets)) {
		if t := cfg.Secrets[name].InjectionTemplate; t != nil && !slices.Contains(slots[t.Header.Name], t.Header) {
			slots[t.Header.Name] = append(slots[t.Header.Name], t.Header)
		}
	}
	return slots
}

func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	tok, tokenHeader, ok := s.authenticateProxy(w, r)
	if !ok {
		return
	}
	// WebSockets are out of scope (ADR-0002), and an upgraded connection
	// would carry bytes TrustedCourier never inspects.
	if r.Header.Get("Upgrade") != "" {
		writeError(w, http.StatusBadRequest, "Proxy Delivery does not support protocol upgrades")
		return
	}
	rest, ok := forwardedPath(r.URL.EscapedPath())
	if !ok {
		writeError(w, http.StatusBadRequest, "the path must not contain dot segments")
		return
	}
	name, upName := r.PathValue("secret_name"), r.PathValue("upstream")
	log := s.log.With("delivery", config.DeliveryProxy, "agent_token_id", tok.ID, "secret_name", name, "upstream", upName)

	reason, allowed := s.access.Authorize(tok, name, config.DeliveryProxy)
	rt := s.routes[routeKey{name, upName}]
	if allowed && rt == nil {
		reason, allowed = "unknown Upstream", false
	}
	if !allowed {
		log.Info("Delivery denied", "reason", reason)
		writeError(w, http.StatusForbidden, deniedMessage)
		return
	}

	value, ok := s.resolve(w, r, log, name)
	if !ok {
		return
	}
	header, err := headerValue(rt.template, value)
	value.Release()
	if err != nil {
		log.Error("Delivery failed: the Secret cannot go in the Injection Template's header", "error", err)
		writeError(w, http.StatusBadGateway, "the Secret could not be delivered")
		return
	}

	target := &url.URL{Scheme: rt.upstream.Scheme, Host: rt.upstream.Host, RawQuery: r.URL.RawQuery}
	escaped := rt.upstream.BasePath + rest
	if escaped == "" {
		escaped = "/"
	}
	// rest came from a valid escaped path, so it unescapes.
	target.Path, _ = url.PathUnescape(escaped)
	target.RawPath = escaped

	// Streams such as server-sent events may outlast the write timeout, and
	// no Secret is held in locked memory while they run.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	(&httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = target
			pr.Out.Host = ""
			pr.Out.Header.Del(AgentTokenHeader)
			pr.Out.Header.Del(tokenHeader)
			pr.Out.Header.Set(rt.template.Name, header)
		},
		Transport: rt.transport,
		// Redirects reach the Agent as they are: the transport never follows
		// them, so the Secret is never sent to another host.
		ModifyResponse: func(res *http.Response) error {
			// noStore already set these; avoid duplicates.
			res.Header.Del("Cache-Control")
			res.Header.Del("X-Content-Type-Options")
			log.Info("Delivery allowed", "upstream_status", res.StatusCode)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				log.Info("Delivery abandoned by the Agent", "error", err)
				return
			}
			log.Error("Delivery failed: Upstream not reached", "error", err)
			writeError(w, http.StatusBadGateway, "the Upstream could not be reached")
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}).ServeHTTP(w, r)
}

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
			if part == "." || part == ".." {
				return "", false
			}
		}
	}
	return "/" + rest, true
}

// headerValue renders the header Injection Template around value. net/http
// takes header values only as strings, so this is where Proxy Delivery copies
// the Secret out of locked memory (ADR-0013).
func headerValue(t config.HeaderTemplate, value *secret.Secret) (string, error) {
	var b strings.Builder
	b.Grow(len(t.Prefix) + value.Len() + len(t.Suffix))
	b.WriteString(t.Prefix)
	if _, err := value.WriteTo(headerValueWriter{&b}); err != nil {
		return "", err
	}
	b.WriteString(t.Suffix)
	return b.String(), nil
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
func (s *Server) authenticateProxy(w http.ResponseWriter, r *http.Request) (access.AgentToken, string, bool) {
	var presented, headers []string
	for _, name := range slices.Sorted(maps.Keys(s.slots)) {
		for _, v := range r.Header.Values(name) {
			for _, t := range s.slots[name] {
				if tok, ok := extract(v, t); ok && strings.HasPrefix(tok, access.AgentTokenPrefix) {
					presented, headers = append(presented, tok), append(headers, name)
					break
				}
			}
		}
	}
	for _, v := range r.Header.Values(AgentTokenHeader) {
		presented, headers = append(presented, v), append(headers, AgentTokenHeader)
	}
	tok, ok := s.verifyAgentToken(w, r, presented)
	if !ok {
		return access.AgentToken{}, "", false
	}
	return tok, headers[0], true
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

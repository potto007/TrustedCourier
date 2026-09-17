package admin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/audit"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/httpserve"
	"github.com/potto007/TrustedCourier/internal/pluginhost"
	"github.com/potto007/TrustedCourier/internal/unixsocket"
)

// Listen binds the admin unix socket. A stale socket file left by a crashed
// process is replaced; a live one is an error.
//
// The peer-credential check is the gate. File modes are defense in depth:
// when only the server's own user is allowed, the socket is owner-only;
// when other users are allowed, it must be connectable by them.
func Listen(socket string, allowedUIDs []int) (net.Listener, error) {
	ownerOnly := !slices.ContainsFunc(allowedUIDs, func(uid int) bool { return uid != os.Getuid() })
	dirMode, sockMode := os.FileMode(0o700), os.FileMode(0o600)
	if !ownerOnly {
		dirMode, sockMode = 0o711, 0o666
	}

	return unixsocket.Listen(socket, dirMode, sockMode, "admin socket")
}

// Certificates supplies the remote admin listener's server certificate for
// each handshake. The certificate manager is one.
type Certificates interface {
	Certificate() (*tls.Certificate, error)
}

// ListenTLS binds the remote admin listener on the IP address and port
// listen. Every handshake requires a client certificate chaining to
// clientCAs, so a connection without one never reaches the admin API, and
// fails while no server certificate is loaded.
func ListenTLS(listen string, certs Certificates, clientCAs *x509.CertPool) (net.Listener, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen on the remote admin address: %w", err)
	}
	return tls.NewListener(ln, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certs.Certificate()
		},
	}), nil
}

// Server serves the admin API.
type Server struct {
	access  *access.Service
	plugins *pluginhost.Host
	audit   *audit.Log
	cfg     *config.Running
	agent   AgentAPI
	// remoteCertificate reports the remote admin listener's certificate,
	// or is nil when the listener is off.
	remoteCertificate CertificateStatus
	log               *slog.Logger
}

// CertificateStatus reports a TLS listener's certificate state. The
// certificate manager, wrapped by the server package, is one.
type CertificateStatus interface {
	Status() TLSCertificateStatus
}

// AgentAPI is how the Agent API is served, as the admin API reports it.
type AgentAPI struct {
	// URL is the Agent API's base URL, such as http://127.0.0.1:8200 or
	// https://0.0.0.0:8443. Empty when it is not served, or served on a unix
	// socket.
	URL string
	// Socket is the unix socket path the Agent API is served on, or empty.
	Socket string
	// Certificate reports the TLS certificate's state. Nil when the Agent
	// API does not serve TLS.
	Certificate CertificateStatus
}

// NewServer returns an admin API server for the running config that admits
// connections from its allowed UIDs presenting the Operator Credential.
// remoteCertificate reports the remote admin listener's certificate, or is
// nil when the listener is off.
func NewServer(svc *access.Service, plugins *pluginhost.Host, auditLog *audit.Log, cfg *config.Running, agent AgentAPI, remoteCertificate CertificateStatus, log *slog.Logger) *Server {
	return &Server{access: svc, plugins: plugins, audit: auditLog, cfg: cfg, agent: agent, remoteCertificate: remoteCertificate, log: log}
}

// Serve serves the admin API on the unix socket listener ln until ctx is
// done. Each connection's local user is checked before the Operator
// Credential.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := s.httpServer(s.requirePeer(s.requireOperator(s.mux())), slog.NewLogLogger(s.log.Handler(), slog.LevelWarn))
	srv.ConnContext = withPeer
	return httpserve.Serve(ctx, srv, ln)
}

// ServeTLS serves the admin API on the remote admin listener ln, from
// ListenTLS, until ctx is done. The listener admits only clients presenting
// a trusted certificate; each request is then checked for one again, then
// for the Operator Credential. Failed handshakes are logged at Debug: any
// remote can fail one per connection.
func (s *Server) ServeTLS(ctx context.Context, ln net.Listener) error {
	srv := s.httpServer(s.requireClientCertificate(s.requireOperator(s.mux())), httpserve.ErrorLog(s.log))
	return httpserve.Serve(ctx, srv, ln)
}

// httpServer is the admin API's HTTP server with the limits both listeners
// share. A client that stops reading must not hold a connection open.
func (s *Server) httpServer(handler http.Handler, errorLog *log.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          errorLog,
	}
}

func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent-tokens", s.listAgentTokens)
	mux.HandleFunc("POST /v1/agent-tokens", s.issueAgentToken)
	mux.HandleFunc("DELETE /v1/agent-tokens/{id}", s.revokeAgentToken)
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/audit/verify", s.verifyAudit)
	mux.HandleFunc("GET /v1/secret-names/{name}/env", s.secretNameEnv)
	mux.HandleFunc("POST /v1/config/reload", s.reloadConfig)
	return mux
}

// requireClientCertificate refuses a request whose connection did not
// verify a client certificate. The listener already requires one, so this
// guards against the handler ever being served another way.
func (s *Server) requireClientCertificate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			s.log.Warn("remote admin request refused: no verified client certificate", "remote", r.RemoteAddr)
			writeError(w, http.StatusForbidden, "remote admin API: a client certificate is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type peerKey struct{}

type peer struct {
	uid int
	err error
}

func withPeer(ctx context.Context, c net.Conn) context.Context {
	p := peer{err: errors.New("not a unix socket connection")}
	if uc, ok := c.(*net.UnixConn); ok {
		p.uid, p.err = peerUID(uc)
	}
	return context.WithValue(ctx, peerKey{}, p)
}

func (s *Server) requirePeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := r.Context().Value(peerKey{}).(peer)
		if !ok {
			p.err = errors.New("peer credentials were not recorded")
		}
		if p.err != nil {
			s.log.Warn("admin connection refused: peer credentials unavailable", "error", p.err)
			writeError(w, http.StatusForbidden, "admin socket: connecting user is not allowed")
			return
		}
		if !slices.Contains(s.cfg.Snapshot().Admin.AllowedUIDs, p.uid) {
			s.log.Warn("admin connection refused: local user not allowed", "uid", p.uid)
			writeError(w, http.StatusForbidden, "admin socket: connecting user is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || presented == "" {
			writeError(w, http.StatusUnauthorized, "Operator Credential required")
			return
		}
		valid, err := s.access.VerifyOperatorCredential(r.Context(), presented)
		if err != nil {
			s.internalError(w, err)
			return
		}
		if !valid {
			writeError(w, http.StatusUnauthorized, "invalid Operator Credential")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) listAgentTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.access.ListAgentTokens(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	now := time.Now()
	out := make([]AgentToken, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, toAPI(t, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// maxRequestBody bounds admin request bodies; none legitimately comes close.
const maxRequestBody = 1 << 20

func (s *Server) issueAgentToken(w http.ResponseWriter, r *http.Request) {
	var req IssueAgentTokenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	issued, err := s.access.IssueAgentToken(r.Context(), req.Policies, req.ExpiresAt)
	if s.requestFailed(w, err) {
		return
	}
	s.log.Info("Agent Token issued", "id", issued.ID, "policies", issued.Policies, "expires_at", issued.ExpiresAt)
	writeJSON(w, http.StatusCreated, IssuedAgentToken{
		AgentToken: toAPI(issued.AgentToken, time.Now()),
		Token:      issued.Token,
	})
}

func (s *Server) revokeAgentToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.requestFailed(w, s.access.RevokeAgentToken(r.Context(), id)) {
		return
	}
	s.log.Info("Agent Token revoked", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	out := Status{
		FIPS140:        HostFIPS140(),
		BackendPlugins: []BackendPluginStatus{},
	}
	out.AuditSigningKey.Loaded, out.AuditSigningKey.Detail = s.audit.KeyStatus()
	out.AuditRecords.Pending, out.AuditRecords.Detail = s.audit.Backlog()
	if s.agent.Certificate != nil {
		status := s.agent.Certificate.Status()
		out.TLSCertificate = &status
	}
	if s.remoteCertificate != nil {
		status := s.remoteCertificate.Status()
		out.RemoteAdminTLSCertificate = &status
	}
	for _, p := range s.plugins.Status(r.Context()) {
		out.BackendPlugins = append(out.BackendPlugins, BackendPluginStatus{
			Name:         p.Name,
			State:        p.State,
			PID:          p.PID,
			Healthy:      p.Healthy,
			Detail:       p.Detail,
			Capabilities: p.Capabilities,
			FIPS140:      p.FIPS140,
			Restarts:     p.Restarts,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	v, err := s.audit.Verify(r.Context())
	switch {
	case errors.Is(err, audit.ErrNoSigningKey):
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	case err != nil:
		s.internalError(w, err)
		return
	}
	out := AuditVerification{Intact: v.Break == nil, Records: v.Records, Checkpoints: v.Checkpoints}
	if v.Break != nil {
		out.Break = &AuditBreak{Seq: v.Break.Seq, Problem: v.Break.Problem}
		s.log.Warn("audit chain broken", "seq", v.Break.Seq, "problem", v.Break.Problem)
	}
	writeJSON(w, http.StatusOK, out)
}

// listensOnUnspecified reports whether agentURL names an unspecified address
// such as 0.0.0.0 or [::], which no Agent can dial.
func listensOnUnspecified(agentURL string) bool {
	u, err := url.Parse(agentURL)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(u.Hostname())
	return err == nil && addr.IsUnspecified()
}

func (s *Server) secretNameEnv(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg := s.cfg.Snapshot()
	sn, ok := cfg.Secrets[name]
	agentURL := s.agent.URL
	if cfg.AgentAPI.PublicURL != "" {
		agentURL = cfg.AgentAPI.PublicURL
	}
	switch {
	case !ok:
		writeError(w, http.StatusNotFound, fmt.Sprintf("Secret Name %q is not defined", name))
		return
	case len(sn.Upstreams) == 0:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Secret Name %q has no upstreams, so no Agent can use it through Proxy Delivery", name))
		return
	case s.agent.Socket != "":
		writeError(w, http.StatusBadRequest, fmt.Sprintf("the Agent API is served on the unix socket %s, which no base URL can name; tc env needs agent_api.listen", s.agent.Socket))
		return
	case s.agent.URL == "":
		writeError(w, http.StatusBadRequest, "the Agent API is not served; set agent_api.listen")
		return
	case listensOnUnspecified(agentURL):
		writeError(w, http.StatusBadRequest, fmt.Sprintf("the Agent API listens on every interface (%s); set agent_api.public_url to the URL Agents reach it at", s.agent.URL))
		return
	}
	upstream := r.URL.Query().Get("upstream")
	names := slices.Sorted(maps.Keys(sn.Upstreams))
	switch _, ok := sn.Upstreams[upstream]; {
	case upstream == "" && len(names) == 1:
		upstream = names[0]
	case upstream == "":
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Secret Name %q has several Upstreams; choose one with --upstream (%s)", name, strings.Join(names, ", ")))
		return
	case !ok:
		writeError(w, http.StatusNotFound, fmt.Sprintf("Secret Name %q has no Upstream %q; it has %s", name, upstream, strings.Join(names, ", ")))
		return
	}
	out := SecretNameEnv{SecretName: name, Upstream: upstream, Env: []EnvVar{}}
	for _, v := range sn.Env {
		var value string
		switch v.Source {
		case config.EnvBaseURL:
			value = agentURL + "/proxy/" + name + "/" + upstream
		case config.EnvAgentToken:
			value = AgentTokenPlaceholder
		case config.EnvUsername:
			value = sn.InjectionTemplate.BasicAuth.Username
		case config.EnvPassword:
			value = sn.InjectionTemplate.BasicAuth.Password
		}
		out.Env = append(out.Env, EnvVar{Name: v.Name, Value: value})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) reloadConfig(w http.ResponseWriter, _ *http.Request) {
	cfg, err := s.cfg.Reload(s.plugins.CheckConfig)
	if err != nil {
		s.log.Warn("config reload refused; the running config stays in effect", "error", err)
		writeError(w, http.StatusBadRequest, "config not reloaded, the running config stays in effect: "+err.Error())
		return
	}
	s.log.Info("config reloaded", "path", cfg.Path, "policies", len(cfg.Policies), "secret_names", len(cfg.Secrets))
	writeJSON(w, http.StatusOK, ConfigReload{Path: cfg.Path, Policies: len(cfg.Policies), SecretNames: len(cfg.Secrets)})
}

func toAPI(t access.AgentToken, now time.Time) AgentToken {
	status := StatusActive
	switch {
	case t.RevokedAt != nil:
		status = StatusRevoked
	case !now.Before(t.ExpiresAt):
		status = StatusExpired
	}
	return AgentToken{
		ID:         t.ID,
		Policies:   t.Policies,
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
		Status:     status,
	}
}

// requestFailed writes the response for a non-nil err and reports whether it
// did.
func (s *Server) requestFailed(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var invalid *access.ValidationError
	if errors.As(err, &invalid) {
		writeError(w, http.StatusBadRequest, invalid.Error())
		return true
	}
	var notFound *access.NotFoundError
	if errors.As(err, &notFound) {
		writeError(w, http.StatusNotFound, notFound.Error())
		return true
	}
	s.internalError(w, err)
	return true
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.log.Error("admin request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

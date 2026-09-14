package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/pluginhost"
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

	if err := os.MkdirAll(filepath.Dir(socket), dirMode); err != nil {
		return nil, fmt.Errorf("create admin socket directory: %w", err)
	}
	if err := removeStaleSocket(socket); err != nil {
		return nil, err
	}
	var ln net.Listener
	// Bind owner-only so the socket is never more open than intended, then
	// widen it if other users are allowed.
	err := withUmask(0o177, func() error {
		var err error
		ln, err = net.Listen("unix", socket)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("listen on admin socket: %w", err)
	}
	if err := os.Chmod(socket, sockMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("set admin socket mode: %w", err)
	}
	return ln, nil
}

// removeStaleSocket removes socket only when it is a socket nothing listens
// on. Any other dial failure (a full backlog, a permission error) may mean a
// live server, so it is reported rather than unlinked.
func removeStaleSocket(socket string) error {
	info, err := os.Lstat(socket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect admin socket: %w", err)
	}
	if info.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("admin socket path %s exists and is not a socket", socket)
	}
	conn, err := net.Dial("unix", socket)
	switch {
	case err == nil:
		_ = conn.Close()
		return fmt.Errorf("another process is serving the admin socket %s", socket)
	case errors.Is(err, syscall.ECONNREFUSED):
		if err := os.Remove(socket); err != nil {
			return fmt.Errorf("remove stale admin socket: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("admin socket %s may be in use: %w", socket, err)
	}
}

// Server serves the admin API.
type Server struct {
	access      *access.Service
	plugins     *pluginhost.Host
	allowedUIDs []int
	log         *slog.Logger
}

// NewServer returns an admin API server that admits connections from
// allowedUIDs presenting the Operator Credential.
func NewServer(svc *access.Service, plugins *pluginhost.Host, allowedUIDs []int, log *slog.Logger) *Server {
	return &Server{access: svc, plugins: plugins, allowedUIDs: allowedUIDs, log: log}
}

// Serve serves the admin API on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent-tokens", s.listAgentTokens)
	mux.HandleFunc("POST /v1/agent-tokens", s.issueAgentToken)
	mux.HandleFunc("DELETE /v1/agent-tokens/{id}", s.revokeAgentToken)
	mux.HandleFunc("GET /v1/status", s.status)

	srv := &http.Server{
		Handler:           s.requirePeer(s.requireOperator(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       withPeer,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
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
		if !slices.Contains(s.allowedUIDs, p.uid) {
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
	out := Status{BackendPlugins: []BackendPluginStatus{}}
	for _, p := range s.plugins.Status(r.Context()) {
		out.BackendPlugins = append(out.BackendPlugins, BackendPluginStatus{
			Name:         p.Name,
			State:        p.State,
			PID:          p.PID,
			Healthy:      p.Healthy,
			Detail:       p.Detail,
			Capabilities: p.Capabilities,
			Restarts:     p.Restarts,
		})
	}
	writeJSON(w, http.StatusOK, out)
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

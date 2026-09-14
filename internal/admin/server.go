package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
)

// Listen binds the admin unix socket. A stale socket file left by a crashed
// process is replaced; a live one is an error.
func Listen(socket string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return nil, fmt.Errorf("create admin socket directory: %w", err)
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("admin socket path %s exists and is not a socket", socket)
		}
		if conn, err := net.Dial("unix", socket); err == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("another process is serving the admin socket %s", socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("remove stale admin socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen on admin socket: %w", err)
	}
	// The peer-credential check is the gate; the mode is defense in depth.
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("restrict admin socket: %w", err)
	}
	return ln, nil
}

// Server serves the admin API.
type Server struct {
	access      *access.Service
	allowedUIDs []int
	log         *slog.Logger
}

// NewServer returns an admin API server that admits connections from
// allowedUIDs presenting the Operator Credential.
func NewServer(svc *access.Service, allowedUIDs []int, log *slog.Logger) *Server {
	return &Server{access: svc, allowedUIDs: allowedUIDs, log: log}
}

// Serve serves the admin API on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent-tokens", s.listAgentTokens)

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
		p, _ := r.Context().Value(peerKey{}).(peer)
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
	out := make([]AgentToken, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, AgentToken(t))
	}
	writeJSON(w, http.StatusOK, out)
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

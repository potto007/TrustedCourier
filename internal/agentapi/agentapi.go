// Package agentapi is the Agent API: the HTTP API Agents call with an Agent
// Token. It serves Reveal Delivery.
package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/resolver"
)

// AgentTokenHeader carries the Agent Token when Authorization cannot.
const AgentTokenHeader = "X-TC-Agent-Token"

// deniedMessage is the one body every denial gets, whatever the reason, so
// Agents cannot tell a Secret Name they may not use from one that does not
// exist.
const deniedMessage = "denied: no Policy on this Agent Token allows this Delivery"

// Listen binds addr, which must be a loopback address: the Agent API serves
// plain HTTP.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on Agent API address: %w", err)
	}
	bound, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil || !bound.Addr().Unmap().IsLoopback() {
		_ = ln.Close()
		return nil, fmt.Errorf("Agent API bound %s, which is not a loopback address", ln.Addr())
	}
	return ln, nil
}

// Server serves the Agent API.
type Server struct {
	access  *access.Service
	secrets *resolver.Resolver
	log     *slog.Logger
}

// NewServer returns an Agent API server that authenticates Agents with svc
// and fetches Secrets through secrets.
func NewServer(svc *access.Service, secrets *resolver.Resolver, log *slog.Logger) *Server {
	return &Server{access: svc, secrets: secrets, log: log}
}

// Serve serves the Agent API on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/reveal/{secret_name}", s.reveal)

	srv := &http.Server{
		Handler:           noStore(mux),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
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

// noStore keeps every Agent API response, Secret or not, out of caches.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) reveal(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	name := r.PathValue("secret_name")
	log := s.log.With("delivery", config.DeliveryReveal, "agent_token_id", tok.ID, "secret_name", name)

	if err := s.access.Authorize(tok, name, config.DeliveryReveal); err != nil {
		var denied *access.DeniedError
		if !errors.As(err, &denied) {
			s.internalError(w, log, err)
			return
		}
		log.Info("Delivery denied", "reason", denied.Reason)
		writeError(w, http.StatusForbidden, deniedMessage)
		return
	}

	value, err := s.secrets.Resolve(r.Context(), name)
	if err != nil {
		log.Error("Delivery failed: Secret not fetched", "error", err)
		writeError(w, http.StatusBadGateway, "the Secret could not be fetched")
		return
	}
	defer value.Release()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(value.Len()))
	w.WriteHeader(http.StatusOK)
	if _, err := value.WriteTo(w); err != nil {
		log.Warn("Delivery interrupted", "error", err)
		return
	}
	log.Info("Delivery allowed")
}

// authenticate returns the Agent Token presented in the Authorization header
// as a bearer token, or in AgentTokenHeader. Otherwise it writes a 401 and
// reports false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (access.AgentToken, bool) {
	var presented []string
	for _, v := range r.Header.Values("Authorization") {
		token, ok := strings.CutPrefix(v, "Bearer ")
		if !ok {
			unauthorized(w, "Authorization must be a Bearer Agent Token")
			return access.AgentToken{}, false
		}
		presented = append(presented, token)
	}
	presented = append(presented, r.Header.Values(AgentTokenHeader)...)
	switch len(presented) {
	case 0:
		unauthorized(w, "Agent Token required")
		return access.AgentToken{}, false
	case 1:
	default:
		unauthorized(w, "present the Agent Token once")
		return access.AgentToken{}, false
	}

	tok, err := s.access.AuthenticateAgentToken(r.Context(), presented[0])
	switch {
	case err == nil:
		return tok, true
	case errors.Is(err, access.ErrAgentTokenInvalid),
		errors.Is(err, access.ErrAgentTokenExpired),
		errors.Is(err, access.ErrAgentTokenRevoked):
		unauthorized(w, err.Error())
	default:
		s.internalError(w, s.log, err)
	}
	return access.AgentToken{}, false
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="TrustedCourier"`)
	writeError(w, http.StatusUnauthorized, msg)
}

func (s *Server) internalError(w http.ResponseWriter, log *slog.Logger, err error) {
	log.Error("Agent API request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

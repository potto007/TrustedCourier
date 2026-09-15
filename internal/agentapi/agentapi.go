// Package agentapi is the Agent API: the HTTP API Agents call with an Agent
// Token. It serves Reveal Delivery and Proxy Delivery.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/audit"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/httpserve"
	"github.com/potto007/TrustedCourier/internal/resolver"
	"github.com/potto007/TrustedCourier/internal/secret"
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
	audit   *audit.Log
	log     *slog.Logger
	cfg     *config.Running

	// snapshotMu serializes rebuilding snapshot after a reload.
	snapshotMu sync.Mutex
	// snapshot is what the running config snapshot serves, built from it.
	snapshot atomic.Pointer[snapshot]

	// inflight is read-locked by every request, so Serve can wait for the
	// ones shutdown cut off to write their Audit Records.
	inflight sync.RWMutex
	// stopping is set once the server has begun shutting down.
	stopping atomic.Bool
}

// NewServer returns an Agent API server that authenticates Agents with svc,
// fetches Secrets through secrets, records every Delivery attempt in
// auditLog, and authorizes and proxies as the running config says.
func NewServer(svc *access.Service, secrets *resolver.Resolver, auditLog *audit.Log, cfg *config.Running, log *slog.Logger) *Server {
	s := &Server{access: svc, secrets: secrets, audit: auditLog, log: log, cfg: cfg}
	snap := cfg.Snapshot()
	s.snapshot.Store(&snapshot{cfg: snap, routes: newRoutes(snap, nil), slots: newSlots(snap)})
	return s
}

// snapshot is one config snapshot and the routes and credential slots built
// from it. A request takes one and uses only it, so a reload never mixes two
// configs in one Delivery.
type snapshot struct {
	cfg    *config.Config
	routes map[routeKey]*route
	slots  slots
}

// currentSnapshot returns the snapshot for the running config, building it
// the first time a request sees a reloaded config.
func (s *Server) currentSnapshot() *snapshot {
	cfg := s.cfg.Snapshot()
	if snap := s.snapshot.Load(); snap.cfg == cfg {
		return snap
	}
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	// Read the running config again: a slower request must not replace a
	// newer snapshot with its older one.
	cfg = s.cfg.Snapshot()
	old := s.snapshot.Load()
	if old.cfg == cfg {
		return old
	}
	snap := &snapshot{cfg: cfg, routes: newRoutes(cfg, old.routes), slots: newSlots(cfg)}
	s.snapshot.Store(snap)
	closeUnused(old.routes, snap.routes)
	return snap
}

// Serve serves the Agent API on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/reveal/{secret_name}", s.reveal)
	mux.HandleFunc("/proxy/{secret_name}/{upstream}", s.proxy)
	mux.HandleFunc("/proxy/{secret_name}/{upstream}/{rest...}", s.proxy)

	// The listener is loopback plain HTTP, so HTTP/2 is by prior knowledge.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	handler := noStore(s.requireAudit(mux))
	srv := &http.Server{
		Protocols: protocols,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.inflight.RLock()
			defer s.inflight.RUnlock()
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		// A client that stops reading must not pin a Secret's locked memory.
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    time.Minute,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	stop := context.AfterFunc(ctx, func() { s.stopping.Store(true) })
	defer stop()
	err := httpserve.Serve(ctx, srv, ln)
	// Every Delivery attempt still gets its Audit Record, even when shutdown
	// cut it off.
	s.inflight.Lock()
	return err
}

// noStore keeps every Agent API response, Secret or not, out of caches.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// requireAudit refuses every request, before any Agent Token is checked,
// while the audit signing key is not loaded or Audit Records cannot be
// stored, so no new Delivery goes unaudited.
func (s *Server) requireAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.audit.Ready(); err != nil {
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "TrustedCourier is not serving Deliveries: "+err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) reveal(w http.ResponseWriter, r *http.Request) {
	// A GET pattern also matches HEAD, which would fetch a Secret and deliver
	// nothing.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tok, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	snap := s.currentSnapshot()
	name := r.PathValue("secret_name")
	log := s.log.With("delivery", config.DeliveryReveal, "agent_token_id", tok.ID, "secret_name", name)
	rec := &audit.Record{AgentTokenID: tok.ID, SecretName: name, Delivery: config.DeliveryReveal}
	defer s.record(r, log, rec)

	if reason, allowed := access.Authorize(snap.cfg, tok, name, config.DeliveryReveal); !allowed {
		log.Info("Delivery denied", "reason", reason)
		rec.Decision, rec.Reason = audit.Denied, string(reason)
		writeError(w, http.StatusForbidden, deniedMessage)
		return
	}
	rec.Decision = audit.Allowed

	value, ok := s.resolve(w, r, log, rec, snap.cfg, name)
	if !ok {
		return
	}
	defer value.Release()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(value.Len()))
	w.WriteHeader(http.StatusOK)
	if _, err := value.WriteTo(w); err != nil {
		log.Warn("Delivery interrupted", "error", err)
		rec.Failure = "the Secret could not be written to the Agent"
		return
	}
	log.Info("Delivery allowed")
}

// record appends the Audit Record for a Delivery attempt once it has ended.
// The Agent may be gone by then, so its request's cancellation does not stop
// the write.
func (s *Server) record(r *http.Request, log *slog.Logger, rec *audit.Record) {
	if err := s.audit.Append(context.WithoutCancel(r.Context()), *rec); err != nil {
		log.Error("Audit Record failed", "error", err)
	}
}

// resolve fetches the Secret for name as the config snapshot cfg maps it.
// Otherwise it writes the error, notes the failure in rec, and reports false.
// The caller must Release the Secret.
func (s *Server) resolve(w http.ResponseWriter, r *http.Request, log *slog.Logger, rec *audit.Record, cfg *config.Config, name string) (*secret.Secret, bool) {
	value, err := s.secrets.Resolve(r.Context(), cfg, name)
	switch {
	case errors.Is(err, secret.ErrLockedMemory):
		log.Error("Delivery failed: no locked memory to hold the Secret; raise RLIMIT_MEMLOCK", "error", err)
		rec.Failure = "no locked memory to hold the Secret"
		writeError(w, http.StatusServiceUnavailable, "the Secret cannot be held safely right now; try again later")
		return nil, false
	case err != nil:
		log.Error("Delivery failed: Secret not fetched", "error", err)
		rec.Failure = "the Secret could not be fetched"
		writeError(w, http.StatusBadGateway, "the Secret could not be fetched")
		return nil, false
	}
	return value, true
}

// authenticate returns the Agent Token presented in the Authorization header
// as a bearer token, or in AgentTokenHeader. Otherwise it writes a 401 and
// reports false.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (access.AgentToken, bool) {
	var presented []string
	for _, v := range r.Header.Values("Authorization") {
		scheme, token, _ := strings.Cut(v, " ")
		if !strings.EqualFold(scheme, "Bearer") {
			unauthorized(w, "Authorization must be a Bearer Agent Token")
			return access.AgentToken{}, false
		}
		presented = append(presented, token)
	}
	presented = append(presented, r.Header.Values(AgentTokenHeader)...)
	return s.verifyAgentToken(w, r, presented)
}

// verifyAgentToken authenticates the one Agent Token in presented. Otherwise
// it writes a 401, or a 500 when the check itself failed, and reports false.
func (s *Server) verifyAgentToken(w http.ResponseWriter, r *http.Request, presented []string) (access.AgentToken, bool) {
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
	case r.Context().Err() != nil:
		// The Agent went away; there is no one to answer.
	default:
		s.log.Error("Agent API request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
	return access.AgentToken{}, false
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="TrustedCourier"`)
	writeError(w, http.StatusUnauthorized, msg)
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

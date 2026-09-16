// Package pluginhost is the Plugin Host: it launches the Backend Plugins the
// Operator pinned, as a separate OS user, supervises and restarts them, and
// reports their health and capabilities (ADR-0004). Every plugin response
// goes through the SDK client, which treats it as untrusted input.
package pluginhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hashicorp/go-hclog"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/secret"
	"github.com/potto007/TrustedCourier/sdk/plugin/client"
)

// Plugin states.
const (
	StateStarting   = "starting"
	StateRunning    = "running"
	StateRestarting = "restarting"
	StateStopped    = "stopped"
	// StateRefused is a plugin the server will not run and will not
	// relaunch: it is outside the server's FIPS 140-3 mode.
	StateRefused = "refused"
)

const (
	minBackoff = 250 * time.Millisecond
	maxBackoff = 30 * time.Second
	// stableAfter is how long a plugin must run before a crash no longer
	// counts toward backoff.
	stableAfter   = time.Minute
	exitPoll      = 100 * time.Millisecond
	healthTimeout = 5 * time.Second
	getTimeout    = 10 * time.Second
)

// Host supervises the configured Backend Plugins.
type Host struct {
	log     *slog.Logger
	plugins []*supervised
	wg      sync.WaitGroup
}

// Status is one Backend Plugin's state as the Operator sees it.
type Status struct {
	Name  string
	State string
	// PID is zero unless the plugin is running.
	PID     int
	Healthy bool
	// Detail is the plugin's health detail when it answered, otherwise why
	// it is not healthy.
	Detail       string
	Capabilities []string
	// FIPS140 is the running plugin's FIPS 140-3 mode: "off", "on", or
	// "only"; empty while it is not running.
	FIPS140 string
	// Restarts counts relaunches after the first launch.
	Restarts int
}

// New checks every configured Backend Plugin can be launched safely: its
// binary matches the pinned SHA-256 and its OS user is separate from the
// server's and cannot read the config or database. It launches nothing.
func New(cfg *config.Config, stderr io.Writer, log *slog.Logger) (*Host, error) {
	h := &Host{log: log}
	for _, name := range slices.Sorted(maps.Keys(cfg.BackendPlugins)) {
		pc := cfg.BackendPlugins[name]
		f, err := openVerified(pc)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		cred, err := pluginCredential(cfg, pc)
		if err != nil {
			return nil, fmt.Errorf("Backend Plugin %q: %w", name, err)
		}
		if cred == nil {
			log.Warn("Backend Plugin shares the server's OS user and can read its config and database; use only for development",
				"backend_plugin", name)
		}
		h.plugins = append(h.plugins, &supervised{
			cfg:   pc,
			cred:  cred,
			state: StateStarting,
			log:   log.With("backend_plugin", name),
			hlog: hclog.New(&hclog.LoggerOptions{
				Name:   "backend-plugin." + name,
				Output: sanitizingWriter{stderr},
				Level:  hclog.Info,
			}),
		})
	}
	return h, nil
}

// CheckConfig checks, as New does, that no Backend Plugin's OS user can read
// cfg's config file or owns its data directory, for a config reloaded while
// the plugins run.
func (h *Host) CheckConfig(cfg *config.Config) error {
	for _, p := range h.plugins {
		if p.cred == nil {
			continue
		}
		if err := checkSeparation(cfg, p.cred, p.cfg.User); err != nil {
			return fmt.Errorf("Backend Plugin %q: %w", p.cfg.Name, err)
		}
	}
	return nil
}

// Start launches every Backend Plugin in the background. When ctx is done
// the plugins are stopped; Wait returns once they have exited.
func (h *Host) Start(ctx context.Context) {
	for _, p := range h.plugins {
		h.wg.Go(func() { p.run(ctx) })
	}
}

// Wait blocks until every plugin stopped after Start's ctx was done.
func (h *Host) Wait() { h.wg.Wait() }

// Status reports every Backend Plugin, asking each running one for its
// health.
func (h *Host) Status(ctx context.Context) []Status {
	out := make([]Status, len(h.plugins))
	var wg sync.WaitGroup
	for i, p := range h.plugins {
		wg.Go(func() { out[i] = p.status(ctx) })
	}
	wg.Wait()
	return out
}

// ErrNotRunning reports a Backend Plugin that is not running, such as one
// being restarted.
var ErrNotRunning = errors.New("Backend Plugin is not running")

// Get fetches the Secret at location from the named Backend Plugin. The
// caller must Release it.
func (h *Host) Get(ctx context.Context, backendPlugin, location string) (*secret.Secret, error) {
	c, err := h.running(backendPlugin)
	if err != nil {
		return nil, err
	}
	gctx, cancel := context.WithTimeout(ctx, getTimeout)
	defer cancel()
	value, err := c.Get(gctx, location)
	if err != nil {
		return nil, fmt.Errorf("Backend Plugin %q: %w", backendPlugin, err)
	}
	return secret.New(value)
}

// ErrReadOnly reports a Backend Plugin without the courier-key-write
// capability.
var ErrReadOnly = errors.New("cannot store Courier Keys: it does not have the courier-key-write capability")

// CanWriteCourierKeys reports nil when the named Backend Plugin is running
// and stores Courier Keys, ErrReadOnly when it runs without that capability,
// and ErrNotRunning while it is down.
func (h *Host) CanWriteCourierKeys(backendPlugin string) error {
	c, err := h.running(backendPlugin)
	if err != nil {
		return err
	}
	if !c.Capabilities().CourierKeyWrite {
		return fmt.Errorf("Backend Plugin %q %w", backendPlugin, ErrReadOnly)
	}
	return nil
}

// WriteCourierKey stores value as the Courier Key at location in the named
// Backend Plugin. value is the caller's to wipe.
func (h *Host) WriteCourierKey(ctx context.Context, backendPlugin, location string, value []byte) error {
	c, err := h.running(backendPlugin)
	if err != nil {
		return err
	}
	if !c.Capabilities().CourierKeyWrite {
		return fmt.Errorf("Backend Plugin %q %w", backendPlugin, ErrReadOnly)
	}
	wctx, cancel := context.WithTimeout(ctx, getTimeout)
	defer cancel()
	if err := c.WriteCourierKey(wctx, location, value); err != nil {
		return fmt.Errorf("Backend Plugin %q: %w", backendPlugin, err)
	}
	return nil
}

// running returns the named plugin's client while it runs.
func (h *Host) running(backendPlugin string) (*client.Client, error) {
	i := slices.IndexFunc(h.plugins, func(p *supervised) bool { return p.cfg.Name == backendPlugin })
	if i < 0 {
		return nil, fmt.Errorf("Backend Plugin %q is not configured", backendPlugin)
	}
	p := h.plugins[i]
	p.mu.Lock()
	c := p.client
	p.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("Backend Plugin %q: %w", backendPlugin, ErrNotRunning)
	}
	return c, nil
}

// FileSHA256 returns the SHA-256 of the file at path as the config pins it.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// openVerified opens the plugin binary and checks it against the pinned
// hash. The returned file is what gets executed, so the binary cannot be
// swapped between the check and exec.
func openVerified(pc config.BackendPlugin) (*os.File, error) {
	f, err := os.Open(pc.Path)
	if err != nil {
		return nil, fmt.Errorf("Backend Plugin %q: %w", pc.Name, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("Backend Plugin %q: read %s: %w", pc.Name, pc.Path, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != pc.SHA256 {
		_ = f.Close()
		return nil, fmt.Errorf("Backend Plugin %q: %s has SHA-256 %s, but the config pins %s; refusing to run it",
			pc.Name, pc.Path, got, pc.SHA256)
	}
	return f, nil
}

// supervised is one Backend Plugin and its supervisor's state.
type supervised struct {
	cfg  config.BackendPlugin
	cred *credential // nil runs the plugin as the server's user
	log  *slog.Logger
	hlog hclog.Logger

	mu       sync.Mutex
	client   *client.Client
	state    string
	restarts int
	lastErr  string
}

func (p *supervised) run(ctx context.Context) {
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.state != StateRefused {
			p.state, p.lastErr = StateStopped, ""
		}
	}()
	backoff := minBackoff
	for attempt := 0; ctx.Err() == nil; attempt++ {
		if attempt > 0 {
			p.mu.Lock()
			p.restarts++
			p.state = StateStarting
			p.mu.Unlock()
		}
		started := time.Now()
		c, err := p.launch()
		if errors.Is(err, ErrNotFIPS) {
			p.log.Error("Backend Plugin refused; it will not be relaunched", "error", err)
			p.setState(StateRefused, err.Error())
			return
		}
		if err != nil {
			p.log.Error("Backend Plugin failed to start", "error", err)
			p.setState(StateRestarting, err.Error())
		} else {
			p.mu.Lock()
			p.client, p.state, p.lastErr = c, StateRunning, ""
			p.mu.Unlock()
			p.log.Info("Backend Plugin running", "pid", c.PID(), "capabilities", c.Capabilities().Names(),
				"fips140", c.FIPS140().Mode(), "fips140_module", c.FIPS140().Version)

			exited := waitExit(ctx, c)
			c.Kill()
			p.mu.Lock()
			p.client = nil
			p.mu.Unlock()
			if !exited {
				return
			}
			p.log.Error("Backend Plugin exited unexpectedly; restarting")
			p.setState(StateRestarting, "Backend Plugin exited unexpectedly")
		}
		if time.Since(started) >= stableAfter {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// waitExit reports true when the plugin exits and false when ctx is done
// first.
func waitExit(ctx context.Context, c *client.Client) bool {
	tick := time.NewTicker(exitPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
			if c.Exited() {
				return true
			}
		}
	}
}

func (p *supervised) launch() (*client.Client, error) {
	f, err := openVerified(p.cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	cmd := verifiedCommand(f, p.cfg.Path)
	cmd.Dir = "/"
	// The plugin's whole environment: what the Operator configured, plus the
	// server's FIPS 140-3 mode, which may come from the build's default
	// rather than the server's own GODEBUG, so it is always spelled out.
	cmd.Env = append(slices.Clone(p.cfg.Env), "GODEBUG="+client.GODEBUG())
	if err := setCredential(cmd, p.cred); err != nil {
		return nil, err
	}
	c, err := client.Start(cmd, p.hlog)
	if err != nil {
		return nil, err
	}
	// A server in FIPS 140-3 mode serves Secrets only through processes in
	// at least its mode (ADR-0004, ADR-0027). A plugin built on the SDK
	// follows the GODEBUG above; one that reports a weaker mode is outside
	// the boundary, and no relaunch changes that.
	if host := client.HostFIPS140(); !c.FIPS140().Covers(host) {
		c.Kill()
		return nil, fmt.Errorf("%w: it reports FIPS 140-3 mode %s and the server runs in mode %s; rebuild it on the current plugin SDK",
			ErrNotFIPS, c.FIPS140().Mode(), host.Mode())
	}
	return c, nil
}

// ErrNotFIPS reports a Backend Plugin refused because it is not in the
// server's FIPS 140-3 mode. The refusal is final: the plugin is not
// relaunched until the server restarts.
var ErrNotFIPS = errors.New("Backend Plugin refused: it is not in FIPS 140-3 mode")

func (p *supervised) setState(state, lastErr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state, p.lastErr = state, lastErr
}

func (p *supervised) status(ctx context.Context) Status {
	p.mu.Lock()
	c := p.client
	s := Status{
		Name:         p.cfg.Name,
		State:        p.state,
		Detail:       p.lastErr,
		Restarts:     p.restarts,
		Capabilities: []string{},
	}
	p.mu.Unlock()
	if c == nil {
		return s
	}
	s.PID = c.PID()
	s.Capabilities = c.Capabilities().Names()
	s.FIPS140 = c.FIPS140().Mode()
	hctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	detail, err := c.Health(hctx)
	if err != nil {
		var unhealthy *client.UnhealthyError
		if !errors.As(err, &unhealthy) {
			p.log.Warn("Backend Plugin health check failed", "error", err)
		}
		s.Detail = err.Error()
		return s
	}
	s.Healthy, s.Detail = true, detail
	return s
}

// sanitizingWriter keeps text relayed from plugin output from forging log
// lines or driving a terminal. hclog writes one entry per Write, so only a
// trailing newline is kept; any other control character (C0, DEL, C1), and
// invalid UTF-8, becomes '?'.
type sanitizingWriter struct{ w io.Writer }

func (s sanitizingWriter) Write(b []byte) (int, error) {
	body, newline := bytes.CutSuffix(b, []byte("\n"))
	clean := []byte(strings.Map(func(r rune) rune {
		if r == utf8.RuneError || (unicode.IsControl(r) && r != '\t') {
			return '?'
		}
		return r
	}, string(body)))
	if newline {
		clean = append(clean, '\n')
	}
	if _, err := s.w.Write(clean); err != nil {
		return 0, err
	}
	return len(b), nil
}

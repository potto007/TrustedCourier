package config

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Running holds the config snapshot in effect. Reload replaces it atomically,
// so a caller that took a snapshot keeps a consistent one for as long as it
// holds it, such as for the whole of one Delivery.
type Running struct {
	mu      sync.Mutex // serializes Reload
	current atomic.Pointer[Config]
}

// NewRunning returns a Running holding cfg.
func NewRunning(cfg *Config) *Running {
	r := &Running{}
	r.current.Store(cfg)
	return r
}

// Snapshot returns the config snapshot in effect. Treat it as read-only.
func (r *Running) Snapshot() *Config { return r.current.Load() }

// Reload loads and validates the config file the running snapshot came from
// and puts it in effect once check, the startup checks that live outside this
// package, accepts it. On any error the running snapshot stays in effect.
//
// Only Policies and Secret Names, with their Upstreams and Injection
// Templates, change on reload. A config that changes anything else is
// refused, naming the keys that need a restart, rather than applied in part.
func (r *Running) Reload(check func(*Config) error) (*Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.current.Load()
	cfg, err := Load(old.Path)
	if err != nil {
		return nil, err
	}
	if keys := restartKeys(old, cfg); len(keys) > 0 {
		return nil, errors.New(strings.Join(keys, ", ") + " changed, which takes effect only on restart; restore it to reload the rest")
	}
	if err := check(cfg); err != nil {
		return nil, err
	}
	r.current.Store(cfg)
	return cfg, nil
}

// restartKeys names the top-level keys that differ between old and cfg but
// cannot change while the server runs: they bind listeners, open the
// database, launch Backend Plugins, or load the audit signing key.
func restartKeys(old, cfg *Config) []string {
	var keys []string
	if old.DataDir != cfg.DataDir {
		keys = append(keys, "data_dir")
	}
	if old.Admin.Socket != cfg.Admin.Socket ||
		!slices.Equal(slices.Sorted(slices.Values(old.Admin.AllowedUIDs)), slices.Sorted(slices.Values(cfg.Admin.AllowedUIDs))) {
		keys = append(keys, "admin")
	}
	if old.AgentAPI != cfg.AgentAPI {
		keys = append(keys, "agent_api")
	}
	if !maps.Equal(old.BackendPlugins, cfg.BackendPlugins) {
		keys = append(keys, "backend_plugins")
	}
	oldKey, newKey := old.Audit.SigningKey, cfg.Audit.SigningKey
	if (oldKey == nil) != (newKey == nil) || (oldKey != nil && *oldKey != *newKey) ||
		old.Audit.CheckpointRecords != cfg.Audit.CheckpointRecords ||
		old.Audit.CheckpointInterval != cfg.Audit.CheckpointInterval {
		keys = append(keys, "audit")
	}
	return keys
}

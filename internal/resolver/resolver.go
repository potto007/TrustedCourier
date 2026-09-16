// Package resolver is the Secret Resolver: it resolves a Secret Name through
// a config snapshot to a Backend location and fetches the Secret through the
// Plugin Host, on every Delivery unless the Secret Name sets a cache TTL.
package resolver

import (
	"context"
	"fmt"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/pluginhost"
	"github.com/potto007/TrustedCourier/internal/secret"
)

// Resolver is the Secret Resolver.
type Resolver struct {
	plugins *pluginhost.Host
	cache   *cache
}

// New returns a Resolver that fetches through plugins and caches as the
// running config allows, wiping what a reload stops caching. Close it to wipe
// the Secrets it caches.
func New(plugins *pluginhost.Host, running *config.Running) *Resolver {
	c := newCache(running.Snapshot)
	running.OnReload(c.prune)
	return &Resolver{plugins: plugins, cache: c}
}

// Resolve returns the Secret for secretName as the config snapshot cfg maps
// it, from the cache while the Secret Name's cache TTL allows. The caller must
// Release it.
func (r *Resolver) Resolve(ctx context.Context, cfg *config.Config, secretName string) (*secret.Secret, error) {
	s, ok := cfg.Secrets[secretName]
	if !ok {
		return nil, fmt.Errorf("unknown Secret Name %q", secretName)
	}
	fetch := func() (*secret.Secret, error) { return r.plugins.Get(ctx, s.Backend, s.Location) }
	if s.CacheTTL == 0 {
		return fetch()
	}
	return r.cache.get(secretName, s.Backend, s.Location, s.CacheTTL, fetch)
}

// Close wipes every cached Secret. Resolve still works after Close, without
// caching.
func (r *Resolver) Close() {
	r.cache.close()
}

// CourierKey fetches the Courier Key at key. The caller must Release it and
// never deliver it to an Agent.
func (r *Resolver) CourierKey(ctx context.Context, key config.CourierKey) (*secret.Secret, error) {
	return r.plugins.Get(ctx, key.Backend, key.Location)
}

// WriteCourierKey stores value as the Courier Key at key. value is the
// caller's to wipe.
func (r *Resolver) WriteCourierKey(ctx context.Context, key config.CourierKey, value []byte) error {
	return r.plugins.WriteCourierKey(ctx, key.Backend, key.Location, value)
}

// CanWriteCourierKey reports whether key's Backend stores Courier Keys, as
// the Plugin Host reports it.
func (r *Resolver) CanWriteCourierKey(key config.CourierKey) error {
	return r.plugins.CanWriteCourierKeys(key.Backend)
}

// Package resolver is the Secret Resolver: it resolves a Secret Name through
// the config to a Backend location and fetches the Secret through the Plugin
// Host on every Delivery.
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
	cfg     *config.Config
	plugins *pluginhost.Host
}

// New returns a Resolver over cfg's Secret Names that fetches through plugins.
func New(cfg *config.Config, plugins *pluginhost.Host) *Resolver {
	return &Resolver{cfg: cfg, plugins: plugins}
}

// Resolve fetches the Secret for secretName. The caller must Release it.
func (r *Resolver) Resolve(ctx context.Context, secretName string) (*secret.Secret, error) {
	s, ok := r.cfg.Secrets[secretName]
	if !ok {
		return nil, fmt.Errorf("unknown Secret Name %q", secretName)
	}
	return r.plugins.Get(ctx, s.Backend, s.Location)
}

// CourierKey fetches the Courier Key at key. The caller must Release it and
// never deliver it to an Agent.
func (r *Resolver) CourierKey(ctx context.Context, key config.CourierKey) (*secret.Secret, error) {
	return r.plugins.Get(ctx, key.Backend, key.Location)
}

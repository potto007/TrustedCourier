package resolver

import (
	"sync"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/secret"
)

// cache holds Secrets for the Secret Names that set a cache TTL (ADR-0001).
// Every cached Secret stays in locked memory and is wiped when its TTL ends,
// when a reload deletes or moves its Secret Name or turns its cache off, and
// by close. Callers get their own copy, so releasing it after a Delivery
// leaves the cached one intact.
type cache struct {
	// running returns the config snapshot in effect.
	running func() *config.Config

	mu      sync.Mutex
	entries map[string]*entry
	closed  bool
}

// entry is one cached Secret and where it was fetched from.
type entry struct {
	backend, location string
	fetched           time.Time
	ttl               time.Duration
	value             *secret.Secret
	timer             *time.Timer
}

func newCache(running func() *config.Config) *cache {
	return &cache{running: running, entries: make(map[string]*entry)}
}

// get returns a copy of the Secret cached for name when it was fetched from
// backend and location less than ttl ago. Otherwise it fetches the Secret
// with fetch and caches it, if the running config still maps name that way.
// The caller must Release the copy.
func (c *cache) get(name, backend, location string, ttl time.Duration, fetch func() (*secret.Secret, error)) (*secret.Secret, error) {
	c.mu.Lock()
	if e := c.entries[name]; e != nil && e.backend == backend && e.location == location && time.Since(e.fetched) < ttl {
		defer c.mu.Unlock()
		return e.value.Clone()
	}
	c.mu.Unlock()

	fetched := time.Now()
	value, err := fetch()
	if err != nil {
		return nil, err
	}
	// Without locked memory for a second copy, deliver this one uncached.
	delivered, err := value.Clone()
	if err != nil {
		return value, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// A request that started before a reload must not cache what the reload
	// removed. Checking under mu is enough: prune runs after the new snapshot
	// is in effect and takes mu, so it wipes anything cached before the check
	// could see that snapshot.
	current, ok := c.running().Secrets[name]
	if c.closed || !ok || current.Backend != backend || current.Location != location || current.CacheTTL == 0 {
		value.Release()
		return delivered, nil
	}
	if old := c.entries[name]; old != nil {
		old.wipe()
	}
	e := &entry{backend: backend, location: location, fetched: fetched, ttl: min(ttl, current.CacheTTL), value: value}
	e.timer = time.AfterFunc(e.ttl-time.Since(fetched), func() { c.expire(name, e) })
	c.entries[name] = e
	return delivered, nil
}

// prune applies a reloaded config snapshot to the cache: it wipes every
// Secret whose Secret Name cfg deletes, moves, or no longer caches, and ends
// the rest by cfg's TTL where that is shorter.
func (c *cache) prune(cfg *config.Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, e := range c.entries {
		s, ok := cfg.Secrets[name]
		left := s.CacheTTL - time.Since(e.fetched)
		switch {
		case !ok || s.Backend != e.backend || s.Location != e.location || s.CacheTTL == 0 || left <= 0:
			e.wipe()
			delete(c.entries, name)
		case s.CacheTTL < e.ttl:
			e.ttl = s.CacheTTL
			e.timer.Reset(left)
		}
	}
}

// expire wipes e once its TTL has ended.
func (c *cache) expire(name string, e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries[name] == e {
		delete(c.entries, name)
	}
	e.value.Release()
}

// close wipes every cached Secret. Later gets fetch without caching.
func (c *cache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for name, e := range c.entries {
		e.wipe()
		delete(c.entries, name)
	}
}

func (e *entry) wipe() {
	e.timer.Stop()
	e.value.Release()
}

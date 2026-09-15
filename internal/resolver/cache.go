package resolver

import (
	"sync"
	"time"

	"github.com/potto007/TrustedCourier/internal/secret"
)

// cache holds Secrets for the Secret Names that set a cache TTL (ADR-0001).
// Every cached Secret stays in locked memory, is wiped when its TTL ends, and
// is wiped by close. Callers get their own copy, so releasing it after a
// Delivery leaves the cached one intact.
type cache struct {
	mu      sync.Mutex
	entries map[string]*entry
	closed  bool
}

// entry is one cached Secret and where it was fetched from.
type entry struct {
	backend, location string
	fetched           time.Time
	value             *secret.Secret
	timer             *time.Timer
}

func newCache() *cache {
	return &cache{entries: make(map[string]*entry)}
}

// get returns a copy of the Secret cached for name when it was fetched from
// backend and location less than ttl ago. Otherwise it fetches the Secret
// with fetch and caches it for ttl. The caller must Release the copy.
func (c *cache) get(name, backend, location string, ttl time.Duration, fetch func() (*secret.Secret, error)) (*secret.Secret, error) {
	c.mu.Lock()
	// A reload may have moved the Secret Name or shortened its TTL since the
	// entry was fetched.
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
	if c.closed {
		value.Release()
		return delivered, nil
	}
	if old := c.entries[name]; old != nil {
		old.wipe()
	}
	e := &entry{backend: backend, location: location, fetched: fetched, value: value}
	e.timer = time.AfterFunc(ttl-time.Since(fetched), func() { c.expire(name, e) })
	c.entries[name] = e
	return delivered, nil
}

// forget wipes the Secret cached for name, if any, as when a reload turned
// its cache off.
func (c *cache) forget(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[name]; e != nil {
		e.wipe()
		delete(c.entries, name)
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

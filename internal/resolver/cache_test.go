package resolver

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/secret"
)

// Wiping is not observable through the process, so these tests check that
// the cache releases the Secrets it holds.

const value = "sk-live-0123456789"

// fixture is a cache over a config snapshot mapping Secret Name github to the
// fake Backend, and a fake Backend fetch that keeps every Secret it returned.
type fixture struct {
	c       *cache
	cfg     atomic.Pointer[config.Config]
	fetched []*secret.Secret
}

func snapshot(location string, ttl time.Duration) *config.Config {
	return &config.Config{Secrets: map[string]config.SecretName{
		"github": {Name: "github", Backend: "fake", Location: location, CacheTTL: ttl},
	}}
}

func newFixture(t *testing.T, location string, ttl time.Duration) *fixture {
	f := &fixture{}
	f.cfg.Store(snapshot(location, ttl))
	f.c = newCache(f.cfg.Load)
	t.Cleanup(f.c.close)
	return f
}

func (f *fixture) fetch() (*secret.Secret, error) {
	s, err := secret.New([]byte(value))
	if err == nil {
		f.fetched = append(f.fetched, s)
	}
	return s, err
}

// get delivers github as the running snapshot maps it.
func (f *fixture) get(t *testing.T) {
	t.Helper()
	s := f.cfg.Load().Secrets["github"]
	f.getAs(t, s.Location, s.CacheTTL)
}

// getAs delivers github as a request on a snapshot mapping it to location
// with ttl would.
func (f *fixture) getAs(t *testing.T, location string, ttl time.Duration) {
	t.Helper()
	got, err := f.c.get("github", "fake", location, ttl, f.fetch)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Release()
	var buf bytes.Buffer
	if _, err := got.WriteTo(&buf); err != nil || buf.String() != value {
		t.Fatalf("delivered %q, %v; want %q", buf.String(), err, value)
	}
}

// reload puts cfg in effect, as config.Running does.
func (f *fixture) reload(cfg *config.Config) {
	f.cfg.Store(cfg)
	f.c.prune(cfg)
}

func (f *fixture) held(i int) bool { return f.fetched[i].Len() != 0 }

func waitWiped(t *testing.T, f *fixture, i int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.held(i) {
		if time.Now().After(deadline) {
			t.Fatal("the cached Secret was not wiped after its TTL")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCacheDeliversCopiesWithinTheTTL(t *testing.T) {
	f := newFixture(t, "kv/github", time.Minute)
	for range 3 {
		f.get(t)
	}
	if len(f.fetched) != 1 {
		t.Fatalf("fetched %d times, want 1", len(f.fetched))
	}
}

func TestCacheWipesTheSecretWhenItsTTLEnds(t *testing.T) {
	f := newFixture(t, "kv/github", 50*time.Millisecond)
	f.get(t)
	waitWiped(t, f, 0)
	f.get(t)
	if len(f.fetched) != 2 {
		t.Fatalf("fetched %d times, want 2", len(f.fetched))
	}
}

func TestCacheCloseWipesEverySecret(t *testing.T) {
	f := newFixture(t, "kv/github", time.Minute)
	f.get(t)
	f.c.close()
	if f.held(0) {
		t.Fatal("close did not wipe the cached Secret")
	}

	// After close, nothing is cached.
	f.get(t)
	if len(f.fetched) != 2 || f.held(1) {
		t.Fatalf("after close: fetched %d times, want 2 with nothing held", len(f.fetched))
	}
}

func TestCacheReloadWipesAtOnce(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"Secret Name deleted", &config.Config{}},
		{"Secret Name moved", snapshot("kv/moved", time.Minute)},
		{"cache turned off", snapshot("kv/github", 0)},
		{"TTL shortened past the Secret's age", snapshot("kv/github", time.Nanosecond)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, "kv/github", time.Minute)
			f.get(t)
			f.reload(c.cfg)
			if f.held(0) {
				t.Fatal("the reload did not wipe the cached Secret")
			}
		})
	}
}

func TestCacheReloadShorteningTheTTLWipesSooner(t *testing.T) {
	f := newFixture(t, "kv/github", time.Minute)
	f.get(t)
	f.reload(snapshot("kv/github", 100*time.Millisecond))
	if !f.held(0) {
		t.Fatal("the reload wiped a Secret still within its new TTL")
	}
	waitWiped(t, f, 0)
}

// A request on the snapshot before a reload may finish its fetch after the
// reload; what it fetched is not cached against the new config.
func TestCacheDoesNotCacheWhatAReloadRemoved(t *testing.T) {
	f := newFixture(t, "kv/github", time.Minute)
	f.reload(snapshot("kv/github", 0))
	f.getAs(t, "kv/github", time.Minute)
	if f.held(0) {
		t.Fatal("a fetch on the old snapshot was cached after the reload turned the cache off")
	}
}

func TestCacheRefetchesWhenTheSecretNameMoves(t *testing.T) {
	f := newFixture(t, "kv/github", time.Minute)
	f.get(t)
	// A request on a snapshot where github moved, before prune has run.
	f.cfg.Store(snapshot("kv/moved", time.Minute))
	f.get(t)
	if len(f.fetched) != 2 {
		t.Fatalf("fetched %d times, want 2", len(f.fetched))
	}
	if f.held(0) {
		t.Fatal("the Secret cached from the old location was not wiped")
	}
}

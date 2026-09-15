package resolver

import (
	"bytes"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/internal/secret"
)

// Wiping is not observable through the process, so these tests check that
// the cache releases the Secrets it holds.

const value = "sk-live-0123456789"

// backend fakes a Backend fetch, keeping every Secret it returned.
type backend struct {
	fetched []*secret.Secret
}

func (b *backend) fetch() (*secret.Secret, error) {
	s, err := secret.New([]byte(value))
	if err == nil {
		b.fetched = append(b.fetched, s)
	}
	return s, err
}

func get(t *testing.T, c *cache, b *backend, location string, ttl time.Duration) {
	t.Helper()
	got, err := c.get("github", "fake", location, ttl, b.fetch)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Release()
	var buf bytes.Buffer
	if _, err := got.WriteTo(&buf); err != nil || buf.String() != value {
		t.Fatalf("delivered %q, %v; want %q", buf.String(), err, value)
	}
}

func TestCacheDeliversCopiesWithinTheTTL(t *testing.T) {
	c, b := newCache(), &backend{}
	t.Cleanup(c.close)
	for range 3 {
		get(t, c, b, "kv/github", time.Minute)
	}
	if len(b.fetched) != 1 {
		t.Fatalf("fetched %d times, want 1", len(b.fetched))
	}
}

func TestCacheWipesTheSecretWhenItsTTLEnds(t *testing.T) {
	c, b := newCache(), &backend{}
	t.Cleanup(c.close)
	get(t, c, b, "kv/github", 50*time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for b.fetched[0].Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the cached Secret was not wiped after its TTL")
		}
		time.Sleep(10 * time.Millisecond)
	}
	get(t, c, b, "kv/github", 50*time.Millisecond)
	if len(b.fetched) != 2 {
		t.Fatalf("fetched %d times, want 2", len(b.fetched))
	}
}

func TestCacheCloseWipesEverySecret(t *testing.T) {
	c, b := newCache(), &backend{}
	get(t, c, b, "kv/github", time.Minute)
	c.close()
	if b.fetched[0].Len() != 0 {
		t.Fatal("close did not wipe the cached Secret")
	}

	// After close, nothing is cached.
	get(t, c, b, "kv/github", time.Minute)
	if len(b.fetched) != 2 || b.fetched[1].Len() != 0 {
		t.Fatalf("after close: fetched %d times, last still held: %v", len(b.fetched), b.fetched[len(b.fetched)-1].Len() != 0)
	}
}

func TestCacheRefetchesAndWipesWhenTheSecretNameMoves(t *testing.T) {
	c, b := newCache(), &backend{}
	t.Cleanup(c.close)
	get(t, c, b, "kv/github", time.Minute)
	get(t, c, b, "kv/moved", time.Minute)
	if len(b.fetched) != 2 {
		t.Fatalf("fetched %d times, want 2", len(b.fetched))
	}
	if b.fetched[0].Len() != 0 {
		t.Fatal("the Secret cached from the old location was not wiped")
	}
}

func TestCacheForgetWipesTheSecret(t *testing.T) {
	c, b := newCache(), &backend{}
	t.Cleanup(c.close)
	get(t, c, b, "kv/github", time.Minute)
	c.forget("github")
	if b.fetched[0].Len() != 0 {
		t.Fatal("forget did not wipe the cached Secret")
	}
}

package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// cacheTTL is the cache TTL the tests give github: long enough to outlast a
// few requests under -race, short enough to wait out.
const cacheTTL = 3 * time.Second

// withCacheTTL gives Secret Name github in config a cache TTL of ttl.
func withCacheTTL(config, ttl string) string {
	return strings.Replace(config, "  github:\n    backend: fake\n    location: kv/github\n",
		"  github:\n    backend: fake\n    location: kv/github\n    cache_ttl: "+ttl+"\n", 1)
}

// withoutGithub is what the fake Backend Plugin holds once github is gone
// from it, so only the cache can deliver github.
var withoutGithub = map[string]string{"kv/openai": "test-value-1", harness.AuditSigningKeyLocation: harness.AuditSigningKey}

// startCached starts revealConfig with github cached for cacheTTL, and the
// fake Backend Plugin installed where the test can change its Secrets. It
// returns the rendered config without the cache TTL, the plugin's path, and
// a Bearer Authorization for an Agent Token with github-reveal.
func startCached(t *testing.T) (tc *harness.Installation, srv *harness.Server, uncached, path, token string) {
	t.Helper()
	tc = harness.New(t)
	path = tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	uncached = strings.Replace(revealConfig, "{{.Fake.Path}}", path, 1)
	srv = tc.Start(withCacheTTL(uncached, cacheTTL.String()))
	waitForPlugin(t, srv, "fake", running)
	return tc, srv, uncached, path, "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token
}

func TestCachedSecretIsDeliveredWithoutCallingTheBackend(t *testing.T) {
	tc, srv, _, path, token := startCached(t)

	fetched := time.Now()
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal github = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	tc.SetBackendSecrets(path, withoutGithub)
	for range 3 {
		got := reveal(t, srv, token, "github")
		if time.Since(fetched) >= cacheTTL {
			t.Skip("the requests outlasted the cache TTL")
		}
		if got.Status != http.StatusOK || got.Body != "test-value-2" {
			t.Fatalf("reveal github within its cache TTL = %d %q, want 200 test-value-2 from the cache\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
		}
	}
	if tc.FilesContain("test-value-2") {
		t.Error("the cached Secret was written to the data directory")
	}
}

func TestCachedSecretIsFetchedAgainOnceItsTTLEnds(t *testing.T) {
	tc, srv, _, path, token := startCached(t)

	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal github = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	tc.SetBackendSecrets(path, map[string]string{"kv/github": "rotated-value-2", harness.AuditSigningKeyLocation: harness.AuditSigningKey})
	time.Sleep(cacheTTL + 500*time.Millisecond)

	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK || got.Body != "rotated-value-2" {
		t.Fatalf("reveal github after its cache TTL = %d %q, want 200 rotated-value-2 from the Backend", got.Status, got.Body)
	}
}

func TestProxyDeliveryUsesTheCache(t *testing.T) {
	tc, srv, _, path, token := startCached(t)
	agentToken := strings.TrimPrefix(token, "Bearer ")

	fetched := time.Now()
	if got := proxy(t, srv, http.MethodGet, "/proxy/github/api/user", bearer(agentToken), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy github = %d %q, want 200", got.Status, got.Body)
	}
	tc.SetBackendSecrets(path, withoutGithub)
	got := proxy(t, srv, http.MethodGet, "/proxy/github/api/user", bearer(agentToken), "")
	if time.Since(fetched) >= cacheTTL {
		t.Skip("the requests outlasted the cache TTL")
	}
	if got.Status != http.StatusOK {
		t.Fatalf("proxy github within its cache TTL = %d %q, want 200\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
	}
	reqs := tc.Upstream().Requests()
	if len(reqs) != 2 || reqs[1].Header.Get("Authorization") != "token test-value-2" {
		t.Fatalf("the Upstream received %+v, want two requests carrying the cached Secret", reqs)
	}
}

// A reload that turns a Secret Name's cache off, or moves the Secret Name to
// another location, is never answered from what the old config cached.
func TestReloadIsNotAnsweredFromTheOldCache(t *testing.T) {
	tc, srv, uncached, path, token := startCached(t)

	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal github = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	moved := strings.Replace(withCacheTTL(uncached, cacheTTL.String()), "    location: kv/github\n    cache_ttl:", "    location: kv/openai\n    cache_ttl:", 1)
	srv.RewriteConfig(moved)
	reload(t, srv)
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK || got.Body != "test-value-1" {
		t.Fatalf("reveal github after moving it to kv/openai = %d %q, want 200 test-value-1", got.Status, got.Body)
	}

	tc.SetBackendSecrets(path, map[string]string{"kv/github": "rotated-value-2", harness.AuditSigningKeyLocation: harness.AuditSigningKey})
	srv.RewriteConfig(uncached)
	reload(t, srv)
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK || got.Body != "rotated-value-2" {
		t.Fatalf("reveal github after turning its cache off = %d %q, want 200 rotated-value-2 from the Backend", got.Status, got.Body)
	}
}

func TestCacheTTLIsValidated(t *testing.T) {
	cases := []struct{ name, ttl, wantErr string }{
		{"not a duration", "soon", `cache_ttl "soon" is not a duration`},
		{"zero", "0s", "must be from 1s to 1h"},
		{"negative", "-5s", "must be from 1s to 1h"},
		{"under a second", "500ms", "must be from 1s to 1h"},
		{"over an hour", "61m", "must be from 1s to 1h"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig +
				"secrets:\n  github:\n    backend: fake\n    location: kv/github\n    cache_ttl: " + c.ttl + "\n")
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

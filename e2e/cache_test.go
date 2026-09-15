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

// startCached starts revealConfig with github cached for cacheTTL, and the
// fake Backend Plugin installed where the test can change its Secrets. It
// returns a Bearer Authorization for an Agent Token with github-reveal and
// openai-proxy.
func startCached(t *testing.T) (*harness.Installation, *harness.Server, string, string) {
	t.Helper()
	tc := harness.New(t)
	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	config := withCacheTTL(strings.Replace(revealConfig, "{{.Fake.Path}}", path, 1), cacheTTL.String())
	srv := tc.Start(config)
	waitForPlugin(t, srv, "fake", running)
	return tc, srv, path, "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token
}

func TestCachedSecretIsDeliveredWithoutCallingTheBackend(t *testing.T) {
	tc, srv, path, token := startCached(t)

	fetched := time.Now()
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal github = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	// The Backend no longer holds github, so only the cache can deliver it.
	tc.SetBackendSecrets(path, map[string]string{"kv/openai": "test-value-1", harness.AuditSigningKeyLocation: harness.AuditSigningKey})
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

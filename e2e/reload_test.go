package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// reload runs tc reload and fails the test unless it succeeds.
func reload(t *testing.T, srv *harness.Server) harness.Result {
	t.Helper()
	res := srv.TC("reload")
	if res.ExitCode != 0 {
		t.Fatalf("reload: exit %d\n%s%s\nserver stderr:\n%s", res.ExitCode, res.Stdout, res.Stderr, srv.Stderr())
	}
	return res
}

func TestReloadAppliesPolicyChanges(t *testing.T) {
	_, srv, token := startProxy(t, "openai-proxy")
	if got := reveal(t, srv, "Bearer "+token, "openai"); got.Status != http.StatusForbidden {
		t.Fatalf("reveal openai before reload = %d %q, want 403", got.Status, got.Body)
	}

	srv.RewriteConfig(strings.Replace(proxyConfig,
		"  openai-proxy:\n    secrets:\n      - name: openai\n        delivery: [proxy]\n",
		"  openai-proxy:\n    secrets:\n      - name: openai\n        delivery: [proxy, reveal]\n", 1))
	res := reload(t, srv)
	if !strings.Contains(res.Stdout, "Config reloaded") {
		t.Errorf("reload printed %q, want it to say the config reloaded", res.Stdout)
	}

	if got := reveal(t, srv, "Bearer "+token, "openai"); got.Status != http.StatusOK || got.Body != "test-value-1" {
		t.Fatalf("reveal openai after reload = %d %q, want 200 with the Secret\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
	}
}

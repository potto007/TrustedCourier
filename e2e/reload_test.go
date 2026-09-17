package e2e

import (
	"io"
	"net/http"
	"os"
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

// A broken config never takes down Delivery: reload refuses it, says why, and
// the running config keeps serving until a valid one is reloaded.
func TestReloadRefusesAnInvalidConfig(t *testing.T) {
	_, srv, token := startProxy(t, "github-reveal")

	cases := []struct{ name, config, wantErr string }{
		{"unknown key", proxyConfig + "polices: {}\n", "field polices not found"},
		{"Policy naming an undefined Secret Name", strings.Replace(proxyConfig, "      - name: github\n        delivery: [proxy, reveal]\n",
			"      - name: githb\n        delivery: [proxy, reveal]\n", 1), `Policy "github-reveal" names Secret Name "githb", which is not defined under secrets`},
		{"not YAML", "data_dir: [\n", "yaml"},
	}
	for _, c := range cases {
		srv.RewriteConfig(c.config)
		res := srv.TC("reload")
		if res.ExitCode != 1 {
			t.Fatalf("%s: reload exit %d, want 1\n%s%s", c.name, res.ExitCode, res.Stdout, res.Stderr)
		}
		if !strings.Contains(res.Stderr, "the running config stays in effect") || !strings.Contains(res.Stderr, c.wantErr) {
			t.Errorf("%s: reload stderr = %q, want it to say the running config stays in effect and %q", c.name, res.Stderr, c.wantErr)
		}
		if got := reveal(t, srv, "Bearer "+token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
			t.Fatalf("%s: reveal github after the refused reload = %d %q, want 200 with the Secret", c.name, got.Status, got.Body)
		}
	}

	// Fixing the file and reloading applies it.
	srv.RewriteConfig(strings.Replace(proxyConfig, "        delivery: [proxy, reveal]\n", "        delivery: [proxy]\n", 1))
	reload(t, srv)
	if got := reveal(t, srv, "Bearer "+token, "github"); got.Status != http.StatusForbidden {
		t.Fatalf("reveal github after the valid reload = %d %q, want 403", got.Status, got.Body)
	}
}

// withoutOpenAIProxy is proxyConfig with the openai-proxy Policy removed.
var withoutOpenAIProxy = strings.Replace(proxyConfig,
	"  openai-proxy:\n    secrets:\n      - name: openai\n        delivery: [proxy]\n", "", 1)

func TestReloadRemovingAPolicyRemovesItsAccessAtOnce(t *testing.T) {
	_, srv, token := startProxy(t, "openai-proxy")
	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/models", bearer(token), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy openai before reload = %d %q, want 200", got.Status, got.Body)
	}
	if withoutOpenAIProxy == proxyConfig {
		t.Fatal("the openai-proxy Policy was not removed from the config")
	}

	srv.RewriteConfig(withoutOpenAIProxy)
	reload(t, srv)

	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/models", bearer(token), ""); got.Status != http.StatusForbidden {
		t.Fatalf("proxy openai after removing its Policy = %d %q, want 403", got.Status, got.Body)
	}
	if rec := auditRecords(t, srv, 2)[1]; rec.Decision != "denied" || rec.Reason != "no Policy allows it" {
		t.Errorf("Audit Record %+v, want denied because no Policy allows it", rec)
	}
	// The Policy can no longer be attached either.
	if res := srv.TC("token", "issue", "--policy", "openai-proxy", "--expires-in", "1h"); res.ExitCode != 1 || !strings.Contains(res.Stderr, `unknown Policy "openai-proxy"`) {
		t.Errorf("token issue with the removed Policy: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
}

// Keys that bind listeners, open the database, launch Backend Plugins, or
// load the audit signing key change only on restart. A reload that changes
// one is refused whole, so a Policy change beside it is not applied either.
func TestReloadRefusesChangesThatNeedARestart(t *testing.T) {
	tc, srv, token := startProxy(t, "github-reveal")
	// Also allow openai's reveal, which must not take effect.
	policyChange := func(config string) string {
		return strings.Replace(config, "      - name: openai\n        delivery: [proxy]\n", "      - name: openai\n        delivery: [proxy, reveal]\n", 1)
	}

	cases := []struct{ name, config, key string }{
		{"data_dir", strings.Replace(proxyConfig, "data_dir: {{.DataDir}}", "data_dir: "+tc.Dir()+"/other-data", 1), "data_dir"},
		{"admin socket", strings.Replace(proxyConfig, "  socket: {{.Socket}}", "  socket: "+tc.Dir()+"/other.sock", 1), "admin"},
		{"allowed UIDs", strings.Replace(proxyConfig, "  socket: {{.Socket}}\n", "  socket: {{.Socket}}\n  allowed_uids: [{{.UID}}, 65534]\n", 1), "admin"},
		{"Agent API address", strings.Replace(proxyConfig, "listen: 127.0.0.1:0", "listen: 127.0.0.1:1", 1), "agent_api"},
		{"Agent API public URL", strings.Replace(proxyConfig, "listen: 127.0.0.1:0", "listen: 127.0.0.1:0\n  public_url: https://agents.example.test", 1), "agent_api"},
		{"Backend Plugin", strings.Replace(proxyConfig, "    insecure_share_core_user: true\n", "    insecure_share_core_user: true\n  unhealthy:\n    path: {{.Unhealthy.Path}}\n    sha256: {{.Unhealthy.SHA256}}\n    insecure_share_core_user: true\n", 1), "backend_plugins"},
		{"checkpoint cadence", proxyConfig + "  checkpoints:\n    records: 5\n", "audit"},
	}
	for _, c := range cases {
		srv.RewriteConfig(policyChange(c.config))
		res := srv.TC("reload")
		if res.ExitCode != 1 || !strings.Contains(res.Stderr, c.key+" changed, which takes effect only on restart") {
			t.Errorf("%s: reload exit %d, stderr %q, want it refused naming %s", c.name, res.ExitCode, res.Stderr, c.key)
		}
		if got := reveal(t, srv, "Bearer "+token, "github"); got.Status != http.StatusOK {
			t.Fatalf("%s: reveal github after the refused reload = %d %q, want 200", c.name, got.Status, got.Body)
		}
	}
	openai := issueAgentToken(t, srv, "openai-proxy", "1h").Token
	if got := reveal(t, srv, "Bearer "+openai, "openai"); got.Status != http.StatusForbidden {
		t.Fatalf("reveal openai = %d %q, want 403: a refused reload applied its Policy change", got.Status, got.Body)
	}

	// A config that only restates a default is no change.
	srv.RewriteConfig(policyChange(strings.Replace(proxyConfig, "  socket: {{.Socket}}\n", "  socket: {{.Socket}}\n  allowed_uids: [{{.UID}}]\n", 1)))
	reload(t, srv)
	if got := reveal(t, srv, "Bearer "+openai, "openai"); got.Status != http.StatusOK {
		t.Fatalf("reveal openai after the valid reload = %d %q, want 200", got.Status, got.Body)
	}
}

func TestReloadAppliesSecretNameAndUpstreamChanges(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")
	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/models", bearer(token), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy openai before reload = %d %q, want 200", got.Status, got.Body)
	}
	other := tc.StartUpstream(true)

	// openai moves to the other Upstream under a new Upstream name, and a new
	// Secret Name with a query Injection Template joins openai-proxy.
	srv.RewriteConfig(strings.NewReplacer(
		"      - name: openai\n        delivery: [proxy]\n",
		"      - name: openai\n        delivery: [proxy]\n      - name: weather\n        delivery: [proxy]\n",
		"  openai:\n    backend: fake\n    location: kv/openai\n    injection_template:\n      header:\n        name: Authorization\n        value: Bearer {secret}\n    upstreams:\n      api:\n        url: {{.Upstream.URL}}\n        ca_bundle: {{.Upstream.CABundle}}\n",
		"  weather:\n    backend: fake\n    location: kv/github\n    injection_template:\n      query:\n        name: appid\n    upstreams:\n      api:\n        url: "+other.URL+"\n        ca_bundle: "+other.CABundle+"\n"+
			"  openai:\n    backend: fake\n    location: kv/openai\n    injection_template:\n      header:\n        name: Authorization\n        value: Bearer {secret}\n    upstreams:\n      v2:\n        url: "+other.URL+"\n        ca_bundle: "+other.CABundle+"\n",
	).Replace(proxyConfig))
	reload(t, srv)

	before := len(tc.Upstream().Requests())
	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/models", bearer(token), ""); got.Status != http.StatusForbidden {
		t.Errorf("proxy openai through its removed Upstream = %d %q, want 403", got.Status, got.Body)
	}
	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/v2/models", bearer(token), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy openai through its new Upstream = %d %q, want 200\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
	}
	if got := proxy(t, srv, http.MethodGet, "/proxy/weather/api/forecast?appid="+token, nil, ""); got.Status != http.StatusOK {
		t.Fatalf("proxy the new Secret Name = %d %q, want 200\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
	}
	if n := len(tc.Upstream().Requests()); n != before {
		t.Errorf("the old Upstream received %d requests after reload, want none", n-before)
	}
	reqs := other.Requests()
	if len(reqs) != 2 || reqs[0].Header.Get("Authorization") != "Bearer test-value-1" || reqs[1].RawQuery != "appid=test-value-2" {
		t.Fatalf("the new Upstream received %+v, want openai's header and weather's query parameter", reqs)
	}
}

// A Delivery under way when the config reloads finishes on the snapshot it
// started with, even when the reload removes its access.
func TestReloadLetsInFlightDeliveriesFinishOnTheOldConfig(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")

	req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = bearer(token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("stream = %d %q, %v, want 200 and the first event", resp.StatusCode, first, err)
	}

	srv.RewriteConfig(withoutOpenAIProxy)
	reload(t, srv)
	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/models", bearer(token), ""); got.Status != http.StatusForbidden {
		t.Fatalf("a new Delivery after reload = %d %q, want 403", got.Status, got.Body)
	}

	tc.Upstream().ReleaseEvents()
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(rest) != "data: second\n\n" {
		t.Fatalf("rest of the stream = %q, %v, want the second event and a clean end", rest, err)
	}
	// The stream's record is written once it ends, after the denial's.
	records := auditRecords(t, srv, 2)
	if rec := records[len(records)-1]; rec.Decision != "allowed" || rec.Failure != "" || rec.UpstreamStatus == nil || *rec.UpstreamStatus != http.StatusOK {
		t.Errorf("the in-flight Delivery's Audit Record = %+v, want allowed and finished", rec)
	}
}

// A reloaded config passes the same separation checks as at startup, so a
// config file an editor rewrote readable by a Backend Plugin's user is
// refused, rather than applied and then fatal at the next restart. It needs
// root, so the plugin can run as another user. Run it with sudo.
func TestReloadRefusesAConfigReadableByAPluginUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	tc := harness.New(t)
	// The plugin user must be able to reach its binary.
	dir, err := os.MkdirTemp("", "tc-plugin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := harness.AdminConfig + `
backend_plugins:
  fake:
    path: ` + tc.InstallPlugin(harness.FakePlugin, dir, 0o755) + `
    sha256: {{.Fake.SHA256}}
    user: nobody
`
	srv := tc.Start(config)
	waitForPlugin(t, srv, "fake", running)

	tc.ConfigMode = 0o644
	srv.RewriteConfig(config)
	res := srv.TC("reload")
	if res.ExitCode != 1 || !strings.Contains(res.Stderr, `readable by user "nobody"`) {
		t.Fatalf("reload of a config readable by the plugin user: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}

	tc.ConfigMode = 0o600
	srv.RewriteConfig(config)
	reload(t, srv)
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

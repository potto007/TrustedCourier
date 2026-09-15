package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// limitsConfig adds to proxyConfig the github-issues Policy, which allows
// Proxy Delivery of github only for GET and HEAD under /repos/o/r/issues and
// /user. BaseConfig's github-reveal Policy allows github without limits.
var limitsConfig = strings.Replace(proxyConfig, "\npolicies:\n", `
policies:
  github-issues:
    secrets:
      - name: github
        delivery: [proxy]
        methods: [GET, head]
        paths: [/repos/o/r/issues/, /user]
`, 1)

func TestProxyDeliveryKeepsToThePolicysMethodsAndPaths(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(limitsConfig)
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-issues", "1h").Token

	allowed := []struct{ method, path, upstreamPath string }{
		{http.MethodGet, "/proxy/github/api/repos/o/r/issues", "/repos/o/r/issues"},
		{http.MethodGet, "/proxy/github/api/repos/o/r/issues/7/comments?page=2", "/repos/o/r/issues/7/comments"},
		{http.MethodHead, "/proxy/github/api/repos/o/r/issues/7", "/repos/o/r/issues/7"},
		{http.MethodGet, "/proxy/github/api/user", "/user"},
		// Matching is on the decoded path, which is what the Upstream reads;
		// the escaped path is forwarded as sent.
		{http.MethodGet, "/proxy/github/api/%72epos/o/r/issues", "/%72epos/o/r/issues"},
	}
	for _, c := range allowed {
		before := len(tc.Upstream().Requests())
		if got := proxy(t, srv, c.method, c.path, bearer(token), ""); got.Status != http.StatusOK {
			t.Fatalf("%s %s = %d %q, want 200\nserver stderr:\n%s", c.method, c.path, got.Status, got.Body, srv.Stderr())
		}
		reqs := tc.Upstream().Requests()
		if len(reqs) != before+1 || reqs[before].Method != c.method || reqs[before].Path != c.upstreamPath {
			t.Fatalf("%s %s: the Upstream received %+v, want %s %s", c.method, c.path, reqs[before:], c.method, c.upstreamPath)
		}
	}
	allowedCount := len(tc.Upstream().Requests())

	// Reveal Delivery's 403 is the one every denial matches.
	want := reveal(t, srv, "Bearer "+token, "github")
	if want.Status != http.StatusForbidden {
		t.Fatalf("reveal github with github-issues = %d %q, want 403", want.Status, want.Body)
	}
	denied := []struct{ name, method, path, reason string }{
		{"method outside the Policy", http.MethodDelete, "/proxy/github/api/repos/o/r", "no Policy allows the method"},
		{"allowed path, method outside the Policy", http.MethodPost, "/proxy/github/api/repos/o/r/issues", "no Policy allows the method"},
		{"methods are case-sensitive", "get", "/proxy/github/api/repos/o/r/issues", "no Policy allows the method"},
		{"parent of a prefix", http.MethodGet, "/proxy/github/api/repos/o/r", "no Policy allows the path"},
		{"prefix is not a whole segment", http.MethodGet, "/proxy/github/api/repos/o/r/issuesx", "no Policy allows the path"},
		{"Upstream base URL", http.MethodGet, "/proxy/github/api", "no Policy allows the path"},
		{"encoded slash", http.MethodGet, "/proxy/github/api/repos%2Fo/r/issues", "no Policy allows the path"},
		{"parameters", http.MethodGet, "/proxy/github/api/repos;x/o/r/issues", "no Policy allows the path"},
		{"overlong UTF-8", http.MethodGet, "/proxy/github/api/repos/o/r/issues/%c0%ae%c0%ae/%c0%ae%c0%ae/x", "no Policy allows the path"},
	}
	for _, c := range denied {
		got := proxy(t, srv, c.method, c.path, bearer(token), "")
		if got.Status != http.StatusForbidden || got.Body != want.Body ||
			got.Header.Get("Content-Type") != want.Header.Get("Content-Type") {
			t.Errorf("%s: %s %s = %d %q %v, want the Reveal Delivery 403: %q %v", c.name, c.method, c.path, got.Status, got.Body, got.Header, want.Body, want.Header)
		}
	}
	if n := len(tc.Upstream().Requests()); n != allowedCount {
		t.Fatalf("the Upstream received %d denied requests", n-allowedCount)
	}

	// Dot segments are refused before any Policy is consulted.
	if got := proxy(t, srv, http.MethodGet, "/proxy/github/api/repos/o/r/issues/%2e%2e/%2e%2e/%2e%2e/x", bearer(token), ""); got.Status != http.StatusBadRequest {
		t.Errorf("dot segments = %d %q, want 400", got.Status, got.Body)
	}

	// allowed, reveal, denied, dot segments.
	records := auditRecords(t, srv, len(allowed)+1+len(denied)+1)
	records = records[len(records)-len(denied)-1 : len(records)-1]
	for i, c := range denied {
		if rec := records[i]; rec.Decision != "denied" || rec.Reason != c.reason || rec.Upstream != "api" {
			t.Errorf("%s: Audit Record %+v, want denied for %q", c.name, rec, c.reason)
		}
	}
}

func TestProxyDeliveryWithoutLimitsAllowsAnyMethodAndPath(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(limitsConfig)
	waitForPlugin(t, srv, "fake", running)
	unlimited := issueAgentToken(t, srv, "github-reveal", "1h").Token
	res := srv.TC("token", "issue", "--policy", "github-issues", "--policy", "github-reveal", "--expires-in", "1h", "--json")
	var both issuedAgentToken
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &both) != nil {
		t.Fatalf("token issue: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}

	for name, token := range map[string]string{"unlimited Policy": unlimited, "limited and unlimited Policies": both.Token} {
		for _, method := range []string{http.MethodDelete, http.MethodPut, "PROPFIND"} {
			if got := proxy(t, srv, method, "/proxy/github/api/repos/o/r", bearer(token), ""); got.Status != http.StatusOK {
				t.Errorf("%s: %s = %d %q, want 200", name, method, got.Status, got.Body)
			}
		}
	}
}

func TestPolicyLimitsAreValidated(t *testing.T) {
	const secrets = `
secrets:
  github:
    backend: fake
    location: kv/github
    injection_template:
      header:
        name: Authorization
        value: token {secret}
    upstreams:
      api:
        url: https://api.github.com
`
	policy := func(fields string) string {
		return "policies:\n  p:\n    secrets:\n      - name: github\n" + fields
	}
	const proxy = "        delivery: [proxy]\n"
	cases := []struct {
		name, config, wantErr string
	}{
		{"empty methods", policy(proxy + "        methods: []\n"), `Policy "p": Secret Name "github": methods is empty`},
		{"unknown method", policy(proxy + "        methods: [GET, FETCH]\n"), `unknown method "FETCH"`},
		{"CONNECT", policy(proxy + "        methods: [CONNECT]\n"), `unknown method "CONNECT"`},
		{"empty paths", policy(proxy + "        paths: []\n"), `Policy "p": Secret Name "github": paths is empty`},
		{"relative path", policy(proxy + "        paths: [repos]\n"), `path "repos": must start with /`},
		{"dot segment", policy(proxy + "        paths: [/repos/../admin]\n"), `path "/repos/../admin"`},
		{"encoded slash", policy(proxy + "        paths: [/repos%2Fo]\n"), `path "/repos%2Fo"`},
		{"limits without Proxy Delivery", policy("        delivery: [reveal]\n        paths: [/user]\n"),
			`Policy "p": Secret Name "github": methods and paths limit Proxy Delivery, which the entry does not allow`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig + secrets + c.config)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

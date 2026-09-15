package e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// querySecret is the Secret the query Injection Template tests deliver. It
// needs escaping in a query, so its raw and encoded forms differ.
const querySecret = "s3cr&t/value+1"

// withSecretNames adds Secret Names (YAML under secrets) and Policies (YAML
// under policies) to a config built on BaseConfig.
func withSecretNames(config, secretNames, policies string) string {
	config = strings.Replace(config, "\nsecrets:\n", "\nsecrets:\n"+secretNames, 1)
	return strings.Replace(config, "\npolicies:\n", "\npolicies:\n"+policies, 1)
}

// startTemplates starts proxyConfig plus secretNames and policies, with the
// fake Backend Plugin holding querySecret at kv/query as well as its usual
// Secrets.
func startTemplates(t *testing.T, secretNames, policies string) (*harness.Installation, *harness.Server) {
	t.Helper()
	tc := harness.New(t)
	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	tc.SetBackendSecrets(path, map[string]string{
		"kv/openai": "test-value-1",
		"kv/github": "test-value-2",
		"kv/query":  querySecret,
	})
	config := strings.Replace(withSecretNames(proxyConfig, secretNames, policies), "{{.Fake.Path}}", path, 1)
	srv := tc.Start(config)
	waitForPlugin(t, srv, "fake", running)
	return tc, srv
}

const querySecretNames = `
  weather:
    backend: fake
    location: kv/query
    injection_template:
      query:
        name: key
    upstreams:
      api:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
`

const queryPolicies = `
  weather-proxy:
    secrets:
      - name: weather
        delivery: [proxy]
`

func TestQueryInjectionTemplateInjectsTheSecret(t *testing.T) {
	tc, srv := startTemplates(t, querySecretNames, queryPolicies)
	token := issueAgentToken(t, srv, "weather-proxy", "1h").Token
	escaped := url.QueryEscape(querySecret)

	cases := []struct {
		name, query string
		header      http.Header
	}{
		{"Agent Token in the query slot", "city=Den+ver&key=" + token + "&units=metric", http.Header{}},
		// A placeholder the Agent sends in the slot is replaced, not repeated.
		{"fallback header", "city=Den+ver&key=placeholder&units=metric", http.Header{"X-Tc-Agent-Token": {token}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(tc.Upstream().Requests())
			got := proxy(t, srv, http.MethodGet, "/proxy/weather/api/v1/forecast?"+c.query, c.header, "")
			if got.Status != http.StatusOK {
				t.Fatalf("proxy = %d %q, want 200\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
			}
			reqs := tc.Upstream().Requests()
			if len(reqs) != before+1 {
				t.Fatalf("the Upstream received %d requests, want 1", len(reqs)-before)
			}
			up := reqs[before]
			if want := "city=Den+ver&units=metric&key=" + escaped; up.RawQuery != want {
				t.Errorf("the Upstream received query %q, want %q", up.RawQuery, want)
			}
			if up.Path != "/v1/forecast" {
				t.Errorf("the Upstream received path %q, want /v1/forecast", up.Path)
			}
			assertNoAgentToken(t, up, token)
		})
	}
}

func TestQueryInjectionTemplateSlotIsReadOnEveryRoute(t *testing.T) {
	_, srv := startTemplates(t, querySecretNames, queryPolicies)
	unknown := "tcat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, path := range []string{"/proxy/weather/api/v1/forecast", "/proxy/openai/api/v1/models", "/proxy/no-such-secret/api/v1"} {
		got := proxy(t, srv, http.MethodGet, path+"?key="+unknown, http.Header{}, "")
		if got.Status != http.StatusUnauthorized || !strings.Contains(got.Body, "invalid Agent Token") {
			t.Errorf("%s = %d %q, want 401 invalid Agent Token", path, got.Status, got.Body)
		}
	}
	// A query parameter no Injection Template names is not a slot.
	got := proxy(t, srv, http.MethodGet, "/proxy/weather/api/v1/forecast?api_key="+unknown, http.Header{}, "")
	if got.Status != http.StatusUnauthorized || !strings.Contains(got.Body, "Agent Token required") {
		t.Errorf("api_key = %d %q, want 401 Agent Token required", got.Status, got.Body)
	}
	token := issueAgentToken(t, srv, "weather-proxy", "1h").Token
	got = proxy(t, srv, http.MethodGet, "/proxy/weather/api/v1/forecast?key="+token, http.Header{"X-Tc-Agent-Token": {token}}, "")
	if got.Status != http.StatusUnauthorized || !strings.Contains(got.Body, "once") {
		t.Errorf("Agent Token in the query and the fallback header = %d %q, want 401 present once", got.Status, got.Body)
	}
}

func TestQueryInjectionTemplateRedactsTheEncodedSecret(t *testing.T) {
	_, srv := startTemplates(t, querySecretNames, queryPolicies)
	token := issueAgentToken(t, srv, "weather-proxy", "1h").Token
	escaped := url.QueryEscape(querySecret)

	for _, c := range []struct{ name, echo, want string }{
		{"as sent", "rawquery=key", strings.Repeat("*", len(escaped))},
		{"decoded", "query=key", strings.Repeat("*", len(querySecret))},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := proxy(t, srv, http.MethodGet, "/proxy/weather/api/echo?"+c.echo+"&key="+token, http.Header{}, "")
			if got.Status != http.StatusOK || got.Body != c.want || got.Header.Get("X-Echo") != c.want {
				t.Fatalf("proxy = %d %q X-Echo %q, want 200 %q", got.Status, got.Body, got.Header.Get("X-Echo"), c.want)
			}
			for _, form := range []string{querySecret, escaped} {
				if strings.Contains(got.Body, form) || strings.Contains(fmt.Sprint(got.Header), form) {
					t.Errorf("the Agent received the Secret as %q: %v %q", form, got.Header, got.Body)
				}
			}
		})
	}
}

func TestQueryInjectionTemplateKeepsTheSecretOutOfTheLog(t *testing.T) {
	tc := harness.New(t)
	secretNames := strings.Replace(querySecretNames, "ca_bundle: {{.Upstream.CABundle}}", "ca_bundle: "+foreignCA(t, t.TempDir()), 1)
	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	tc.SetBackendSecrets(path, map[string]string{"kv/openai": "test-value-1", "kv/github": "test-value-2", "kv/query": querySecret})
	srv := tc.Start(strings.Replace(withSecretNames(proxyConfig, secretNames, queryPolicies), "{{.Fake.Path}}", path, 1))
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "weather-proxy", "1h").Token

	if got := proxy(t, srv, http.MethodGet, "/proxy/weather/api/v1/forecast?key="+token, http.Header{}, ""); got.Status != http.StatusBadGateway {
		t.Fatalf("proxy to an unverified Upstream = %d %q, want 502", got.Status, got.Body)
	}
	if !strings.Contains(srv.Stderr(), "certificate") {
		t.Errorf("server log does not record the TLS failure:\n%s", srv.Stderr())
	}
	for _, form := range []string{querySecret, url.QueryEscape(querySecret), token} {
		if strings.Contains(srv.Stderr(), form) {
			t.Errorf("server log contains %q:\n%s", form, srv.Stderr())
		}
	}
}

func TestQueryInjectionTemplateIsValidated(t *testing.T) {
	const name = "secrets:\n  weather:\n    backend: fake\n    location: kv/openai\n"
	const upstream = "    upstreams:\n      api:\n        url: https://api.example.com\n"
	cases := []struct{ name, template, wantErr string }{
		{"empty name", "      query:\n        name: \"\"\n", "query parameter name"},
		{"name that needs escaping", "      query:\n        name: \"a&b\"\n", "query parameter name"},
		{"two kinds", "      header:\n        name: X-Key\n        value: \"{secret}\"\n      query:\n        name: key\n", "only one"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig + name + "    injection_template:\n" + c.template + upstream)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

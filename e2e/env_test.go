package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

func TestEnvUsesPublicURLWithWildcardListener(t *testing.T) {
	tc := harness.New(t)
	config := harness.BaseConfig + tlsAgentAPI("0.0.0.0:0") + auditConfig
	config = strings.Replace(config, "agent_api:\n", "agent_api:\n  public_url: https://agents.example.test:9443/\n", 1)
	srv := tc.Start(config)
	if bound := srv.ListeningAgentURL(); !strings.HasPrefix(bound, "https://0.0.0.0:") || strings.HasSuffix(bound, ":9443") {
		t.Fatalf("listener = %q, want wildcard binding on a different port", bound)
	}
	res := srv.TC("env", "openai")
	want := "OPENAI_BASE_URL=https://agents.example.test:9443/proxy/openai/api\nOPENAI_API_KEY=<Agent Token>\n"
	if res.ExitCode != 0 || res.Stdout != want {
		t.Fatalf("tc env: exit %d\n%s%s\nwant:\n%s", res.ExitCode, res.Stdout, res.Stderr, want)
	}
	res = srv.TC("env", "openai", "--json")
	var env map[string]string
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &env) != nil ||
		env["OPENAI_BASE_URL"] != "https://agents.example.test:9443/proxy/openai/api" || env["OPENAI_API_KEY"] != "<Agent Token>" {
		t.Fatalf("tc env --json: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestEnvAcceptsPublicURLOrigins(t *testing.T) {
	for _, origin := range []string{
		"https://agents.example.test", "https://[2001:db8::1]:8443",
		"http://127.0.0.1:9000", "http://[::1]:9000", "http://[::ffff:127.0.0.1]:9000",
	} {
		t.Run(origin, func(t *testing.T) {
			tc := harness.New(t)
			srv := tc.Start(harness.BaseConfig + fmt.Sprintf("\nagent_api:\n  listen: 127.0.0.1:0\n  public_url: %q\n", origin) + auditConfig)
			res := srv.TC("env", "openai")
			if res.ExitCode != 0 || !strings.Contains(res.Stdout, "OPENAI_BASE_URL="+origin+"/proxy/openai/api\n") {
				t.Fatalf("tc env: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
			}
		})
	}
}

func TestEnvPublicURLIsValidated(t *testing.T) {
	for _, origin := range []string{
		"agents.example.test", "//agents.example.test", "https:///", "ftp://agents.example.test",
		"https:agents.example.test", "https://user:password@agents.example.test",
		"https://agents.example.test/path", "https://agents.example.test/%2f",
		"https://agents.example.test?query=1", "https://agents.example.test?",
		"https://agents.example.test#fragment", "https://agents.example.test#",
		"https://0.0.0.0", "https://[::]", "https://[::ffff:0.0.0.0]",
		"https://*.example.test", "https://bad host", "https://-invalid.test", "https://[example.test]",
		"https://[127.0.0.1]", "https://::1", "https://[fe80::1%25eth0]",
		"https://agents.example.test:0", "https://agents.example.test:65536",
		"https://agents.example.test:bad", "https://agents.example.test:",
		"http://agents.example.test", "http://localhost", "http://192.0.2.1", "http://[2001:db8::1]",
	} {
		t.Run(origin, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.BaseConfig + fmt.Sprintf("\nagent_api:\n  listen: 127.0.0.1:0\n  public_url: %q\n", origin) + auditConfig)
			if code == 0 || !strings.Contains(stderr, "agent_api.public_url") {
				t.Fatalf("public URL accepted or failed for another reason: exit %d\n%s", code, stderr)
			}
		})
	}
	for _, listener := range []string{"", "  socket: agent.sock\n"} {
		tc := harness.New(t)
		code, stderr := tc.Refused(harness.BaseConfig + "\nagent_api:\n" + listener + "  public_url: https://agents.example.test\n" + auditConfig)
		if code == 0 || !strings.Contains(stderr, "agent_api.public_url needs agent_api.listen") {
			t.Fatalf("public URL without TCP listener: exit %d\n%s", code, stderr)
		}
	}
}

// envSecretNames adds, to proxyConfig, a Secret Name for each kind of
// Injection Template tc env handles differently, and one with two Upstreams.
const envSecretNames = `
  pinned:
    backend: fake
    location: kv/openai
    preset: openai
  twilio:
    backend: fake
    location: kv/github
    injection_template:
      basic_auth:
        username: AC123
        password: "{secret}"
    upstreams:
      api:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
  my-weather.v2:
    backend: fake
    location: kv/github
    injection_template:
      query:
        name: key
    upstreams:
      api:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
  multi:
    backend: fake
    location: kv/github
    preset: github
    upstreams:
      first:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
      second:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
`

func TestEnvPrintsWhatAnAgentNeeds(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(withSecretNames(proxyConfig, envSecretNames, ""))
	waitForPlugin(t, srv, "fake", running)
	base := srv.AgentURL() + "/proxy/"

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"Preset", []string{"pinned"}, "OPENAI_BASE_URL=" + base + "pinned/api\nOPENAI_API_KEY=<Agent Token>\n"},
		{"header template", []string{"anthropic"}, "ANTHROPIC_BASE_URL=" + base + "anthropic/api\nANTHROPIC_API_KEY=<Agent Token>\n"},
		{"query template", []string{"my-weather.v2"}, "MY_WEATHER_V2_BASE_URL=" + base + "my-weather.v2/api\nMY_WEATHER_V2_API_KEY=<Agent Token>\n"},
		{"basic auth template", []string{"twilio"}, "TWILIO_BASE_URL=" + base + "twilio/api\nTWILIO_USERNAME=AC123\nTWILIO_PASSWORD=<Agent Token>\n"},
		{"chosen Upstream", []string{"multi", "--upstream", "second"}, "GITHUB_API_URL=" + base + "multi/second\nGITHUB_TOKEN=<Agent Token>\n"},
		{"flag before the Secret Name", []string{"--upstream", "first", "multi"}, "GITHUB_API_URL=" + base + "multi/first\nGITHUB_TOKEN=<Agent Token>\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := srv.TC(append([]string{"env"}, c.args...)...)
			if res.ExitCode != 0 || res.Stdout != c.want {
				t.Fatalf("tc env %v: exit %d\nstdout:\n%s\nwant:\n%s\nstderr:\n%s", c.args, res.ExitCode, res.Stdout, c.want, res.Stderr)
			}
		})
	}

	res := srv.TC("env", "twilio", "--json")
	var env map[string]string
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &env) != nil {
		t.Fatalf("tc env --json: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	if env["TWILIO_BASE_URL"] != base+"twilio/api" || env["TWILIO_USERNAME"] != "AC123" || env["TWILIO_PASSWORD"] != "<Agent Token>" || len(env) != 3 {
		t.Errorf("tc env --json = %v", env)
	}
}

// The printed base URL, with an Agent Token where the Secret would go, is a
// working Proxy Delivery route.
func TestEnvBaseURLReachesTheUpstream(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")
	res := srv.TC("env", "openai")
	if res.ExitCode != 0 {
		t.Fatalf("tc env openai: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	vars := map[string]string{}
	for line := range strings.Lines(res.Stdout) {
		name, value, _ := strings.Cut(strings.TrimSuffix(line, "\n"), "=")
		vars[name] = value
	}
	if vars["OPENAI_API_KEY"] != "<Agent Token>" {
		t.Fatalf("OPENAI_API_KEY = %q, want the Agent Token placeholder", vars["OPENAI_API_KEY"])
	}
	req, err := http.NewRequest(http.MethodGet, vars["OPENAI_BASE_URL"]+"/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = bearer(token)
	if got := agentDo(t, req); got.Status != http.StatusOK {
		t.Fatalf("GET OPENAI_BASE_URL/models = %d %q, want 200", got.Status, got.Body)
	}
	if reqs := tc.Upstream().Requests(); len(reqs) != 1 || reqs[0].Path != "/models" {
		t.Errorf("the Upstream received %+v, want one request to /models", reqs)
	}
}

func TestEnvRefusesWhatAnAgentCannotUse(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(withSecretNames(proxyConfig, envSecretNames, ""))

	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no Secret Name", []string{}, 2, "exactly one Secret Name"},
		{"two Secret Names", []string{"pinned", "twilio"}, 2, "exactly one Secret Name"},
		{"unknown Secret Name", []string{"no-such-secret"}, 1, `Secret Name "no-such-secret" is not defined`},
		{"Secret Name without Upstreams", []string{"unlisted"}, 1, "no upstreams"},
		{"several Upstreams", []string{"multi"}, 1, "--upstream (first, second)"},
		{"unknown Upstream", []string{"multi", "--upstream", "third"}, 1, `no Upstream "third"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := srv.TC(append([]string{"env"}, c.args...)...)
			if res.ExitCode != c.wantCode || !strings.Contains(res.Stderr, c.wantErr) {
				t.Fatalf("tc env %v: exit %d, want %d with %q\nstdout:\n%s\nstderr:\n%s", c.args, res.ExitCode, c.wantCode, c.wantErr, res.Stdout, res.Stderr)
			}
		})
	}
}

func TestEnvNeedsTheAgentAPI(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	res := srv.TC("env", "openai")
	if res.ExitCode != 1 || !strings.Contains(res.Stderr, "agent_api.listen") {
		t.Fatalf("tc env without the Agent API: exit %d, want 1 naming agent_api.listen\n%s", res.ExitCode, res.Stderr)
	}
}

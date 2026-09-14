package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// revealConfig serves the Agent API on loopback with Secret Names backed by
// the fake Backend Plugin. github-reveal allows Reveal Delivery of github;
// openai-proxy allows only Proxy Delivery of openai.
const revealConfig = harness.PluginConfig + `
agent_api:
  listen: 127.0.0.1:0
secrets:
  openai:
    backend: fake
    location: kv/openai
  github:
    backend: fake
    location: kv/github
  unlisted:
    backend: fake
    location: kv/openai
`

type agentResponse struct {
	Status int
	Header http.Header
	Body   string
}

// reveal asks for secretName with an Authorization header of authorization,
// or none when it is empty.
func reveal(t *testing.T, srv *harness.Server, authorization, secretName string) agentResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/v1/reveal/"+secretName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return agentDo(t, req)
}

func agentDo(t *testing.T, req *http.Request) agentResponse {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return agentResponse{Status: resp.StatusCode, Header: resp.Header, Body: string(body)}
}

type issuedAgentToken struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// issueAgentToken issues an Agent Token carrying policy.
func issueAgentToken(t *testing.T, srv *harness.Server, policy, expiresIn string) issuedAgentToken {
	t.Helper()
	res := srv.TC("token", "issue", "--policy", policy, "--expires-in", expiresIn, "--json")
	var issued issuedAgentToken
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &issued) != nil || issued.Token == "" {
		t.Fatalf("token issue: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	return issued
}

func TestRevealDeliveryReturnsTheSecret(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token

	got := reveal(t, srv, "Bearer "+token, "github")
	if got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal github = %d %q, want 200 with the Secret\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
	}
	if cc := got.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestDeniedAndUnknownSecretNamesGetIdentical403(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	proxyOnly := issueAgentToken(t, srv, "openai-proxy", "1h").Token
	revealGithub := issueAgentToken(t, srv, "github-reveal", "1h").Token

	cases := []struct{ name, token, secretName string }{
		{"Policy allows only Proxy Delivery", proxyOnly, "openai"},
		{"Secret Name in no attached Policy", revealGithub, "openai"},
		{"Secret Name in no Policy at all", revealGithub, "unlisted"},
		{"unknown Secret Name", revealGithub, "no-such-secret"},
		{"invalid Secret Name", revealGithub, "bad%20name"},
	}
	var first agentResponse
	for i, c := range cases {
		got := reveal(t, srv, "Bearer "+c.token, c.secretName)
		if got.Status != http.StatusForbidden {
			t.Fatalf("%s: status %d %q, want 403", c.name, got.Status, got.Body)
		}
		for _, leak := range []string{"test-value", "kv/", "fake", c.secretName} {
			if strings.Contains(got.Body, leak) {
				t.Errorf("%s: 403 body %q contains %q", c.name, got.Body, leak)
			}
		}
		if i == 0 {
			first = got
			continue
		}
		if got.Body != first.Body || got.Header.Get("Content-Type") != first.Header.Get("Content-Type") ||
			got.Header.Get("Content-Length") != first.Header.Get("Content-Length") {
			t.Errorf("%s: 403 differs from %q:\n%q %v\n%q %v", c.name, cases[0].name, got.Body, got.Header, first.Body, first.Header)
		}
	}

	// The same Agent Token still gets the Secret its Policy allows.
	if got := reveal(t, srv, "Bearer "+revealGithub, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal github = %d %q, want 200", got.Status, got.Body)
	}
}

func TestRevealDeliveryRecordsAgentTokenUse(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	issued := issueAgentToken(t, srv, "github-reveal", "1h")

	if got := reveal(t, srv, "Bearer "+issued.Token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal github = %d %q, want 200", got.Status, got.Body)
	}
	res := srv.TC("token", "list", "--json")
	var tokens []struct {
		ID         string     `json:"id"`
		LastUsedAt *time.Time `json:"last_used_at"`
	}
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &tokens) != nil || len(tokens) != 1 {
		t.Fatalf("token list: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	if last := tokens[0].LastUsedAt; last == nil || time.Since(*last) > time.Minute {
		t.Fatalf("last_used_at = %v after a Reveal Delivery, want about now", last)
	}
}

func TestRefusedAgentTokenReturns401(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	expired := issueAgentToken(t, srv, "github-reveal", "1s")
	revoked := issueAgentToken(t, srv, "github-reveal", "1h")

	if got := reveal(t, srv, "Bearer "+revoked.Token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal before revocation = %d %q, want 200", got.Status, got.Body)
	}
	if res := srv.TC("token", "revoke", revoked.ID); res.ExitCode != 0 {
		t.Fatalf("token revoke: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	time.Sleep(1100 * time.Millisecond) // past the expiry

	cases := []struct {
		name    string
		header  http.Header
		wantErr string
	}{
		{"no Agent Token", http.Header{}, "Agent Token required"},
		{"not a bearer token", http.Header{"Authorization": {"Basic dXNlcjpwYXNz"}}, "Bearer"},
		{"unknown Agent Token", http.Header{"Authorization": {"Bearer tcat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, "invalid Agent Token"},
		{"Operator Credential", http.Header{"Authorization": {"Bearer " + srv.Credential}}, "invalid Agent Token"},
		{"expired", http.Header{"Authorization": {"Bearer " + expired.Token}}, "Agent Token expired"},
		{"revoked", http.Header{"Authorization": {"Bearer " + revoked.Token}}, "Agent Token revoked"},
		{"revoked in the fallback header", http.Header{"X-Tc-Agent-Token": {revoked.Token}}, "Agent Token revoked"},
		{"two Agent Tokens", http.Header{"Authorization": {"Bearer " + expired.Token}, "X-Tc-Agent-Token": {revoked.Token}}, "once"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/v1/reveal/github", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = c.header
			got := agentDo(t, req)
			if got.Status != http.StatusUnauthorized || !strings.Contains(got.Body, c.wantErr) {
				t.Fatalf("reveal = %d %q, want 401 containing %q", got.Status, got.Body, c.wantErr)
			}
			if strings.Contains(got.Body, "test-value") {
				t.Fatalf("a refused request received the Secret: %q", got.Body)
			}
		})
	}
}

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

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

// issueAgentToken issues an Agent Token carrying policy and returns its value.
func issueAgentToken(t *testing.T, srv *harness.Server, policy, expiresIn string) string {
	t.Helper()
	res := srv.TC("token", "issue", "--policy", policy, "--expires-in", expiresIn, "--json")
	var issued struct {
		Token string `json:"token"`
	}
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &issued) != nil || issued.Token == "" {
		t.Fatalf("token issue: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	return issued.Token
}

func TestRevealDeliveryReturnsTheSecret(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h")

	got := reveal(t, srv, "Bearer "+token, "github")
	if got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal github = %d %q, want 200 with the Secret\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
	}
	if cc := got.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

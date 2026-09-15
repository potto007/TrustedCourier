package e2e

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// proxyConfig serves the Agent API over BaseConfig and adds:
//   - anthropic, pinned to the fake Upstream with an X-Api-Key Injection
//     Template, and the anthropic-proxy Policy allowing its Proxy Delivery;
//   - unlisted, with no Upstreams, which no Policy lists;
//   - the github-reveal-only Policy, allowing only Reveal Delivery of github.
var proxyConfig = strings.NewReplacer(
	"\npolicies:\n", `
policies:
  anthropic-proxy:
    secrets:
      - name: anthropic
        delivery: [proxy]
  github-reveal-only:
    secrets:
      - name: github
        delivery: [reveal]
`,
	"\nsecrets:\n", `
secrets:
  anthropic:
    backend: fake
    location: kv/github
    injection_template:
      header:
        name: X-Api-Key
        value: "{secret}"
    upstreams:
      api:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
  unlisted:
    backend: fake
    location: kv/openai
`,
).Replace(harness.BaseConfig) + `
agent_api:
  listen: 127.0.0.1:0
`

// proxy sends method to path on the Agent API with header and body.
func proxy(t *testing.T, srv *harness.Server, method, path string, header http.Header, body string) agentResponse {
	t.Helper()
	req, err := http.NewRequest(method, srv.AgentURL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	return agentDo(t, req)
}

func bearer(token string) http.Header { return http.Header{"Authorization": {"Bearer " + token}} }

// startProxy starts proxyConfig and issues an Agent Token carrying policy.
func startProxy(t *testing.T, policy string) (*harness.Installation, *harness.Server, string) {
	t.Helper()
	tc := harness.New(t)
	srv := tc.Start(proxyConfig)
	waitForPlugin(t, srv, "fake", running)
	return tc, srv, issueAgentToken(t, srv, policy, "1h").Token
}

// assertNoAgentToken fails if the Agent Token reached the Upstream anywhere.
func assertNoAgentToken(t *testing.T, got harness.UpstreamRequest, token string) {
	t.Helper()
	if _, ok := got.Header["X-Tc-Agent-Token"]; ok {
		t.Errorf("the Upstream received X-TC-Agent-Token: %v", got.Header)
	}
	for name, values := range got.Header {
		for _, v := range values {
			if strings.Contains(v, token) || strings.Contains(v, "tcat_") {
				t.Errorf("the Upstream received the Agent Token in %s: %q", name, v)
			}
		}
	}
	if strings.Contains(got.Path+got.RawQuery+got.Body, token) {
		t.Errorf("the Upstream received the Agent Token in the URL or body: %+v", got)
	}
}

func TestProxyDeliveryInjectsTheSecret(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")

	header := bearer(token)
	header.Set("X-Agent-Header", "kept")
	header.Set("Content-Type", "application/json")
	got := proxy(t, srv, http.MethodPost, "/proxy/openai/api/v1/chat/completions?stream=false&next=%2Fa%20b", header, `{"model":"m"}`)
	if got.Status != http.StatusOK || got.Body != "upstream saw POST /v1/chat/completions" {
		t.Fatalf("proxy = %d %q, want 200 with the Upstream's body\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
	}
	if got.Header.Get("X-Upstream") != "fake" {
		t.Errorf("the Upstream's response headers did not reach the Agent: %v", got.Header)
	}

	reqs := tc.Upstream().Requests()
	if len(reqs) != 1 {
		t.Fatalf("the Upstream received %d requests, want 1", len(reqs))
	}
	up := reqs[0]
	if up.Header.Get("Authorization") != "Bearer test-value-1" {
		t.Errorf("the Upstream received Authorization %q, want the Secret in the Injection Template", up.Header.Get("Authorization"))
	}
	if up.Method != http.MethodPost || up.Path != "/v1/chat/completions" || up.RawQuery != "stream=false&next=%2Fa%20b" {
		t.Errorf("the Upstream received %s %s?%s, want the rest of the path and the query unchanged", up.Method, up.Path, up.RawQuery)
	}
	if up.Body != `{"model":"m"}` || up.Header.Get("X-Agent-Header") != "kept" || up.Header.Get("Content-Type") != "application/json" {
		t.Errorf("the Agent's body and headers were not forwarded: %+v", up)
	}
	if want := strings.TrimPrefix(tc.Upstream().URL, "https://"); up.Host != want {
		t.Errorf("the Upstream received Host %q, want %q", up.Host, want)
	}
	assertNoAgentToken(t, up, token)
}

func TestProxyDeliveryFindsTheAgentTokenInTheCredentialSlot(t *testing.T) {
	tc, srv, anthropicToken := startProxy(t, "anthropic-proxy")
	openaiToken := issueAgentToken(t, srv, "openai-proxy", "1h").Token

	cases := []struct {
		name, path, token, wantHeader, wantValue string
		header                                   http.Header
	}{
		{"Authorization: Bearer", "/proxy/openai/api/v1/models", openaiToken, "Authorization", "Bearer test-value-1",
			http.Header{"Authorization": {"Bearer " + openaiToken}}},
		{"case-insensitive literal", "/proxy/openai/api/v1/models", openaiToken, "Authorization", "Bearer test-value-1",
			http.Header{"Authorization": {"bearer " + openaiToken}}},
		{"X-Api-Key", "/proxy/anthropic/api/v1/messages", anthropicToken, "X-Api-Key", "test-value-2",
			http.Header{"X-Api-Key": {anthropicToken}}},
		// An SDK that insists on some API key still works with the fallback.
		{"fallback header", "/proxy/openai/api/v1/models", openaiToken, "Authorization", "Bearer test-value-1",
			http.Header{"X-Tc-Agent-Token": {openaiToken}, "Authorization": {"Bearer placeholder"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(tc.Upstream().Requests())
			if got := proxy(t, srv, http.MethodGet, c.path, c.header, ""); got.Status != http.StatusOK {
				t.Fatalf("proxy = %d %q, want 200", got.Status, got.Body)
			}
			reqs := tc.Upstream().Requests()
			if len(reqs) != before+1 {
				t.Fatalf("the Upstream received %d requests, want 1", len(reqs)-before)
			}
			up := reqs[before]
			if v := up.Header.Values(c.wantHeader); len(v) != 1 || v[0] != c.wantValue {
				t.Errorf("the Upstream received %s %q, want %q", c.wantHeader, v, c.wantValue)
			}
			assertNoAgentToken(t, up, c.token)
		})
	}
}

func TestProxyDeliveryRefusesAgentTokensItCannotUse(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")
	revoked := issueAgentToken(t, srv, "openai-proxy", "1h")
	if res := srv.TC("token", "revoke", revoked.ID); res.ExitCode != 0 {
		t.Fatalf("token revoke: exit %d\n%s", res.ExitCode, res.Stderr)
	}

	cases := []struct {
		name, path, wantErr string
		header              http.Header
	}{
		{"no Agent Token", "/proxy/openai/api/v1/models", "Agent Token required", http.Header{}},
		{"Agent Token only in the URL", "/proxy/openai/api/v1/models?api_key=" + token, "Agent Token required", http.Header{}},
		{"not an Agent Token in the slot", "/proxy/openai/api/v1/models", "Agent Token required", http.Header{"Authorization": {"Bearer sk-real-looking"}}},
		{"unknown Agent Token", "/proxy/openai/api/v1/models", "invalid Agent Token", bearer("tcat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		{"revoked", "/proxy/openai/api/v1/models", "Agent Token revoked", bearer(revoked.Token)},
		{"two Agent Tokens", "/proxy/openai/api/v1/models", "once",
			http.Header{"Authorization": {"Bearer " + token}, "X-Tc-Agent-Token": {token}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := proxy(t, srv, http.MethodGet, c.path, c.header, "")
			if got.Status != http.StatusUnauthorized || !strings.Contains(got.Body, c.wantErr) {
				t.Fatalf("proxy = %d %q, want 401 containing %q", got.Status, got.Body, c.wantErr)
			}
		})
	}
	if n := len(tc.Upstream().Requests()); n != 0 {
		t.Fatalf("the Upstream received %d refused requests", n)
	}
}

// A 401 must not depend on the route: otherwise a guesser without an Agent
// Token could tell which Secret Names exist from which slots are read.
func TestProxyDelivery401DoesNotRevealSecretNames(t *testing.T) {
	_, srv, _ := startProxy(t, "openai-proxy")
	unknown := "tcat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	presentations := map[string]http.Header{
		"none":          {},
		"Authorization": {"Authorization": {"Bearer " + unknown}},
		"X-Api-Key":     {"X-Api-Key": {unknown}},
		"fallback":      {"X-Tc-Agent-Token": {"not-a-token"}},
	}
	for name, header := range presentations {
		t.Run(name, func(t *testing.T) {
			known := proxy(t, srv, http.MethodGet, "/proxy/openai/api/v1/models", header, "")
			if known.Status != http.StatusUnauthorized {
				t.Fatalf("known route = %d %q, want 401", known.Status, known.Body)
			}
			for _, path := range []string{"/proxy/no-such-secret/api/v1/models", "/proxy/openai/no-such-upstream/v1/models", "/proxy/unlisted/api/v1/models"} {
				if got := proxy(t, srv, http.MethodGet, path, header, ""); got.Status != known.Status || got.Body != known.Body {
					t.Errorf("%s = %d %q, want the same as a known route: %d %q", path, got.Status, got.Body, known.Status, known.Body)
				}
			}
		})
	}
}

func TestProxyDeliveryDenialsAreIdentical(t *testing.T) {
	tc, srv, openai := startProxy(t, "openai-proxy")
	revealOnly := issueAgentToken(t, srv, "github-reveal-only", "1h").Token

	// Reveal Delivery's 403 is the one every denial matches.
	want := reveal(t, srv, "Bearer "+openai, "github")
	if want.Status != http.StatusForbidden {
		t.Fatalf("reveal github with openai-proxy = %d %q, want 403", want.Status, want.Body)
	}
	cases := []struct{ name, token, path string }{
		{"Policy allows only Reveal Delivery", revealOnly, "/proxy/github/api/user"},
		{"Secret Name in no attached Policy", openai, "/proxy/github/api/user"},
		{"Secret Name in no Policy at all", openai, "/proxy/anthropic/api/v1/messages"},
		{"Secret Name with no Upstreams", openai, "/proxy/unlisted/api/v1/models"},
		{"unknown Secret Name", openai, "/proxy/no-such-secret/api/v1/models"},
		{"unknown Upstream", openai, "/proxy/openai/no-such-upstream/v1/models"},
		{"invalid Secret Name", openai, "/proxy/bad%20name/api/v1/models"},
	}
	for _, c := range cases {
		got := proxy(t, srv, http.MethodGet, c.path, bearer(c.token), "")
		if got.Status != http.StatusForbidden || got.Body != want.Body ||
			got.Header.Get("Content-Type") != want.Header.Get("Content-Type") {
			t.Errorf("%s: %d %q %v, want the Reveal Delivery 403: %q %v", c.name, got.Status, got.Body, got.Header, want.Body, want.Header)
		}
	}
	if n := len(tc.Upstream().Requests()); n != 0 {
		t.Fatalf("the Upstream received %d denied requests", n)
	}
}

func TestProxyDeliveryExposesOneRoutePerUpstream(t *testing.T) {
	tc := harness.New(t)
	second := tc.StartUpstream(true)
	config := strings.Replace(proxyConfig, `
  unlisted:
`, fmt.Sprintf(`
  multi:
    backend: fake
    location: kv/openai
    injection_template:
      header:
        name: Authorization
        value: Bearer {secret}
    upstreams:
      first:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
      second:
        url: %s/base/
        ca_bundle: %s
  unlisted:
`, second.URL, second.CABundle), 1)
	config = strings.Replace(config, "\npolicies:\n", "\npolicies:\n  multi-proxy:\n    secrets:\n      - name: multi\n        delivery: [proxy]\n", 1)
	srv := tc.Start(config)
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "multi-proxy", "1h").Token

	if got := proxy(t, srv, http.MethodGet, "/proxy/multi/first/v1/models", bearer(token), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy to first = %d %q, want 200", got.Status, got.Body)
	}
	if got := proxy(t, srv, http.MethodGet, "/proxy/multi/second/v1/models", bearer(token), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy to second = %d %q, want 200", got.Status, got.Body)
	}
	// The route with nothing after the Upstream name reaches its base URL.
	if got := proxy(t, srv, http.MethodGet, "/proxy/multi/second", bearer(token), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy to second's base URL = %d %q, want 200", got.Status, got.Body)
	}
	if reqs := tc.Upstream().Requests(); len(reqs) != 1 || reqs[0].Path != "/v1/models" {
		t.Errorf("first Upstream received %+v, want only /v1/models", reqs)
	}
	reqs := second.Requests()
	if len(reqs) != 2 || reqs[0].Path != "/base/v1/models" || reqs[1].Path != "/base" {
		t.Errorf("second Upstream received %+v, want /base/v1/models and /base", reqs)
	}

	// Dot segments could climb out of an Upstream's base path.
	for _, path := range []string{"/proxy/multi/second/%2e%2e/admin", "/proxy/multi/second/v1/%2E%2e/%2e%2E/admin", "/proxy/multi/second/v1/x%2F..%2Fy", "/proxy/multi/second/v1/.%2e/z",
		// Servlet containers read "..;" as "..".
		"/proxy/multi/second/..;/admin", "/proxy/multi/second/v1/%2e%2e;jsessionid=x/admin", "/proxy/multi/second/.;/admin"} {
		if got := proxy(t, srv, http.MethodGet, path, bearer(token), ""); got.Status != http.StatusBadRequest {
			t.Errorf("%s = %d %q, want 400", path, got.Status, got.Body)
		}
	}
	if n := len(second.Requests()); n != 2 {
		t.Errorf("second Upstream received %d requests, want no more than the 2 allowed", n)
	}
}

func TestProxyDeliveryReturnsRedirectsUnfollowed(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")

	req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = bearer(token)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != harness.UpstreamRedirectLocation {
		t.Fatalf("proxy redirect = %d Location %q, want 302 to %q", resp.StatusCode, resp.Header.Get("Location"), harness.UpstreamRedirectLocation)
	}
	if n := len(tc.Upstream().Requests()); n != 1 {
		t.Fatalf("the Upstream received %d requests, want 1", n)
	}
}

func TestProxyDeliveryStreamsServerSentEvents(t *testing.T) {
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy events = %d, want 200", resp.StatusCode)
	}

	// The Upstream holds back the second event until the first arrives, so
	// a buffering proxy delivers nothing.
	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if line := scanner.Text(); line != "" {
				lines <- line
			}
		}
	}()
	select {
	case line := <-lines:
		if line != "data: first" {
			t.Fatalf("first event = %q, want data: first", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first event did not arrive while the stream was still open")
	}
	tc.Upstream().ReleaseEvents()
	if line := <-lines; line != "data: second" {
		t.Fatalf("second event = %q, want data: second", line)
	}
}

func TestProxyDeliverySpeaksHTTP1AndHTTP2(t *testing.T) {
	tc := harness.New(t)
	h1 := tc.StartUpstream(false)
	config := strings.Replace(proxyConfig, `
  unlisted:
`, fmt.Sprintf(`
  h1only:
    backend: fake
    location: kv/openai
    injection_template:
      header:
        name: Authorization
        value: Bearer {secret}
    upstreams:
      api:
        url: %s
        ca_bundle: %s
  unlisted:
`, h1.URL, h1.CABundle), 1)
	config = strings.Replace(config, "      - name: openai\n        delivery: [proxy]\n",
		"      - name: openai\n        delivery: [proxy]\n      - name: h1only\n        delivery: [proxy]\n", 1)
	srv := tc.Start(config)
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "openai-proxy", "1h").Token

	h2c := &http.Transport{Protocols: new(http.Protocols)}
	h2c.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(h2c.CloseIdleConnections)
	clients := map[int]*http.Client{1: http.DefaultClient, 2: {Transport: h2c}}

	upstreams := []struct {
		secretName string
		up         *harness.Upstream
		wantProto  int
	}{{"openai", tc.Upstream(), 2}, {"h1only", h1, 1}}
	for agentProto, client := range clients {
		for _, u := range upstreams {
			t.Run(fmt.Sprintf("Agent HTTP/%d to Upstream HTTP/%d", agentProto, u.wantProto), func(t *testing.T) {
				req, err := http.NewRequest(http.MethodPost, srv.AgentURL()+"/proxy/"+u.secretName+"/api/v1/x", strings.NewReader("hello"))
				if err != nil {
					t.Fatal(err)
				}
				req.Header = bearer(token)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK || resp.ProtoMajor != agentProto {
					t.Fatalf("proxy = %d over HTTP/%d %q, want 200 over HTTP/%d", resp.StatusCode, resp.ProtoMajor, body, agentProto)
				}
				reqs := u.up.Requests()
				if last := reqs[len(reqs)-1]; last.ProtoMajor != u.wantProto || last.Body != "hello" ||
					last.Header.Get("Authorization") != "Bearer test-value-1" {
					t.Fatalf("the Upstream received %+v, want HTTP/%d with the body and the Secret", last, u.wantProto)
				}
			})
		}
	}
}

// foreignCA writes a CA certificate that signs nothing the tests serve.
func foreignCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "foreign test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "foreign-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProxyDeliveryVerifiesUpstreamTLS(t *testing.T) {
	tc := harness.New(t)
	up := tc.Upstream()
	port := up.URL[strings.LastIndex(up.URL, ":")+1:]
	secret := func(name, upstream string) string {
		return fmt.Sprintf(`
  %s:
    backend: fake
    location: kv/openai
    injection_template:
      header:
        name: Authorization
        value: Bearer {secret}
    upstreams:
      api:
%s`, name, upstream)
	}
	config := strings.Replace(proxyConfig, "\n  unlisted:\n",
		secret("system-roots", "        url: "+up.URL+"\n")+
			secret("foreign-ca", "        url: "+up.URL+"\n        ca_bundle: "+foreignCA(t, t.TempDir())+"\n")+
			secret("wrong-name", "        url: https://localhost:"+port+"\n        ca_bundle: "+up.CABundle+"\n")+
			"\n  unlisted:\n", 1)
	config = strings.Replace(config, "\npolicies:\n", `
policies:
  tls:
    secrets:
      - name: system-roots
        delivery: [proxy]
      - name: foreign-ca
        delivery: [proxy]
      - name: wrong-name
        delivery: [proxy]
`, 1)
	srv := tc.Start(config)
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "tls", "1h").Token

	for _, name := range []string{"system-roots", "foreign-ca", "wrong-name"} {
		got := proxy(t, srv, http.MethodGet, "/proxy/"+name+"/api/v1/models", bearer(token), "")
		if got.Status != http.StatusBadGateway {
			t.Errorf("%s: proxy = %d %q, want 502", name, got.Status, got.Body)
		}
		for _, leak := range []string{"certificate", "x509", "127.0.0.1", "localhost"} {
			if strings.Contains(got.Body, leak) {
				t.Errorf("%s: 502 body %q reveals %q", name, got.Body, leak)
			}
		}
	}
	if n := len(up.Requests()); n != 0 {
		t.Fatalf("an unverified Upstream received %d requests", n)
	}
	if !strings.Contains(srv.Stderr(), "certificate") {
		t.Errorf("server log does not record the TLS verification failure:\n%s", srv.Stderr())
	}
}

func TestProxyDeliveryRefusesProtocolUpgrades(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")
	header := bearer(token)
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")
	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/v1/realtime", header, ""); got.Status != http.StatusBadRequest {
		t.Fatalf("upgrade = %d %q, want 400", got.Status, got.Body)
	}
	if n := len(tc.Upstream().Requests()); n != 0 {
		t.Fatalf("the Upstream received %d upgrade requests", n)
	}

	// curl --http2 offers h2c on plain HTTP; the request is served as
	// HTTP/1.1 and the offer goes no further.
	h2c := bearer(token)
	h2c.Set("Connection", "Upgrade, HTTP2-Settings")
	h2c.Set("Upgrade", "h2c")
	h2c.Set("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")
	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/v1/models", h2c, ""); got.Status != http.StatusOK {
		t.Fatalf("request offering h2c = %d %q, want 200", got.Status, got.Body)
	}
	reqs := tc.Upstream().Requests()
	if len(reqs) != 1 {
		t.Fatalf("the Upstream received %d requests, want 1", len(reqs))
	}
	for _, name := range []string{"Upgrade", "Http2-Settings", "Connection"} {
		if v := reqs[0].Header.Values(name); len(v) != 0 {
			t.Errorf("the Upstream received %s %q", name, v)
		}
	}
}

func TestProxyConfigIsValidated(t *testing.T) {
	const name = "secrets:\n  openai:\n    backend: fake\n    location: kv/openai\n"
	const header = "    injection_template:\n      header:\n        name: Authorization\n        value: Bearer {secret}\n"
	upstream := func(fields string) string { return "    upstreams:\n      api:\n" + fields }
	const url = "        url: https://api.example.com\n"
	cases := []struct {
		name, config, wantErr string
	}{
		{"skip-verify does not exist", name + header + upstream(url+"        insecure_skip_verify: true\n"), "insecure_skip_verify"},
		{"plain HTTP Upstream", name + header + upstream("        url: http://api.example.com\n"), "https"},
		{"Upstream URL with a query", name + header + upstream("        url: https://api.example.com/?k=v\n"), "query"},
		{"Upstream URL with credentials", name + header + upstream("        url: https://user:pass@api.example.com\n"), "user"},
		{"Upstream URL without a host", name + header + upstream("        url: https:///v1\n"), "host"},
		{"missing Upstream URL", name + header + upstream("        ca_bundle: ./ca.pem\n"), "url is required"},
		{"invalid Upstream name", name + header + "    upstreams:\n      \"bad name\":\n" + url, `invalid Upstream name "bad name"`},
		{"missing CA bundle file", name + header + upstream(url+"        ca_bundle: ./no-such-ca.pem\n"), "no-such-ca.pem"},
		{"CA bundle without certificates", name + header + upstream(url+"        ca_bundle: ./config.yaml\n"), "no certificates"},
		{"Upstreams without an Injection Template", name + upstream(url), "injection_template is required"},
		{"Injection Template without Upstreams", name + header, "upstreams"},
		{"template without {secret}", name + strings.Replace(header, "{secret}", "static", 1) + upstream(url), "{secret}"},
		{"template with two {secret}", name + strings.Replace(header, "{secret}", "{secret}{secret}", 1) + upstream(url), "{secret}"},
		{"control character in template", name + strings.Replace(header, "Bearer {secret}", "\"Bearer\\r\\n{secret}\"", 1) + upstream(url), "control character"},
		{"invalid header name", name + strings.Replace(header, "Authorization", "\"Bad Header\"", 1) + upstream(url), "header name"},
		{"fallback header", name + strings.Replace(header, "Authorization", "X-TC-Agent-Token", 1) + upstream(url), "X-TC-Agent-Token"},
		{"hop-by-hop header", name + strings.Replace(header, "Authorization", "Connection", 1) + upstream(url), "Connection"},
		{"Host header", name + strings.Replace(header, "Authorization", "host", 1) + upstream(url), "host"},
		{"no Injection Template kind", name + "    injection_template: {}\n" + upstream(url), "header"},
		{"Proxy Delivery of a Secret Name without Upstreams",
			name + "policies:\n  p:\n    secrets:\n      - name: openai\n        delivery: [proxy]\n",
			`Policy "p" allows Proxy Delivery of Secret Name "openai", which has no upstreams`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig + c.config)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

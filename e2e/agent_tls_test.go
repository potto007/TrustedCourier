package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// Where the fake Backend Plugin holds the Agent API's certificate and key in
// the TLS tests.
const (
	tlsCertificateLocation = "courier/tls-certificate"
	tlsKeyLocation         = "courier/tls-key"
)

// tlsAgentAPI serves the Agent API with TLS from the Courier Keys at
// tlsCertificateLocation and tlsKeyLocation, on the given listen address.
func tlsAgentAPI(listen string) string {
	return `
agent_api:
  listen: "` + listen + `"
  tls:
    certificate:
      backend: fake
      location: ` + tlsCertificateLocation + `
    key:
      backend: fake
      location: ` + tlsKeyLocation + `
`
}

// startTLS starts BaseConfig with the Agent API on listen over TLS, holding
// cert in the fake Backend Plugin when withCertificate is set, and returns
// the server and the path of the installed plugin copy, for later rotation.
func startTLS(t *testing.T, tc *harness.Installation, listen string, cert *harness.Certificate, withCertificate bool) (*harness.Server, string) {
	t.Helper()
	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	secrets := map[string]string{
		"kv/openai": "test-value-1", "kv/github": "test-value-2",
		harness.AuditSigningKeyLocation: harness.AuditSigningKey,
	}
	if withCertificate {
		secrets[tlsCertificateLocation] = cert.CertificatePEM
		secrets[tlsKeyLocation] = cert.KeyPEM
	}
	tc.SetBackendSecrets(path, secrets)
	config := strings.Replace(harness.BaseConfig, "{{.Fake.Path}}", path, 1) + tlsAgentAPI(listen) + auditConfig
	return tc.Start(config), path
}

// revealWith is reveal with the given client and base URL.
func revealWith(t *testing.T, client *http.Client, baseURL, token, secretName string) (agentResponse, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/reveal/"+secretName, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return agentResponse{Status: resp.StatusCode, Header: resp.Header, Body: string(body)}, resp
}

func TestAgentAPIServesOperatorSuppliedTLS(t *testing.T) {
	tc := harness.New(t)
	cert := tc.IssueCertificate(24*time.Hour, "127.0.0.1")
	srv, _ := startTLS(t, tc, "127.0.0.1:0", cert, true)
	url := srv.AgentURL()
	if !strings.HasPrefix(url, "https://") {
		t.Fatalf("Agent API URL %q is not https", url)
	}
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	client := cert.Client()
	defer client.CloseIdleConnections()

	got, resp := revealWith(t, client, url, token, "github")
	if got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal over TLS = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	if resp.TLS == nil {
		t.Fatal("the response did not arrive over TLS")
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("the Agent API served %s over TLS, want HTTP/2 by ALPN", resp.Proto)
	}
	if !strings.Contains(srv.Stderr(), "TLS certificate loaded") {
		t.Errorf("server log does not record the certificate:\n%s", srv.Stderr())
	}

	// A client that does not trust the CA is refused by its own TLS stack,
	// and plain HTTP to the TLS listener gets at most a 400, never a
	// Delivery.
	untrusting := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: nil}}}
	defer untrusting.CloseIdleConnections()
	if _, err := untrusting.Get(url + "/v1/reveal/github"); err == nil {
		t.Error("a client without the CA reached the Agent API")
	}
	plain := &http.Client{Timeout: 5 * time.Second}
	defer plain.CloseIdleConnections()
	got, _ = revealWith(t, plain, "http://"+strings.TrimPrefix(url, "https://"), token, "github")
	if got.Status != http.StatusBadRequest || strings.Contains(got.Body, "test-value") {
		t.Errorf("plain HTTP to the TLS listener = %d %q, want 400 without a Secret", got.Status, got.Body)
	}

	if status := srv.TC("status"); status.ExitCode != 0 || !strings.Contains(status.Stdout, "TLS certificate: loaded") {
		t.Errorf("tc status does not report the certificate: exit %d\n%s%s", status.ExitCode, status.Stdout, status.Stderr)
	}
}

func TestAgentAPIServesTLSOnAllInterfaces(t *testing.T) {
	tc := harness.New(t)
	cert := tc.IssueCertificate(24*time.Hour, "127.0.0.1")
	srv, _ := startTLS(t, tc, "0.0.0.0:0", cert, true)
	url := srv.AgentURL()
	if !strings.HasPrefix(url, "https://0.0.0.0:") {
		t.Fatalf("Agent API URL %q, want https://0.0.0.0:<port>", url)
	}
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	client := cert.Client()
	defer client.CloseIdleConnections()

	got, _ := revealWith(t, client, strings.Replace(url, "0.0.0.0", "127.0.0.1", 1), token, "github")
	if got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal over TLS on all interfaces = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
}

func TestAgentAPIWaitsForTheTLSCertificate(t *testing.T) {
	tc := harness.New(t)
	cert := tc.IssueCertificate(24*time.Hour, "127.0.0.1")
	srv, path := startTLS(t, tc, "127.0.0.1:0", cert, false)
	url := srv.ListeningAgentURL()
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	client := cert.Client()
	defer client.CloseIdleConnections()

	// The listener is bound, but no handshake completes until the
	// certificate is loaded.
	if _, err := client.Get(url + "/v1/reveal/github"); err == nil {
		t.Fatal("a TLS handshake completed before the certificate was loaded")
	}
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(srv.TC("status").Stdout, "TLS certificate: not loaded") {
		if time.Now().After(deadline) {
			t.Fatalf("tc status never reported the missing certificate:\n%s", srv.TC("status").Stdout)
		}
		time.Sleep(50 * time.Millisecond)
	}

	tc.SetBackendSecrets(path, map[string]string{
		"kv/github":                     "test-value-2",
		harness.AuditSigningKeyLocation: harness.AuditSigningKey,
		tlsCertificateLocation:          cert.CertificatePEM,
		tlsKeyLocation:                  cert.KeyPEM,
	})
	deadline = time.Now().Add(20 * time.Second)
	for {
		resp, err := client.Get(url + "/v1/reveal/github")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Agent API never served TLS after the certificate appeared: %v\nstderr:\n%s", err, srv.Stderr())
		}
		time.Sleep(100 * time.Millisecond)
	}
	got, _ := revealWith(t, client, url, token, "github")
	if got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal after the certificate loaded = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	if status := srv.TC("status"); !strings.Contains(status.Stdout, "TLS certificate: loaded") {
		t.Errorf("tc status does not report the loaded certificate:\n%s", status.Stdout)
	}
}

func TestAgentAPIRefusesAnUnusableCertificate(t *testing.T) {
	cases := []struct {
		name string
		// held returns the certificate and key PEM the Backend holds, given
		// a good pair and another good pair.
		held    func(own, other *harness.Certificate) (cert, key string)
		wantLog string
	}{
		{"expired", func(own, _ *harness.Certificate) (string, string) { return own.CertificatePEM, own.KeyPEM }, "expired"},
		{"key does not match", func(own, other *harness.Certificate) (string, string) { return own.CertificatePEM, other.KeyPEM }, "does not match"},
		{"certificate not PEM", func(own, _ *harness.Certificate) (string, string) { return "not a certificate", own.KeyPEM }, "not PEM"},
		{"key not PEM", func(own, _ *harness.Certificate) (string, string) { return own.CertificatePEM, "not a key" }, "not PEM"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			validFor := 24 * time.Hour
			if c.name == "expired" {
				validFor = -time.Hour
			}
			own := tc.IssueCertificate(validFor, "127.0.0.1")
			other := tc.IssueCertificate(24*time.Hour, "127.0.0.1")
			certPEM, keyPEM := c.held(own, other)
			path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
			tc.SetBackendSecrets(path, map[string]string{
				"kv/github":                     "test-value-2",
				harness.AuditSigningKeyLocation: harness.AuditSigningKey,
				tlsCertificateLocation:          certPEM,
				tlsKeyLocation:                  keyPEM,
			})
			config := strings.Replace(harness.BaseConfig, "{{.Fake.Path}}", path, 1) + tlsAgentAPI("127.0.0.1:0") + auditConfig
			srv := tc.Start(config)
			url := srv.ListeningAgentURL()
			deadline := time.Now().Add(15 * time.Second)
			for !strings.Contains(srv.Stderr(), c.wantLog) {
				if time.Now().After(deadline) {
					t.Fatalf("server log does not say %q:\n%s", c.wantLog, srv.Stderr())
				}
				time.Sleep(50 * time.Millisecond)
			}
			if strings.Contains(srv.Stderr(), "TLS certificate loaded") {
				t.Fatalf("the unusable certificate was loaded:\n%s", srv.Stderr())
			}
			client := own.Client()
			defer client.CloseIdleConnections()
			if _, err := client.Get(url + "/v1/reveal/github"); err == nil {
				t.Fatal("a TLS handshake completed with an unusable certificate")
			}
			if status := srv.TC("status"); !strings.Contains(status.Stdout, "TLS certificate: not loaded (") ||
				!strings.Contains(status.Stdout, c.wantLog) {
				t.Errorf("tc status does not report the unusable certificate:\n%s", status.Stdout)
			}
		})
	}
}

func TestAgentAPIServesAUnixSocket(t *testing.T) {
	tc := harness.New(t)
	socket := filepath.Join(tc.Dir(), "agent.sock")
	srv := tc.Start(harness.BaseConfig + "\nagent_api:\n  socket: " + socket + "\n" + auditConfig)
	if got := srv.AgentSocket(); got != socket {
		t.Fatalf("Agent API socket = %q, want %q", got, socket)
	}
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	defer client.CloseIdleConnections()

	got, _ := revealWith(t, client, "http://trustedcourier", token, "github")
	if got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal over the unix socket = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	// tc env prints a base URL, which a unix socket has none of.
	if env := srv.TC("env", "openai"); env.ExitCode == 0 || !strings.Contains(env.Stderr, "unix socket") {
		t.Errorf("tc env with a unix socket Agent API: exit %d\n%s%s", env.ExitCode, env.Stdout, env.Stderr)
	}
}

func TestAgentAPIListenerConfigIsValidated(t *testing.T) {
	tlsOnly := strings.TrimPrefix(tlsAgentAPI("127.0.0.1:8200"), "\nagent_api:\n  listen: \"127.0.0.1:8200\"\n")
	cases := []struct {
		name, config, wantErr string
	}{
		{"all interfaces without TLS", "agent_api:\n  listen: 0.0.0.0:8200\n", "agent_api.tls is required"},
		{"IPv6 all interfaces without TLS", "agent_api:\n  listen: \"[::]:8200\"\n", "agent_api.tls is required"},
		{"routable address without TLS", "agent_api:\n  listen: 192.0.2.10:8200\n", "agent_api.tls is required"},
		{"host name", "agent_api:\n  listen: localhost:8200\n", "IP address and port"},
		{"no port", "agent_api:\n  listen: 127.0.0.1\n", "IP address and port"},
		{"TLS without listen", "agent_api:\n" + tlsOnly, "agent_api.tls needs agent_api.listen"},
		{"listen and socket", "agent_api:\n  listen: 127.0.0.1:8200\n  socket: /tmp/agent.sock\n", "not both"},
		{"socket with TLS", "agent_api:\n  socket: /tmp/agent.sock\n" + tlsOnly, "agent_api.tls needs agent_api.listen"},
		{"TLS without key", "agent_api:\n  listen: 127.0.0.1:8200\n  tls:\n    certificate:\n      backend: fake\n      location: courier/tls-certificate\n", "agent_api.tls.key: backend is required"},
		{"TLS certificate in unknown backend", "agent_api:\n  listen: 127.0.0.1:8200\n  tls:\n    certificate:\n      backend: nope\n      location: courier/tls-certificate\n    key:\n      backend: fake\n      location: courier/tls-key\n", `agent_api.tls.certificate: unknown backend "nope"`},
		{"Secret Name maps to the TLS key", tlsAgentAPI("127.0.0.1:8200") + "secrets:\n  leak:\n    backend: fake\n    location: " + tlsKeyLocation + "\n", "Courier Key is never delivered to Agents"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig + auditConfig + c.config)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

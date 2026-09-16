package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// Where the fake Backend Plugin holds the remote admin listener's
// certificate and key.
const (
	adminCertificateLocation = "courier/admin-tls-certificate"
	adminKeyLocation         = "courier/admin-tls-key"
)

// adminListener enables the remote admin listener on listen, serving the
// Courier Keys at certificate and key, admitting client certificates the CA
// file at clientCA signed.
func adminListener(listen, certificate, key, clientCA string) string {
	return `
admin:
  socket: {{.Socket}}
  listen: "` + listen + `"
  tls:
    certificate:
      backend: fake
      location: ` + certificate + `
    key:
      backend: fake
      location: ` + key + `
    client_ca: ` + clientCA + `
`
}

// remoteAdmin is what a test needs to reach a remote admin listener: the
// server, its URL, the Operator's client certificate, and the files tc reads
// it from.
type remoteAdmin struct {
	srv                        *harness.Server
	url                        string
	server                     *harness.Certificate
	client                     *harness.ClientCertificate
	caFile, certFile, keyFile  string
	env                        []string
	adminCertificate, adminKey string
}

// startRemoteAdmin starts BaseConfig with the remote admin listener on
// loopback. With shared set, the listener serves the Agent API's certificate
// rather than its own pair.
func startRemoteAdmin(t *testing.T, tc *harness.Installation, shared bool) remoteAdmin {
	t.Helper()
	dir := t.TempDir()
	server := tc.IssueCertificate(24*time.Hour, "127.0.0.1")
	clientCA := tc.IssueCertificate(24*time.Hour, "client-ca")
	client := clientCA.IssueClient("operator")
	caFile := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caFile, []byte(clientCA.CAPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	serverCAFile := filepath.Join(dir, "server-ca.pem")
	if err := os.WriteFile(serverCAFile, []byte(server.CAPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "operator.pem")
	if err := os.WriteFile(certFile, []byte(client.CertificatePEM), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "operator-key.pem")
	if err := os.WriteFile(keyFile, []byte(client.KeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	secrets := map[string]string{
		"kv/openai": "test-value-1", "kv/github": "test-value-2",
		harness.AuditSigningKeyLocation: harness.AuditSigningKey,
		tlsCertificateLocation:          server.CertificatePEM,
		tlsKeyLocation:                  server.KeyPEM,
	}
	certificate, key := tlsCertificateLocation, tlsKeyLocation
	if !shared {
		certificate, key = adminCertificateLocation, adminKeyLocation
		secrets[certificate] = server.CertificatePEM
		secrets[key] = server.KeyPEM
	}
	tc.SetBackendSecrets(path, secrets)
	config := strings.Replace(harness.BaseConfig, "{{.Fake.Path}}", path, 1)
	config = strings.Replace(config, "admin:\n  socket: {{.Socket}}\n", adminListener("127.0.0.1:0", certificate, key, caFile), 1)
	srv := tc.Start(config + tlsAgentAPI("127.0.0.1:0") + auditConfig)
	return remoteAdmin{
		srv: srv, url: srv.AdminURL(), server: server, client: client,
		caFile: caFile, certFile: certFile, keyFile: keyFile,
		env: []string{
			"TC_ADMIN_URL=" + srv.AdminURL(),
			"TC_ADMIN_CA_BUNDLE=" + serverCAFile,
			"TC_ADMIN_CLIENT_CERT=" + certFile,
			"TC_ADMIN_CLIENT_KEY=" + keyFile,
		},
		adminCertificate: certificate, adminKey: key,
	}
}

// adminClient returns an HTTPS client that trusts the listener's CA and
// presents cert, or no client certificate when cert is nil.
func adminClient(pool *x509.CertPool, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: pool}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// adminGet calls the admin API at url with the given Operator Credential
// (none when empty) and returns the status code, or the transport error.
func adminGet(t *testing.T, client *http.Client, url, credential string) (int, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+"/v1/agent-tokens", nil)
	if err != nil {
		t.Fatal(err)
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func TestRemoteAdminListenerIsOffByDefault(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	if res := srv.TC("token", "list"); res.ExitCode != 0 {
		t.Fatalf("token list: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	if strings.Contains(srv.Stderr(), "remote admin API listening") {
		t.Fatalf("a remote admin listener started without admin.listen:\n%s", srv.Stderr())
	}
}

func TestRemoteAdminRequiresClientCertificateAndOperatorCredential(t *testing.T) {
	tc := harness.New(t)
	ra := startRemoteAdmin(t, tc, false)
	if !strings.HasPrefix(ra.url, "https://127.0.0.1:") {
		t.Fatalf("remote admin URL %q, want https://127.0.0.1:<port>", ra.url)
	}
	credential := ra.srv.Credential

	// No client certificate: refused at the TLS layer, no HTTP response.
	none := adminClient(ra.server.Pool, nil)
	defer none.CloseIdleConnections()
	if status, err := adminGet(t, none, ra.url, credential); err == nil {
		t.Errorf("a connection without a client certificate got HTTP %d, want a TLS failure", status)
	} else if !isTLSRejection(err) {
		t.Errorf("a connection without a client certificate failed with %v, want a TLS rejection", err)
	}

	// A client certificate from a CA the listener does not trust.
	stranger := tc.IssueCertificate(24*time.Hour, "stranger-ca").IssueClient("stranger")
	untrusted := adminClient(ra.server.Pool, &stranger.TLS)
	defer untrusted.CloseIdleConnections()
	if status, err := adminGet(t, untrusted, ra.url, credential); err == nil {
		t.Errorf("a connection with an untrusted client certificate got HTTP %d, want a TLS failure", status)
	} else if !isTLSRejection(err) {
		t.Errorf("a connection with an untrusted client certificate failed with %v, want a TLS rejection", err)
	}

	// A valid client certificate alone is not enough.
	trusted := adminClient(ra.server.Pool, &ra.client.TLS)
	defer trusted.CloseIdleConnections()
	if status, err := adminGet(t, trusted, ra.url, ""); err != nil || status != http.StatusUnauthorized {
		t.Errorf("client certificate without the Operator Credential = %d, %v; want 401", status, err)
	}
	if status, err := adminGet(t, trusted, ra.url, "tcoc_wrong"); err != nil || status != http.StatusUnauthorized {
		t.Errorf("client certificate with a wrong Operator Credential = %d, %v; want 401", status, err)
	}
	if status, err := adminGet(t, trusted, ra.url, credential); err != nil || status != http.StatusOK {
		t.Errorf("client certificate with the Operator Credential = %d, %v; want 200", status, err)
	}

	// tc targets the listener from its environment.
	env := append([]string{"TC_OPERATOR_CREDENTIAL=" + credential}, ra.env...)
	if res := tc.TC(env, "token", "list"); res.ExitCode != 0 {
		t.Errorf("tc token list over the remote admin listener: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	if res := tc.TC(env, "status"); res.ExitCode != 0 || !strings.Contains(res.Stdout, "TLS certificate: loaded") {
		t.Errorf("tc status over the remote admin listener: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	issued := tc.TC(env, "token", "issue", "--policy", "openai-proxy", "--expires-in", "1h")
	if issued.ExitCode != 0 || !strings.Contains(issued.Stdout, "tcat_") {
		t.Errorf("tc token issue over the remote admin listener: exit %d\n%s%s", issued.ExitCode, issued.Stdout, issued.Stderr)
	}
	// Without the client certificate, tc gets nowhere.
	noCert := []string{"TC_OPERATOR_CREDENTIAL=" + credential, "TC_ADMIN_URL=" + ra.url, "TC_ADMIN_CA_BUNDLE=" + ra.env[1][len("TC_ADMIN_CA_BUNDLE="):]}
	if res := tc.TC(noCert, "token", "list"); res.ExitCode == 0 {
		t.Errorf("tc without a client certificate listed Agent Tokens:\n%s", res.Stdout)
	}
	// A certificate without its key is a usage error, not a connection.
	half := append([]string{"TC_OPERATOR_CREDENTIAL=" + credential}, ra.env[:3]...)
	if res := tc.TC(half, "token", "list"); res.ExitCode == 0 || !strings.Contains(res.Stderr, "TC_ADMIN_CLIENT_KEY") {
		t.Errorf("tc with a client certificate but no key: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	// The unix socket still works beside the listener.
	if res := ra.srv.TC("token", "list"); res.ExitCode != 0 {
		t.Errorf("tc over the admin socket beside the listener: exit %d\n%s", res.ExitCode, res.Stderr)
	}
}

func TestRemoteAdminSharesTheAgentAPICertificate(t *testing.T) {
	tc := harness.New(t)
	ra := startRemoteAdmin(t, tc, true)
	if ra.adminCertificate != tlsCertificateLocation {
		t.Fatal("the test did not share the Agent API's certificate")
	}
	trusted := adminClient(ra.server.Pool, &ra.client.TLS)
	defer trusted.CloseIdleConnections()
	if status, err := adminGet(t, trusted, ra.url, ra.srv.Credential); err != nil || status != http.StatusOK {
		t.Errorf("admin API over the shared certificate = %d, %v; want 200", status, err)
	}
	if url := ra.srv.AgentURL(); !strings.HasPrefix(url, "https://") {
		t.Errorf("Agent API URL %q is not https", url)
	}
}

// isTLSRejection reports whether err is the client's view of a handshake the
// server refused: a TLS alert, or the connection closed during the handshake.
func isTLSRejection(err error) bool {
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "tls:") || strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset")
}

func TestRemoteAdminListenerConfigIsValidated(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tlsBlock := func(clientCA string) string {
		return "  tls:\n    certificate:\n      backend: fake\n      location: " + adminCertificateLocation +
			"\n    key:\n      backend: fake\n      location: " + adminKeyLocation + "\n    client_ca: " + clientCA + "\n"
	}
	cases := []struct {
		name, config, wantErr string
	}{
		{"listen without tls", "admin:\n  socket: {{.Socket}}\n  listen: 127.0.0.1:8300\n", "admin.tls is required"},
		{"tls without listen", "admin:\n  socket: {{.Socket}}\n" + tlsBlock(caFile), "admin.tls needs admin.listen"},
		{"host name", "admin:\n  socket: {{.Socket}}\n  listen: localhost:8300\n" + tlsBlock(caFile), "IP address and port"},
		{"no client_ca", "admin:\n  socket: {{.Socket}}\n  listen: 127.0.0.1:8300\n  tls:\n    certificate:\n      backend: fake\n      location: " + adminCertificateLocation + "\n    key:\n      backend: fake\n      location: " + adminKeyLocation + "\n", "admin.tls.client_ca is required"},
		{"missing client_ca file", "admin:\n  socket: {{.Socket}}\n  listen: 127.0.0.1:8300\n" + tlsBlock(filepath.Join(dir, "missing.pem")), "admin.tls.client_ca"},
		{"empty client_ca file", "admin:\n  socket: {{.Socket}}\n  listen: 127.0.0.1:8300\n" + tlsBlock(empty), "holds no certificates"},
		{"certificate and key share a location", "admin:\n  socket: {{.Socket}}\n  listen: 127.0.0.1:8300\n  tls:\n    certificate:\n      backend: fake\n      location: courier/same\n    key:\n      backend: fake\n      location: courier/same\n    client_ca: " + caFile + "\n", "same location"},
		{"same port as the Agent API", "admin:\n  socket: {{.Socket}}\n  listen: 127.0.0.1:8300\n" + tlsBlock(caFile) + "agent_api:\n  listen: 127.0.0.1:8300\n", "admin.listen"},
		{"Secret Name maps to the admin key", "admin:\n  socket: {{.Socket}}\n  listen: 127.0.0.1:8300\n" + tlsBlock(caFile) + "secrets:\n  leak:\n    backend: fake\n    location: " + adminKeyLocation + "\n", "Courier Key is never delivered to Agents"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			ca := tc.IssueCertificate(time.Hour, "ca")
			if err := os.WriteFile(caFile, []byte(ca.CAPEM), 0o600); err != nil {
				t.Fatal(err)
			}
			code, stderr := tc.Refused("data_dir: {{.DataDir}}\n" + c.config + fakePluginConfig + auditConfig)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

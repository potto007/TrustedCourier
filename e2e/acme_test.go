package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// Where the fake Backend Plugin holds the ACME Courier Keys in these tests.
const (
	acmeAccountKeyLocation = "courier/acme-account-key"
	acmeEABKeyLocation     = "courier/acme-eab-key"
)

// acmeDomain is the name the certificate is issued for. Pebble validates
// challenges against whatever it resolves to, so the server listens on every
// interface.
const acmeDomain = "localhost"

// acmeConfig is the agent_api section for a TLS listener on port with ACME
// against pebble, plus extra lines under acme.
func acmeConfig(port int, pebble *harness.Pebble, extra string) string {
	return fmt.Sprintf(`
agent_api:
  listen: "0.0.0.0:%d"
  tls:
    certificate:
      backend: fake
      location: %s
    key:
      backend: fake
      location: %s
    acme:
      domains: [%s]
      directory: %s
      ca_bundle: %s
      account_key:
        backend: fake
        location: %s
%s`, port, tlsCertificateLocation, tlsKeyLocation, acmeDomain, pebble.DirectoryURL, pebble.CABundle, acmeAccountKeyLocation, extra)
}

// startACME installs the fake Backend Plugin with a secrets file, so the
// Courier Keys TrustedCourier stores can be read back, and starts BaseConfig
// with the given agent_api section. It returns the server and the plugin
// path.
func startACME(t *testing.T, tc *harness.Installation, plugin harness.PluginBinary, agentAPI string, extraSecrets map[string]string) (*harness.Server, string) {
	t.Helper()
	path := tc.InstallPlugin(plugin, t.TempDir(), 0o755)
	secrets := map[string]string{
		"kv/openai": "test-value-1", "kv/github": "test-value-2",
		harness.AuditSigningKeyLocation: harness.AuditSigningKey,
	}
	for k, v := range extraSecrets {
		secrets[k] = v
	}
	tc.SetBackendSecrets(path, secrets)
	config := strings.Replace(harness.BaseConfig, "{{.Fake.Path}}", path, 1)
	config = strings.Replace(config, "{{.Fake.SHA256}}", plugin.SHA256, 1)
	return tc.Start(config + agentAPI + auditConfig), path
}

// agentURLOn is the Agent API's URL with the wildcard host replaced by
// loopback, which is what a client can dial.
func agentURLOn(url string) string {
	return strings.Replace(url, "0.0.0.0", "127.0.0.1", 1)
}

// servedCertificate completes a TLS handshake with the Agent API at url as a
// client for acmeDomain and returns the leaf it served.
func servedCertificate(t *testing.T, pebble *harness.Pebble, url string) *x509.Certificate {
	t.Helper()
	addr := strings.TrimPrefix(url, "https://")
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pebble.Roots, ServerName: acmeDomain})
	if err != nil {
		t.Fatalf("TLS handshake with %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0]
}

// waitForCertificate waits until the Agent API at url serves a certificate
// Pebble issued that differs from previous (which may be nil), and returns
// it.
func waitForCertificate(t *testing.T, pebble *harness.Pebble, url string, previous *x509.Certificate, within time.Duration) *x509.Certificate {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		addr := strings.TrimPrefix(url, "https://")
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pebble.Roots, ServerName: acmeDomain})
		if err == nil {
			leaf := conn.ConnectionState().PeerCertificates[0]
			_ = conn.Close()
			if previous == nil || leaf.SerialNumber.Cmp(previous.SerialNumber) != 0 {
				return leaf
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Agent API never served a new certificate from Pebble: %v\npebble:\n%s", err, pebble.Log())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func assertACMECertificate(t *testing.T, tc *harness.Installation, srv *harness.Server, pebble *harness.Pebble, pluginPath string) *x509.Certificate {
	t.Helper()
	url := agentURLOn(srv.AgentURL())
	leaf := servedCertificate(t, pebble, url)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != acmeDomain {
		t.Errorf("the certificate names %v, want [%s]", leaf.DNSNames, acmeDomain)
	}
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	client := pebble.Client(acmeDomain)
	defer client.CloseIdleConnections()
	got, resp := revealWith(t, client, url, token, "github")
	if got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal over an ACME certificate = %d %q, want 200 test-value-2", got.Status, got.Body)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("the Agent API served %s over TLS, want HTTP/2 by ALPN", resp.Proto)
	}
	if status := srv.TC("status"); status.ExitCode != 0 || !strings.Contains(status.Stdout, "TLS certificate: loaded") {
		t.Errorf("tc status does not report the certificate: exit %d\n%s%s", status.ExitCode, status.Stdout, status.Stderr)
	}

	// The certificate, its key, and the account key are Courier Keys in
	// the Backend, and nothing of them is on TrustedCourier's disk.
	stored := tc.BackendSecrets(pluginPath)
	for _, loc := range []string{tlsCertificateLocation, tlsKeyLocation, acmeAccountKeyLocation} {
		if !strings.HasPrefix(stored[loc], "-----BEGIN ") {
			t.Errorf("the Backend holds no PEM at %s: %q", loc, stored[loc])
		}
	}
	if key := stored[tlsKeyLocation]; key != "" && tc.FilesContain(strings.TrimSpace(key)) {
		t.Error("the TLS key is on TrustedCourier's disk")
	}
	if key := stored[acmeAccountKeyLocation]; key != "" && tc.FilesContain(strings.TrimSpace(key)) {
		t.Error("the ACME account key is on TrustedCourier's disk")
	}
	return leaf
}

func TestACMEObtainsACertificateByTLSALPN01(t *testing.T) {
	tc := harness.New(t)
	port := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{TLSPort: port})
	srv, path := startACME(t, tc, harness.FakePlugin, acmeConfig(port, pebble, ""), nil)
	first := assertACMECertificate(t, tc, srv, pebble, path)
	if !strings.Contains(srv.Stderr(), "TLS certificate obtained") {
		t.Errorf("server log does not record obtaining the certificate:\n%s", srv.Stderr())
	}

	// A restart reuses the stored certificate rather than requesting a new
	// one.
	srv.Stop()
	srv = tc.Start(strings.Replace(harness.BaseConfig, "{{.Fake.Path}}", path, 1) + acmeConfig(port, pebble, "") + auditConfig)
	url := agentURLOn(srv.AgentURL())
	if again := servedCertificate(t, pebble, url); again.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Errorf("after a restart the Agent API serves serial %s, want the stored %s", again.SerialNumber, first.SerialNumber)
	}
	if strings.Contains(srv.Stderr(), "TLS certificate obtained") {
		t.Errorf("the restarted server requested a new certificate:\n%s", srv.Stderr())
	}
}

func TestACMEObtainsACertificateByHTTP01(t *testing.T) {
	tc := harness.New(t)
	port := harness.FreePort(t)
	httpPort := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{HTTPPort: httpPort})
	extra := "      challenge: http-01\n      http_listen: \"0.0.0.0:" + strconv.Itoa(httpPort) + "\"\n"
	srv, path := startACME(t, tc, harness.FakePlugin, acmeConfig(port, pebble, extra), nil)
	assertACMECertificate(t, tc, srv, pebble, path)

	// The HTTP-01 listener serves nothing but challenges.
	plain := &http.Client{Timeout: 5 * time.Second}
	defer plain.CloseIdleConnections()
	resp, err := plain.Get("http://127.0.0.1:" + strconv.Itoa(httpPort) + "/v1/reveal/github")
	if err != nil {
		t.Fatalf("GET on the HTTP-01 listener: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /v1/reveal/github on the HTTP-01 listener = %d, want 404", resp.StatusCode)
	}
}

func TestACMERenewsBeforeExpiry(t *testing.T) {
	tc := harness.New(t)
	port := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{TLSPort: port, Validity: 24 * time.Second})
	srv, path := startACME(t, tc, harness.FakePlugin, acmeConfig(port, pebble, ""), nil)
	first := assertACMECertificate(t, tc, srv, pebble, path)
	url := agentURLOn(srv.AgentURL())

	// Renewal happens at two thirds of the lifetime, while the first
	// certificate is still valid, and the Backend holds the new one.
	renewed := waitForCertificate(t, pebble, url, first, 40*time.Second)
	if !time.Now().Before(first.NotAfter) {
		t.Errorf("the certificate was renewed at %s, after it expired at %s", time.Now().UTC().Format(time.RFC3339), first.NotAfter.UTC().Format(time.RFC3339))
	}
	if stored := tc.BackendSecrets(path)[tlsCertificateLocation]; !strings.Contains(stored, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("the Backend does not hold the renewed certificate")
	} else if leaf := parseFirstCertificate(t, stored); leaf.SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Errorf("the Backend holds serial %s, the Agent API serves %s", leaf.SerialNumber, renewed.SerialNumber)
	}
}

func TestACMERequiresABackendThatStoresCourierKeys(t *testing.T) {
	tc := harness.New(t)
	port := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{TLSPort: port})
	srv, _ := startACME(t, tc, harness.ReadOnlyPlugin, acmeConfig(port, pebble, ""), nil)
	srv.ListeningAgentURL()
	waitForPlugin(t, srv, "fake", running)
	deadline := time.Now().Add(15 * time.Second)
	for {
		status := srv.TC("status").Stdout
		if strings.Contains(status, "TLS certificate: not loaded (") && strings.Contains(status, "cannot store Courier Keys") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tc status never reported the read-only Backend:\n%s\nstderr:\n%s", status, srv.Stderr())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(pebble.Log(), "newOrder") || strings.Contains(srv.Stderr(), "TLS certificate obtained") {
		t.Errorf("TrustedCourier requested a certificate it could not store\npebble:\n%s", pebble.Log())
	}
}

func TestACMEWithExternalAccountBinding(t *testing.T) {
	// A base64url MAC key, as a CA hands it out.
	const keyID, macKey = "kid-1", "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
	tc := harness.New(t)
	port := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{TLSPort: port, EAB: map[string]string{keyID: macKey}})
	extra := "      external_account_binding:\n        key_id: " + keyID + "\n        hmac_key:\n          backend: fake\n          location: " + acmeEABKeyLocation + "\n"
	srv, path := startACME(t, tc, harness.FakePlugin, acmeConfig(port, pebble, extra), map[string]string{acmeEABKeyLocation: macKey})
	assertACMECertificate(t, tc, srv, pebble, path)
	if strings.Contains(srv.Stderr(), macKey) {
		t.Error("the External Account Binding key appears in the server log")
	}
}

func TestACMEReportsARefusedAccount(t *testing.T) {
	tc := harness.New(t)
	port := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{TLSPort: port, EAB: map[string]string{"kid-1": "c2VjcmV0"}})
	srv, _ := startACME(t, tc, harness.FakePlugin, acmeConfig(port, pebble, ""), nil)
	srv.ListeningAgentURL()
	deadline := time.Now().Add(20 * time.Second)
	for {
		status := srv.TC("status").Stdout
		if strings.Contains(status, "TLS certificate: not loaded (") && strings.Contains(status, "externalAccountRequired") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tc status never reported the refused account:\n%s\nstderr:\n%s", status, srv.Stderr())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestACMEConfigIsValidated(t *testing.T) {
	base := "agent_api:\n  listen: 0.0.0.0:8443\n  tls:\n    certificate:\n      backend: fake\n      location: courier/tls-certificate\n    key:\n      backend: fake\n      location: courier/tls-key\n    acme:\n"
	accountKey := "      account_key:\n        backend: fake\n        location: courier/acme-account-key\n"
	cases := []struct {
		name, acme, wantErr string
	}{
		{"no domains", accountKey, "agent_api.tls.acme.domains"},
		{"wildcard domain", "      domains: ['*.example.com']\n" + accountKey, "wildcard"},
		{"IP address domain", "      domains: [192.0.2.10]\n" + accountKey, "not a DNS name"},
		{"no account key", "      domains: [example.com]\n", "agent_api.tls.acme.account_key: backend is required"},
		{"plain HTTP directory", "      domains: [example.com]\n      directory: http://acme.example.com/dir\n" + accountKey, "https"},
		{"unknown challenge", "      domains: [example.com]\n      challenge: dns-01\n" + accountKey, "challenge"},
		{"http_listen without http-01", "      domains: [example.com]\n      http_listen: 0.0.0.0:80\n" + accountKey, "http_listen"},
		{"EAB without key", "      domains: [example.com]\n      external_account_binding:\n        key_id: kid\n" + accountKey, "external_account_binding.hmac_key"},
		{"account key at the certificate location", "      domains: [example.com]\n      account_key:\n        backend: fake\n        location: courier/tls-certificate\n", "name the same location"},
		{"http_listen on the Agent API port", "      domains: [example.com]\n      challenge: http-01\n      http_listen: \"[::]:8443\"\n" + accountKey, "http_listen"},
		{"missing ca_bundle", "      domains: [example.com]\n      ca_bundle: /nonexistent/ca.pem\n" + accountKey, "ca_bundle"},
		{"Secret Name maps to the account key", "      domains: [example.com]\n" + accountKey + "secrets:\n  leak:\n    backend: fake\n    location: courier/acme-account-key\n", "Courier Key is never delivered to Agents"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig + auditConfig + base + c.acme)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

// parseFirstCertificate parses the first certificate in chainPEM.
func parseFirstCertificate(t *testing.T, chainPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil {
		t.Fatal("no PEM block in the stored certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the stored certificate: %v", err)
	}
	return leaf
}

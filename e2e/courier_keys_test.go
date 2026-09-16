package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// These ACME settings need only pass config validation; refused startup and
// reload must never contact the CA or DNS provider.
const courierKeyACME = `    acme:
      domains: [example.com]
      account_key: {backend: fake, location: courier/acme-account-key}
      external_account_binding:
        key_id: test-account
        hmac_key: {backend: fake, location: courier/acme-eab-key}
      challenge: dns-01
      dns:
        provider: cloudflare
        credentials:
          api_token: {backend: fake, location: courier/dns-token}
`

func TestCourierKeyCollisionsAreRefusedBeforeBackendStartup(t *testing.T) {
	cases := []struct {
		name, configKey, location string
		adminOnly                 bool
	}{
		{"TLS certificate", "agent_api.tls.certificate", tlsCertificateLocation, false},
		{"TLS private key", "agent_api.tls.key", tlsKeyLocation, false},
		{"ACME account", "agent_api.tls.acme.account_key", acmeAccountKeyLocation, false},
		{"ACME EAB", "agent_api.tls.acme.external_account_binding.hmac_key", acmeEABKeyLocation, false},
		{"DNS credential", "agent_api.tls.acme.dns.credentials.api_token", "courier/dns-token", false},
		{"admin certificate", "admin.tls.certificate", adminCertificateLocation, false},
		{"admin private key", "admin.tls.key", adminKeyLocation, false},
		{"admin-only certificate", "admin.tls.certificate", adminCertificateLocation, true},
		{"admin-only private key", "admin.tls.key", adminKeyLocation, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			ca := tc.IssueCertificate(time.Hour, "client-ca")
			caFile := filepath.Join(tc.Dir(), "client-ca.pem")
			if err := os.WriteFile(caFile, []byte(ca.CAPEM), 0o600); err != nil {
				t.Fatal(err)
			}
			config := "data_dir: {{.DataDir}}\n" + fakePluginConfig +
				adminListener("127.0.0.1:8300", adminCertificateLocation, adminKeyLocation, caFile) +
				strings.Replace(auditConfig, harness.AuditSigningKeyLocation, c.location, 1)
			if !c.adminOnly {
				config += tlsAgentAPI("127.0.0.1:8200") + courierKeyACME
			}
			// A missing binary would fail plugin setup if startup got that
			// far. The location collision must be reported first, before any
			// Backend Plugin can run or overwrite a Courier Key.
			config = strings.Replace(config, "{{.Fake.Path}}", filepath.Join(tc.Dir(), "must-not-run"), 1)
			code, stderr := tc.Refused(config)
			want := c.configKey + " and audit.signing_key name the same location"
			if code == 0 || !strings.Contains(stderr, want) {
				t.Fatalf("startup exit %d, stderr %q; want refusal naming %q", code, stderr, want)
			}
		})
	}
}

func TestCourierKeysAllowDistinctFieldsAndSharedTLS(t *testing.T) {
	tc := harness.New(t)
	cert := tc.IssueCertificate(time.Hour, "127.0.0.1")
	const certificate = "secret/data/courier#certificate"
	const key = "secret/data/courier#tls-key"
	const audit = "secret/data/courier#audit-key"
	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	tc.SetBackendSecrets(path, map[string]string{
		"kv/openai": "test-value-1", "kv/github": "test-value-2",
		certificate: cert.CertificatePEM, key: cert.KeyPEM,
		audit: harness.AuditSigningKey,
	})
	caFile := filepath.Join(tc.Dir(), "client-ca.pem")
	if err := os.WriteFile(caFile, []byte(cert.CAPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	config := strings.Replace(harness.BaseConfig, "admin:\n  socket: {{.Socket}}\n",
		adminListener("127.0.0.1:0", certificate, key, caFile), 1)
	config = strings.NewReplacer(
		"{{.Fake.Path}}", path,
		tlsCertificateLocation, certificate,
		tlsKeyLocation, key,
		harness.AuditSigningKeyLocation, audit,
	).Replace(config + tlsAgentAPI("127.0.0.1:0") + auditConfig)
	srv := tc.Start(config)
	url := srv.AgentURL()
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	client := cert.Client()
	t.Cleanup(client.CloseIdleConnections)
	if got, _ := revealWith(t, client, url, token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal with distinct Courier Key fields = %d %q", got.Status, got.Body)
	}
	operator := cert.IssueClient("operator")
	remote := adminClient(cert.Pool, &operator.TLS)
	t.Cleanup(remote.CloseIdleConnections)
	if status, err := adminGet(t, remote, srv.AdminURL(true), srv.Credential); err != nil || status != http.StatusOK {
		t.Fatalf("admin API with the shared TLS pair = %d, %v", status, err)
	}
}

func TestReloadRefusesCourierKeyCollisions(t *testing.T) {
	_, srv, token := startProxy(t, "github-reveal")
	policyChange := strings.Replace(proxyConfig, "delivery: [proxy, reveal]", "delivery: [proxy]", 1)
	tls := strings.Replace(tlsAgentAPI("127.0.0.1:0"), tlsKeyLocation, harness.AuditSigningKeyLocation, 1) + courierKeyACME
	invalid := strings.Replace(policyChange, "agent_api:\n  listen: 127.0.0.1:0\n", tls, 1)
	srv.RewriteConfig(invalid)
	res := srv.TC("reload")
	if res.ExitCode != 1 || !strings.Contains(res.Stderr, "agent_api.tls.key and audit.signing_key name the same location") ||
		!strings.Contains(res.Stderr, "the running config stays in effect") {
		t.Fatalf("reload exit %d, stderr %q; want a location collision and unchanged running config", res.ExitCode, res.Stderr)
	}
	if got := reveal(t, srv, "Bearer "+token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Fatalf("reveal after refused reload = %d %q, want the old Policy and Secret", got.Status, got.Body)
	}
	// Once the collision is removed, the Policy change must take effect.
	srv.RewriteConfig(policyChange)
	reload(t, srv)
	if got := reveal(t, srv, "Bearer "+token, "github"); got.Status != http.StatusForbidden {
		t.Fatalf("reveal after valid reload = %d, want 403", got.Status)
	}
}

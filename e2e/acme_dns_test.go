package e2e

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// The zone and names the DNS-01 tests issue for. Pebble resolves them
// through the test name server, so they need not exist.
const (
	dnsZone   = "example.test"
	dnsDomain = "courier.example.test"
	// dnsCredentialPrefix is where the fake Backend holds the DNS provider's
	// credentials, followed by the field name.
	dnsCredentialPrefix = "courier/dns-"
)

// acmeDNSConfig is the agent_api section for a TLS listener on port with
// ACME against pebble by DNS-01 through provider, for domains (a YAML
// list), resolving through ns.
func acmeDNSConfig(port int, pebble *harness.Pebble, ns *harness.NameServer, provider harness.DNSProvider, domains string) (string, map[string]string) {
	credentials, secrets := provider.CredentialsConfig("fake", dnsCredentialPrefix)
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
      domains: %s
      directory: %s
      ca_bundle: %s
      challenge: dns-01
      dns:
%s%s        resolvers: [%q]
      account_key:
        backend: fake
        location: %s
`, port, tlsCertificateLocation, tlsKeyLocation, domains, pebble.DirectoryURL, pebble.CABundle, provider.Config, credentials, ns.Addr, acmeAccountKeyLocation), secrets
}

func TestACMEObtainsACertificateByDNS01(t *testing.T) {
	for _, name := range []string{"cloudflare", "route53", "azure", "google"} {
		t.Run(name, func(t *testing.T) {
			tc := harness.New(t)
			ns := tc.StartNameServer()
			// One fake per built-in provider, all sharing the records the
			// name server answers from.
			providers := tc.StartDNSProviders(ns.Records(dnsZone, "other.test"))
			provider := providers[slices.IndexFunc(providers, func(p harness.DNSProvider) bool { return p.Name == name })]
			port := harness.FreePort(t)
			pebble := tc.StartPebble(harness.PebbleOptions{Resolver: ns.Addr})
			agentAPI, secrets := acmeDNSConfig(port, pebble, ns, provider, "["+dnsDomain+"]")
			srv, path := startACME(t, tc, harness.FakePlugin, agentAPI, secrets)
			assertACMECertificate(t, tc, srv, pebble, path, dnsDomain, dnsDomain)

			// The record was set at the provider, seen by Pebble through
			// the name server, and removed once the order was done.
			if !strings.Contains(srv.Stderr(), "DNS-01 record set") {
				t.Errorf("server log does not record setting the DNS-01 record:\n%s", srv.Stderr())
			}
			if left := ns.TXT("_acme-challenge." + dnsDomain); len(left) != 0 {
				t.Errorf("DNS-01 records left behind: %v", left)
			}
			// The credentials are Courier Keys: read from the Backend, never
			// on disk or in the log.
			for _, value := range provider.Credentials {
				if tc.FilesContain(value) {
					t.Error("a DNS provider credential is on TrustedCourier's disk")
				}
			}
		})
	}
}

func TestACMEObtainsAWildcardCertificateByDNS01(t *testing.T) {
	tc := harness.New(t)
	ns := tc.StartNameServer()
	provider := tc.StartDNSProviders(ns.Records(dnsZone))[0]
	port := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{Resolver: ns.Addr})
	agentAPI, secrets := acmeDNSConfig(port, pebble, ns, provider, "['*."+dnsZone+"', "+dnsZone+"]")
	srv, path := startACME(t, tc, harness.FakePlugin, agentAPI, secrets)
	// Any name under the zone is served by the wildcard.
	assertACMECertificate(t, tc, srv, pebble, path, "anything."+dnsZone, "*."+dnsZone, dnsZone)
	servedCertificate(t, pebble, agentURLOn(srv.AgentURL()), dnsZone)
	// Both authorizations put their records at the same name, which held
	// both values at once and holds none now.
	if left := ns.TXT("_acme-challenge." + dnsZone); len(left) != 0 {
		t.Errorf("DNS-01 records left behind: %v", left)
	}
	if n := strings.Count(srv.Stderr(), "DNS-01 record set"); n != 2 {
		t.Errorf("the server log records %d DNS-01 records set, want 2:\n%s", n, srv.Stderr())
	}

	// A restart reuses the stored wildcard certificate.
	srv.Stop()
	srv = tc.Start(strings.Replace(harness.BaseConfig, "{{.Fake.Path}}", path, 1) + agentAPI + auditConfig)
	if strings.Contains(srv.Stderr(), "TLS certificate obtained") {
		t.Errorf("the restarted server requested a new certificate:\n%s", srv.Stderr())
	}
	servedCertificate(t, pebble, agentURLOn(srv.AgentURL()), "other."+dnsZone)
}

func TestACMEReportsRefusedDNSCredentials(t *testing.T) {
	tc := harness.New(t)
	ns := tc.StartNameServer()
	provider := tc.StartDNSProviders(ns.Records(dnsZone))[0]
	port := harness.FreePort(t)
	pebble := tc.StartPebble(harness.PebbleOptions{Resolver: ns.Addr})
	agentAPI, secrets := acmeDNSConfig(port, pebble, ns, provider, "["+dnsDomain+"]")
	for k := range secrets {
		secrets[k] = "not-the-" + secrets[k]
	}
	srv, _ := startACME(t, tc, harness.FakePlugin, agentAPI, secrets)
	srv.ListeningAgentURL()
	deadline := time.Now().Add(20 * time.Second)
	for {
		status := srv.TC("status").Stdout
		if strings.Contains(status, "TLS certificate: not loaded (") && strings.Contains(status, provider.Name) && strings.Contains(status, "HTTP 403") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tc status never reported the refused DNS credentials:\n%s\nstderr:\n%s", status, srv.Stderr())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if left := ns.TXT("_acme-challenge." + dnsDomain); len(left) != 0 {
		t.Errorf("DNS-01 records set with refused credentials: %v", left)
	}
}

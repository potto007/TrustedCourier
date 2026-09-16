package harness

import (
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/letsencrypt/challtestsrv"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/dnsprovider/providertest"
)

// NameServer is an in-process name server, Pebble's own DNS test server:
// Pebble resolves DNS-01 records through it, TrustedCourier checks
// propagation against it, and the fake DNS provider APIs mirror their
// records into it.
type NameServer struct {
	// Addr is the server's IP address and port, for PebbleOptions.Resolver
	// and agent_api.tls.acme.dns.resolvers.
	Addr string
	srv  *challtestsrv.ChallSrv
}

// StartNameServer starts a NameServer that stops when the test ends.
func (in *Installation) StartNameServer() *NameServer {
	in.t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		in.t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port))
	_ = pc.Close()
	srv, err := challtestsrv.New(challtestsrv.Config{DNSAddrs: []string{addr}, Log: log.New(io.Discard, "", 0)})
	if err != nil {
		in.t.Fatal(err)
	}
	srv.Run()
	in.t.Cleanup(srv.Shutdown)
	return &NameServer{Addr: addr, srv: srv}
}

// TXT returns the TXT values the name server answers for name.
func (ns *NameServer) TXT(name string) []string {
	return ns.srv.GetDNSTXTRecords(name)
}

// Records returns a fake provider's Records for zones whose every change
// is mirrored into the name server.
func (ns *NameServer) Records(zones ...string) *providertest.Records {
	records := providertest.NewRecords(zones...)
	records.OnChange = func(name string, values []string) {
		ns.srv.DeleteDNSTXTRecord(name)
		for _, v := range values {
			ns.srv.AddDNSTXTRecord(name, v)
		}
	}
	return records
}

// DNSProvider is a fake DNS provider API a test points TrustedCourier at.
type DNSProvider struct {
	// Name is the provider's name in agent_api.tls.acme.dns.provider.
	Name string
	// Config is the YAML under agent_api.tls.acme.dns that reaches the
	// fake: provider, endpoint, ca_bundle, and the provider's settings,
	// each line indented eight spaces, without credentials.
	Config string
	// Credentials are the credential values the fake accepts, by field, to
	// store in a Backend.
	Credentials map[string]string
}

// StartDNSProviders starts a fake of every built-in DNS provider API,
// serving records, each stopping when the test ends.
func (in *Installation) StartDNSProviders(records *providertest.Records) []DNSProvider {
	in.t.Helper()
	var out []DNSProvider

	cf := providertest.NewCloudflare(records, "cf-api-token-1")
	in.t.Cleanup(cf.Close)
	out = append(out, DNSProvider{
		Name:        config.DNSProviderCloudflare,
		Config:      in.dnsConfig(config.DNSProviderCloudflare, cf.Server, cf.URL),
		Credentials: map[string]string{"api_token": "cf-api-token-1"},
	})

	r53 := providertest.NewRoute53(records, "AKIAFAKEROUTE53", []byte("aws-secret-access-key-1"))
	in.t.Cleanup(r53.Close)
	out = append(out, DNSProvider{
		Name:        config.DNSProviderRoute53,
		Config:      in.dnsConfig(config.DNSProviderRoute53, r53.Server, r53.URL),
		Credentials: map[string]string{"access_key_id": "AKIAFAKEROUTE53", "secret_access_key": "aws-secret-access-key-1"},
	})

	az := providertest.NewAzure(records, providertest.AzureOptions{
		TenantID: "tenant-1", ClientID: "client-1", SubscriptionID: "sub-1", ResourceGroup: "rg-1", ClientSecret: "azure-client-secret-1",
	})
	in.t.Cleanup(az.Close)
	out = append(out, DNSProvider{
		Name: config.DNSProviderAzure,
		Config: in.dnsConfig(config.DNSProviderAzure, az.Server, az.URL) +
			"        authority: " + az.URL + "\n        tenant_id: tenant-1\n        client_id: client-1\n        subscription_id: sub-1\n        resource_group: rg-1\n",
		Credentials: map[string]string{"client_secret": "azure-client-secret-1"},
	})

	g := providertest.NewGoogle(records, "project-1")
	in.t.Cleanup(g.Close)
	out = append(out, DNSProvider{
		Name:        config.DNSProviderGoogle,
		Config:      in.dnsConfig(config.DNSProviderGoogle, g.Server, g.URL+"/dns/v1"),
		Credentials: map[string]string{"service_account_key": string(g.ServiceAccountKey())},
	})
	return out
}

// dnsConfig is the config that points provider at the fake at endpoint,
// trusting its certificate.
func (in *Installation) dnsConfig(provider string, srv *httptest.Server, endpoint string) string {
	bundle := filepath.Join(in.dir, provider+"-ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		in.t.Fatal(err)
	}
	return fmt.Sprintf("        provider: %s\n        endpoint: %s\n        ca_bundle: %s\n", provider, endpoint, bundle)
}

// CredentialsConfig is the credentials block for the provider, each field
// a Courier Key in backend at location prefix plus the field name, and the
// Backend contents that hold the values.
func (p DNSProvider) CredentialsConfig(backend, locationPrefix string) (yaml string, secrets map[string]string) {
	var b strings.Builder
	b.WriteString("        credentials:\n")
	secrets = map[string]string{}
	for field, value := range p.Credentials {
		fmt.Fprintf(&b, "          %s:\n            backend: %s\n            location: %s%s\n", field, backend, locationPrefix, field)
		secrets[locationPrefix+field] = value
	}
	return b.String(), secrets
}

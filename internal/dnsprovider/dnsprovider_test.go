package dnsprovider_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/dnsprovider"
	"github.com/potto007/TrustedCourier/internal/dnsprovider/providertest"
)

// fixture is a built-in provider pointed at its fake.
type fixture struct {
	provider string
	cfg      config.DNS
	creds    dnsprovider.Credentials
	// badCreds are credentials the fake refuses.
	badCreds dnsprovider.Credentials
	records  *providertest.Records
	client   *http.Client
}

// fixtures returns one fixture per built-in provider, each serving the
// zones given.
func fixtures(t *testing.T, zones ...string) []fixture {
	t.Helper()
	var out []fixture

	cf := providertest.NewCloudflare(providertest.NewRecords(zones...), "cf-token")
	t.Cleanup(cf.Close)
	out = append(out, fixture{
		provider: config.DNSProviderCloudflare,
		cfg:      config.DNS{Provider: config.DNSProviderCloudflare, Endpoint: cf.URL},
		creds:    dnsprovider.Credentials{"api_token": []byte("cf-token")},
		badCreds: dnsprovider.Credentials{"api_token": []byte("wrong")},
		records:  cf.Records, client: trusting(cf.Server),
	})

	r53 := providertest.NewRoute53(providertest.NewRecords(zones...), "AKIDEXAMPLE", []byte("aws-secret"))
	t.Cleanup(r53.Close)
	out = append(out, fixture{
		provider: config.DNSProviderRoute53,
		cfg:      config.DNS{Provider: config.DNSProviderRoute53, Endpoint: r53.URL},
		creds:    dnsprovider.Credentials{"access_key_id": []byte("AKIDEXAMPLE"), "secret_access_key": []byte("aws-secret")},
		badCreds: dnsprovider.Credentials{"access_key_id": []byte("AKIDEXAMPLE"), "secret_access_key": []byte("wrong-secret-key")},
		records:  r53.Records, client: trusting(r53.Server),
	})

	az := providertest.NewAzure(providertest.NewRecords(zones...), providertest.AzureOptions{
		TenantID: "tenant-1", ClientID: "client-1", SubscriptionID: "sub-1", ResourceGroup: "rg-1", ClientSecret: "az-secret",
	})
	t.Cleanup(az.Close)
	out = append(out, fixture{
		provider: config.DNSProviderAzure,
		cfg: config.DNS{
			Provider: config.DNSProviderAzure, Endpoint: az.URL, Authority: az.URL,
			TenantID: "tenant-1", ClientID: "client-1", SubscriptionID: "sub-1", ResourceGroup: "rg-1",
		},
		creds:    dnsprovider.Credentials{"client_secret": []byte("az-secret")},
		badCreds: dnsprovider.Credentials{"client_secret": []byte("wrong")},
		records:  az.Records, client: trusting(az.Server),
	})

	g := providertest.NewGoogle(providertest.NewRecords(zones...), "project-1")
	t.Cleanup(g.Close)
	other := providertest.NewGoogle(providertest.NewRecords(zones...), "project-1")
	t.Cleanup(other.Close)
	out = append(out, fixture{
		provider: config.DNSProviderGoogle,
		cfg:      config.DNS{Provider: config.DNSProviderGoogle, Endpoint: g.URL + "/dns/v1"},
		creds:    dnsprovider.Credentials{"service_account_key": g.ServiceAccountKey()},
		// Another service account's key, signed by a key the fake does not
		// know, but pointing its token_uri at the fake.
		badCreds: dnsprovider.Credentials{"service_account_key": []byte(strings.Replace(string(other.ServiceAccountKey()), other.URL, g.URL, 1))},
		records:  g.Records, client: trusting(g.Server),
	})
	return out
}

func trusting(srv *httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func newProvider(t *testing.T, f fixture, creds dnsprovider.Credentials) dnsprovider.Provider {
	t.Helper()
	p, err := dnsprovider.New(f.cfg, creds, f.client)
	if err != nil {
		t.Fatalf("%s: %v", f.provider, err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestPresentAddsToTheSetAndCleanupRemovesOnlyTheValue(t *testing.T) {
	const name = "_acme-challenge.tc.sub.example.com"
	for _, f := range fixtures(t, "example.com", "sub.example.com", "other.test") {
		t.Run(f.provider, func(t *testing.T) {
			ctx := context.Background()
			p := newProvider(t, f, f.creds)
			for _, value := range []string{"value-1", "value-1", "value-2"} {
				if err := p.Present(ctx, name, value); err != nil {
					t.Fatalf("Present(%s): %v", value, err)
				}
			}
			got := f.records.TXT(name)
			slices.Sort(got)
			if want := []string{"value-1", "value-2"}; !slices.Equal(got, want) {
				t.Fatalf("after presenting value-1 twice and value-2, TXT %s = %v, want %v", name, got, want)
			}
			if err := p.Cleanup(ctx, name, "value-1"); err != nil {
				t.Fatalf("Cleanup(value-1): %v", err)
			}
			if got := f.records.TXT(name); !slices.Equal(got, []string{"value-2"}) {
				t.Fatalf("after removing value-1, TXT %s = %v, want [value-2]", name, got)
			}
			if err := p.Cleanup(ctx, name, "value-2"); err != nil {
				t.Fatalf("Cleanup(value-2): %v", err)
			}
			if got := f.records.TXT(name); len(got) != 0 {
				t.Fatalf("after removing value-2, TXT %s = %v, want none", name, got)
			}
			if err := p.Cleanup(ctx, name, "value-2"); err != nil {
				t.Fatalf("Cleanup of a value already gone: %v", err)
			}
			if names := f.records.Names(); len(names) != 0 {
				t.Errorf("records left behind at %v", names)
			}
		})
	}
}

func TestPresentUsesTheConfiguredZone(t *testing.T) {
	const name = "_acme-challenge.tc.example.com"
	for _, f := range fixtures(t, "example.com") {
		t.Run(f.provider, func(t *testing.T) {
			ctx := context.Background()
			f.cfg.Zone = "example.com"
			p := newProvider(t, f, f.creds)
			if err := p.Present(ctx, name, "value"); err != nil {
				t.Fatalf("Present: %v", err)
			}
			if got := f.records.TXT(name); !slices.Equal(got, []string{"value"}) {
				t.Fatalf("TXT %s = %v", name, got)
			}
			f.cfg.Zone = "nowhere.example"
			p = newProvider(t, f, f.creds)
			err := p.Present(ctx, "_acme-challenge.tc.nowhere.example", "value")
			if err == nil || !strings.Contains(err.Error(), "nowhere.example") {
				t.Fatalf("Present in a zone the provider does not serve: %v, want an error naming the zone", err)
			}
		})
	}
}

func TestPresentReportsANameNoZoneHolds(t *testing.T) {
	for _, f := range fixtures(t, "example.com") {
		t.Run(f.provider, func(t *testing.T) {
			p := newProvider(t, f, f.creds)
			err := p.Present(context.Background(), "_acme-challenge.tc.example.org", "value")
			if err == nil || !strings.Contains(err.Error(), "example.org") {
				t.Fatalf("Present for a name outside every zone: %v, want an error naming it", err)
			}
		})
	}
}

func TestPresentReportsRefusedCredentials(t *testing.T) {
	for _, f := range fixtures(t, "example.com") {
		t.Run(f.provider, func(t *testing.T) {
			p := newProvider(t, f, f.badCreds)
			err := p.Present(context.Background(), "_acme-challenge.tc.example.com", "value")
			if err == nil || !strings.Contains(err.Error(), f.provider) {
				t.Fatalf("Present with refused credentials: %v, want an error naming %s", err, f.provider)
			}
			for _, c := range f.badCreds {
				if strings.Contains(err.Error(), string(c)) && len(c) < 100 {
					t.Errorf("the error carries the credential: %v", err)
				}
			}
			if len(f.records.Names()) != 0 {
				t.Error("a record was set with refused credentials")
			}
		})
	}
}

// TestNewRefusesShortRoute53Secret: a secret access key too short to HMAC
// with in FIPS 140-only mode is a credential error, not a panic.
func TestNewRefusesShortRoute53Secret(t *testing.T) {
	for _, f := range fixtures(t, "example.com") {
		if f.provider != config.DNSProviderRoute53 {
			continue
		}
		creds := dnsprovider.Credentials{"access_key_id": []byte("AKIDEXAMPLE"), "secret_access_key": []byte("tiny")}
		_, err := dnsprovider.New(f.cfg, creds, f.client)
		if err == nil || !strings.Contains(err.Error(), "secret_access_key") || strings.Contains(err.Error(), "tiny") {
			t.Fatalf("New with a short secret: %v, want an error naming the field and not the value", err)
		}
	}
}

func TestNewRefusesMissingCredentials(t *testing.T) {
	for _, f := range fixtures(t, "example.com") {
		t.Run(f.provider, func(t *testing.T) {
			if _, err := dnsprovider.New(f.cfg, dnsprovider.Credentials{}, f.client); err == nil {
				t.Fatal("New without credentials succeeded")
			}
		})
	}
}

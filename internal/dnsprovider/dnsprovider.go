// Package dnsprovider sets and removes the TXT records DNS-01 validation
// looks for, at a built-in set of DNS providers (ADR-0006). Each provider
// speaks its vendor's HTTP API with the standard library, so no vendor SDK
// is linked and FIPS mode covers every signature.
//
// A Provider lives for one ACME order: it is built from credentials fetched
// from a Backend, and Close wipes what it holds.
package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/potto007/TrustedCourier/internal/config"
)

// Provider sets and removes TXT records. Names are DNS names without a
// trailing dot, such as _acme-challenge.example.com.
type Provider interface {
	// Present ensures a TXT record for name carries value, beside any
	// values already there.
	Present(ctx context.Context, name, value string) error
	// Cleanup removes value from name's TXT records, and the record set
	// once no value is left. A value already gone is no error.
	Cleanup(ctx context.Context, name, value string) error
	// Close wipes the credentials and tokens the Provider holds.
	Close()
}

// Credentials are a provider's credential fields, as config.DNSProviders
// lists them, fetched from a Backend. They are the caller's to wipe.
type Credentials map[string][]byte

// TTL is the TTL of the records set, in seconds: short, since they live for
// one validation.
const TTL = 60

// maxErrorBody is how much of an API error body an error carries.
const maxErrorBody = 300

// New returns the Provider cfg names, authenticating with creds. The
// Provider keeps its own copies of the credentials it needs, so creds may
// be wiped once New returns.
func New(cfg config.DNS, creds Credentials, client *http.Client) (Provider, error) {
	for _, field := range config.DNSProviders[cfg.Provider] {
		if len(creds[field]) == 0 {
			return nil, fmt.Errorf("the %s DNS credential %s is empty", cfg.Provider, field)
		}
	}
	switch cfg.Provider {
	case config.DNSProviderCloudflare:
		return newCloudflare(cfg, creds, client), nil
	case config.DNSProviderRoute53:
		return newRoute53(cfg, creds, client), nil
	case config.DNSProviderAzure:
		return newAzure(cfg, creds, client), nil
	case config.DNSProviderGoogle:
		return newGoogle(cfg, creds, client)
	}
	return nil, fmt.Errorf("%q is not a built-in DNS provider", cfg.Provider)
}

// api is what every provider shares: an HTTP client and error reporting
// that names the provider and the failed request, never a credential.
type api struct {
	provider string
	cfg      config.DNS
	client   *http.Client
}

func newAPI(cfg config.DNS, client *http.Client) api {
	return api{provider: cfg.Provider, cfg: cfg, client: client}
}

// endpoint is the configured API URL, or fallback.
func (a api) endpoint(fallback string) string {
	if a.cfg.Endpoint != "" {
		return a.cfg.Endpoint
	}
	return fallback
}

// do sends req and decodes a 2xx JSON response into out, when out is not
// nil. Any other status is an error carrying the start of the body.
func (a api) do(ctx context.Context, req *http.Request, out any) error {
	body, status, err := a.send(ctx, req)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return a.httpError(req, status, body)
	}
	if out == nil {
		return nil
	}
	if err := decodeJSON(body, out); err != nil {
		return fmt.Errorf("%s: %s %s: %w", a.provider, req.Method, req.URL.Path, err)
	}
	return nil
}

// send sends req and returns the whole response body and its status.
func (a api) send(ctx context.Context, req *http.Request) ([]byte, int, error) {
	resp, err := a.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %s %s: %w", a.provider, req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %s %s: read the response: %w", a.provider, req.Method, req.URL.Path, err)
	}
	return body, resp.StatusCode, nil
}

func (a api) httpError(req *http.Request, status int, body []byte) error {
	return fmt.Errorf("%s: %s %s: HTTP %d: %s", a.provider, req.Method, req.URL.Path, status, errorSnippet(body))
}

// errorSnippet is the start of an API error body, on one line, without
// control characters.
func errorSnippet(body []byte) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, string(body))
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxErrorBody {
		s = s[:maxErrorBody] + "..."
	}
	return s
}

// errNoZone is why a name cannot be served: no zone the provider holds
// contains it.
var errNoZone = errors.New("no zone at the provider holds the name")

// zoneCandidates lists the zones that could hold name, longest first, or
// the configured zone alone.
func zoneCandidates(cfg config.DNS, name string) []string {
	if cfg.Zone != "" {
		return []string{cfg.Zone}
	}
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	var out []string
	// The record's own name is never a zone apex; its parents may be.
	for i := 1; i < len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// findZone finds the zone that holds name with lookup, which reports the
// provider's id for a candidate zone and whether it exists. The first
// candidate found, the longest, wins.
func findZone(ctx context.Context, cfg config.DNS, name string, lookup func(ctx context.Context, zone string) (id string, ok bool, err error)) (id, zone string, err error) {
	for _, candidate := range zoneCandidates(cfg, name) {
		id, ok, err := lookup(ctx, candidate)
		if err != nil {
			return "", "", err
		}
		if ok {
			return id, candidate, nil
		}
	}
	if cfg.Zone != "" {
		return "", "", fmt.Errorf("%s: the zone %s is not at the provider", cfg.Provider, cfg.Zone)
	}
	return "", "", fmt.Errorf("%s: %w: %s", cfg.Provider, errNoZone, name)
}

// zoneCache remembers zones found during one order.
type zoneCache struct {
	ids map[string]string // zone id by record name
	zns map[string]string // zone name by record name
}

func (c *zoneCache) get(name string) (id, zone string, ok bool) {
	if c.ids == nil {
		return "", "", false
	}
	id, ok = c.ids[name]
	return id, c.zns[name], ok
}

func (c *zoneCache) put(name, id, zone string) {
	if c.ids == nil {
		c.ids, c.zns = map[string]string{}, map[string]string{}
	}
	c.ids[name], c.zns[name] = id, zone
}

// withValue returns values with value added once.
func withValue(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(slices.Clone(values), value)
}

// withoutValue returns values without value.
func withoutValue(values []string, value string) []string {
	return slices.DeleteFunc(slices.Clone(values), func(v string) bool { return v == value })
}

// unquote strips one pair of surrounding double quotes, as most APIs carry
// TXT values.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// quote wraps a TXT value in double quotes.
func quote(s string) string { return `"` + s + `"` }

// fqdn is name with a trailing dot.
func fqdn(name string) string { return strings.TrimSuffix(name, ".") + "." }

// decodeJSON decodes body into out.
func decodeJSON(body []byte, out any) error {
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(out); err != nil {
		return fmt.Errorf("the response is not the JSON expected: %w", err)
	}
	return nil
}

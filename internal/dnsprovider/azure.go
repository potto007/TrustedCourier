package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/potto007/TrustedCourier/internal/config"
)

// Azure's public cloud endpoints.
const (
	DefaultAzureEndpoint  = "https://management.azure.com"
	DefaultAzureAuthority = "https://login.microsoftonline.com"
	azureDNSAPIVersion    = "2018-05-01"
)

// azure sets records with a service principal's client secret, the
// principal having DNS Zone Contributor on the zone.
type azure struct {
	api
	base, authority string
	secret          []byte
	token           []byte
	zones           zoneCache
}

func newAzure(cfg config.DNS, creds Credentials, client *http.Client) *azure {
	a := newAPI(cfg, client)
	authority := cfg.Authority
	if authority == "" {
		authority = DefaultAzureAuthority
	}
	return &azure{api: a, base: a.endpoint(DefaultAzureEndpoint), authority: authority, secret: bytes.TrimSpace(slices.Clone(creds["client_secret"]))}
}

func (z *azure) Close() {
	clear(z.secret)
	clear(z.token)
}

// azureRecordSet is a TXT record set as the API carries it.
type azureRecordSet struct {
	Properties struct {
		TTL     int `json:"TTL"`
		Records []struct {
			Value []string `json:"value"`
		} `json:"TXTRecords"`
	} `json:"properties"`
}

func (z *azure) Present(ctx context.Context, name, value string) error {
	zone, relative, err := z.zone(ctx, name)
	if err != nil {
		return err
	}
	current, err := z.values(ctx, zone, relative)
	if err != nil {
		return err
	}
	if slices.Contains(current, value) {
		return nil
	}
	return z.put(ctx, zone, relative, withValue(current, value))
}

func (z *azure) Cleanup(ctx context.Context, name, value string) error {
	zone, relative, err := z.zone(ctx, name)
	if err != nil {
		return err
	}
	current, err := z.values(ctx, zone, relative)
	if err != nil {
		return err
	}
	if !slices.Contains(current, value) {
		return nil
	}
	if remaining := withoutValue(current, value); len(remaining) > 0 {
		return z.put(ctx, zone, relative, remaining)
	}
	req, err := z.request(ctx, http.MethodDelete, z.recordPath(zone, relative), nil)
	if err != nil {
		return err
	}
	return z.do(ctx, req, nil)
}

// zone finds the zone in the resource group that holds name, and name's
// label relative to it.
func (z *azure) zone(ctx context.Context, name string) (zone, relative string, err error) {
	zone, _, ok := z.zones.get(name)
	if !ok {
		var names []string
		if z.cfg.Zone == "" {
			if names, err = z.listZones(ctx); err != nil {
				return "", "", err
			}
		}
		zone, _, err = findZone(ctx, z.cfg, name, func(_ context.Context, candidate string) (string, bool, error) {
			if z.cfg.Zone != "" {
				return candidate, true, nil
			}
			return candidate, slices.Contains(names, candidate), nil
		})
		if err != nil {
			return "", "", err
		}
		z.zones.put(name, zone, zone)
	}
	relative = strings.TrimSuffix(strings.TrimSuffix(name, "."+zone), zone)
	if relative == "" {
		relative = "@"
	}
	return zone, relative, nil
}

// listZones lists the zone names in the resource group.
func (z *azure) listZones(ctx context.Context) ([]string, error) {
	var names []string
	next := z.base + z.groupPath() + "/providers/Microsoft.Network/dnsZones?api-version=" + azureDNSAPIVersion
	for next != "" {
		req, err := z.request(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := z.do(ctx, req, &resp); err != nil {
			return nil, err
		}
		for _, v := range resp.Value {
			names = append(names, strings.ToLower(v.Name))
		}
		next = resp.NextLink
	}
	return names, nil
}

// values lists the TXT values at relative in zone.
func (z *azure) values(ctx context.Context, zone, relative string) ([]string, error) {
	req, err := z.request(ctx, http.MethodGet, z.recordPath(zone, relative), nil)
	if err != nil {
		return nil, err
	}
	body, status, err := z.send(ctx, req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status/100 != 2 {
		return nil, z.httpError(req, status, body)
	}
	var set azureRecordSet
	if err := decodeJSON(body, &set); err != nil {
		return nil, fmt.Errorf("%s: %s %s: %w", z.provider, req.Method, req.URL.Path, err)
	}
	var values []string
	for _, r := range set.Properties.Records {
		values = append(values, strings.Join(r.Value, ""))
	}
	return values, nil
}

// put replaces the TXT set at relative in zone with values.
func (z *azure) put(ctx context.Context, zone, relative string, values []string) error {
	records := make([]map[string][]string, len(values))
	for i, v := range values {
		records[i] = map[string][]string{"value": {v}}
	}
	body, err := json.Marshal(map[string]any{"properties": map[string]any{"TTL": TTL, "TXTRecords": records}})
	if err != nil {
		return err
	}
	req, err := z.request(ctx, http.MethodPut, z.recordPath(zone, relative), body)
	if err != nil {
		return err
	}
	return z.do(ctx, req, nil)
}

func (z *azure) groupPath() string {
	return "/subscriptions/" + url.PathEscape(z.cfg.SubscriptionID) + "/resourceGroups/" + url.PathEscape(z.cfg.ResourceGroup)
}

func (z *azure) recordPath(zone, relative string) string {
	return z.base + z.groupPath() + "/providers/Microsoft.Network/dnsZones/" + url.PathEscape(zone) + "/TXT/" + url.PathEscape(relative) + "?api-version=" + azureDNSAPIVersion
}

// request builds a request to u with a bearer token, fetching the token on
// first use.
func (z *azure) request(ctx context.Context, method, u string, body []byte) (*http.Request, error) {
	if z.token == nil {
		if err := z.authenticate(ctx); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(z.token))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// authenticate gets an access token by the client credentials grant.
func (z *azure) authenticate(ctx context.Context) error {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {z.cfg.ClientID},
		"client_secret": {string(z.secret)},
		"scope":         {z.base + "/.default"},
	}
	req, err := http.NewRequest(http.MethodPost, z.authority+"/"+url.PathEscape(z.cfg.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := z.do(ctx, req, &resp); err != nil {
		return err
	}
	if resp.AccessToken == "" {
		return fmt.Errorf("%s: the token endpoint returned no access token", z.provider)
	}
	z.token = []byte(resp.AccessToken)
	return nil
}

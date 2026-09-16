package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"

	"github.com/potto007/TrustedCourier/internal/config"
)

// DefaultCloudflareEndpoint is the Cloudflare v4 API.
const DefaultCloudflareEndpoint = "https://api.cloudflare.com/client/v4"

// cloudflare sets records with an API token that has Zone:Read and
// DNS:Edit on the zone.
type cloudflare struct {
	api
	base  string
	token []byte
	zones zoneCache
}

func newCloudflare(cfg config.DNS, creds Credentials, client *http.Client) *cloudflare {
	a := newAPI(cfg, client)
	return &cloudflare{api: a, base: a.endpoint(DefaultCloudflareEndpoint), token: bytes.TrimSpace(slices.Clone(creds["api_token"]))}
}

func (c *cloudflare) Close() { clear(c.token) }

type cloudflareRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (c *cloudflare) Present(ctx context.Context, name, value string) error {
	zoneID, err := c.zone(ctx, name)
	if err != nil {
		return err
	}
	records, err := c.records(ctx, zoneID, name)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(records, func(r cloudflareRecord) bool { return unquote(r.Content) == value }) {
		return nil
	}
	body, err := json.Marshal(map[string]any{"type": "TXT", "name": name, "content": value, "ttl": TTL, "comment": "TrustedCourier ACME DNS-01"})
	if err != nil {
		return err
	}
	req, err := c.request(http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, body)
	if err != nil {
		return err
	}
	return c.do(ctx, req, nil)
}

func (c *cloudflare) Cleanup(ctx context.Context, name, value string) error {
	zoneID, err := c.zone(ctx, name)
	if err != nil {
		return err
	}
	records, err := c.records(ctx, zoneID, name)
	if err != nil {
		return err
	}
	for _, r := range records {
		if unquote(r.Content) != value {
			continue
		}
		req, err := c.request(http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(r.ID), nil, nil)
		if err != nil {
			return err
		}
		if err := c.do(ctx, req, nil); err != nil {
			return err
		}
	}
	return nil
}

// zone finds the id of the zone that holds name.
func (c *cloudflare) zone(ctx context.Context, name string) (string, error) {
	id, _, err := c.zones.find(ctx, c.cfg, name, func(ctx context.Context, zone string) (string, bool, error) {
		req, err := c.request(http.MethodGet, "/zones", url.Values{"name": {zone}, "per_page": {"1"}}, nil)
		if err != nil {
			return "", false, err
		}
		var resp struct {
			Result []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := c.do(ctx, req, &resp); err != nil {
			return "", false, err
		}
		for _, z := range resp.Result {
			if z.Name == zone {
				return z.ID, true, nil
			}
		}
		return "", false, nil
	})
	return id, err
}

// records lists the TXT records at name in the zone.
func (c *cloudflare) records(ctx context.Context, zoneID, name string) ([]cloudflareRecord, error) {
	req, err := c.request(http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records", url.Values{"type": {"TXT"}, "name": {name}, "per_page": {"100"}}, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result []cloudflareRecord `json:"result"`
	}
	if err := c.do(ctx, req, &resp); err != nil {
		return nil, err
	}
	return resp.Result, nil
}

func (c *cloudflare) request(method, path string, query url.Values, body []byte) (*http.Request, error) {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

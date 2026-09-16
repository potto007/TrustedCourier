package dnsprovider

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/dnsprovider/sigv4"
)

// DefaultRoute53Endpoint is the Route 53 API, which is global and signed
// for us-east-1.
const DefaultRoute53Endpoint = "https://route53.amazonaws.com"

// Route 53's API version and signing scope.
const (
	route53Version = "/2013-04-01"
	route53Region  = "us-east-1"
	route53Service = "route53"
)

// route53 sets records with an IAM access key allowed
// route53:ListHostedZonesByName, route53:ListResourceRecordSets, and
// route53:ChangeResourceRecordSets on the zone.
type route53 struct {
	api
	base        string
	accessKeyID string
	secret      []byte
	zones       zoneCache
}

// minSecretAccessKeyBytes is the shortest secret access key SigV4 can sign
// with in FIPS 140-only mode, where an HMAC key under 112 bits panics: the
// first key is "AWS4" plus the secret. AWS keys are 40 characters.
const minSecretAccessKeyBytes = 10

func newRoute53(cfg config.DNS, creds Credentials, client *http.Client) (*route53, error) {
	secret := bytes.TrimSpace(slices.Clone(creds["secret_access_key"]))
	if len(secret) < minSecretAccessKeyBytes {
		clear(secret)
		return nil, fmt.Errorf("the %s DNS credential secret_access_key is shorter than %d bytes; it is not an AWS secret access key",
			cfg.Provider, minSecretAccessKeyBytes)
	}
	a := newAPI(cfg, client)
	return &route53{
		api:         a,
		base:        a.endpoint(DefaultRoute53Endpoint),
		accessKeyID: strings.TrimSpace(string(creds["access_key_id"])),
		secret:      secret,
	}, nil
}

func (r *route53) Close() { clear(r.secret) }

// route53RecordSet is a resource record set as the API carries it.
type route53RecordSet struct {
	Name   string   `xml:"Name"`
	Type   string   `xml:"Type"`
	TTL    int      `xml:"TTL"`
	Values []string `xml:"ResourceRecords>ResourceRecord>Value"`
}

func (r *route53) Present(ctx context.Context, name, value string) error {
	zoneID, err := r.zone(ctx, name)
	if err != nil {
		return err
	}
	current, _, err := r.values(ctx, zoneID, name)
	if err != nil {
		return err
	}
	if slices.Contains(current, value) {
		return nil
	}
	return r.change(ctx, zoneID, "UPSERT", name, TTL, withValue(current, value))
}

func (r *route53) Cleanup(ctx context.Context, name, value string) error {
	zoneID, err := r.zone(ctx, name)
	if err != nil {
		return err
	}
	current, ttl, err := r.values(ctx, zoneID, name)
	if err != nil {
		return err
	}
	if !slices.Contains(current, value) {
		return nil
	}
	if remaining := withoutValue(current, value); len(remaining) > 0 {
		return r.change(ctx, zoneID, "UPSERT", name, ttl, remaining)
	}
	// A DELETE must name the set's current values and TTL exactly.
	return r.change(ctx, zoneID, "DELETE", name, ttl, current)
}

// zone finds the hosted zone id of the zone that holds name.
func (r *route53) zone(ctx context.Context, name string) (string, error) {
	id, _, err := r.zones.find(ctx, r.cfg, name, func(ctx context.Context, zone string) (string, bool, error) {
		req, err := r.request(http.MethodGet, "/hostedzonesbyname", url.Values{"dnsname": {fqdn(zone)}, "maxitems": {"10"}}, nil)
		if err != nil {
			return "", false, err
		}
		var resp struct {
			Zones []struct {
				ID      string `xml:"Id"`
				Name    string `xml:"Name"`
				Private bool   `xml:"Config>PrivateZone"`
			} `xml:"HostedZones>HostedZone"`
		}
		if err := r.do(ctx, req, &resp); err != nil {
			return "", false, err
		}
		// Listing starts at the first zone whose name is at or after the
		// one asked for, so only an exact match counts; a public zone is
		// preferred, since the CA resolves through public DNS.
		var found string
		for _, z := range resp.Zones {
			if z.Name != fqdn(zone) {
				continue
			}
			if !z.Private {
				return strings.TrimPrefix(z.ID, "/hostedzone/"), true, nil
			}
			if found == "" {
				found = strings.TrimPrefix(z.ID, "/hostedzone/")
			}
		}
		return found, found != "", nil
	})
	return id, err
}

// values lists the TXT values at name in the zone, unquoted, and the set's
// TTL.
func (r *route53) values(ctx context.Context, zoneID, name string) (values []string, ttl int, err error) {
	req, err := r.request(http.MethodGet, "/hostedzone/"+url.PathEscape(zoneID)+"/rrset", url.Values{"name": {fqdn(name)}, "type": {"TXT"}, "maxitems": {"1"}}, nil)
	if err != nil {
		return nil, 0, err
	}
	var resp struct {
		Sets []route53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	}
	if err := r.do(ctx, req, &resp); err != nil {
		return nil, 0, err
	}
	for _, s := range resp.Sets {
		if strings.EqualFold(s.Name, fqdn(name)) && s.Type == "TXT" {
			ttl = s.TTL
			for _, v := range s.Values {
				values = append(values, unquote(v))
			}
		}
	}
	return values, ttl, nil
}

// change submits one change to name's TXT set with values and ttl.
func (r *route53) change(ctx context.Context, zoneID, action, name string, ttl int, values []string) error {
	set := route53RecordSet{Name: fqdn(name), Type: "TXT", TTL: ttl}
	for _, v := range values {
		set.Values = append(set.Values, quote(v))
	}
	type change struct {
		Action string           `xml:"Action"`
		Set    route53RecordSet `xml:"ResourceRecordSet"`
	}
	body, err := xml.Marshal(struct {
		XMLName xml.Name `xml:"ChangeResourceRecordSetsRequest"`
		XMLNS   string   `xml:"xmlns,attr"`
		Comment string   `xml:"ChangeBatch>Comment"`
		Changes []change `xml:"ChangeBatch>Changes>Change"`
	}{
		XMLNS:   "https://route53.amazonaws.com/doc/2013-04-01/",
		Comment: "TrustedCourier ACME DNS-01",
		Changes: []change{{Action: action, Set: set}},
	})
	if err != nil {
		return err
	}
	req, err := r.request(http.MethodPost, "/hostedzone/"+url.PathEscape(zoneID)+"/rrset", nil, body)
	if err != nil {
		return err
	}
	return r.do(ctx, req, nil)
}

// do is api.do for XML: it sends req and decodes a 2xx response into out.
func (r *route53) do(ctx context.Context, req *http.Request, out any) error {
	body, status, err := r.send(ctx, req)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return r.httpError(req, status, body)
	}
	if out == nil {
		return nil
	}
	if err := xml.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s: %s %s: the response is not the XML expected: %w", r.provider, req.Method, req.URL.Path, err)
	}
	return nil
}

func (r *route53) request(method, path string, query url.Values, body []byte) (*http.Request, error) {
	u := r.base + route53Version + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/xml")
	}
	sigv4.Sign(req, body, r.accessKeyID, r.secret, route53Region, route53Service, time.Now())
	return req, nil
}

package dnsprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/pemkey"
)

// Google Cloud DNS's API and the OAuth scope that edits records.
const (
	DefaultGoogleEndpoint = "https://dns.googleapis.com/dns/v1"
	googleDNSScope        = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
)

// google sets records with a service account key whose account has DNS
// Administrator on the project.
type google struct {
	api
	base     string
	project  string
	email    string
	tokenURI string
	key      *rsa.PrivateKey
	token    []byte
	zones    zoneCache
}

func newGoogle(cfg config.DNS, creds Credentials, client *http.Client) (*google, error) {
	var account struct {
		Type        string `json:"type"`
		ProjectID   string `json:"project_id"`
		PrivateKey  string `json:"private_key"`
		ClientEmail string `json:"client_email"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(creds["service_account_key"], &account); err != nil || account.Type != "service_account" {
		return nil, errors.New("google: the service account key is not a service account key file")
	}
	if account.ClientEmail == "" || account.PrivateKey == "" {
		return nil, errors.New("google: the service account key names no client_email or private_key")
	}
	keyPEM := []byte(account.PrivateKey)
	defer clear(keyPEM)
	signer, err := pemkey.ParseSigner(keyPEM, "the service account key's private_key")
	if err != nil {
		return nil, fmt.Errorf("google: %w", err)
	}
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("google: the service account key's private_key is not an RSA key")
	}
	project := cfg.Project
	if project == "" {
		project = account.ProjectID
	}
	if project == "" {
		return nil, errors.New("google: the service account key names no project_id; set agent_api.tls.acme.dns.project")
	}
	tokenURI := account.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}
	a := newAPI(cfg, client)
	return &google{api: a, base: a.endpoint(DefaultGoogleEndpoint), project: project, email: account.ClientEmail, tokenURI: tokenURI, key: key}, nil
}

func (g *google) Close() {
	clear(g.token)
	// The RSA key's big integers cannot be wiped; drop the reference.
	g.key = nil
}

// googleRRSet is a resource record set as the API carries it.
type googleRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	RRDatas []string `json:"rrdatas"`
}

func (g *google) Present(ctx context.Context, name, value string) error {
	zone, err := g.zone(ctx, name)
	if err != nil {
		return err
	}
	current, err := g.values(ctx, zone, name)
	if err != nil {
		return err
	}
	if slices.Contains(current, value) {
		return nil
	}
	return g.change(ctx, zone, name, current, withValue(current, value))
}

func (g *google) Cleanup(ctx context.Context, name, value string) error {
	zone, err := g.zone(ctx, name)
	if err != nil {
		return err
	}
	current, err := g.values(ctx, zone, name)
	if err != nil {
		return err
	}
	if !slices.Contains(current, value) {
		return nil
	}
	return g.change(ctx, zone, name, current, withoutValue(current, value))
}

// zone finds the managed zone name of the zone that holds name.
func (g *google) zone(ctx context.Context, name string) (string, error) {
	if id, _, ok := g.zones.get(name); ok {
		return id, nil
	}
	id, zone, err := findZone(ctx, g.cfg, name, func(ctx context.Context, zone string) (string, bool, error) {
		req, err := g.request(ctx, http.MethodGet, "/projects/"+url.PathEscape(g.project)+"/managedZones", url.Values{"dnsName": {fqdn(zone)}}, nil)
		if err != nil {
			return "", false, err
		}
		var resp struct {
			Zones []struct {
				Name       string `json:"name"`
				DNSName    string `json:"dnsName"`
				Visibility string `json:"visibility"`
			} `json:"managedZones"`
		}
		if err := g.do(ctx, req, &resp); err != nil {
			return "", false, err
		}
		// A public zone is preferred, since the CA resolves through public
		// DNS.
		var found string
		for _, z := range resp.Zones {
			if !strings.EqualFold(z.DNSName, fqdn(zone)) {
				continue
			}
			if z.Visibility != "private" {
				return z.Name, true, nil
			}
			if found == "" {
				found = z.Name
			}
		}
		return found, found != "", nil
	})
	if err != nil {
		return "", err
	}
	g.zones.put(name, id, zone)
	return id, nil
}

// values lists the TXT values at name in the managed zone, unquoted.
func (g *google) values(ctx context.Context, zone, name string) ([]string, error) {
	req, err := g.request(ctx, http.MethodGet, "/projects/"+url.PathEscape(g.project)+"/managedZones/"+url.PathEscape(zone)+"/rrsets", url.Values{"name": {fqdn(name)}, "type": {"TXT"}}, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Sets []googleRRSet `json:"rrsets"`
	}
	if err := g.do(ctx, req, &resp); err != nil {
		return nil, err
	}
	var values []string
	for _, s := range resp.Sets {
		if strings.EqualFold(s.Name, fqdn(name)) && s.Type == "TXT" {
			for _, v := range s.RRDatas {
				values = append(values, unquote(v))
			}
		}
	}
	return values, nil
}

// change replaces the TXT set at name, currently holding current, with
// values, in one atomic change.
func (g *google) change(ctx context.Context, zone, name string, current, values []string) error {
	var body struct {
		Additions []googleRRSet `json:"additions"`
		Deletions []googleRRSet `json:"deletions"`
	}
	if len(current) > 0 {
		body.Deletions = []googleRRSet{rrset(name, current)}
	}
	if len(values) > 0 {
		body.Additions = []googleRRSet{rrset(name, values)}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := g.request(ctx, http.MethodPost, "/projects/"+url.PathEscape(g.project)+"/managedZones/"+url.PathEscape(zone)+"/changes", nil, data)
	if err != nil {
		return err
	}
	return g.do(ctx, req, nil)
}

func rrset(name string, values []string) googleRRSet {
	set := googleRRSet{Name: fqdn(name), Type: "TXT", TTL: TTL, RRDatas: []string{}}
	for _, v := range values {
		set.RRDatas = append(set.RRDatas, quote(v))
	}
	return set
}

// request builds a request with a bearer token, fetching the token on
// first use.
func (g *google) request(ctx context.Context, method, path string, query url.Values, body []byte) (*http.Request, error) {
	if g.token == nil {
		if err := g.authenticate(ctx); err != nil {
			return nil, err
		}
	}
	u := g.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(g.token))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// authenticate gets an access token with a JWT the service account key
// signs, as Google's service account flow specifies.
func (g *google) authenticate(ctx context.Context) error {
	if g.key == nil {
		return errors.New("google: the provider is closed")
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   g.email,
		"scope": googleDNSScope,
		"aud":   g.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, digest[:])
	if err != nil {
		return fmt.Errorf("google: sign the token request: %w", err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)},
	}
	req, err := http.NewRequest(http.MethodPost, g.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := g.do(ctx, req, &resp); err != nil {
		return err
	}
	if resp.AccessToken == "" {
		return errors.New("google: the token endpoint returned no access token")
	}
	g.token = []byte(resp.AccessToken)
	return nil
}

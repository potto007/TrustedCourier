// Package openbao is the OpenBao Backend Plugin's Backend: it serves Secrets
// from OpenBao's KV secrets engine, versions 1 and 2, over OpenBao's HTTP
// API, and stores Courier Keys there (ADR-0008, ADR-0028).
//
// A location is "<path>#<field>": the API path of a KV record, as the
// OpenBao CLI's `bao kv get -mount=secret openai` spells it for the API,
// "secret/data/openai" on a KV v2 mount or "secret/openai" on a KV v1 mount,
// and the field in that record. The field's value must be a non-empty
// string; OpenBao KV holds JSON, and a number, object, or empty string at a
// location is not a Secret.
//
// Only the standard library speaks HTTP and TLS, so the plugin follows the
// core's FIPS 140-3 mode with nothing outside Go's cryptographic module.
package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/potto007/TrustedCourier/sdk/plugin"
)

// Config is how the plugin reaches OpenBao.
type Config struct {
	// Address is OpenBao's URL, such as https://openbao.internal:8200.
	Address string
	// Token authenticates every call.
	Token string
	// Namespace, when set, is the OpenBao namespace every path is under.
	Namespace string
	// CACertFile, when set, is a PEM file of CA certificates that verify
	// OpenBao's TLS certificate in place of the system roots.
	CACertFile string
}

// Backend serves Secrets from one OpenBao.
type Backend struct {
	base      *url.URL
	token     string
	namespace string
	http      *http.Client
}

const (
	// requestTimeout bounds one call to OpenBao.
	requestTimeout = 30 * time.Second
	// maxResponseBytes bounds a response body; a KV record is far smaller.
	maxResponseBytes = 4 << 20
	// maxLocations is the most a List returns, the plugin contract's limit.
	maxLocations = 10000
	// casRetries is how many times a Courier Key write retries after
	// another writer changed the record.
	casRetries = 3
)

// New returns a Backend for cfg. It reads the CA file but does not call
// OpenBao.
func New(cfg Config) (*Backend, error) {
	base, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("BAO_ADDR: %w", err)
	}
	if (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("BAO_ADDR %q: want http://host:port or https://host:port", cfg.Address)
	}
	if base.Path != "" && base.Path != "/" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return nil, fmt.Errorf("BAO_ADDR %q: want only a scheme, host, and port", cfg.Address)
	}
	base.Path, base.RawQuery, base.Fragment = "", "", ""
	if cfg.Token == "" {
		return nil, errors.New("BAO_TOKEN or BAO_TOKEN_FILE is required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("BAO_CACERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("BAO_CACERT %s: no CA certificates found", cfg.CACertFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.Proxy = nil
	return &Backend{
		base:      base,
		token:     cfg.Token,
		namespace: cfg.Namespace,
		http: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// The token must never follow a redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Capabilities reports that Courier Keys can be stored.
func (b *Backend) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{CourierKeyWrite: true}
}

// Get returns the field of the KV record at location.
func (b *Backend) Get(ctx context.Context, location string) ([]byte, error) {
	loc, err := parseLocation(location)
	if err != nil {
		return nil, err
	}
	fields, _, err := b.readRecord(ctx, loc.path)
	if err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, plugin.ErrNotFound
	}
	raw, ok := fields[loc.field]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no field %q", plugin.ErrNotFound, loc.path, loc.field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("%s field %q is not a string; a Secret must be a string", loc.path, loc.field)
	}
	if value == "" {
		return nil, fmt.Errorf("%s field %q is empty", loc.path, loc.field)
	}
	return []byte(value), nil
}

// List returns every location starting with prefix, across the KV mounts
// the token can see. Each record under the prefix is read to name its
// fields, so a long prefix is much cheaper than a short one.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	mounts, err := b.kvMounts(ctx)
	if err != nil {
		return nil, err
	}
	pathPrefix, fieldPrefix, hasField := strings.Cut(prefix, "#")
	var locations []string
	emit := func(path string, fields map[string]json.RawMessage) error {
		for _, field := range slices.Sorted(maps.Keys(fields)) {
			if !strings.HasPrefix(field, fieldPrefix) {
				continue
			}
			if len(locations) == maxLocations {
				return fmt.Errorf("more than %d locations start with %q; list a longer prefix", maxLocations, prefix)
			}
			locations = append(locations, path+"#"+field)
		}
		return nil
	}
	for _, m := range mounts {
		if hasField {
			// A whole record path: read that one record.
			if !strings.HasPrefix(pathPrefix, m.dataRoot()) {
				continue
			}
			fields, _, err := b.readRecord(ctx, pathPrefix)
			if err != nil {
				return nil, err
			}
			if fields != nil {
				if err := emit(pathPrefix, fields); err != nil {
					return nil, err
				}
			}
			continue
		}
		if !overlaps(m.dataRoot(), pathPrefix) {
			continue
		}
		if err := b.walk(ctx, m, "", pathPrefix, emit); err != nil {
			return nil, err
		}
	}
	slices.Sort(locations)
	return locations, nil
}

// walk lists the records under dir in m, in order, reading each whose path
// starts with pathPrefix and descending into each folder that could hold
// one.
func (b *Backend) walk(ctx context.Context, m mount, dir, pathPrefix string, emit func(string, map[string]json.RawMessage) error) error {
	keys, err := b.listKeys(ctx, m.listPath(dir))
	if err != nil {
		return err
	}
	for _, key := range keys {
		full := m.dataRoot() + dir + key
		if strings.HasSuffix(key, "/") {
			if overlaps(full, pathPrefix) {
				if err := b.walk(ctx, m, dir+key, pathPrefix, emit); err != nil {
					return err
				}
			}
			continue
		}
		if !strings.HasPrefix(full, pathPrefix) {
			continue
		}
		fields, _, err := b.readRecord(ctx, full)
		if err != nil {
			return err
		}
		if fields == nil {
			continue // deleted since it was listed
		}
		if err := emit(full, fields); err != nil {
			return err
		}
	}
	return nil
}

// overlaps reports whether a location under folder could start with prefix.
func overlaps(folder, prefix string) bool {
	return strings.HasPrefix(folder, prefix) || strings.HasPrefix(prefix, folder)
}

// Health checks that OpenBao is initialized and unsealed and the token is
// valid.
func (b *Backend) Health(ctx context.Context) (string, error) {
	var health struct {
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
		Version     string `json:"version"`
	}
	status, body, err := b.call(ctx, http.MethodGet, "sys/health?standbyok=true&perfstandbyok=true&uninitcode=501&sealedcode=503", nil)
	if err != nil {
		return "", err
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &health); err != nil {
			return "", fmt.Errorf("sys/health: %w", err)
		}
	}
	detail := "OpenBao " + health.Version
	switch {
	case status == http.StatusNotImplemented || !health.Initialized && status != http.StatusOK:
		return detail, errors.New("OpenBao is not initialized")
	case status == http.StatusServiceUnavailable || health.Sealed:
		return detail, errors.New("OpenBao is sealed")
	case status != http.StatusOK:
		return detail, fmt.Errorf("sys/health reports status %d", status)
	}
	var lookup struct {
		Data struct {
			TTL       int64  `json:"ttl"`
			Renewable bool   `json:"renewable"`
			Display   string `json:"display_name"`
		} `json:"data"`
	}
	status, body, err = b.call(ctx, http.MethodGet, "auth/token/lookup-self", nil)
	if err != nil {
		return detail, err
	}
	if status == http.StatusForbidden {
		return detail, errors.New("the token is invalid, expired, or revoked")
	}
	if status != http.StatusOK {
		return detail, fmt.Errorf("auth/token/lookup-self: %s", apiError(status, body))
	}
	if err := json.Unmarshal(body, &lookup); err != nil {
		return detail, fmt.Errorf("auth/token/lookup-self: %w", err)
	}
	if lookup.Data.TTL > 0 {
		detail += ", token expires in " + (time.Duration(lookup.Data.TTL) * time.Second).String()
		if lookup.Data.TTL < 3600 {
			return detail, errors.New("the token expires within the hour; the plugin does not renew it")
		}
	}
	return detail, nil
}

// WriteCourierKey stores value in the field of the KV record at location,
// keeping the record's other fields. On a KV v2 mount the write is
// check-and-set against the version read, so a concurrent write to another
// field is never lost.
func (b *Backend) WriteCourierKey(ctx context.Context, location string, value []byte) error {
	loc, err := parseLocation(location)
	if err != nil {
		return err
	}
	if !utf8.Valid(value) {
		return errors.New("a Courier Key in OpenBao must be text, such as PEM; the value is not valid UTF-8")
	}
	encoded, err := json.Marshal(string(value))
	if err != nil {
		return err
	}
	m, err := b.mountFor(ctx, loc.path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(loc.path, m.dataRoot()) {
		return fmt.Errorf("%s is on KV v2 mount %s, so its location starts with %s", loc.path, m.path, m.dataRoot())
	}
	for attempt := 0; ; attempt++ {
		fields, version, err := b.readRecord(ctx, loc.path)
		if err != nil {
			return err
		}
		if fields == nil {
			fields = map[string]json.RawMessage{}
		}
		fields[loc.field] = encoded
		var body any = fields
		if m.v2 {
			body = map[string]any{"data": fields, "options": map[string]any{"cas": version}}
		}
		status, resp, err := b.call(ctx, http.MethodPost, loc.path, body)
		if err != nil {
			return err
		}
		if status == http.StatusOK || status == http.StatusNoContent {
			return nil
		}
		if m.v2 && status == http.StatusBadRequest && strings.Contains(string(resp), "check-and-set") && attempt < casRetries {
			continue
		}
		return fmt.Errorf("write %s: %s", loc.path, apiError(status, resp))
	}
}

// location is a parsed "<path>#<field>".
type location struct {
	path, field string
}

func parseLocation(s string) (location, error) {
	path, field, ok := strings.Cut(s, "#")
	if !ok || path == "" || field == "" {
		return location{}, fmt.Errorf("location %q: want <path>#<field>, such as secret/data/openai#key", s)
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") || strings.Contains(path, "?") {
		return location{}, fmt.Errorf("location %q: the path must be an API path without a leading or trailing slash", s)
	}
	return location{path: path, field: field}, nil
}

// readRecord reads the KV record at path. It returns nil fields when there
// is no record there, and on a KV v2 mount the record's version.
func (b *Backend) readRecord(ctx context.Context, path string) (map[string]json.RawMessage, int64, error) {
	status, body, err := b.call(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, err
	}
	switch status {
	case http.StatusNotFound:
		return nil, 0, nil
	case http.StatusOK:
	default:
		return nil, 0, fmt.Errorf("read %s: %s", path, apiError(status, body))
	}
	var resp struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	// A KV v2 record wraps its fields in data with metadata beside them.
	if inner, ok := resp.Data["data"]; ok {
		if meta, ok := resp.Data["metadata"]; ok {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(inner, &fields); err != nil {
				return nil, 0, fmt.Errorf("read %s: data is not an object", path)
			}
			var metadata struct {
				Version int64 `json:"version"`
			}
			if err := json.Unmarshal(meta, &metadata); err != nil {
				return nil, 0, fmt.Errorf("read %s: metadata: %w", path, err)
			}
			if fields == nil {
				return nil, metadata.Version, nil // deleted or destroyed version
			}
			return fields, metadata.Version, nil
		}
	}
	if resp.Data == nil {
		return nil, 0, nil
	}
	return resp.Data, 0, nil
}

// listKeys lists the keys under a folder, folders with a trailing slash.
func (b *Backend) listKeys(ctx context.Context, path string) ([]string, error) {
	status, body, err := b.call(ctx, "LIST", path, nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusNotFound:
		return nil, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("list %s: %s", path, apiError(status, body))
	}
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("list %s: %w", path, err)
	}
	slices.Sort(resp.Data.Keys)
	return resp.Data.Keys, nil
}

// mount is a KV secrets engine mount.
type mount struct {
	// path is the mount path with its trailing slash, such as "secret/".
	path string
	v2   bool
}

// dataRoot is the API path prefix of the mount's records.
func (m mount) dataRoot() string {
	if m.v2 {
		return m.path + "data/"
	}
	return m.path
}

// listPath is the API path that lists the folder dir of the mount.
func (m mount) listPath(dir string) string {
	if m.v2 {
		return m.path + "metadata/" + dir
	}
	return m.path + dir
}

// mountInfo is what OpenBao reports about a mount.
type mountInfo struct {
	Type    string `json:"type"`
	Options struct {
		Version string `json:"version"`
	} `json:"options"`
}

func (mi mountInfo) isKV() bool { return mi.Type == "kv" || mi.Type == "generic" }

// kvMounts lists the KV mounts the token can see, by path.
func (b *Backend) kvMounts(ctx context.Context) ([]mount, error) {
	status, body, err := b.call(ctx, http.MethodGet, "sys/internal/ui/mounts", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("sys/internal/ui/mounts: %s", apiError(status, body))
	}
	var resp struct {
		Data struct {
			Secret map[string]mountInfo `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("sys/internal/ui/mounts: %w", err)
	}
	var mounts []mount
	for _, path := range slices.Sorted(maps.Keys(resp.Data.Secret)) {
		if mi := resp.Data.Secret[path]; mi.isKV() {
			mounts = append(mounts, mount{path: path, v2: mi.Options.Version == "2"})
		}
	}
	return mounts, nil
}

// mountFor returns the KV mount holding path.
func (b *Backend) mountFor(ctx context.Context, path string) (mount, error) {
	status, body, err := b.call(ctx, http.MethodGet, "sys/internal/ui/mounts/"+path, nil)
	if err != nil {
		return mount{}, err
	}
	if status != http.StatusOK {
		return mount{}, fmt.Errorf("no secrets engine the token can use is mounted at %s: %s", path, apiError(status, body))
	}
	var resp struct {
		Data struct {
			mountInfo
			Path string `json:"path"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return mount{}, fmt.Errorf("sys/internal/ui/mounts/%s: %w", path, err)
	}
	if !resp.Data.isKV() {
		return mount{}, fmt.Errorf("%s is on a %q secrets engine, not KV", path, resp.Data.Type)
	}
	return mount{path: resp.Data.Path, v2: resp.Data.Options.Version == "2"}, nil
}

// call makes one API call and returns the status and body. A transport
// error is returned as err; an API error is left to the caller to read
// from the status, since not found and forbidden mean different things per
// call.
func (b *Backend) call(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base.String()+"/v1/"+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-Vault-Token", b.token)
	req.Header.Set("X-Vault-Request", "true")
	if b.namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("OpenBao at %s: %w", b.base.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("OpenBao at %s: %w", b.base.Host, err)
	}
	if len(data) > maxResponseBytes {
		return 0, nil, fmt.Errorf("OpenBao at %s: response over %d bytes", b.base.Host, maxResponseBytes)
	}
	return resp.StatusCode, data, nil
}

// apiError describes a failed call from its status and OpenBao's error list.
func apiError(status int, body []byte) string {
	var resp struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err == nil && len(resp.Errors) > 0 {
		return fmt.Sprintf("status %d: %s", status, strings.Join(resp.Errors, "; "))
	}
	return fmt.Sprintf("status %d", status)
}

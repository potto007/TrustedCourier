// Package openbao is the OpenBao Backend Plugin's Backend: it serves Secrets
// from OpenBao's KV secrets engine, versions 1 and 2, over OpenBao's HTTP
// API, and stores Courier Keys there (ADR-0008, ADR-0028).
//
// A location is "<path>#<field>": the API path of a KV record, as the
// OpenBao CLI's `bao kv get -mount=secret openai` spells it for the API,
// "secret/data/openai" on a KV v2 mount or "secret/openai" on a KV v1 mount,
// and the field in that record. The field's value must be a non-empty
// string of at most 1 MiB; OpenBao KV holds JSON, and a number, object, or
// empty string at a location is not a Secret.
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
	"sync"
	"time"
	"unicode"
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
	base      url.URL
	token     string
	namespace string
	http      *http.Client

	// mounts caches what OpenBao reports about each KV mount, by mount
	// path, since every call needs the mount's KV version and mounts
	// rarely change.
	mu     sync.Mutex
	mounts map[string]cachedMount
}

type cachedMount struct {
	mount
	fetched time.Time
}

const (
	// requestTimeout bounds one call to OpenBao.
	requestTimeout = 30 * time.Second
	// maxResponseBytes bounds a response body; a KV record is far smaller.
	maxResponseBytes = 4 << 20
	// maxValueBytes is the largest Secret the plugin contract allows.
	maxValueBytes = 1 << 20
	// maxLocations is the most a List returns, the plugin contract's limit.
	maxLocations = 10000
	// maxListReads bounds the records a List reads, so a short prefix on a
	// large mount fails with a clear error rather than at the caller's
	// deadline.
	maxListReads = 1000
	// casRetries is how many times a Courier Key write retries after
	// another writer changed the record.
	casRetries = 3
	// mountTTL is how long a mount's version is trusted before it is read
	// again.
	mountTTL = 5 * time.Minute
	// maxVersionBytes bounds the OpenBao version shown in the health detail.
	maxVersionBytes = 64
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
	transport.MaxIdleConnsPerHost = 16 // the core calls from every Delivery at once
	return &Backend{
		base:      url.URL{Scheme: base.Scheme, Host: base.Host},
		token:     cfg.Token,
		namespace: cfg.Namespace,
		http: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// The token must never follow a redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		mounts: map[string]cachedMount{},
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
	m, err := b.mountFor(ctx, loc.path)
	if err != nil {
		return nil, err
	}
	rec, err := b.readRecord(ctx, m, loc.path)
	if err != nil {
		return nil, err
	}
	if rec.fields == nil {
		return nil, fmt.Errorf("%w: no record at %s", plugin.ErrNotFound, loc.path)
	}
	raw, ok := rec.fields[loc.field]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no field %q", plugin.ErrNotFound, loc.path, loc.field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("%s field %q is not a string; a Secret must be a string", loc.path, loc.field)
	}
	switch {
	case value == "":
		return nil, fmt.Errorf("%s field %q is empty", loc.path, loc.field)
	case len(value) > maxValueBytes:
		return nil, fmt.Errorf("%s field %q is %d bytes, over the %d byte limit for a Secret", loc.path, loc.field, len(value), maxValueBytes)
	}
	return []byte(value), nil
}

// List returns every location starting with prefix. With an empty prefix
// it walks every KV mount the token can see; otherwise the mount holding
// the prefix. Each record under the prefix is read to name its fields, so
// a long prefix is much cheaper than a short one, and a List that would
// read more than a thousand records fails.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	pathPrefix, fieldPrefix, hasField := strings.Cut(prefix, "#")
	if err := checkPath(pathPrefix, true); err != nil {
		return nil, fmt.Errorf("prefix %q: %w", prefix, err)
	}
	var mounts []mount
	if pathPrefix == "" {
		var err error
		if mounts, err = b.kvMounts(ctx); err != nil {
			return nil, err
		}
	} else if m, err := b.mountFor(ctx, pathPrefix); err == nil {
		mounts = []mount{m}
	} else if all, listErr := b.kvMounts(ctx); listErr == nil {
		// The prefix may be shorter than a mount path, such as "sec".
		for _, m := range all {
			if strings.HasPrefix(m.path, pathPrefix) {
				mounts = append(mounts, m)
			}
		}
	} else {
		return nil, err
	}
	l := &lister{b: b, prefix: prefix, fieldPrefix: fieldPrefix}
	for _, m := range mounts {
		if hasField {
			// A whole record path: read that one record.
			if !strings.HasPrefix(pathPrefix, m.dataRoot()) {
				continue
			}
			rec, err := l.read(ctx, m, pathPrefix)
			if err != nil {
				return nil, err
			}
			if err := l.emit(pathPrefix, rec.fields); err != nil {
				return nil, err
			}
			continue
		}
		if !overlaps(m.dataRoot(), pathPrefix) {
			continue
		}
		if err := l.walk(ctx, m, "", pathPrefix); err != nil {
			return nil, err
		}
	}
	slices.Sort(l.locations)
	return l.locations, nil
}

// lister accumulates one List.
type lister struct {
	b                   *Backend
	prefix, fieldPrefix string
	reads               int
	locations           []string
}

func (l *lister) read(ctx context.Context, m mount, path string) (record, error) {
	if l.reads == maxListReads {
		return record{}, fmt.Errorf("listing %q would read more than %d records; list a longer prefix", l.prefix, maxListReads)
	}
	l.reads++
	return l.b.readRecord(ctx, m, path)
}

func (l *lister) emit(path string, fields map[string]json.RawMessage) error {
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		if !strings.HasPrefix(field, l.fieldPrefix) {
			continue
		}
		if len(l.locations) == maxLocations {
			return fmt.Errorf("more than %d locations start with %q; list a longer prefix", maxLocations, l.prefix)
		}
		l.locations = append(l.locations, path+"#"+field)
	}
	return nil
}

// walk lists the records under dir in m, in order, reading each whose path
// starts with pathPrefix and descending into each folder that could hold
// one. A key OpenBao holds that cannot be spelled as a location, one with
// a '#' in it, is skipped.
func (l *lister) walk(ctx context.Context, m mount, dir, pathPrefix string) error {
	keys, err := l.b.listKeys(ctx, m.listPath(dir))
	if err != nil {
		return err
	}
	for _, key := range keys {
		full := m.dataRoot() + dir + key
		if strings.HasSuffix(key, "/") {
			if overlaps(full, pathPrefix) {
				if err := l.walk(ctx, m, dir+key, pathPrefix); err != nil {
					return err
				}
			}
			continue
		}
		if !strings.HasPrefix(full, pathPrefix) || checkPath(full, false) != nil {
			continue
		}
		rec, err := l.read(ctx, m, full)
		if err != nil {
			return err
		}
		if err := l.emit(full, rec.fields); err != nil {
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
	status, body, err := b.call(ctx, http.MethodGet, "sys/health", "standbyok=true&perfstandbyok=true&uninitcode=501&sealedcode=503", nil)
	if err != nil {
		return "", err
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &health); err != nil {
			return "", fmt.Errorf("sys/health: %w", err)
		}
	}
	detail := "OpenBao " + printable(health.Version, maxVersionBytes)
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
			TTL int64 `json:"ttl"`
		} `json:"data"`
	}
	status, body, err = b.call(ctx, http.MethodGet, "auth/token/lookup-self", "", nil)
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
	for attempt := 0; ; attempt++ {
		rec, err := b.readRecord(ctx, m, loc.path)
		if err != nil {
			return err
		}
		fields := rec.fields
		if fields == nil {
			fields = map[string]json.RawMessage{}
		}
		fields[loc.field] = encoded
		var body any = fields
		if m.v2 {
			body = map[string]any{"data": fields, "options": map[string]any{"cas": rec.version}}
		}
		status, resp, err := b.call(ctx, http.MethodPost, loc.path, "", body)
		if err != nil {
			return err
		}
		if status == http.StatusOK || status == http.StatusNoContent {
			return nil
		}
		if m.v2 && status == http.StatusBadRequest && strings.Contains(string(resp), "check-and-set") && attempt < casRetries {
			continue // another writer got in between; read the new version
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
	if err := checkPath(path, false); err != nil {
		return location{}, fmt.Errorf("location %q: %w", s, err)
	}
	return location{path: path, field: field}, nil
}

// checkPath checks a record path, or with prefix a leading part of one: an
// API path without a leading slash, empty segments, or characters that a
// URL or a location would read as something else.
func checkPath(path string, prefix bool) error {
	if path == "" && prefix {
		return nil
	}
	if strings.HasPrefix(path, "/") || strings.Contains(path, "//") || (!prefix && strings.HasSuffix(path, "/")) {
		return errors.New("the path must be an API path without a leading slash or empty segments")
	}
	if i := strings.IndexFunc(path, func(r rune) bool {
		return r == '#' || r == '?' || r == '%' || unicode.IsControl(r) || unicode.IsSpace(r)
	}); i >= 0 {
		return fmt.Errorf("the path contains %q, which a location cannot hold", path[i:i+utf8.RuneLen([]rune(path[i:])[0])])
	}
	return nil
}

// record is a KV record read from OpenBao: its fields, nil when there is
// none, and on a KV v2 mount its version, which a deleted record keeps.
type record struct {
	fields  map[string]json.RawMessage
	version int64
}

// readRecord reads the KV record at path on mount m.
func (b *Backend) readRecord(ctx context.Context, m mount, path string) (record, error) {
	if !strings.HasPrefix(path, m.dataRoot()) {
		return record{}, fmt.Errorf("%s is on KV v2 mount %s, so its location starts with %s", path, m.path, m.dataRoot())
	}
	status, body, err := b.call(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return record{}, err
	}
	var resp struct {
		Errors []string                   `json:"errors"`
		Data   map[string]json.RawMessage `json:"data"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &resp); err != nil {
			return record{}, fmt.Errorf("read %s: %w", path, err)
		}
	}
	switch {
	case status == http.StatusNotFound && len(resp.Errors) > 0:
		// Not a missing record but a refused path, such as one that
		// skips the data segment on a KV v2 mount.
		return record{}, fmt.Errorf("read %s: %s", path, apiError(status, body))
	case status != http.StatusOK && status != http.StatusNotFound:
		return record{}, fmt.Errorf("read %s: %s", path, apiError(status, body))
	}
	if !m.v2 {
		if status == http.StatusNotFound {
			return record{}, nil
		}
		return record{fields: resp.Data}, nil
	}
	// A KV v2 response wraps the fields in data with metadata beside them,
	// and a deleted record answers 404 with its metadata and no fields.
	var rec record
	if meta, ok := resp.Data["metadata"]; ok {
		var metadata struct {
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(meta, &metadata); err != nil {
			return record{}, fmt.Errorf("read %s: metadata: %w", path, err)
		}
		rec.version = metadata.Version
	}
	if status == http.StatusNotFound {
		return rec, nil
	}
	if err := json.Unmarshal(resp.Data["data"], &rec.fields); err != nil {
		return record{}, fmt.Errorf("read %s: data is not an object", path)
	}
	return rec, nil
}

// listKeys lists the keys under a folder, folders with a trailing slash.
func (b *Backend) listKeys(ctx context.Context, path string) ([]string, error) {
	status, body, err := b.call(ctx, "LIST", path, "", nil)
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
	status, body, err := b.call(ctx, http.MethodGet, "sys/internal/ui/mounts", "", nil)
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

// mountFor returns the KV mount holding path, from the cache when it was
// read recently.
func (b *Backend) mountFor(ctx context.Context, path string) (mount, error) {
	if m, ok := b.cachedMount(path); ok {
		return m, nil
	}
	status, body, err := b.call(ctx, http.MethodGet, "sys/internal/ui/mounts/"+path, "", nil)
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
	if !strings.HasPrefix(path+"/", resp.Data.Path) {
		return mount{}, fmt.Errorf("sys/internal/ui/mounts/%s: reports mount %q", path, resp.Data.Path)
	}
	m := mount{path: resp.Data.Path, v2: resp.Data.Options.Version == "2"}
	b.mu.Lock()
	b.mounts[m.path] = cachedMount{mount: m, fetched: time.Now()}
	b.mu.Unlock()
	return m, nil
}

func (b *Backend) cachedMount(path string) (mount, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for mountPath, c := range b.mounts {
		if time.Since(c.fetched) > mountTTL {
			delete(b.mounts, mountPath)
			continue
		}
		if strings.HasPrefix(path+"/", mountPath) {
			return c.mount, true
		}
	}
	return mount{}, false
}

// call makes one API call and returns the status and body. A transport
// error is returned as err; an API error is left to the caller to read
// from the status, since not found and forbidden mean different things per
// call.
func (b *Backend) call(ctx context.Context, method, path, query string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	u := b.base
	u.Path = "/v1/" + path
	u.RawQuery = query
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
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
		return fmt.Sprintf("status %d: %s", status, printable(strings.Join(resp.Errors, "; "), 512))
	}
	return fmt.Sprintf("status %d", status)
}

// printable makes text OpenBao sent safe for a health detail or an error:
// control characters and invalid UTF-8 become '?', and it is cut at max
// bytes.
func printable(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("...")
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Package config loads and validates the TrustedCourier config file into an
// immutable snapshot.
package config

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/sdk/plugin/client"
	"go.yaml.in/yaml/v3"
)

// DefaultAdminSocket is where the admin API listens when the config names no
// socket.
const DefaultAdminSocket = "/run/trustedcourier/admin.sock"

// Config is a fully validated config snapshot. Treat it as read-only.
type Config struct {
	// Path is the absolute path of the config file.
	Path string
	// DataDir holds the SQLite database.
	DataDir string
	Admin   Admin
	// AgentAPI configures the listener Agents call.
	AgentAPI AgentAPI
	// Policies by name.
	Policies map[string]Policy
	// BackendPlugins by name.
	BackendPlugins map[string]BackendPlugin
	// Secrets are the Secret Names Agents may ask for, by name.
	Secrets map[string]SecretName
	// Audit configures how the audit chain is signed.
	Audit Audit
}

// Checkpoint cadences used when the config sets none.
const (
	DefaultCheckpointRecords  = 1000
	DefaultCheckpointInterval = time.Minute
)

// Audit configures the audit chain's signed checkpoints (ADR-0007).
type Audit struct {
	// SigningKey is where the audit signing key lives. Nil when the config
	// names none, which it must when the Agent API is served.
	SigningKey *CourierKey
	// CheckpointRecords is how many Audit Records may follow the last
	// checkpoint before the next is signed.
	CheckpointRecords int
	// CheckpointInterval is how long a record may go unsigned before a
	// checkpoint covers it.
	CheckpointInterval time.Duration
}

// CourierKey is where a Courier Key lives in a Backend.
type CourierKey struct {
	// Backend names the entry in BackendPlugins that holds the key.
	Backend string
	// Location is the key's location in that Backend.
	Location string
}

// AgentAPI configures the Agent API listener.
type AgentAPI struct {
	// Listen is the loopback address and port to serve plain HTTP on, such
	// as 127.0.0.1:8200. Empty serves no Agent API.
	Listen string
}

// MaxCacheTTL is the longest a Secret Name may cache its Secret: the cache
// trades plaintext lifetime for fewer Backend calls, so the trade stays short.
const MaxCacheTTL = time.Hour

// SecretName maps a Secret Name to where its Secret lives. Agents never see
// the mapping.
type SecretName struct {
	Name string
	// Backend names the entry in BackendPlugins that holds the Secret.
	Backend string
	// Location is the Secret's location in that Backend.
	Location string
	// CacheTTL is how long the Secret may be kept in memory and delivered
	// without calling the Backend. Zero, the default, fetches on every
	// Delivery.
	CacheTTL time.Duration
	// InjectionTemplate says where Proxy Delivery puts the Secret. Nil
	// exactly when Upstreams is empty.
	InjectionTemplate *InjectionTemplate
	// Upstreams are the Upstreams the Secret is pinned to, by name.
	Upstreams map[string]Upstream
	// Preset names the Preset that supplied InjectionTemplate, and Upstreams
	// unless the Operator set them. Empty without one.
	Preset string
	// Env are the environment variables an Agent needs to use the Secret Name
	// through Proxy Delivery. Nil exactly when Upstreams is empty.
	Env []EnvVar
}

// InjectionTemplate is where Proxy Delivery puts a Secret in a request, and
// so where it finds the Agent Token. Exactly one field is set.
type InjectionTemplate struct {
	// Header puts the Secret in a header.
	Header *HeaderTemplate
	// Query puts the Secret in a query parameter.
	Query *QueryTemplate
	// BasicAuth puts the Secret in HTTP basic auth.
	BasicAuth *BasicAuthTemplate
}

// BasicAuthTemplate puts the Secret in the Authorization header as the whole
// basic auth username or password. The other field is literal.
type BasicAuthTemplate struct {
	// Username and Password are the literal credentials. The one the Secret
	// takes is empty.
	Username, Password string
	// SecretIsUsername says the Secret is the username; otherwise it is the
	// password.
	SecretIsUsername bool
}

// QueryTemplate puts the Secret in a query parameter, as its whole value.
type QueryTemplate struct {
	// Name is the query parameter's name, which never needs escaping.
	Name string
}

// HeaderTemplate puts the Secret in a header as Prefix, the Secret, Suffix.
type HeaderTemplate struct {
	// Name is the canonical header name.
	Name   string
	Prefix string
	Suffix string
}

// SecretPlaceholder marks where the Secret goes in a header or basic auth
// template.
const SecretPlaceholder = "{secret}"

// Upstream is one Upstream a Secret Name is pinned to.
type Upstream struct {
	Name string
	// Scheme and Host of the Upstream; Scheme is always https.
	Scheme, Host string
	// BasePath is the escaped path requests are forwarded under, without a
	// trailing slash. Empty for the root.
	BasePath string
	// RootCAs verify the Upstream's certificate. Nil means the system roots.
	RootCAs *x509.CertPool
}

// BackendPlugin is a Backend Plugin binary the Operator approved (ADR-0004).
type BackendPlugin struct {
	Name string
	// Path is the absolute path of the binary.
	Path string
	// SHA256 is the pinned hash of the binary, lowercase hexadecimal.
	SHA256 string
	// User is the OS user name or ID the plugin runs as. Empty only when
	// InsecureShareCoreUser is set.
	User string
	// InsecureShareCoreUser runs the plugin as the server's own user, giving
	// it access to the config and database. For development only.
	InsecureShareCoreUser bool
}

// Admin configures the admin API.
type Admin struct {
	// Socket is the unix socket path of the admin API.
	Socket string
	// AllowedUIDs are the local users allowed to connect to Socket.
	AllowedUIDs []int
}

// Policy states which Secret Names an Agent Token may use and how.
type Policy struct {
	Name    string
	Secrets []SecretAccess
}

// SecretAccess allows one Secret Name in the listed Delivery modes.
type SecretAccess struct {
	SecretName string
	Delivery   []DeliveryMode
	// Methods are the uppercase HTTP methods Proxy Delivery may send. Nil
	// allows any method.
	Methods []string
	// Paths are the path prefixes Proxy Delivery may reach. Nil allows any
	// path.
	Paths []PathPrefix
}

// ProxyMethods are the HTTP methods a Policy may limit Proxy Delivery to.
var ProxyMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// DeliveryMode is proxy or reveal.
type DeliveryMode string

// Delivery modes.
const (
	DeliveryProxy  DeliveryMode = "proxy"
	DeliveryReveal DeliveryMode = "reveal"
)

type fileConfig struct {
	DataDir        string                       `yaml:"data_dir"`
	Admin          fileAdmin                    `yaml:"admin"`
	AgentAPI       fileAgentAPI                 `yaml:"agent_api"`
	Policies       map[string]filePolicy        `yaml:"policies"`
	BackendPlugins map[string]fileBackendPlugin `yaml:"backend_plugins"`
	Secrets        map[string]fileSecretName    `yaml:"secrets"`
	Audit          fileAudit                    `yaml:"audit"`
}

type fileAudit struct {
	SigningKey  *fileCourierKey `yaml:"signing_key"`
	Checkpoints fileCheckpoints `yaml:"checkpoints"`
}

type fileCourierKey struct {
	Backend  string `yaml:"backend"`
	Location string `yaml:"location"`
}

type fileCheckpoints struct {
	// Records is kept as a node, so a key left without a value is told apart
	// from an omitted one (Kind 0).
	Records  yaml.Node `yaml:"records"`
	Interval string    `yaml:"interval"`
}

type fileAgentAPI struct {
	Listen string `yaml:"listen"`
}

type fileSecretName struct {
	Backend           string                  `yaml:"backend"`
	Location          string                  `yaml:"location"`
	CacheTTL          string                  `yaml:"cache_ttl"`
	Preset            string                  `yaml:"preset"`
	InjectionTemplate *fileInjectionTemplate  `yaml:"injection_template"`
	Upstreams         map[string]fileUpstream `yaml:"upstreams"`
}

type fileInjectionTemplate struct {
	Header    *fileHeaderTemplate    `yaml:"header"`
	Query     *fileQueryTemplate     `yaml:"query"`
	BasicAuth *fileBasicAuthTemplate `yaml:"basic_auth"`
}

type fileBasicAuthTemplate struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type fileQueryTemplate struct {
	Name string `yaml:"name"`
}

type fileHeaderTemplate struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type fileUpstream struct {
	URL      string `yaml:"url"`
	CABundle string `yaml:"ca_bundle"`
}

type fileBackendPlugin struct {
	Path                  string `yaml:"path"`
	SHA256                string `yaml:"sha256"`
	User                  string `yaml:"user"`
	InsecureShareCoreUser bool   `yaml:"insecure_share_core_user"`
}

type fileAdmin struct {
	Socket      string `yaml:"socket"`
	AllowedUIDs *[]int `yaml:"allowed_uids"` // nil when omitted
}

type filePolicy struct {
	Secrets []fileSecretAccess `yaml:"secrets"`
}

type fileSecretAccess struct {
	Name     string   `yaml:"name"`
	Delivery []string `yaml:"delivery"`
	// Methods and Paths are kept as nodes, so a key left without a value is
	// told apart from an omitted one (Kind 0).
	Methods yaml.Node `yaml:"methods"`
	Paths   yaml.Node `yaml:"paths"`
}

// Load reads and validates the config file at path. Relative paths in the
// file are resolved to absolute paths against the file's directory.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// A second document would otherwise be silently ignored.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: config must be a single YAML document", path)
	}
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	cfg, err := raw.validate(baseDir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Path, err = filepath.Abs(path); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (raw fileConfig) validate(baseDir string) (*Config, error) {
	cfg := &Config{
		Policies:       make(map[string]Policy, len(raw.Policies)),
		BackendPlugins: make(map[string]BackendPlugin, len(raw.BackendPlugins)),
		Secrets:        make(map[string]SecretName, len(raw.Secrets)),
	}

	if raw.DataDir == "" {
		return nil, errors.New("data_dir is required")
	}
	cfg.DataDir = resolve(baseDir, raw.DataDir)

	cfg.Admin.Socket = DefaultAdminSocket
	if raw.Admin.Socket != "" {
		cfg.Admin.Socket = resolve(baseDir, raw.Admin.Socket)
	}
	cfg.Admin.AllowedUIDs = []int{os.Getuid()}
	if raw.Admin.AllowedUIDs != nil {
		if len(*raw.Admin.AllowedUIDs) == 0 {
			return nil, errors.New("admin.allowed_uids is empty, so no local user could administer TrustedCourier; omit it to allow only the server's own user")
		}
		cfg.Admin.AllowedUIDs = *raw.Admin.AllowedUIDs
	}

	// Validate in name order so the reported error is deterministic.
	for _, name := range slices.Sorted(maps.Keys(raw.Policies)) {
		policy, err := raw.Policies[name].validate(name)
		if err != nil {
			return nil, err
		}
		cfg.Policies[name] = policy
	}
	for _, name := range slices.Sorted(maps.Keys(raw.BackendPlugins)) {
		plugin, err := raw.BackendPlugins[name].validate(name, baseDir)
		if err != nil {
			return nil, err
		}
		cfg.BackendPlugins[name] = plugin
	}
	for _, name := range slices.Sorted(maps.Keys(raw.Secrets)) {
		s, err := raw.Secrets[name].validate(name, baseDir, cfg.BackendPlugins)
		if err != nil {
			return nil, err
		}
		cfg.Secrets[name] = s
	}
	// A Policy entry naming an undefined Secret Name, or allowing a Proxy
	// Delivery that has nowhere to go, is a typo or a half-finished change;
	// refuse it rather than deny Agents at runtime.
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		for _, a := range cfg.Policies[name].Secrets {
			s, ok := cfg.Secrets[a.SecretName]
			if !ok {
				return nil, fmt.Errorf("Policy %q names Secret Name %q, which is not defined under secrets", name, a.SecretName)
			}
			if slices.Contains(a.Delivery, DeliveryProxy) && len(s.Upstreams) == 0 {
				return nil, fmt.Errorf("Policy %q allows Proxy Delivery of Secret Name %q, which has no upstreams", name, a.SecretName)
			}
		}
	}
	if raw.AgentAPI.Listen != "" {
		if err := checkLoopback(raw.AgentAPI.Listen); err != nil {
			return nil, err
		}
		cfg.AgentAPI.Listen = raw.AgentAPI.Listen
	}
	if err := raw.Audit.validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate sets cfg.Audit. It needs cfg's Backend Plugins, Secret Names, and
// Agent API already validated.
func (a fileAudit) validate(cfg *Config) error {
	if a.SigningKey == nil {
		if cfg.AgentAPI.Listen != "" {
			return errors.New("audit.signing_key is required with agent_api.listen: every Delivery attempt is audited, and TrustedCourier signs the audit chain with that Courier Key")
		}
	} else {
		key, err := a.SigningKey.validate(cfg.BackendPlugins)
		if err != nil {
			return fmt.Errorf("audit.signing_key: %w", err)
		}
		// A Courier Key is never delivered to Agents.
		for _, name := range slices.Sorted(maps.Keys(cfg.Secrets)) {
			if s := cfg.Secrets[name]; s.Backend == key.Backend && s.Location == key.Location {
				return fmt.Errorf("Secret Name %q maps to the audit signing key's location; a Courier Key is never delivered to Agents", name)
			}
		}
		cfg.Audit.SigningKey = &key
	}

	cfg.Audit.CheckpointRecords = DefaultCheckpointRecords
	if n := a.Checkpoints.Records; n.Kind != 0 {
		var records int
		if n.ShortTag() == "!!null" || n.Decode(&records) != nil || records < 1 {
			return fmt.Errorf("audit.checkpoints.records must be at least 1; omit it for the default of %d", DefaultCheckpointRecords)
		}
		cfg.Audit.CheckpointRecords = records
	}
	cfg.Audit.CheckpointInterval = DefaultCheckpointInterval
	if a.Checkpoints.Interval != "" {
		d, err := time.ParseDuration(a.Checkpoints.Interval)
		switch {
		case err != nil:
			return fmt.Errorf("audit.checkpoints.interval %q is not a duration such as 1m", a.Checkpoints.Interval)
		case d < time.Second:
			return fmt.Errorf("audit.checkpoints.interval %q must be at least 1s", a.Checkpoints.Interval)
		}
		cfg.Audit.CheckpointInterval = d
	}
	return nil
}

func (k fileCourierKey) validate(plugins map[string]BackendPlugin) (CourierKey, error) {
	switch {
	case k.Backend == "":
		return CourierKey{}, errors.New("backend is required")
	case k.Location == "":
		return CourierKey{}, errors.New("location is required")
	}
	if err := client.ValidateLocation(k.Location); err != nil {
		return CourierKey{}, err
	}
	if _, ok := plugins[k.Backend]; !ok {
		return CourierKey{}, fmt.Errorf("unknown backend %q; name one of backend_plugins", k.Backend)
	}
	return CourierKey{Backend: k.Backend, Location: k.Location}, nil
}

// checkLoopback accepts only a loopback IP address and port: the Agent API
// serves plain HTTP, and TLS is required on every other listener (ADR-0006).
func checkLoopback(listen string) error {
	addr, err := netip.ParseAddrPort(listen)
	if err != nil {
		return fmt.Errorf("agent_api.listen %q must be a loopback IP address and port, such as 127.0.0.1:8200", listen)
	}
	if !addr.Addr().Unmap().IsLoopback() {
		return fmt.Errorf("agent_api.listen %q is not a loopback address; the Agent API serves plain HTTP, so it may only listen on loopback", listen)
	}
	return nil
}

func (s fileSecretName) validate(name, baseDir string, plugins map[string]BackendPlugin) (SecretName, error) {
	if !namePattern.MatchString(name) {
		return SecretName{}, fmt.Errorf("invalid Secret Name %q: use up to 64 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	switch {
	case s.Backend == "":
		return SecretName{}, fmt.Errorf("Secret Name %q: backend is required", name)
	case s.Location == "":
		return SecretName{}, fmt.Errorf("Secret Name %q: location is required", name)
	}
	if err := client.ValidateLocation(s.Location); err != nil {
		return SecretName{}, fmt.Errorf("Secret Name %q: %w", name, err)
	}
	if _, ok := plugins[s.Backend]; !ok {
		return SecretName{}, fmt.Errorf("Secret Name %q: unknown backend %q; name one of backend_plugins", name, s.Backend)
	}
	out := SecretName{Name: name, Backend: s.Backend, Location: s.Location}
	if s.CacheTTL != "" {
		d, err := time.ParseDuration(s.CacheTTL)
		switch {
		case err != nil:
			return SecretName{}, fmt.Errorf("Secret Name %q: cache_ttl %q is not a duration such as 30s", name, s.CacheTTL)
		case d < time.Second || d > MaxCacheTTL:
			return SecretName{}, fmt.Errorf("Secret Name %q: cache_ttl %q must be from 1s to 1h; omit it to fetch the Secret on every Delivery", name, s.CacheTTL)
		}
		out.CacheTTL = d
	}

	if s.Preset != "" {
		presets, err := builtinPresets()
		if err != nil {
			return SecretName{}, err
		}
		p, ok := presets[s.Preset]
		switch {
		case !ok:
			return SecretName{}, fmt.Errorf("Secret Name %q: unknown preset %q; use one of %s", name, s.Preset, strings.Join(slices.Sorted(maps.Keys(presets)), ", "))
		case s.InjectionTemplate != nil:
			return SecretName{}, fmt.Errorf("Secret Name %q: set preset or injection_template, not both", name)
		}
		out.Preset, out.InjectionTemplate, out.Upstreams, out.Env = s.Preset, &p.template, p.upstreams, p.env
		// Upstreams set beside a Preset replace its own, as for a GitHub
		// Enterprise Server.
		if len(s.Upstreams) > 0 {
			if out.Upstreams, err = validateUpstreams(s.Upstreams, baseDir); err != nil {
				return SecretName{}, fmt.Errorf("Secret Name %q: %w", name, err)
			}
		}
		return out, nil
	}

	switch {
	case s.InjectionTemplate == nil && len(s.Upstreams) == 0:
		return out, nil
	case s.InjectionTemplate == nil:
		return SecretName{}, fmt.Errorf("Secret Name %q: injection_template is required with upstreams, unless preset is set", name)
	case len(s.Upstreams) == 0:
		return SecretName{}, fmt.Errorf("Secret Name %q: injection_template needs upstreams to deliver to", name)
	}
	tmpl, err := s.InjectionTemplate.validate()
	if err != nil {
		return SecretName{}, fmt.Errorf("Secret Name %q: injection_template: %w", name, err)
	}
	out.InjectionTemplate = &tmpl
	if out.Upstreams, err = validateUpstreams(s.Upstreams, baseDir); err != nil {
		return SecretName{}, fmt.Errorf("Secret Name %q: %w", name, err)
	}
	out.Env = defaultEnv(name, tmpl)
	return out, nil
}

func validateUpstreams(raw map[string]fileUpstream, baseDir string) (map[string]Upstream, error) {
	out := make(map[string]Upstream, len(raw))
	for _, name := range slices.Sorted(maps.Keys(raw)) {
		up, err := raw[name].validate(name, baseDir)
		if err != nil {
			return nil, err
		}
		out[name] = up
	}
	return out, nil
}

// headerNamePattern is an HTTP field name token (RFC 9110).
var headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// reservedHeaders cannot carry a Secret: they are hop-by-hop, which the
// forwarding strips, framing the transport sets itself, or the fallback
// Agent Token header, which Proxy Delivery removes.
var reservedHeaders = []string{
	"Connection", "Content-Length", "Host", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Proxy-Connection", "Te", "Trailer",
	"Transfer-Encoding", "Upgrade", "X-Tc-Agent-Token",
}

// templateKinds names the kinds of Injection Template, as the config spells
// them.
const templateKinds = "header, query, basic_auth"

func (t fileInjectionTemplate) validate() (InjectionTemplate, error) {
	set := 0
	for _, kind := range []bool{t.Header != nil, t.Query != nil, t.BasicAuth != nil} {
		if kind {
			set++
		}
	}
	switch {
	case set == 0:
		return InjectionTemplate{}, errors.New("set one of " + templateKinds)
	case set > 1:
		return InjectionTemplate{}, errors.New("set only one of " + templateKinds)
	case t.Query != nil:
		q, err := t.Query.validate()
		return InjectionTemplate{Query: q}, err
	case t.BasicAuth != nil:
		b, err := t.BasicAuth.validate()
		return InjectionTemplate{BasicAuth: b}, err
	}
	h, err := t.Header.validate()
	return InjectionTemplate{Header: h}, err
}

func (h fileHeaderTemplate) validate() (*HeaderTemplate, error) {
	if !headerNamePattern.MatchString(h.Name) {
		return nil, fmt.Errorf("invalid header name %q", h.Name)
	}
	name := http.CanonicalHeaderKey(h.Name)
	if slices.Contains(reservedHeaders, name) {
		return nil, fmt.Errorf("header %q is reserved and cannot carry a Secret", h.Name)
	}
	if strings.Count(h.Value, SecretPlaceholder) != 1 {
		return nil, fmt.Errorf("header value must contain %s exactly once", SecretPlaceholder)
	}
	if hasControl(h.Value) {
		return nil, errors.New("header value contains a control character")
	}
	prefix, suffix, _ := strings.Cut(h.Value, SecretPlaceholder)
	return &HeaderTemplate{Name: name, Prefix: prefix, Suffix: suffix}, nil
}

// queryNamePattern is a query parameter name made only of bytes a query never
// escapes, so the name matches as the Agent sends it.
var queryNamePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

func (q fileQueryTemplate) validate() (*QueryTemplate, error) {
	if !queryNamePattern.MatchString(q.Name) {
		return nil, fmt.Errorf("invalid query parameter name %q: use up to 64 letters, digits, '.', '_', '~' or '-'", q.Name)
	}
	return &QueryTemplate{Name: q.Name}, nil
}

func (b fileBasicAuthTemplate) validate() (*BasicAuthTemplate, error) {
	if strings.Count(b.Username+"\x00"+b.Password, SecretPlaceholder) != 1 {
		return nil, fmt.Errorf("basic_auth must contain %s exactly once, as the username or the password", SecretPlaceholder)
	}
	out := &BasicAuthTemplate{Username: b.Username, Password: b.Password}
	switch {
	case b.Username == SecretPlaceholder:
		out.Username, out.SecretIsUsername = "", true
	case b.Password == SecretPlaceholder:
		out.Password = ""
	default:
		return nil, fmt.Errorf("basic_auth: %s must be the whole username or the whole password", SecretPlaceholder)
	}
	switch {
	case strings.Contains(out.Username, ":"):
		return nil, errors.New("basic_auth username must not contain ':'")
	case hasControl(out.Username) || hasControl(out.Password):
		return nil, errors.New("basic_auth contains a control character")
	}
	return out, nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func (u fileUpstream) validate(name, baseDir string) (Upstream, error) {
	if !namePattern.MatchString(name) {
		return Upstream{}, fmt.Errorf("invalid Upstream name %q: use up to 64 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	if u.URL == "" {
		return Upstream{}, fmt.Errorf("Upstream %q: url is required", name)
	}
	parsed, err := url.Parse(u.URL)
	switch {
	case err != nil:
		return Upstream{}, fmt.Errorf("Upstream %q: %w", name, err)
	case parsed.Scheme != "https":
		return Upstream{}, fmt.Errorf("Upstream %q: url must use https; Upstream TLS is always verified", name)
	case parsed.User != nil:
		return Upstream{}, fmt.Errorf("Upstream %q: url must not contain user information", name)
	case parsed.Host == "" || parsed.Opaque != "":
		return Upstream{}, fmt.Errorf("Upstream %q: url needs a host", name)
	case parsed.RawQuery != "" || parsed.ForceQuery:
		return Upstream{}, fmt.Errorf("Upstream %q: url must not contain a query", name)
	case parsed.Fragment != "":
		return Upstream{}, fmt.Errorf("Upstream %q: url must not contain a fragment", name)
	}
	out := Upstream{
		Name:     name,
		Scheme:   parsed.Scheme,
		Host:     parsed.Host,
		BasePath: strings.TrimRight(parsed.EscapedPath(), "/"),
	}
	if u.CABundle != "" {
		path := resolve(baseDir, u.CABundle)
		data, err := os.ReadFile(path)
		if err != nil {
			return Upstream{}, fmt.Errorf("Upstream %q: ca_bundle: %w", name, err)
		}
		out.RootCAs = x509.NewCertPool()
		if !out.RootCAs.AppendCertsFromPEM(data) {
			return Upstream{}, fmt.Errorf("Upstream %q: ca_bundle %s holds no certificates", name, path)
		}
	}
	return out, nil
}

var sha256Pattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func (p fileBackendPlugin) validate(name, baseDir string) (BackendPlugin, error) {
	if !namePattern.MatchString(name) {
		return BackendPlugin{}, fmt.Errorf("invalid Backend Plugin name %q: use up to 64 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	switch {
	case p.Path == "":
		return BackendPlugin{}, fmt.Errorf("Backend Plugin %q: path is required", name)
	case p.SHA256 == "":
		return BackendPlugin{}, fmt.Errorf("Backend Plugin %q: sha256 is required; print it with tc plugin sha256 <path>", name)
	case !sha256Pattern.MatchString(p.SHA256):
		return BackendPlugin{}, fmt.Errorf("Backend Plugin %q: sha256 must be 64 hexadecimal digits", name)
	case p.User == "" && !p.InsecureShareCoreUser:
		return BackendPlugin{}, fmt.Errorf("Backend Plugin %q: user is required, naming the separate OS user the plugin runs as", name)
	case p.User != "" && p.InsecureShareCoreUser:
		return BackendPlugin{}, fmt.Errorf("Backend Plugin %q: set user or insecure_share_core_user, not both", name)
	}
	return BackendPlugin{
		Name:                  name,
		Path:                  resolve(baseDir, p.Path),
		SHA256:                strings.ToLower(p.SHA256),
		User:                  p.User,
		InsecureShareCoreUser: p.InsecureShareCoreUser,
	}, nil
}

// namePattern constrains Policy names and Secret Names so they are safe on a
// command line, in a URL path, and in logs.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (p filePolicy) validate(name string) (Policy, error) {
	if !namePattern.MatchString(name) {
		return Policy{}, fmt.Errorf("invalid Policy name %q: use up to 64 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	policy := Policy{Name: name}
	if len(p.Secrets) == 0 {
		return Policy{}, fmt.Errorf("Policy %q lists no Secret Names", name)
	}
	for i, s := range p.Secrets {
		if s.Name == "" {
			return Policy{}, fmt.Errorf("Policy %q: secrets[%d]: Secret Name is required", name, i)
		}
		if !namePattern.MatchString(s.Name) {
			return Policy{}, fmt.Errorf("Policy %q: invalid Secret Name %q", name, s.Name)
		}
		if slices.ContainsFunc(policy.Secrets, func(a SecretAccess) bool { return a.SecretName == s.Name }) {
			return Policy{}, fmt.Errorf("Policy %q lists Secret Name %q more than once", name, s.Name)
		}
		if len(s.Delivery) == 0 {
			return Policy{}, fmt.Errorf("Policy %q: Secret Name %q needs at least one Delivery mode (proxy, reveal)", name, s.Name)
		}
		access := SecretAccess{SecretName: s.Name}
		for _, m := range s.Delivery {
			mode := DeliveryMode(m)
			if mode != DeliveryProxy && mode != DeliveryReveal {
				return Policy{}, fmt.Errorf("Policy %q: Secret Name %q: unknown Delivery mode %q (want proxy or reveal)", name, s.Name, m)
			}
			if !slices.Contains(access.Delivery, mode) {
				access.Delivery = append(access.Delivery, mode)
			}
		}
		if err := s.validateLimits(&access); err != nil {
			return Policy{}, fmt.Errorf("Policy %q: Secret Name %q: %w", name, s.Name, err)
		}
		policy.Secrets = append(policy.Secrets, access)
	}
	return policy, nil
}

// validateLimits sets the methods and paths that limit access's Proxy
// Delivery. An empty list, or a key without a value, is refused rather than
// read as allowing nothing or everything.
func (s fileSecretAccess) validateLimits(access *SecretAccess) error {
	methods, hasMethods, err := limitList(s.Methods, "methods", "method")
	if err != nil {
		return err
	}
	paths, hasPaths, err := limitList(s.Paths, "paths", "path")
	if err != nil {
		return err
	}
	if !hasMethods && !hasPaths {
		return nil
	}
	if !slices.Contains(access.Delivery, DeliveryProxy) {
		return errors.New("methods and paths limit Proxy Delivery, which the entry does not allow")
	}
	if hasMethods {
		access.Methods = []string{}
		for _, m := range methods {
			method := strings.ToUpper(m)
			if !slices.Contains(ProxyMethods, method) {
				return fmt.Errorf("unknown method %q (want %s)", m, strings.Join(ProxyMethods, ", "))
			}
			if !slices.Contains(access.Methods, method) {
				access.Methods = append(access.Methods, method)
			}
		}
	}
	if hasPaths {
		access.Paths = []PathPrefix{}
		for _, p := range paths {
			prefix, err := ParsePathPrefix(p)
			if err != nil {
				return fmt.Errorf("path %q: %w", p, err)
			}
			access.Paths = append(access.Paths, prefix)
		}
	}
	return nil
}

// limitList decodes the list under key, reporting whether the key was set.
// A key without a value is set but empty.
func limitList(n yaml.Node, key, item string) ([]string, bool, error) {
	if n.Kind == 0 {
		return nil, false, nil
	}
	var list []string
	if n.ShortTag() != "!!null" {
		if err := n.Decode(&list); err != nil {
			return nil, true, fmt.Errorf("%s must be a list: %w", key, err)
		}
	}
	if len(list) == 0 {
		return nil, true, fmt.Errorf("%s is empty; omit it to allow any %s", key, item)
	}
	return list, true, nil
}

func resolve(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

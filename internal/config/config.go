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
}

// AgentAPI configures the Agent API listener.
type AgentAPI struct {
	// Listen is the loopback address and port to serve plain HTTP on, such
	// as 127.0.0.1:8200. Empty serves no Agent API.
	Listen string
}

// SecretName maps a Secret Name to where its Secret lives. Agents never see
// the mapping.
type SecretName struct {
	Name string
	// Backend names the entry in BackendPlugins that holds the Secret.
	Backend string
	// Location is the Secret's location in that Backend.
	Location string
	// InjectionTemplate says where Proxy Delivery puts the Secret. Nil
	// exactly when Upstreams is empty.
	InjectionTemplate *InjectionTemplate
	// Upstreams are the Upstreams the Secret is pinned to, by name.
	Upstreams map[string]Upstream
}

// InjectionTemplate is where Proxy Delivery puts a Secret in a request, and
// so where it finds the Agent Token. Exactly one field is set.
type InjectionTemplate struct {
	// Header puts the Secret in a header.
	Header *HeaderTemplate
	// Query puts the Secret in a query parameter.
	Query *QueryTemplate
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

// SecretPlaceholder marks where the Secret goes in a header template.
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
}

type fileAgentAPI struct {
	Listen string `yaml:"listen"`
}

type fileSecretName struct {
	Backend           string                  `yaml:"backend"`
	Location          string                  `yaml:"location"`
	InjectionTemplate *fileInjectionTemplate  `yaml:"injection_template"`
	Upstreams         map[string]fileUpstream `yaml:"upstreams"`
}

type fileInjectionTemplate struct {
	Header *fileHeaderTemplate `yaml:"header"`
	Query  *fileQueryTemplate  `yaml:"query"`
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
	return cfg, nil
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

	switch {
	case s.InjectionTemplate == nil && len(s.Upstreams) == 0:
		return out, nil
	case s.InjectionTemplate == nil:
		return SecretName{}, fmt.Errorf("Secret Name %q: injection_template is required with upstreams", name)
	case len(s.Upstreams) == 0:
		return SecretName{}, fmt.Errorf("Secret Name %q: injection_template needs upstreams to deliver to", name)
	}
	tmpl, err := s.InjectionTemplate.validate()
	if err != nil {
		return SecretName{}, fmt.Errorf("Secret Name %q: injection_template: %w", name, err)
	}
	out.InjectionTemplate = &tmpl
	out.Upstreams = make(map[string]Upstream, len(s.Upstreams))
	for _, upName := range slices.Sorted(maps.Keys(s.Upstreams)) {
		up, err := s.Upstreams[upName].validate(upName, baseDir)
		if err != nil {
			return SecretName{}, fmt.Errorf("Secret Name %q: %w", name, err)
		}
		out.Upstreams[upName] = up
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
const templateKinds = "header, query"

func (t fileInjectionTemplate) validate() (InjectionTemplate, error) {
	set := 0
	for _, kind := range []bool{t.Header != nil, t.Query != nil} {
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
		policy.Secrets = append(policy.Secrets, access)
	}
	return policy, nil
}

func resolve(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

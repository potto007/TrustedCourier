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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

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

// AgentAPI configures the Agent API listener: a TCP address or a unix
// socket, never both. Both empty serves no Agent API.
type AgentAPI struct {
	// Listen is the IP address and port to serve on, such as 127.0.0.1:8200
	// or 0.0.0.0:8443. Plain HTTP is served only on a loopback address;
	// anywhere else TLS is set (ADR-0006).
	Listen string
	// Socket is the unix socket path to serve plain HTTP on.
	Socket string
	// TLS holds the Courier Keys the listener serves TLS with. Nil serves
	// plain HTTP, which validation allows only on loopback or a unix socket.
	TLS *AgentTLS
}

// Served reports whether an Agent API is served at all.
func (a AgentAPI) Served() bool { return a.Listen != "" || a.Socket != "" }

// Equal reports whether a and b configure the same listener.
func (a AgentAPI) Equal(b AgentAPI) bool {
	return a.Listen == b.Listen && a.Socket == b.Socket &&
		(a.TLS == nil) == (b.TLS == nil) && (a.TLS == nil || a.TLS.Equal(*b.TLS))
}

// AgentTLS is where the Agent API's certificate and key live: Courier Keys
// in a Backend, never on TrustedCourier's disk (ADR-0001). Either the
// Operator put them there, or ACME writes them there.
type AgentTLS struct {
	// Certificate holds the certificate chain as PEM, leaf first.
	Certificate CourierKey
	// Key holds the leaf's private key as PEM.
	Key CourierKey
	// ACME, when set, obtains and renews the pair from an ACME directory
	// (ADR-0006). Nil serves an Operator-supplied pair.
	ACME *ACME
}

// Equal reports whether a and b configure the same TLS.
func (a AgentTLS) Equal(b AgentTLS) bool {
	return a.Certificate == b.Certificate && a.Key == b.Key &&
		(a.ACME == nil) == (b.ACME == nil) && (a.ACME == nil || a.ACME.Equal(*b.ACME))
}

// ACME challenge types.
const (
	ChallengeTLSALPN01 = "tls-alpn-01"
	ChallengeHTTP01    = "http-01"
	ChallengeDNS01     = "dns-01"
)

// ACME defaults.
const (
	DefaultACMEDirectory  = "https://acme-v02.api.letsencrypt.org/directory"
	DefaultACMEHTTPListen = "0.0.0.0:80"
)

// ACME configures automatic certificates for the Agent API.
type ACME struct {
	// Directory is the ACME directory URL.
	Directory string
	// Domains are the DNS names the certificate covers, lowercase, the
	// first being the subject. A wildcard such as *.example.com needs
	// ChallengeDNS01; TLS-ALPN-01 and HTTP-01 cannot validate one.
	Domains []string
	// Contact is the account contact as a URL, such as mailto:ops@example.com,
	// or empty.
	Contact string
	// Challenge is ChallengeTLSALPN01, ChallengeHTTP01, or ChallengeDNS01.
	Challenge string
	// HTTPListen is the address the HTTP-01 challenge listener binds. Empty
	// unless Challenge is ChallengeHTTP01.
	HTTPListen string
	// DNS is the DNS provider DNS-01 validation records are set with. Set
	// exactly when Challenge is ChallengeDNS01.
	DNS *DNS
	// CABundle is the path of the PEM file that verifies the directory's
	// certificate, or empty for the system roots.
	CABundle string
	// RootCAs verify the directory's certificate. Nil means the system roots.
	RootCAs *x509.CertPool
	// AccountKey is where the ACME account key lives.
	AccountKey CourierKey
	// EAB is the External Account Binding the directory requires, or nil.
	EAB *ExternalAccountBinding
}

// ExternalAccountBinding binds a new ACME account to an account at the CA.
type ExternalAccountBinding struct {
	// KeyID is the key identifier the CA issued.
	KeyID string
	// HMACKey is where the base64url MAC key the CA issued lives.
	HMACKey CourierKey
}

// Equal reports whether a and b configure the same ACME.
func (a ACME) Equal(b ACME) bool {
	return a.Directory == b.Directory && slices.Equal(a.Domains, b.Domains) &&
		a.Contact == b.Contact && a.Challenge == b.Challenge && a.HTTPListen == b.HTTPListen &&
		a.CABundle == b.CABundle && a.RootCAs.Equal(b.RootCAs) && a.AccountKey == b.AccountKey &&
		(a.EAB == nil) == (b.EAB == nil) && (a.EAB == nil || *a.EAB == *b.EAB) &&
		(a.DNS == nil) == (b.DNS == nil) && (a.DNS == nil || a.DNS.Equal(*b.DNS))
}

// DNS providers DNS-01 can set records with (ADR-0006).
const (
	DNSProviderCloudflare = "cloudflare"
	DNSProviderRoute53    = "route53"
	DNSProviderAzure      = "azure"
	DNSProviderGoogle     = "google"
)

// DNSProviders lists the built-in DNS providers and the credential fields
// each needs, every one a Courier Key in a Backend.
var DNSProviders = map[string][]string{
	DNSProviderCloudflare: {"api_token"},
	DNSProviderRoute53:    {"access_key_id", "secret_access_key"},
	DNSProviderAzure:      {"client_secret"},
	DNSProviderGoogle:     {"service_account_key"},
}

// DefaultDNSPropagationTimeout is how long a DNS-01 record may take to
// appear on the name servers before the order fails.
const DefaultDNSPropagationTimeout = 2 * time.Minute

// DNS configures the DNS provider DNS-01 validation sets records with. The
// provider's credentials are Courier Keys: fetched from a Backend for each
// order, never values in the config.
type DNS struct {
	// Provider is one of the DNSProviders keys.
	Provider string
	// Credentials holds the provider's credential fields, as DNSProviders
	// lists them for Provider.
	Credentials map[string]CourierKey
	// Zone is the DNS zone the records go in, lowercase, or empty to find
	// the zone that holds each name at the provider.
	Zone string
	// Endpoint replaces the provider's API URL, for a sovereign cloud or a
	// test, or is empty.
	Endpoint string
	// Authority replaces Azure's token endpoint, https://login.microsoftonline.com,
	// or is empty. Only for DNSProviderAzure.
	Authority string
	// CABundle is the path of the PEM file that verifies the provider's
	// certificates, or empty for the system roots.
	CABundle string
	// RootCAs verify the provider's certificates. Nil means the system roots.
	RootCAs *x509.CertPool
	// Resolvers are the name servers, as IP address and port, the record is
	// checked on before validation is requested. Empty checks the zone's
	// authoritative name servers.
	Resolvers []string
	// PropagationTimeout is how long the record may take to appear.
	PropagationTimeout time.Duration
	// TenantID, ClientID, SubscriptionID, and ResourceGroup locate the
	// zone at Azure. Only for DNSProviderAzure.
	TenantID, ClientID, SubscriptionID, ResourceGroup string
	// Project is the Google Cloud project that holds the zone, or empty for
	// the service account key's project. Only for DNSProviderGoogle.
	Project string
}

// Equal reports whether d and e configure the same DNS provider.
func (d DNS) Equal(e DNS) bool {
	return d.Provider == e.Provider && maps.Equal(d.Credentials, e.Credentials) &&
		d.Zone == e.Zone && d.Endpoint == e.Endpoint && d.Authority == e.Authority &&
		d.CABundle == e.CABundle && d.RootCAs.Equal(e.RootCAs) &&
		slices.Equal(d.Resolvers, e.Resolvers) && d.PropagationTimeout == e.PropagationTimeout &&
		d.TenantID == e.TenantID && d.ClientID == e.ClientID &&
		d.SubscriptionID == e.SubscriptionID && d.ResourceGroup == e.ResourceGroup &&
		d.Project == e.Project
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
	// Env is the plugin's environment beyond what the Plugin Host sets, as
	// "NAME=value" entries sorted by name. It never contains GODEBUG.
	Env []string
}

// Equal reports whether a and b configure the same Backend Plugin.
func (a BackendPlugin) Equal(b BackendPlugin) bool {
	return a.Name == b.Name && a.Path == b.Path && a.SHA256 == b.SHA256 && a.User == b.User &&
		a.InsecureShareCoreUser == b.InsecureShareCoreUser && slices.Equal(a.Env, b.Env)
}

// Admin configures the admin API.
type Admin struct {
	// Socket is the unix socket path of the admin API.
	Socket string
	// AllowedUIDs are the local users allowed to connect to Socket.
	AllowedUIDs []int
	// Listen is the IP address and port of the remote admin listener, or
	// empty for none. It serves TLS from TLS and admits only clients
	// presenting a certificate TLS.ClientCAs signed.
	Listen string
	// TLS is what the remote admin listener serves and admits. Set exactly
	// when Listen is.
	TLS *AdminTLS
}

// Equal reports whether a and b configure the same admin API.
func (a Admin) Equal(b Admin) bool {
	return a.Socket == b.Socket && a.Listen == b.Listen &&
		slices.Equal(slices.Sorted(slices.Values(a.AllowedUIDs)), slices.Sorted(slices.Values(b.AllowedUIDs))) &&
		(a.TLS == nil) == (b.TLS == nil) && (a.TLS == nil || a.TLS.Equal(*b.TLS))
}

// AdminTLS is where the remote admin listener's certificate and key live,
// as Courier Keys like the Agent API's (ADR-0023), and which CA signs the
// client certificates it admits.
type AdminTLS struct {
	// Certificate holds the certificate chain as PEM, leaf first. It may be
	// the Agent API's certificate, in which case the listener shares it.
	Certificate CourierKey
	// Key holds the leaf's private key as PEM.
	Key CourierKey
	// ClientCA is the path of the PEM file of CA certificates that client
	// certificates must chain to.
	ClientCA string
	// ClientCAs is ClientCA loaded.
	ClientCAs *x509.CertPool
}

// Equal reports whether a and b configure the same TLS.
func (a AdminTLS) Equal(b AdminTLS) bool {
	return a.Certificate == b.Certificate && a.Key == b.Key &&
		a.ClientCA == b.ClientCA && a.ClientCAs.Equal(b.ClientCAs)
}

// SharesAgentCertificate reports whether the remote admin listener serves
// the Agent API's certificate and key.
func (c *Config) SharesAgentCertificate() bool {
	return c.Admin.TLS != nil && c.AgentAPI.TLS != nil &&
		c.Admin.TLS.Certificate == c.AgentAPI.TLS.Certificate && c.Admin.TLS.Key == c.AgentAPI.TLS.Key
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
	Listen string        `yaml:"listen"`
	Socket string        `yaml:"socket"`
	TLS    *fileAgentTLS `yaml:"tls"`
}

type fileAgentTLS struct {
	Certificate *fileCourierKey `yaml:"certificate"`
	Key         *fileCourierKey `yaml:"key"`
	ACME        *fileACME       `yaml:"acme"`
}

type fileACME struct {
	Directory  string          `yaml:"directory"`
	Domains    []string        `yaml:"domains"`
	Contact    string          `yaml:"contact"`
	Challenge  string          `yaml:"challenge"`
	HTTPListen string          `yaml:"http_listen"`
	DNS        *fileDNS        `yaml:"dns"`
	CABundle   string          `yaml:"ca_bundle"`
	AccountKey *fileCourierKey `yaml:"account_key"`
	EAB        *fileEAB        `yaml:"external_account_binding"`
}

type fileDNS struct {
	Provider           string                     `yaml:"provider"`
	Credentials        map[string]*fileCourierKey `yaml:"credentials"`
	Zone               string                     `yaml:"zone"`
	Endpoint           string                     `yaml:"endpoint"`
	Authority          string                     `yaml:"authority"`
	CABundle           string                     `yaml:"ca_bundle"`
	Resolvers          []string                   `yaml:"resolvers"`
	PropagationTimeout string                     `yaml:"propagation_timeout"`
	TenantID           string                     `yaml:"tenant_id"`
	ClientID           string                     `yaml:"client_id"`
	SubscriptionID     string                     `yaml:"subscription_id"`
	ResourceGroup      string                     `yaml:"resource_group"`
	Project            string                     `yaml:"project"`
}

type fileEAB struct {
	KeyID   string          `yaml:"key_id"`
	HMACKey *fileCourierKey `yaml:"hmac_key"`
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
	Path                  string            `yaml:"path"`
	SHA256                string            `yaml:"sha256"`
	User                  string            `yaml:"user"`
	InsecureShareCoreUser bool              `yaml:"insecure_share_core_user"`
	Env                   map[string]string `yaml:"env"`
}

type fileAdmin struct {
	Socket      string        `yaml:"socket"`
	AllowedUIDs *[]int        `yaml:"allowed_uids"` // nil when omitted
	Listen      string        `yaml:"listen"`
	TLS         *fileAdminTLS `yaml:"tls"`
}

type fileAdminTLS struct {
	Certificate *fileCourierKey `yaml:"certificate"`
	Key         *fileCourierKey `yaml:"key"`
	ClientCA    string          `yaml:"client_ca"`
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
	if err := raw.Admin.validateListener(cfg, baseDir); err != nil {
		return nil, err
	}
	if err := raw.AgentAPI.validate(cfg, baseDir); err != nil {
		return nil, err
	}
	if err := raw.Audit.validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validateListener sets cfg.Admin.Listen and cfg.Admin.TLS. It needs cfg's
// Backend Plugins and Secret Names already validated.
func (a fileAdmin) validateListener(cfg *Config, baseDir string) error {
	switch {
	case a.Listen == "" && a.TLS == nil:
		return nil
	case a.Listen == "":
		return errors.New("admin.tls needs admin.listen: the admin socket serves plain HTTP to local users")
	case a.TLS == nil:
		return fmt.Errorf("admin.listen %q is a network listener, so admin.tls is required: remote administration takes a client certificate and the Operator Credential", a.Listen)
	}
	if _, err := netip.ParseAddrPort(a.Listen); err != nil {
		return fmt.Errorf("admin.listen %q must be an IP address and port, such as 0.0.0.0:8300", a.Listen)
	}
	cert, err := a.TLS.Certificate.validateCourierKey("admin.tls.certificate", "the remote admin listener's TLS certificate", cfg)
	if err != nil {
		return err
	}
	key, err := a.TLS.Key.validateCourierKey("admin.tls.key", "the remote admin listener's TLS key", cfg)
	if err != nil {
		return err
	}
	if cert == key {
		return errors.New("admin.tls.certificate and admin.tls.key name the same location; each Courier Key needs its own")
	}
	if a.TLS.ClientCA == "" {
		return errors.New("admin.tls.client_ca is required: the PEM file of CA certificates that Operator client certificates must chain to")
	}
	clientCA := resolve(baseDir, a.TLS.ClientCA)
	pool, err := LoadCABundle(clientCA)
	if err != nil {
		return fmt.Errorf("admin.tls.client_ca: %w", err)
	}
	cfg.Admin.Listen = a.Listen
	cfg.Admin.TLS = &AdminTLS{Certificate: cert, Key: key, ClientCA: clientCA, ClientCAs: pool}
	return nil
}

// validate sets cfg.AgentAPI. It needs cfg's admin socket and listener,
// Backend Plugins, and Secret Names already validated.
func (a fileAgentAPI) validate(cfg *Config, baseDir string) error {
	switch {
	case a.Listen != "" && a.Socket != "":
		return errors.New("set agent_api.listen or agent_api.socket, not both")
	case a.TLS != nil && a.Listen == "":
		return errors.New("agent_api.tls needs agent_api.listen: a unix socket serves plain HTTP")
	}
	if a.Listen != "" {
		addr, err := netip.ParseAddrPort(a.Listen)
		if err != nil {
			return fmt.Errorf("agent_api.listen %q must be an IP address and port, such as 127.0.0.1:8200", a.Listen)
		}
		// TLS is required on every listener except loopback and unix
		// sockets (ADR-0006).
		if a.TLS == nil && !addr.Addr().Unmap().IsLoopback() {
			return fmt.Errorf("agent_api.listen %q is not a loopback address, so agent_api.tls is required: Agent Tokens and Reveal Deliveries never cross a network in plaintext", a.Listen)
		}
		if sameBind(a.Listen, cfg.Admin.Listen) {
			return fmt.Errorf("agent_api.listen %q is the remote admin listener's address (admin.listen); give the Agent API its own", a.Listen)
		}
		cfg.AgentAPI.Listen = a.Listen
	}
	if a.Socket != "" {
		cfg.AgentAPI.Socket = resolve(baseDir, a.Socket)
		if cfg.AgentAPI.Socket == cfg.Admin.Socket {
			return fmt.Errorf("agent_api.socket %s is the admin socket; give the Agent API its own", cfg.AgentAPI.Socket)
		}
	}
	if a.TLS != nil {
		cert, err := a.TLS.Certificate.validateCourierKey("agent_api.tls.certificate", "the Agent API's TLS certificate", cfg)
		if err != nil {
			return err
		}
		key, err := a.TLS.Key.validateCourierKey("agent_api.tls.key", "the Agent API's TLS key", cfg)
		if err != nil {
			return err
		}
		cfg.AgentAPI.TLS = &AgentTLS{Certificate: cert, Key: key}
		keys := []namedCourierKey{{"agent_api.tls.certificate", cert}, {"agent_api.tls.key", key}}
		if a.TLS.ACME != nil {
			acme, err := a.TLS.ACME.validate(cfg, baseDir, a.Listen)
			if err != nil {
				return err
			}
			cfg.AgentAPI.TLS.ACME = &acme
			keys = append(keys, namedCourierKey{"agent_api.tls.acme.account_key", acme.AccountKey})
			if acme.EAB != nil {
				keys = append(keys, namedCourierKey{"agent_api.tls.acme.external_account_binding.hmac_key", acme.EAB.HMACKey})
			}
			if acme.DNS != nil {
				for _, field := range slices.Sorted(maps.Keys(acme.DNS.Credentials)) {
					keys = append(keys, namedCourierKey{"agent_api.tls.acme.dns.credentials." + field, acme.DNS.Credentials[field]})
				}
			}
		}
		// The remote admin listener shares the pair whole, or names its own
		// locations; ACME writes the Agent API's, so a partial overlap would
		// pair a certificate with the wrong key or overwrite the admin pair.
		if admin := cfg.Admin.TLS; admin != nil && !cfg.SharesAgentCertificate() {
			if admin.Certificate == cert || admin.Key == key {
				return errors.New("admin.tls shares only one of agent_api.tls.certificate and agent_api.tls.key; name both to share the Agent API's certificate, or neither")
			}
			keys = append(keys, namedCourierKey{"admin.tls.certificate", admin.Certificate}, namedCourierKey{"admin.tls.key", admin.Key})
		}
		// ACME writes the certificate and key locations, so each Courier
		// Key needs its own.
		for i, k := range keys {
			for _, other := range keys[:i] {
				if k.key == other.key {
					return fmt.Errorf("%s and %s name the same location; each Courier Key needs its own", other.name, k.name)
				}
			}
		}
	}
	return nil
}

type namedCourierKey struct {
	name string
	key  CourierKey
}

// sameBind reports whether two IP address and port strings would bind the
// same socket: the same port, on the same address or a wildcard.
func sameBind(a, b string) bool {
	x, errX := netip.ParseAddrPort(a)
	y, errY := netip.ParseAddrPort(b)
	if errX != nil || errY != nil {
		return a == b
	}
	// Port 0 asks the kernel for a free port, so it never collides.
	return x.Port() == y.Port() && x.Port() != 0 &&
		(x.Addr().IsUnspecified() || y.Addr().IsUnspecified() || x.Addr().Unmap() == y.Addr().Unmap())
}

// domainPattern is a DNS name ACME can issue for: lowercase labels of
// letters, digits, and hyphens, at least two of them.
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (a fileACME) validate(cfg *Config, baseDir, listen string) (ACME, error) {
	out := ACME{Directory: DefaultACMEDirectory, Challenge: ChallengeTLSALPN01}
	if len(a.Domains) == 0 {
		return ACME{}, errors.New("agent_api.tls.acme.domains is required: the DNS names the certificate is issued for")
	}
	if a.Challenge != "" {
		if !slices.Contains([]string{ChallengeTLSALPN01, ChallengeHTTP01, ChallengeDNS01}, a.Challenge) {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.challenge %q is not a challenge type (want %s, %s, or %s)", a.Challenge, ChallengeTLSALPN01, ChallengeHTTP01, ChallengeDNS01)
		}
		out.Challenge = a.Challenge
	}
	for _, d := range a.Domains {
		domain := strings.ToLower(strings.TrimSuffix(d, "."))
		name, wildcard := strings.CutPrefix(domain, "*.")
		switch {
		case wildcard && out.Challenge != ChallengeDNS01:
			return ACME{}, fmt.Errorf("agent_api.tls.acme.domains: %q is a wildcard, which only %s can validate; set challenge: %s", d, ChallengeDNS01, ChallengeDNS01)
		case net.ParseIP(name) != nil || !domainPattern.MatchString(name) ||
			(!strings.Contains(name, ".") && (name != "localhost" || wildcard)):
			return ACME{}, fmt.Errorf("agent_api.tls.acme.domains: %q is not a DNS name", d)
		}
		if slices.Contains(out.Domains, domain) {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.domains lists %q more than once", d)
		}
		out.Domains = append(out.Domains, domain)
	}
	if a.Directory != "" {
		u, err := url.Parse(a.Directory)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.directory %q must be an https URL; omit it for Let's Encrypt", a.Directory)
		}
		out.Directory = a.Directory
	}
	if a.Contact != "" {
		contact := a.Contact
		if !strings.Contains(contact, ":") {
			contact = "mailto:" + contact
		}
		if u, err := url.Parse(contact); err != nil || u.Scheme != "mailto" || u.Opaque == "" || !strings.Contains(u.Opaque, "@") {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.contact %q must be an email address", a.Contact)
		}
		out.Contact = contact
	}
	switch {
	case out.Challenge == ChallengeHTTP01:
		out.HTTPListen = DefaultACMEHTTPListen
		if a.HTTPListen != "" {
			if _, err := netip.ParseAddrPort(a.HTTPListen); err != nil {
				return ACME{}, fmt.Errorf("agent_api.tls.acme.http_listen %q must be an IP address and port, such as 0.0.0.0:80", a.HTTPListen)
			}
			out.HTTPListen = a.HTTPListen
		}
		if sameBind(out.HTTPListen, listen) {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.http_listen %q is the Agent API's own address; HTTP-01 is validated over plain HTTP on a different port", out.HTTPListen)
		}
		if sameBind(out.HTTPListen, cfg.Admin.Listen) {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.http_listen %q is the remote admin listener's address (admin.listen); HTTP-01 needs its own port", out.HTTPListen)
		}
	case a.HTTPListen != "":
		return ACME{}, fmt.Errorf("agent_api.tls.acme.http_listen is only for challenge %s", ChallengeHTTP01)
	}
	switch {
	case out.Challenge == ChallengeDNS01:
		if a.DNS == nil {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.dns is required for challenge %s: the DNS provider that sets the validation records", ChallengeDNS01)
		}
		dns, err := a.DNS.validate(cfg, baseDir, out.Domains)
		if err != nil {
			return ACME{}, err
		}
		out.DNS = &dns
	case a.DNS != nil:
		return ACME{}, fmt.Errorf("agent_api.tls.acme.dns is only for challenge %s", ChallengeDNS01)
	}
	if a.CABundle != "" {
		out.CABundle = resolve(baseDir, a.CABundle)
		pool, err := LoadCABundle(out.CABundle)
		if err != nil {
			return ACME{}, fmt.Errorf("agent_api.tls.acme.ca_bundle: %w", err)
		}
		out.RootCAs = pool
	}
	accountKey, err := a.AccountKey.validateCourierKey("agent_api.tls.acme.account_key", "the ACME account key", cfg)
	if err != nil {
		return ACME{}, err
	}
	out.AccountKey = accountKey
	if a.EAB != nil {
		if a.EAB.KeyID == "" {
			return ACME{}, errors.New("agent_api.tls.acme.external_account_binding.key_id is required")
		}
		hmacKey, err := a.EAB.HMACKey.validateCourierKey("agent_api.tls.acme.external_account_binding.hmac_key", "the ACME External Account Binding key", cfg)
		if err != nil {
			return ACME{}, err
		}
		out.EAB = &ExternalAccountBinding{KeyID: a.EAB.KeyID, HMACKey: hmacKey}
	}
	return out, nil
}

// dnsProviderSettings are the config keys each DNS provider takes beside
// the common ones, and whether each is required.
var dnsProviderSettings = map[string]map[string]bool{
	DNSProviderCloudflare: {},
	DNSProviderRoute53:    {},
	DNSProviderAzure:      {"tenant_id": true, "client_id": true, "subscription_id": true, "resource_group": true, "authority": false},
	DNSProviderGoogle:     {"project": false},
}

func (d fileDNS) validate(cfg *Config, baseDir string, domains []string) (DNS, error) {
	const prefix = "agent_api.tls.acme.dns"
	providers := strings.Join(slices.Sorted(maps.Keys(DNSProviders)), ", ")
	if d.Provider == "" {
		return DNS{}, fmt.Errorf("%s.provider is required: one of %s", prefix, providers)
	}
	fields, ok := DNSProviders[d.Provider]
	if !ok {
		return DNS{}, fmt.Errorf("%s.provider %q is not a built-in DNS provider (want one of %s)", prefix, d.Provider, providers)
	}
	out := DNS{Provider: d.Provider, Credentials: map[string]CourierKey{}, PropagationTimeout: DefaultDNSPropagationTimeout}
	for _, field := range slices.Sorted(maps.Keys(d.Credentials)) {
		if !slices.Contains(fields, field) {
			return DNS{}, fmt.Errorf("%s.credentials.%s is not a credential of %s (want %s)", prefix, field, d.Provider, strings.Join(fields, ", "))
		}
	}
	for _, field := range fields {
		key, err := d.Credentials[field].validateCourierKey(prefix+".credentials."+field, "the "+d.Provider+" DNS credential "+field, cfg)
		if err != nil {
			return DNS{}, err
		}
		out.Credentials[field] = key
	}
	if d.Zone != "" {
		zone := strings.ToLower(strings.TrimSuffix(d.Zone, "."))
		if !domainPattern.MatchString(zone) || !strings.Contains(zone, ".") {
			return DNS{}, fmt.Errorf("%s.zone %q is not a DNS zone name", prefix, d.Zone)
		}
		for _, domain := range domains {
			if name := strings.TrimPrefix(domain, "*."); name != zone && !strings.HasSuffix(name, "."+zone) {
				return DNS{}, fmt.Errorf("%s.zone %q does not hold %s", prefix, d.Zone, domain)
			}
		}
		out.Zone = zone
	}
	for _, u := range []struct{ key, value string }{{"endpoint", d.Endpoint}, {"authority", d.Authority}} {
		if u.value == "" {
			continue
		}
		parsed, err := url.Parse(u.value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return DNS{}, fmt.Errorf("%s.%s %q must be an https URL without query, fragment, or user information", prefix, u.key, u.value)
		}
	}
	out.Endpoint = strings.TrimSuffix(d.Endpoint, "/")
	out.Authority = strings.TrimSuffix(d.Authority, "/")
	if d.CABundle != "" {
		out.CABundle = resolve(baseDir, d.CABundle)
		pool, err := LoadCABundle(out.CABundle)
		if err != nil {
			return DNS{}, fmt.Errorf("%s.ca_bundle: %w", prefix, err)
		}
		out.RootCAs = pool
	}
	for _, r := range d.Resolvers {
		addrPort, err := netip.ParseAddrPort(r)
		if err != nil {
			addr, err := netip.ParseAddr(r)
			if err != nil {
				return DNS{}, fmt.Errorf("%s.resolvers: %q must be an IP address with an optional port, such as 192.0.2.53 or 192.0.2.53:5353", prefix, r)
			}
			addrPort = netip.AddrPortFrom(addr, 53)
		}
		out.Resolvers = append(out.Resolvers, addrPort.String())
	}
	if d.PropagationTimeout != "" {
		t, err := time.ParseDuration(d.PropagationTimeout)
		switch {
		case err != nil:
			return DNS{}, fmt.Errorf("%s.propagation_timeout %q is not a duration such as 2m", prefix, d.PropagationTimeout)
		case t < time.Second || t > 30*time.Minute:
			return DNS{}, fmt.Errorf("%s.propagation_timeout %q must be from 1s to 30m", prefix, d.PropagationTimeout)
		}
		out.PropagationTimeout = t
	}
	settings := map[string]string{
		"tenant_id": d.TenantID, "client_id": d.ClientID, "subscription_id": d.SubscriptionID,
		"resource_group": d.ResourceGroup, "project": d.Project, "authority": d.Authority,
	}
	takes := dnsProviderSettings[d.Provider]
	for _, key := range slices.Sorted(maps.Keys(settings)) {
		required, ok := takes[key]
		switch {
		case !ok && settings[key] != "":
			return DNS{}, fmt.Errorf("%s.%s is not a setting of %s", prefix, key, d.Provider)
		case required && settings[key] == "":
			return DNS{}, fmt.Errorf("%s.%s is required for %s", prefix, key, d.Provider)
		}
	}
	out.TenantID, out.ClientID, out.SubscriptionID, out.ResourceGroup, out.Project =
		d.TenantID, d.ClientID, d.SubscriptionID, d.ResourceGroup, d.Project
	return out, nil
}

// LoadCABundle reads the CA certificates in the PEM file at path.
func LoadCABundle(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s holds no certificates", path)
	}
	return pool, nil
}

// validate sets cfg.Audit. It needs cfg's Backend Plugins, Secret Names, and
// Agent API already validated.
func (a fileAudit) validate(cfg *Config) error {
	if a.SigningKey == nil {
		if cfg.AgentAPI.Served() {
			return errors.New("audit.signing_key is required with agent_api: every Delivery attempt is audited, and TrustedCourier signs the audit chain with that Courier Key")
		}
	} else {
		key, err := a.SigningKey.validateCourierKey("audit.signing_key", "the audit signing key", cfg)
		if err != nil {
			return err
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

// validateCourierKey validates the Courier Key at config key configKey,
// described as what, against cfg's Backend Plugins and Secret Names. k may
// be nil, when the key is missing.
func (k *fileCourierKey) validateCourierKey(configKey, what string, cfg *Config) (CourierKey, error) {
	switch {
	case k == nil || k.Backend == "":
		return CourierKey{}, fmt.Errorf("%s: backend is required", configKey)
	case k.Location == "":
		return CourierKey{}, fmt.Errorf("%s: location is required", configKey)
	}
	if err := client.ValidateLocation(k.Location); err != nil {
		return CourierKey{}, fmt.Errorf("%s: %w", configKey, err)
	}
	if _, ok := cfg.BackendPlugins[k.Backend]; !ok {
		return CourierKey{}, fmt.Errorf("%s: unknown backend %q; name one of backend_plugins", configKey, k.Backend)
	}
	// A Courier Key is never delivered to Agents.
	for _, name := range slices.Sorted(maps.Keys(cfg.Secrets)) {
		if s := cfg.Secrets[name]; s.Backend == k.Backend && s.Location == k.Location {
			return CourierKey{}, fmt.Errorf("Secret Name %q maps to the location of %s; a Courier Key is never delivered to Agents", name, what)
		}
	}
	return CourierKey{Backend: k.Backend, Location: k.Location}, nil
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
		pool, err := LoadCABundle(resolve(baseDir, u.CABundle))
		if err != nil {
			return Upstream{}, fmt.Errorf("Upstream %q: ca_bundle: %w", name, err)
		}
		out.RootCAs = pool
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
	env, err := p.validateEnv(name)
	if err != nil {
		return BackendPlugin{}, err
	}
	return BackendPlugin{
		Name:                  name,
		Path:                  resolve(baseDir, p.Path),
		SHA256:                strings.ToLower(p.SHA256),
		User:                  p.User,
		InsecureShareCoreUser: p.InsecureShareCoreUser,
		Env:                   env,
	}, nil
}

// pluginEnvNamePattern is what a portable environment variable name looks
// like.
var pluginEnvNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// maxEnvValueBytes bounds one environment value a plugin is given.
const maxEnvValueBytes = 4096

// validateEnv returns the plugin's configured environment as sorted
// "NAME=value" entries. GODEBUG is reserved: the Plugin Host sets it to
// carry the server's FIPS 140-3 mode (ADR-0027).
func (p fileBackendPlugin) validateEnv(name string) ([]string, error) {
	env := make([]string, 0, len(p.Env))
	for _, k := range slices.Sorted(maps.Keys(p.Env)) {
		v := p.Env[k]
		switch {
		case !pluginEnvNamePattern.MatchString(k):
			return nil, fmt.Errorf("Backend Plugin %q: env %q: use up to 128 letters, digits, and '_', not starting with a digit", name, k)
		case k == "GODEBUG":
			return nil, fmt.Errorf("Backend Plugin %q: env GODEBUG is set by the server to carry its FIPS 140-3 mode and cannot be configured", name)
		case len(v) > maxEnvValueBytes:
			return nil, fmt.Errorf("Backend Plugin %q: env %s is %d bytes, over the %d byte limit", name, k, len(v), maxEnvValueBytes)
		case strings.ContainsFunc(v, unicode.IsControl):
			return nil, fmt.Errorf("Backend Plugin %q: env %s contains a control character", name, k)
		}
		env = append(env, k+"="+v)
	}
	return env, nil
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

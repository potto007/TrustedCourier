// Package bootstrap initializes the bundled OpenBao for tc init (ADR-0008):
// it writes the static seal key, initializes OpenBao with recovery keys,
// and issues the OpenBao Backend Plugin its token. It speaks OpenBao's HTTP
// API with the standard library only, as the plugin does (ADR-0028).
package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
)

// SealKeySize is the static seal's key size: AES-256-GCM.
const SealKeySize = 32

// Plugin policy and mount names in OpenBao.
const (
	// PolicyName is the OpenBao policy the Backend Plugin's token carries.
	PolicyName = "trustedcourier"
	// KVMount is the KV v2 mount tc init creates for Secrets and Courier
	// Keys, the one OpenBao's dev mode ships with.
	KVMount = "secret"
)

// pluginPolicy is what the OpenBao Backend Plugin needs and nothing more:
// Secrets and Courier Keys under the KV mount (ADR-0028). Listing metadata
// serves the plugin's List.
const pluginPolicy = `path "` + KVMount + `/data/*"     { capabilities = ["read", "create", "update"] }
path "` + KVMount + `/metadata/*" { capabilities = ["list", "read"] }
`

// EnsureSealKey returns the static seal key at path, generating and writing
// it, owner-only, when there is none. created reports whether it was
// generated now.
func EnsureSealKey(path string) (key []byte, created bool, err error) {
	key, err = os.ReadFile(path)
	switch {
	case err == nil:
		if len(key) != SealKeySize {
			return nil, false, fmt.Errorf("the seal key file %s holds %d bytes, not the %d of an AES-256 key", path, len(key), SealKeySize)
		}
		return key, false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, false, fmt.Errorf("read the seal key file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create the seal key directory: %w", err)
	}
	key = make([]byte, SealKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("create the seal key file: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, false, fmt.Errorf("write the seal key file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, false, fmt.Errorf("write the seal key file: %w", err)
	}
	return key, true, nil
}

// Client talks to one OpenBao.
type Client struct {
	Address string
	// Token is sent on every request; empty for unauthenticated calls.
	Token string
	http  *http.Client
}

// NewClient returns a client for the OpenBao at address, verifying its TLS
// certificate against the system roots or the CA bundle at caCertFile when
// set. Redirects are never followed.
func NewClient(address, caCertFile string) (*Client, error) {
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		return nil, fmt.Errorf("BAO_ADDR %q must start with http:// or https://", address)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caCertFile != "" {
		pool, err := config.LoadCABundle(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("BAO_CACERT: %w", err)
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		Address: strings.TrimRight(address, "/"),
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Health is what sys/health reports.
type Health struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Version     string `json:"version"`
}

// Health asks OpenBao whether it is initialized and unsealed. An OpenBao
// that does not answer is an error.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var h Health
	status, body, err := c.call(ctx, http.MethodGet, "sys/health?standbyok=true&perfstandbyok=true&uninitcode=200&sealedcode=200", nil)
	if err != nil {
		return h, err
	}
	if status != http.StatusOK {
		return h, fmt.Errorf("sys/health: %s", apiError(status, body))
	}
	if err := json.Unmarshal(body, &h); err != nil {
		return h, fmt.Errorf("sys/health: %w", err)
	}
	return h, nil
}

// WaitHealth polls Health until OpenBao answers or ctx is done. It calls
// waiting once, before the first retry, so a caller can tell the Operator
// what it is waiting for.
func (c *Client) WaitHealth(ctx context.Context, waiting func(err error)) (Health, error) {
	var told bool
	for {
		h, err := c.Health(ctx)
		if err == nil {
			return h, nil
		}
		if !told {
			waiting(err)
			told = true
		}
		select {
		case <-ctx.Done():
			return h, fmt.Errorf("OpenBao at %s did not answer: %w", c.Address, err)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// InitResult is what initializing OpenBao returned, the only time it exists.
type InitResult struct {
	RecoveryKeys []string `json:"recovery_keys_base64"`
	RootToken    string   `json:"root_token"`
}

// Init initializes an OpenBao whose seal is an auto seal, such as the
// static seal, splitting its recovery key into shares of which threshold
// are needed.
func (c *Client) Init(ctx context.Context, shares, threshold int) (InitResult, error) {
	var out InitResult
	status, body, err := c.call(ctx, http.MethodPut, "sys/init", map[string]any{
		"recovery_shares":    shares,
		"recovery_threshold": threshold,
	})
	if err != nil {
		return out, err
	}
	if status != http.StatusOK {
		return out, fmt.Errorf("sys/init: %s", apiError(status, body))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("sys/init: %w", err)
	}
	if out.RootToken == "" || len(out.RecoveryKeys) != shares {
		return out, fmt.Errorf("sys/init returned %d recovery keys and %s root token", len(out.RecoveryKeys), present(out.RootToken))
	}
	return out, nil
}

func present(s string) string {
	if s == "" {
		return "no"
	}
	return "a"
}

// EnsureKVMount mounts a KV v2 secrets engine at KVMount unless one is
// there. It reports whether it created the mount.
func (c *Client) EnsureKVMount(ctx context.Context) (created bool, err error) {
	status, body, err := c.call(ctx, http.MethodGet, "sys/mounts/"+KVMount, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		var mount struct {
			Type    string `json:"type"`
			Options struct {
				Version string `json:"version"`
			} `json:"options"`
		}
		if err := json.Unmarshal(body, &mount); err != nil {
			return false, fmt.Errorf("sys/mounts/%s: %w", KVMount, err)
		}
		if mount.Type != "kv" && mount.Type != "generic" {
			return false, fmt.Errorf("%s/ is mounted as %q, not a KV secrets engine", KVMount, mount.Type)
		}
		return false, nil
	case http.StatusNotFound, http.StatusBadRequest:
		// Not mounted: OpenBao answers 400 "No secret engine mount at ..."
		// on some versions and 404 on others.
	default:
		return false, fmt.Errorf("sys/mounts/%s: %s", KVMount, apiError(status, body))
	}
	status, body, err = c.call(ctx, http.MethodPost, "sys/mounts/"+KVMount, map[string]any{
		"type":    "kv",
		"options": map[string]any{"version": "2"},
	})
	if err != nil {
		return false, err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return false, fmt.Errorf("mount %s/: %s", KVMount, apiError(status, body))
	}
	return true, nil
}

// WritePluginPolicy writes the policy the Backend Plugin's token carries.
func (c *Client) WritePluginPolicy(ctx context.Context) error {
	status, body, err := c.call(ctx, http.MethodPut, "sys/policies/acl/"+PolicyName, map[string]any{"policy": pluginPolicy})
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return fmt.Errorf("write policy %s: %s", PolicyName, apiError(status, body))
	}
	return nil
}

// PluginToken is the token issued to the Backend Plugin.
type PluginToken struct {
	// Token is the only copy of the value.
	Token string
	// TTL is how long it lives; zero means it does not expire.
	TTL time.Duration
}

// CreatePluginToken issues the Backend Plugin a token carrying PolicyName,
// living for ttl, or as long as OpenBao allows when ttl is longer than
// that. Zero asks for a token that does not expire, which OpenBao caps to
// its maximum lease.
func (c *Client) CreatePluginToken(ctx context.Context, ttl time.Duration) (PluginToken, error) {
	req := map[string]any{
		"policies":     []string{PolicyName},
		"display_name": "trustedcourier-backend-plugin",
		"renewable":    true,
		// An orphan, so revoking the root token that made it, as an
		// Operator should once Secrets are stored, does not revoke it.
		"no_parent": true,
	}
	if ttl > 0 {
		req["ttl"] = ttl.String()
	}
	status, body, err := c.call(ctx, http.MethodPost, "auth/token/create", req)
	if err != nil {
		return PluginToken{}, err
	}
	if status != http.StatusOK {
		return PluginToken{}, fmt.Errorf("auth/token/create: %s", apiError(status, body))
	}
	var resp struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return PluginToken{}, fmt.Errorf("auth/token/create: %w", err)
	}
	if resp.Auth.ClientToken == "" {
		return PluginToken{}, errors.New("auth/token/create returned no token")
	}
	return PluginToken{Token: resp.Auth.ClientToken, TTL: time.Duration(resp.Auth.LeaseDuration) * time.Second}, nil
}

// call makes one API call and returns the status and body. A status of 0
// with an error means OpenBao did not answer.
func (c *Client) call(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Address+"/v1/"+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, data, nil
}

// apiError describes an OpenBao error response by its status and the
// errors it lists, never the whole body.
func apiError(status int, body []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		return fmt.Sprintf("status %d: %s", status, strings.Join(e.Errors, "; "))
	}
	return fmt.Sprintf("status %d", status)
}

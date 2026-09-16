package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client calls the admin API over its unix socket or its remote listener.
type Client struct {
	base       string
	credential string
	http       *http.Client
}

// NewClient returns a Client for the admin socket that authenticates with
// credential.
func NewClient(socket, credential string) *Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &Client{
		base:       "http://trustedcourier",
		credential: credential,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// NewRemoteClient returns a Client for the remote admin listener at baseURL,
// an https URL such as https://courier.example.com:8300, presenting the
// client certificate and trusting rootCAs (nil for the system roots), that
// authenticates with credential.
func NewRemoteClient(baseURL string, client tls.Certificate, rootCAs *x509.CertPool, credential string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("remote admin URL %q must be https://host:port, with no path", baseURL)
	}
	return &Client{
		base:       "https://" + u.Host,
		credential: credential,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:   tls.VersionTLS12,
					Certificates: []tls.Certificate{client},
					RootCAs:      rootCAs,
				},
				ForceAttemptHTTP2: true,
				DialContext:       (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}, nil
}

// ListAgentTokens lists every Agent Token.
func (c *Client) ListAgentTokens(ctx context.Context) ([]AgentToken, error) {
	var tokens []AgentToken
	err := c.do(ctx, http.MethodGet, "/v1/agent-tokens", nil, &tokens)
	return tokens, err
}

// IssueAgentToken issues an Agent Token.
func (c *Client) IssueAgentToken(ctx context.Context, req IssueAgentTokenRequest) (IssuedAgentToken, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return IssuedAgentToken{}, err
	}
	var issued IssuedAgentToken
	err = c.do(ctx, http.MethodPost, "/v1/agent-tokens", bytes.NewReader(body), &issued)
	return issued, err
}

// Status returns the server's operational state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var status Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &status)
	return status, err
}

// VerifyAudit checks the audit chain.
func (c *Client) VerifyAudit(ctx context.Context) (AuditVerification, error) {
	var v AuditVerification
	err := c.do(ctx, http.MethodPost, "/v1/audit/verify", nil, &v)
	return v, err
}

// ReloadConfig reloads the server's config file. On error the running config
// stays in effect.
func (c *Client) ReloadConfig(ctx context.Context) (ConfigReload, error) {
	var reloaded ConfigReload
	err := c.do(ctx, http.MethodPost, "/v1/config/reload", nil, &reloaded)
	return reloaded, err
}

// SecretNameEnv returns the environment an Agent needs to use secretName
// through Proxy Delivery to upstream, which may be empty when the Secret Name
// has only one Upstream.
func (c *Client) SecretNameEnv(ctx context.Context, secretName, upstream string) (SecretNameEnv, error) {
	path := "/v1/secret-names/" + url.PathEscape(secretName) + "/env"
	if upstream != "" {
		path += "?" + url.Values{"upstream": {upstream}}.Encode()
	}
	var env SecretNameEnv
	err := c.do(ctx, http.MethodGet, path, nil, &env)
	return env, err
}

// RevokeAgentToken revokes the Agent Token with id.
func (c *Client) RevokeAgentToken(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/agent-tokens/"+url.PathEscape(id), nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		var e errorResponse
		if err := json.NewDecoder(resp.Body).Decode(&e); err != nil || e.Error == "" {
			return fmt.Errorf("admin API: %s", resp.Status)
		}
		return fmt.Errorf("admin API: %s", e.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("admin API: decode response: %w", err)
	}
	return nil
}

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client calls the admin API over its unix socket.
type Client struct {
	credential string
	http       *http.Client
}

// NewClient returns a Client for the admin socket that authenticates with
// credential.
func NewClient(socket, credential string) *Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &Client{
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

// RevokeAgentToken revokes the Agent Token with id.
func (c *Client) RevokeAgentToken(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/agent-tokens/"+url.PathEscape(id), nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://trustedcourier"+path, body)
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

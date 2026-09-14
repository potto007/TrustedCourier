// Package admin is the admin API: an HTTP API served on a unix socket, gated
// by a peer-credential check and the Operator Credential, plus the client tc
// uses to call it.
package admin

import "time"

// Agent Token statuses.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

// AgentToken is an Agent Token as the admin API lists it. It never carries
// the token value.
type AgentToken struct {
	ID         string     `json:"id"`
	Policies   []string   `json:"policies"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	// Status is active, expired, or revoked as of the server's clock.
	Status string `json:"status"`
}

// IssueAgentTokenRequest asks for a new Agent Token.
type IssueAgentTokenRequest struct {
	Policies  []string  `json:"policies"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssuedAgentToken is a new Agent Token, the only response that carries its
// value.
type IssuedAgentToken struct {
	AgentToken
	Token string `json:"token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

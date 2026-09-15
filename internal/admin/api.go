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

// Status is the server's operational state.
type Status struct {
	BackendPlugins []BackendPluginStatus `json:"backend_plugins"`
}

// BackendPluginStatus is one Backend Plugin's state.
type BackendPluginStatus struct {
	Name string `json:"name"`
	// State is starting, running, restarting, or stopped.
	State string `json:"state"`
	// PID is present only while the plugin runs.
	PID     int  `json:"pid,omitempty"`
	Healthy bool `json:"healthy"`
	// Detail is the plugin's health detail, or why it is not healthy.
	Detail       string   `json:"detail"`
	Capabilities []string `json:"capabilities"`
	Restarts     int      `json:"restarts"`
}

// AuditVerification is the result of checking the audit chain.
type AuditVerification struct {
	Intact bool `json:"intact"`
	// Records is how many Audit Records were found intact before the first
	// break, or in all when there is none.
	Records int64 `json:"records"`
	// Break is the first break in the chain, or null when it is intact.
	Break *AuditBreak `json:"break"`
}

// AuditBreak is the first place the audit chain does not hold.
type AuditBreak struct {
	Seq     int64  `json:"seq"`
	Problem string `json:"problem"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Package access issues and verifies the credentials that reach
// TrustedCourier: the Operator Credential and Agent Tokens. Both are stored
// only as SHA-256 hashes.
package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
)

// Credential prefixes let secret scanners recognize leaked values.
const (
	OperatorCredentialPrefix = "tcoc_"
	AgentTokenPrefix         = "tcat_"
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Service is the Access module.
type Service struct {
	db  *sql.DB
	cfg *config.Config
	now func() time.Time
}

// New returns a Service over db that checks Policy names against cfg.
func New(db *sql.DB, cfg *config.Config) *Service {
	return &Service{db: db, cfg: cfg, now: time.Now}
}

// EnsureOperatorCredential creates the Operator Credential on first boot and
// returns its value. It returns "" when the credential already exists, since
// the value is never recoverable after first boot.
func (s *Service) EnsureOperatorCredential(ctx context.Context) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operator_credential").Scan(&exists); err != nil {
		return "", fmt.Errorf("read Operator Credential: %w", err)
	}
	if exists > 0 {
		return "", nil
	}
	credential := OperatorCredentialPrefix + randomString(32)
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO operator_credential (id, hash, created_at) VALUES (1, ?, ?)",
		hash(credential), s.now().UnixNano()); err != nil {
		return "", fmt.Errorf("store Operator Credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return credential, nil
}

// VerifyOperatorCredential reports whether presented is the Operator
// Credential.
func (s *Service) VerifyOperatorCredential(ctx context.Context, presented string) (bool, error) {
	var stored []byte
	err := s.db.QueryRowContext(ctx, "SELECT hash FROM operator_credential WHERE id = 1").Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(stored, hash(presented)) == 1, nil
}

// ValidationError reports a request the Operator must correct.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// IssuedAgentToken is a newly issued Agent Token. Token is the only copy of
// the value and must not be kept after it is shown to the Operator.
type IssuedAgentToken struct {
	AgentToken
	Token string
}

// IssueAgentToken issues an Agent Token carrying the named Policies that
// expires at expiresAt.
func (s *Service) IssueAgentToken(ctx context.Context, policies []string, expiresAt time.Time) (IssuedAgentToken, error) {
	now := s.now()
	if expiresAt.IsZero() {
		return IssuedAgentToken{}, invalid("an expiry is required")
	}
	if !expiresAt.After(now) {
		return IssuedAgentToken{}, invalid("expiry %s is not in the future", expiresAt.UTC().Format(time.RFC3339))
	}
	if len(policies) == 0 {
		return IssuedAgentToken{}, invalid("at least one Policy is required")
	}
	var names []string
	for _, name := range policies {
		if _, ok := s.cfg.Policies[name]; !ok {
			return IssuedAgentToken{}, invalid("unknown Policy %q", name)
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	encodedPolicies, err := json.Marshal(names)
	if err != nil {
		return IssuedAgentToken{}, err
	}

	issued := IssuedAgentToken{
		AgentToken: AgentToken{
			ID:        randomString(10),
			Policies:  names,
			CreatedAt: now.UTC(),
			ExpiresAt: expiresAt.UTC(),
		},
		Token: AgentTokenPrefix + randomString(32),
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_tokens (id, hash, policies, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		issued.ID, hash(issued.Token), string(encodedPolicies),
		issued.CreatedAt.UnixNano(), issued.ExpiresAt.UnixNano()); err != nil {
		return IssuedAgentToken{}, fmt.Errorf("store Agent Token: %w", err)
	}
	return issued, nil
}

// AgentToken is an Agent Token's stored metadata. It never carries the value.
type AgentToken struct {
	ID         string
	Policies   []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// ListAgentTokens returns every Agent Token, newest first.
func (s *Service) ListAgentTokens(ctx context.Context) ([]AgentToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, policies, created_at, expires_at, last_used_at, revoked_at
		 FROM agent_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	tokens := []AgentToken{}
	for rows.Next() {
		var (
			tok               AgentToken
			policies          string
			created, expires  int64
			lastUsed, revoked sql.NullInt64
		)
		if err := rows.Scan(&tok.ID, &policies, &created, &expires, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(policies), &tok.Policies); err != nil {
			return nil, fmt.Errorf("Agent Token %s: decode Policies: %w", tok.ID, err)
		}
		tok.CreatedAt = time.Unix(0, created).UTC()
		tok.ExpiresAt = time.Unix(0, expires).UTC()
		tok.LastUsedAt = nullTime(lastUsed)
		tok.RevokedAt = nullTime(revoked)
		tokens = append(tokens, tok)
	}
	return tokens, rows.Err()
}

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(0, v.Int64).UTC()
	return &t
}

func hash(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// randomString returns n random bytes as lowercase unpadded base32.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return strings.ToLower(encoding.EncodeToString(b))
}

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
// passes its value to show, the only time the value exists. The credential
// is kept only if show succeeds, so a first boot that cannot show it leaves
// the next boot to try again. When the credential already exists, show is
// not called.
func (s *Service) EnsureOperatorCredential(ctx context.Context, show func(credential string) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operator_credential").Scan(&exists); err != nil {
		return fmt.Errorf("read Operator Credential: %w", err)
	}
	if exists > 0 {
		return nil
	}
	credential := OperatorCredentialPrefix + randomString(32)
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO operator_credential (id, hash, created_at) VALUES (1, ?, ?)",
		hash(credential), s.now().UnixMilli()); err != nil {
		return fmt.Errorf("store Operator Credential: %w", err)
	}
	if err := show(credential); err != nil {
		return fmt.Errorf("show Operator Credential: %w", err)
	}
	return tx.Commit()
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

	// Timestamps are stored as Unix milliseconds, so return them at that
	// precision too.
	issued := IssuedAgentToken{
		AgentToken: AgentToken{
			ID:        randomString(10),
			Policies:  names,
			CreatedAt: time.UnixMilli(now.UnixMilli()).UTC(),
			ExpiresAt: time.UnixMilli(expiresAt.UnixMilli()).UTC(),
		},
		Token: AgentTokenPrefix + randomString(32),
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_tokens (id, hash, policies, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		issued.ID, hash(issued.Token), string(encodedPolicies),
		issued.CreatedAt.UnixMilli(), issued.ExpiresAt.UnixMilli()); err != nil {
		return IssuedAgentToken{}, fmt.Errorf("store Agent Token: %w", err)
	}
	return issued, nil
}

// NotFoundError reports an Agent Token ID that does not exist.
type NotFoundError struct{ ID string }

func (e *NotFoundError) Error() string { return fmt.Sprintf("no Agent Token with ID %q", e.ID) }

// RevokeAgentToken revokes the Agent Token with id. Revoking an already
// revoked Agent Token succeeds and keeps the original revocation time.
func (s *Service) RevokeAgentToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
		s.now().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("revoke Agent Token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return &NotFoundError{ID: id}
	}
	return nil
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
		"SELECT "+agentTokenColumns+" FROM agent_tokens ORDER BY created_at DESC, id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	tokens := []AgentToken{}
	for rows.Next() {
		tok, err := scanAgentToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
	}
	return tokens, rows.Err()
}

const agentTokenColumns = "id, policies, created_at, expires_at, last_used_at, revoked_at"

func scanAgentToken(row interface{ Scan(...any) error }) (AgentToken, error) {
	var (
		tok               AgentToken
		policies          string
		created, expires  int64
		lastUsed, revoked sql.NullInt64
	)
	if err := row.Scan(&tok.ID, &policies, &created, &expires, &lastUsed, &revoked); err != nil {
		return AgentToken{}, err
	}
	if err := json.Unmarshal([]byte(policies), &tok.Policies); err != nil {
		return AgentToken{}, fmt.Errorf("Agent Token %s: decode Policies: %w", tok.ID, err)
	}
	tok.CreatedAt = time.UnixMilli(created).UTC()
	tok.ExpiresAt = time.UnixMilli(expires).UTC()
	tok.LastUsedAt = nullTime(lastUsed)
	tok.RevokedAt = nullTime(revoked)
	return tok, nil
}

// Reasons an Agent Token is refused.
var (
	ErrAgentTokenInvalid = errors.New("invalid Agent Token")
	ErrAgentTokenExpired = errors.New("Agent Token expired")
	ErrAgentTokenRevoked = errors.New("Agent Token revoked")
)

// AuthenticateAgentToken returns the Agent Token whose value is presented and
// records its use. It fails with ErrAgentTokenInvalid, ErrAgentTokenExpired,
// or ErrAgentTokenRevoked when the token must be refused. Revocation takes
// effect on the next call.
func (s *Service) AuthenticateAgentToken(ctx context.Context, presented string) (AgentToken, error) {
	if !strings.HasPrefix(presented, AgentTokenPrefix) {
		return AgentToken{}, ErrAgentTokenInvalid
	}
	now := s.now().UnixMilli()
	// Check and record use in one statement, so a revocation committed in
	// between cannot be missed.
	tok, err := scanAgentToken(s.db.QueryRowContext(ctx,
		`UPDATE agent_tokens SET last_used_at = ?
		 WHERE hash = ? AND revoked_at IS NULL AND expires_at > ?
		 RETURNING `+agentTokenColumns,
		now, hash(presented), now))
	if err == nil {
		return tok, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AgentToken{}, fmt.Errorf("authenticate Agent Token: %w", err)
	}
	// Refused: find out why.
	var revoked sql.NullInt64
	err = s.db.QueryRowContext(ctx,
		"SELECT revoked_at FROM agent_tokens WHERE hash = ?", hash(presented)).Scan(&revoked)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return AgentToken{}, ErrAgentTokenInvalid
	case err != nil:
		return AgentToken{}, fmt.Errorf("read Agent Token: %w", err)
	case revoked.Valid:
		return AgentToken{}, ErrAgentTokenRevoked
	default:
		return AgentToken{}, ErrAgentTokenExpired
	}
}

// Denial is why a Delivery was denied. Agents never see it.
type Denial string

// Denials.
const (
	DenialUnknownSecretName Denial = "unknown Secret Name"
	DenialPolicy            Denial = "no Policy allows it"
	DenialMethod            Denial = "no Policy allows the method"
	DenialPath              Denial = "no Policy allows the path"
)

// Authorize reports whether tok's Policies allow Delivery of secretName in
// mode, and if not, why. A Policy must name the Delivery mode explicitly;
// allowing proxy never allows reveal.
func (s *Service) Authorize(tok AgentToken, secretName string, mode config.DeliveryMode) (Denial, bool) {
	if _, ok := s.cfg.Secrets[secretName]; !ok {
		return DenialUnknownSecretName, false
	}
	for _, name := range tok.Policies {
		// A Policy removed from the config since issuance allows nothing.
		for _, a := range s.cfg.Policies[name].Secrets {
			if a.SecretName == secretName && slices.Contains(a.Delivery, mode) {
				return "", true
			}
		}
	}
	return DenialPolicy, false
}

// AuthorizeProxy reports whether tok's Policies allow Proxy Delivery of
// secretName for a request with method to escapedPath, the escaped path after
// the Upstream name, and if not, why. One Policy entry must allow both the
// method and the path; an entry without limits allows any of either.
func (s *Service) AuthorizeProxy(tok AgentToken, secretName, method, escapedPath string) (Denial, bool) {
	if _, ok := s.cfg.Secrets[secretName]; !ok {
		return DenialUnknownSecretName, false
	}
	denial := DenialPolicy
	for _, name := range tok.Policies {
		for _, a := range s.cfg.Policies[name].Secrets {
			if a.SecretName != secretName || !slices.Contains(a.Delivery, config.DeliveryProxy) {
				continue
			}
			if a.Methods != nil && !slices.Contains(a.Methods, method) {
				if denial == DenialPolicy {
					denial = DenialMethod
				}
				continue
			}
			if a.Paths != nil && !slices.ContainsFunc(a.Paths, func(p config.PathPrefix) bool { return p.Matches(escapedPath) }) {
				denial = DenialPath
				continue
			}
			return "", true
		}
	}
	return denial, false
}

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
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

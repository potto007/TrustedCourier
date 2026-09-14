package e2e

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

var agentTokenPattern = regexp.MustCompile(`tcat_[a-z2-7]+`)

func TestIssueAgentTokenShowsValueOnceAndListsMetadata(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	issued := srv.TC("token", "issue", "--policy", "openai-proxy", "--policy", "github-reveal", "--expires-in", "24h")
	if issued.ExitCode != 0 {
		t.Fatalf("token issue: exit %d\n%s", issued.ExitCode, issued.Stderr)
	}
	token := agentTokenPattern.FindString(issued.Stdout)
	if token == "" {
		t.Fatalf("token issue did not show a prefixed Agent Token:\n%s", issued.Stdout)
	}

	list := srv.TC("token", "list")
	if list.ExitCode != 0 {
		t.Fatalf("token list: exit %d\n%s", list.ExitCode, list.Stderr)
	}
	if strings.Contains(list.Stdout, token) || strings.Contains(list.Stdout, "tcat_") {
		t.Fatalf("token list shows an Agent Token value:\n%s", list.Stdout)
	}
	for _, want := range []string{"openai-proxy", "github-reveal", "never", "active"} {
		if !strings.Contains(list.Stdout, want) {
			t.Errorf("token list is missing %q:\n%s", want, list.Stdout)
		}
	}
	if !strings.Contains(list.Stdout, time.Now().Add(24*time.Hour).UTC().Format("2006-01-02")) {
		t.Errorf("token list does not show the expiry date:\n%s", list.Stdout)
	}
}

func TestIssueAgentTokenRejectsIncompleteRequests(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no expiry", []string{"--policy", "openai-proxy"}, "expiry is required"},
		{"past expiry", []string{"--policy", "openai-proxy", "--expires-at", "2001-01-01T00:00:00Z"}, "not in the future"},
		{"no Policy", []string{"--expires-in", "1h"}, "--policy"},
		{"unknown Policy", []string{"--policy", "openai-proxy", "--policy", "no-such-policy", "--expires-in", "1h"}, `unknown Policy "no-such-policy"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := srv.TC(append([]string{"token", "issue"}, c.args...)...)
			if res.ExitCode == 0 {
				t.Fatalf("token issue succeeded; stdout:\n%s", res.Stdout)
			}
			if !strings.Contains(res.Stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, res.Stderr)
			}
			if agentTokenPattern.MatchString(res.Stdout + res.Stderr) {
				t.Fatalf("a rejected request still produced an Agent Token")
			}
		})
	}

	list := srv.TC("token", "list", "--json")
	if list.ExitCode != 0 || strings.TrimSpace(list.Stdout) != "[]" {
		t.Fatalf("rejected requests left Agent Tokens behind: exit %d\n%s%s", list.ExitCode, list.Stdout, list.Stderr)
	}
}

func TestAgentTokenIsNotStoredOnDisk(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	issued := srv.TC("token", "issue", "--policy", "openai-proxy", "--expires-in", "1h")
	token := agentTokenPattern.FindString(issued.Stdout)
	if token == "" {
		t.Fatalf("token issue: exit %d\n%s%s", issued.ExitCode, issued.Stdout, issued.Stderr)
	}
	srv.Stop()

	if tc.FilesContain(token) {
		t.Fatal("the Agent Token value is stored in the data directory")
	}
	if strings.Contains(srv.Stderr(), token) {
		t.Fatal("the Agent Token value appears in TrustedCourier's logs")
	}
}

func TestRevokeAgentTokenTakesEffectImmediately(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	keep := issueJSON(t, srv, "openai-proxy")
	revoke := issueJSON(t, srv, "github-reveal")

	res := srv.TC("token", "revoke", revoke)
	if res.ExitCode != 0 {
		t.Fatalf("token revoke: exit %d\n%s", res.ExitCode, res.Stderr)
	}

	statuses := listStatuses(t, srv)
	if statuses[revoke] != "revoked" || statuses[keep] != "active" {
		t.Fatalf("statuses after revoke = %v, want %s revoked and %s active", statuses, revoke, keep)
	}

	srv.Stop()
	restarted := tc.Start(harness.BaseConfig)
	restarted.Credential = srv.Credential
	if got := listStatuses(t, restarted)[revoke]; got != "revoked" {
		t.Fatalf("status after restart = %q, want revoked", got)
	}
}

func TestRevokeUnknownAgentTokenFails(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	res := srv.TC("token", "revoke", "doesnotexist")
	if res.ExitCode == 0 {
		t.Fatalf("revoking an unknown Agent Token succeeded")
	}
	if !strings.Contains(res.Stderr, "doesnotexist") {
		t.Fatalf("error does not name the Agent Token ID:\n%s", res.Stderr)
	}
}

func TestFarFutureExpiryIsListedAsIssued(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	res := srv.TC("token", "issue", "--policy", "openai-proxy", "--expires-at", "9999-12-31T23:59:59Z", "--json")
	var issued struct {
		ID string `json:"id"`
	}
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &issued) != nil {
		t.Fatalf("token issue: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}

	list := srv.TC("token", "list")
	if !strings.Contains(list.Stdout, "9999-12-31T23:59:59Z") {
		t.Fatalf("token list does not show the issued expiry:\n%s%s", list.Stdout, list.Stderr)
	}
	if got := listStatuses(t, srv)[issued.ID]; got != "active" {
		t.Fatalf("status = %q, want active", got)
	}
}

func TestOverlongLifetimeIsRejected(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	res := srv.TC("token", "issue", "--policy", "openai-proxy", "--expires-in", "213504d")
	if res.ExitCode == 0 {
		t.Fatalf("token issue accepted a lifetime that overflows; stdout:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "too long") {
		t.Fatalf("error does not say the lifetime is too long:\n%s", res.Stderr)
	}
}

func TestExpiredAgentTokenListsAsExpired(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	id := issueJSONExpiring(t, srv, "2s", "openai-proxy")

	time.Sleep(2500 * time.Millisecond)
	if got := listStatuses(t, srv)[id]; got != "expired" {
		t.Fatalf("status = %q, want expired", got)
	}
}

func issueJSON(t *testing.T, srv *harness.Server, policy string) string {
	t.Helper()
	return issueJSONExpiring(t, srv, "1h", policy)
}

func issueJSONExpiring(t *testing.T, srv *harness.Server, expiresIn, policy string) string {
	t.Helper()
	res := srv.TC("token", "issue", "--policy", policy, "--expires-in", expiresIn, "--json")
	var issued struct {
		ID string `json:"id"`
	}
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &issued) != nil || issued.ID == "" {
		t.Fatalf("token issue: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	return issued.ID
}

func listStatuses(t *testing.T, srv *harness.Server) map[string]string {
	t.Helper()
	res := srv.TC("token", "list", "--json")
	var tokens []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &tokens) != nil {
		t.Fatalf("token list: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	statuses := make(map[string]string, len(tokens))
	for _, tok := range tokens {
		statuses[tok.ID] = tok.Status
	}
	return statuses
}

func TestIssuedAgentTokenListsAsJSON(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	issued := srv.TC("token", "issue", "--policy", "openai-proxy", "--expires-in", "1h", "--json")
	if issued.ExitCode != 0 {
		t.Fatalf("token issue: exit %d\n%s", issued.ExitCode, issued.Stderr)
	}
	var created struct {
		ID        string    `json:"id"`
		Token     string    `json:"token"`
		Policies  []string  `json:"policies"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(issued.Stdout), &created); err != nil {
		t.Fatalf("token issue --json: %v\n%s", err, issued.Stdout)
	}
	if !strings.HasPrefix(created.Token, "tcat_") || created.ID == "" {
		t.Fatalf("token issue --json = %+v", created)
	}
	if d := time.Until(created.ExpiresAt); d < 59*time.Minute || d > time.Hour {
		t.Errorf("expires_at %v is not about one hour away", created.ExpiresAt)
	}

	list := srv.TC("token", "list", "--json")
	if list.ExitCode != 0 {
		t.Fatalf("token list --json: exit %d\n%s", list.ExitCode, list.Stderr)
	}
	if strings.Contains(list.Stdout, created.Token) {
		t.Fatalf("token list --json shows the Agent Token value:\n%s", list.Stdout)
	}
	var listed []struct {
		ID         string     `json:"id"`
		Policies   []string   `json:"policies"`
		ExpiresAt  time.Time  `json:"expires_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
		Status     string     `json:"status"`
	}
	if err := json.Unmarshal([]byte(list.Stdout), &listed); err != nil {
		t.Fatalf("token list --json: %v\n%s", err, list.Stdout)
	}
	if len(listed) != 1 {
		t.Fatalf("token list --json has %d tokens, want 1:\n%s", len(listed), list.Stdout)
	}
	got := listed[0]
	if got.ID != created.ID || strings.Join(got.Policies, ",") != "openai-proxy" ||
		!got.ExpiresAt.Equal(created.ExpiresAt) || got.LastUsedAt != nil || got.Status != "active" {
		t.Fatalf("listed token = %+v, issued %+v", got, created)
	}
}

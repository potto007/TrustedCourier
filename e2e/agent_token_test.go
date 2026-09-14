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

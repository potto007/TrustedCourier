package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// refuseAuditRecords makes every insert into audit_records fail, as a full
// disk or a failing volume would, until allowAuditRecords.
const (
	refuseAuditRecords = `CREATE TRIGGER refuse_audit_records BEFORE INSERT ON audit_records
		BEGIN SELECT RAISE(FAIL, 'audit storage unavailable'); END`
	allowAuditRecords = "DROP TRIGGER refuse_audit_records"
)

// pendingAuditRecords returns tc status --json's Audit Records waiting to be
// stored, and why they are.
func pendingAuditRecords(t *testing.T, srv *harness.Server) (pending int, detail string) {
	t.Helper()
	res := srv.TC("status", "--json")
	var status struct {
		AuditRecords *struct {
			Pending int    `json:"pending"`
			Detail  string `json:"detail"`
		} `json:"audit_records"`
	}
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &status) != nil || status.AuditRecords == nil {
		t.Fatalf("tc status --json: exit %d, want audit_records\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	return status.AuditRecords.Pending, status.AuditRecords.Detail
}

// waitForPending polls tc status until want Audit Records are waiting to be
// stored.
func waitForPending(t *testing.T, srv *harness.Server, want int) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		pending, detail := pendingAuditRecords(t, srv)
		if pending == want {
			return detail
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d Audit Records waiting to be stored, want %d (%s)\nstderr:\n%s", pending, want, detail, srv.Stderr())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDeliveriesStopWhileAuditRecordsCannotBeStored(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	issued := issueAgentToken(t, srv, "github-reveal", "1h")
	token := "Bearer " + issued.Token
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal github = %d %q, want 200", got.Status, got.Body)
	}
	auditRecords(t, srv, 1)

	tc.TamperDatabase(refuseAuditRecords)
	// The Delivery under way when storage fails completes; its record waits.
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal github as storage fails = %d %q, want 200", got.Status, got.Body)
	}
	if detail := waitForPending(t, srv, 1); !strings.Contains(detail, "audit storage unavailable") {
		t.Errorf("tc status detail = %q, want the storage error", detail)
	}
	if text := srv.TC("status"); !strings.Contains(text.Stdout, "Audit Records: 1 waiting to be stored") {
		t.Errorf("tc status does not report the waiting Audit Record:\n%s", text.Stdout)
	}

	// Every later Delivery is refused before anything is fetched or recorded.
	for _, name := range []string{"github", "openai"} {
		got := reveal(t, srv, token, name)
		if got.Status != http.StatusServiceUnavailable || !strings.Contains(got.Body, "Audit Records cannot be stored") {
			t.Fatalf("reveal %s while Audit Records cannot be stored = %d %q, want 503", name, got.Status, got.Body)
		}
	}
	if pending, _ := pendingAuditRecords(t, srv); pending != 1 {
		t.Fatalf("%d Audit Records waiting after refused requests, want 1", pending)
	}
	if n := len(srv.AuditRecords(1)); n != 1 {
		t.Fatalf("%d Audit Records streamed while storage failed, want 1", n)
	}

	// Once storage recovers, the waiting record is stored in order and
	// Deliveries resume.
	tc.TamperDatabase(allowAuditRecords)
	records := auditRecords(t, srv, 2)
	if len(records) != 2 || records[1].Seq != 2 || records[1].SecretName != "github" || records[1].Decision != "allowed" {
		t.Fatalf("Audit Records after recovery = %+v, want record 2 for the allowed github Delivery", records)
	}
	waitForPending(t, srv, 0)
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal github after recovery = %d %q, want 200", got.Status, got.Body)
	}
	auditRecords(t, srv, 3)
	if v, res := verifyAudit(t, srv); res.ExitCode != 0 || !v.Intact || v.Records != 3 {
		t.Fatalf("tc audit verify --json = %+v, exit %d; want intact with 3 records", v, res.ExitCode)
	}
}

func TestAuditRecordsNotStoredByShutdownAreLogged(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	issued := issueAgentToken(t, srv, "github-reveal", "1h")

	tc.TamperDatabase(refuseAuditRecords)
	if got := reveal(t, srv, "Bearer "+issued.Token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal github = %d %q, want 200", got.Status, got.Body)
	}
	waitForPending(t, srv, 1)
	srv.Stop()

	stderr := srv.Stderr()
	if !strings.Contains(stderr, "Audit Record lost") || !strings.Contains(stderr, issued.ID) || !strings.Contains(stderr, "github") {
		t.Fatalf("stderr does not log the Audit Record lost at shutdown:\n%s", stderr)
	}
}

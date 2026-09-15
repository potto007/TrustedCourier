package e2e

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// withCheckpoints sets audit.checkpoints in a config ending with auditConfig.
func withCheckpoints(config string, records int, interval string) string {
	return config + fmt.Sprintf("  checkpoints:\n    records: %d\n    interval: %s\n", records, interval)
}

// checkpoint is a signed audit checkpoint as SQLite stores it.
type checkpoint struct {
	Seq, PrevSeq, Time int64
	Head, Signature    []byte
}

// checkpoints reads every checkpoint from the installation's database.
func checkpoints(tc *harness.Installation) []checkpoint {
	var out []checkpoint
	tc.QueryDatabase("SELECT seq, prev_seq, time, head, signature FROM audit_checkpoints ORDER BY seq", func(rows *sql.Rows) error {
		var c checkpoint
		if err := rows.Scan(&c.Seq, &c.PrevSeq, &c.Time, &c.Head, &c.Signature); err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	return out
}

// checkpointMessage is what a checkpoint's signature covers (ADR-0019).
func checkpointMessage(c checkpoint) []byte {
	msg := []byte("TrustedCourier audit checkpoint\x00")
	msg = binary.BigEndian.AppendUint64(msg, uint64(c.Seq))
	msg = binary.BigEndian.AppendUint64(msg, uint64(c.PrevSeq))
	msg = binary.BigEndian.AppendUint64(msg, uint64(c.Time))
	return append(msg, c.Head...)
}

func TestAuditCheckpointsAreSignedEveryNRecords(t *testing.T) {
	tc := harness.New(t)
	config := withCheckpoints(revealConfig, 2, "1h")
	srv := tc.Start(config)
	waitForPlugin(t, srv, "fake", running)
	token := "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token
	for _, name := range []string{"github", "openai", "github", "github", "openai"} {
		reveal(t, srv, token, name)
	}
	records := auditRecords(t, srv, 5)

	if v, res := verifyAudit(t, srv); res.ExitCode != 0 || !v.Intact || v.Records != 5 || v.Checkpoints != 2 {
		t.Fatalf("tc audit verify --json = %+v, exit %d; want intact with 5 records and 2 checkpoints", v, res.ExitCode)
	}

	// Shutdown signs the records after the last checkpoint.
	srv.Stop()
	credential := srv.Credential
	srv = tc.Start(config)
	srv.Credential = credential
	srv.AgentURL()
	if v, res := verifyAudit(t, srv); res.ExitCode != 0 || !v.Intact || v.Records != 5 || v.Checkpoints != 3 {
		t.Fatalf("after a restart, tc audit verify --json = %+v, exit %d; want intact with 5 records and 3 checkpoints", v, res.ExitCode)
	}
	text := srv.TC("audit", "verify")
	if text.ExitCode != 0 || !strings.Contains(text.Stdout, "5 Audit Records") || !strings.Contains(text.Stdout, "3 signed checkpoints") {
		t.Fatalf("tc audit verify: exit %d, want 0 reporting 5 Audit Records and 3 signed checkpoints\n%s%s", text.ExitCode, text.Stdout, text.Stderr)
	}

	// The checkpoints verify from the database alone, with the public key.
	got := checkpoints(tc)
	wantSeqs := []int64{2, 4, 5}
	if len(got) != len(wantSeqs) {
		t.Fatalf("%d checkpoints in the database, want %d: %+v", len(got), len(wantSeqs), got)
	}
	prev := int64(0)
	for i, c := range got {
		if c.Seq != wantSeqs[i] || c.PrevSeq != prev {
			t.Errorf("checkpoint %d: seq %d, prev_seq %d; want seq %d, prev_seq %d", i, c.Seq, c.PrevSeq, wantSeqs[i], prev)
		}
		if head := hex.EncodeToString(c.Head); head != records[c.Seq-1].Hash {
			t.Errorf("checkpoint at record %d: head %s, want the record's hash %s", c.Seq, head, records[c.Seq-1].Hash)
		}
		if !ed25519.Verify(harness.AuditSigningPublicKey, checkpointMessage(c), c.Signature) {
			t.Errorf("checkpoint at record %d: signature does not verify with the audit signing key", c.Seq)
		}
		if ts := time.UnixMilli(c.Time); time.Since(ts) > time.Minute || time.Until(ts) > time.Second {
			t.Errorf("checkpoint at record %d: time %v, want about now", c.Seq, ts)
		}
		prev = c.Seq
	}
}

func TestAuditCheckpointsAreSignedEveryInterval(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(withCheckpoints(revealConfig, 1000, "1s"))
	waitForPlugin(t, srv, "fake", running)
	token := "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token
	reveal(t, srv, token, "github")
	auditRecords(t, srv, 1)

	deadline := time.Now().Add(10 * time.Second)
	for {
		v, res := verifyAudit(t, srv)
		if res.ExitCode != 0 || !v.Intact {
			t.Fatalf("tc audit verify --json = %+v, exit %d; want intact", v, res.ExitCode)
		}
		if v.Checkpoints == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no checkpoint within 10s of a record with a 1s interval: %+v", v)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// With no new records there is nothing new to sign.
	time.Sleep(2500 * time.Millisecond)
	if n := len(checkpoints(tc)); n != 1 {
		t.Fatalf("%d checkpoints after an idle interval, want 1", n)
	}
}

// rewriteChain changes secret_name in record from to newName, then rebuilds
// the chain from there in the documented format, as someone with write
// access to the database but not the audit signing key could.
func rewriteChain(t *testing.T, tc *harness.Installation, lines []string, from int, oldName, newName string) {
	t.Helper()
	var statements []string
	prevHash := ""
	for seq := from; seq <= len(lines); seq++ {
		line := lines[seq-1]
		var rec auditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		set := ""
		if seq == from {
			line = strings.Replace(line, `"secret_name":"`+oldName+`"`, `"secret_name":"`+newName+`"`, 1)
			set = fmt.Sprintf("secret_name = '%s', ", newName)
		} else {
			line = strings.Replace(line, `"prev_hash":"`+rec.PrevHash+`"`, `"prev_hash":"`+prevHash+`"`, 1)
			set = fmt.Sprintf("prev_hash = X'%s', ", prevHash)
		}
		prevHash = lineHash(t, line)
		statements = append(statements, fmt.Sprintf("UPDATE audit_records SET %shash = X'%s' WHERE seq = %d", set, prevHash, seq))
	}
	tc.TamperDatabase(strings.Join(statements, "; "))
}

func TestAuditVerifyReportsTamperingCheckpointsCatch(t *testing.T) {
	cases := []struct {
		name        string
		tamper      func(t *testing.T, tc *harness.Installation, lines []string)
		wantSeq     int
		wantProblem string
		wantRecords int
	}{
		{"chain rewritten after a checkpoint", func(t *testing.T, tc *harness.Installation, lines []string) {
			rewriteChain(t, tc, lines, 3, "github", "openai")
		}, 4, "record 4 does not match its signed checkpoint", 2},
		{"whole chain rewritten", func(t *testing.T, tc *harness.Installation, lines []string) {
			rewriteChain(t, tc, lines, 1, "github", "openai")
		}, 2, "record 2 does not match its signed checkpoint", 0},
		{"checkpoint signature replaced", func(t *testing.T, tc *harness.Installation, _ []string) {
			tc.TamperDatabase("UPDATE audit_checkpoints SET signature = zeroblob(64) WHERE seq = 4")
		}, 4, "the signed checkpoint at record 4 does not verify with the audit signing key", 2},
		{"checkpoint deleted", func(t *testing.T, tc *harness.Installation, _ []string) {
			tc.TamperDatabase("DELETE FROM audit_checkpoints WHERE seq = 2")
		}, 2, "the signed checkpoint at record 2 is missing", 0},
		{"last record deleted while stopped", func(t *testing.T, tc *harness.Installation, _ []string) {
			tc.TamperDatabase("DELETE FROM audit_records WHERE seq = 4")
		}, 4, "record 4 is missing", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			config := withCheckpoints(revealConfig, 2, "1h")
			srv := tc.Start(config)
			waitForPlugin(t, srv, "fake", running)
			token := "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token
			for _, name := range []string{"github", "openai", "github", "github"} {
				reveal(t, srv, token, name)
			}
			auditRecords(t, srv, 4)
			lines := srv.AuditRecords(4)
			if v, res := verifyAudit(t, srv); res.ExitCode != 0 || !v.Intact || v.Checkpoints != 2 {
				t.Fatalf("before tampering: tc audit verify = %+v, exit %d; want intact with 2 checkpoints", v, res.ExitCode)
			}

			// Tamper while the server is stopped, so only the database remains.
			srv.Stop()
			c.tamper(t, tc, lines)
			credential := srv.Credential
			srv = tc.Start(config)
			srv.Credential = credential
			srv.AgentURL()

			v, res := verifyAudit(t, srv)
			if res.ExitCode != 1 || v.Intact || v.Break == nil || v.Break.Seq != c.wantSeq ||
				!strings.Contains(v.Break.Problem, c.wantProblem) || v.Records != c.wantRecords {
				t.Fatalf("tc audit verify --json = %+v (break %+v), exit %d; want a break at record %d that is %q, after %d intact",
					v, v.Break, res.ExitCode, c.wantSeq, c.wantProblem, c.wantRecords)
			}
		})
	}
}

// auditSigningKeyStatus returns tc status --json's audit signing key.
func auditSigningKeyStatus(t *testing.T, srv *harness.Server) (loaded bool, detail string) {
	t.Helper()
	res := srv.TC("status", "--json")
	var status struct {
		AuditSigningKey *struct {
			Loaded bool   `json:"loaded"`
			Detail string `json:"detail"`
		} `json:"audit_signing_key"`
	}
	if res.ExitCode != 0 || json.Unmarshal([]byte(res.Stdout), &status) != nil || status.AuditSigningKey == nil {
		t.Fatalf("tc status --json: exit %d, want an audit_signing_key\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	return status.AuditSigningKey.Loaded, status.AuditSigningKey.Detail
}

func TestDeliveriesWaitForTheAuditSigningKey(t *testing.T) {
	tc := harness.New(t)
	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	tc.SetBackendSecrets(path, map[string]string{"kv/github": "test-value-2", harness.AuditSigningKeyLocation: "malformed-audit-signing-key"})
	srv := tc.Start(strings.Replace(revealConfig, "{{.Fake.Path}}", path, 1))
	waitForPlugin(t, srv, "fake", running)
	token := "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token

	deadline := time.Now().Add(15 * time.Second)
	for {
		loaded, detail := auditSigningKeyStatus(t, srv)
		if loaded {
			t.Fatal("tc status reports a malformed audit signing key as loaded")
		}
		if strings.Contains(detail, "not PEM") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tc status never said why the audit signing key is not loaded; last detail %q", detail)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if text := srv.TC("status"); text.ExitCode != 0 || !strings.Contains(text.Stdout, "Audit signing key: not loaded") {
		t.Errorf("tc status: exit %d, want it to report the audit signing key not loaded\n%s", text.ExitCode, text.Stdout)
	}

	req, err := http.NewRequest(http.MethodGet, srv.ListeningAgentURL()+"/v1/reveal/github", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "audit signing key") || bytes.Contains(body, []byte("test-value-2")) {
		t.Fatalf("reveal without the audit signing key = %d %q, want 503 naming the audit signing key", resp.StatusCode, body)
	}
	if res := srv.TC("audit", "verify"); res.ExitCode != 1 || !strings.Contains(res.Stderr, "audit signing key") {
		t.Errorf("tc audit verify without the audit signing key: exit %d, want 1 naming the key\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	for line := range strings.Lines(srv.Stdout()) {
		if strings.HasPrefix(line, "{") {
			t.Fatalf("a refused Delivery produced an Audit Record: %s", line)
		}
	}

	// Once the Backend holds a valid key, Deliveries are served.
	tc.SetBackendSecrets(path, map[string]string{"kv/github": "test-value-2", harness.AuditSigningKeyLocation: harness.AuditSigningKey})
	if got := reveal(t, srv, token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal after the key was loaded = %d %q, want 200", got.Status, got.Body)
	}
	auditRecords(t, srv, 1)
	if loaded, detail := auditSigningKeyStatus(t, srv); !loaded {
		t.Fatalf("tc status: audit signing key not loaded after Deliveries started: %q", detail)
	}
}

func TestAuditConfigIsValidated(t *testing.T) {
	signingKey := "audit:\n  signing_key:\n    backend: fake\n    location: " + harness.AuditSigningKeyLocation + "\n"
	cases := []struct {
		name, config, wantErr string
	}{
		{"Agent API without an audit signing key", "agent_api:\n  listen: 127.0.0.1:0\n", "audit.signing_key is required"},
		{"unknown backend", "audit:\n  signing_key:\n    backend: nope\n    location: courier/key\n", `unknown backend "nope"`},
		{"missing location", "audit:\n  signing_key:\n    backend: fake\n", "location is required"},
		{"zero records", signingKey + "  checkpoints:\n    records: 0\n", "records must be at least 1"},
		{"records without a value", signingKey + "  checkpoints:\n    records:\n", "records must be at least 1"},
		{"unparsable interval", signingKey + "  checkpoints:\n    interval: soon\n", "audit.checkpoints.interval"},
		{"interval too short", signingKey + "  checkpoints:\n    interval: 10ms\n", "at least 1s"},
		{"Secret Name at the key's location", signingKey + "secrets:\n  leak:\n    backend: fake\n    location: " + harness.AuditSigningKeyLocation + "\n",
			"audit signing key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig + c.config)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

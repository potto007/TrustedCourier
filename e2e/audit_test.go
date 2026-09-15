package e2e

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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

// auditRecord is an Audit Record as the JSON-lines stream carries it. Decoding
// refuses unknown fields, so a field added to the record must be added here
// and reviewed for what it could leak.
type auditRecord struct {
	Seq            int64     `json:"seq"`
	Time           time.Time `json:"time"`
	AgentTokenID   string    `json:"agent_token_id"`
	SecretName     string    `json:"secret_name"`
	Delivery       string    `json:"delivery"`
	Upstream       string    `json:"upstream"`
	UpstreamHost   string    `json:"upstream_host"`
	Decision       string    `json:"decision"`
	Reason         string    `json:"reason"`
	UpstreamStatus *int      `json:"upstream_status"`
	Failure        string    `json:"failure"`
	PrevHash       string    `json:"prev_hash"`
	Hash           string    `json:"hash"`
}

// auditRecords waits for at least n Audit Records on srv's stream and decodes
// every one streamed so far.
func auditRecords(t *testing.T, srv *harness.Server, n int) []auditRecord {
	t.Helper()
	var records []auditRecord
	for _, line := range srv.AuditRecords(n) {
		dec := json.NewDecoder(bytes.NewReader([]byte(line)))
		dec.DisallowUnknownFields()
		var rec auditRecord
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("Audit Record %s: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

// sameRecord reports the fields of got that differ from want, ignoring the
// time and hashes, which tests check separately.
func sameRecord(got, want auditRecord) bool {
	gotStatus, wantStatus := 0, 0
	if got.UpstreamStatus != nil {
		gotStatus = *got.UpstreamStatus
	}
	if want.UpstreamStatus != nil {
		wantStatus = *want.UpstreamStatus
	}
	want.Time, want.PrevHash, want.Hash, want.UpstreamStatus = got.Time, got.PrevHash, got.Hash, nil
	got.UpstreamStatus = nil
	return got == want && gotStatus == wantStatus
}

func status(code int) *int { return &code }

func TestEveryDeliveryAttemptProducesOneAuditRecord(t *testing.T) {
	tc := harness.New(t)
	path := tc.InstallPlugin(harness.FakePlugin, t.TempDir(), 0o755)
	srv := tc.Start(strings.Replace(proxyConfig, "{{.Fake.Path}}", path, 1))
	waitForPlugin(t, srv, "fake", running)
	issued := issueAgentToken(t, srv, "openai-proxy", "1h")
	host := strings.TrimPrefix(tc.Upstream().URL, "https://")

	// send makes a request and reads what it can of the response, which may
	// be cut off, before or after its headers: then the status is 0. Redirects
	// are not followed, and without keep-alives a dropped connection is never
	// retried as a second attempt.
	client := &http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	send := func(method, path string, header http.Header) int {
		req, err := http.NewRequest(method, srv.AgentURL()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = header
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	proxied := func(upstream, upstreamHost string) auditRecord {
		return auditRecord{AgentTokenID: issued.ID, SecretName: "openai", Delivery: "proxy", Upstream: upstream, UpstreamHost: upstreamHost}
	}
	withUpgrade := bearer(issued.Token)
	withUpgrade.Set("Connection", "Upgrade")
	withUpgrade.Set("Upgrade", "websocket")

	attempts := []struct {
		name string
		do   func() int
		// wantStatus is -1 when the response may be cut off at any point.
		wantStatus int
		// want is nil when the attempt is no Delivery attempt.
		want *auditRecord
	}{
		{"allowed Proxy Delivery", func() int { return send(http.MethodGet, "/proxy/openai/api/v1/models", bearer(issued.Token)) }, 200,
			&auditRecord{AgentTokenID: issued.ID, SecretName: "openai", Delivery: "proxy", Upstream: "api", UpstreamHost: host, Decision: "allowed", UpstreamStatus: status(200)}},
		{"no Agent Token", func() int { return send(http.MethodGet, "/proxy/openai/api/v1/models", http.Header{}) }, 401, nil},
		{"invalid Agent Token", func() int {
			return send(http.MethodGet, "/v1/reveal/github", bearer("tcat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
		}, 401, nil},
		{"redirect", func() int { return send(http.MethodGet, "/proxy/openai/api/redirect", bearer(issued.Token)) }, 302,
			&auditRecord{AgentTokenID: issued.ID, SecretName: "openai", Delivery: "proxy", Upstream: "api", UpstreamHost: host, Decision: "allowed", UpstreamStatus: status(302)}},
		{"response cut off", func() int { return send(http.MethodGet, "/proxy/openai/api/cut", bearer(issued.Token)) }, -1,
			&auditRecord{AgentTokenID: issued.ID, SecretName: "openai", Delivery: "proxy", Upstream: "api", UpstreamHost: host, Decision: "allowed", UpstreamStatus: status(200), Failure: "the Upstream's response broke off"}},
		{"Secret Name in no attached Policy", func() int { return send(http.MethodGet, "/proxy/github/api/user", bearer(issued.Token)) }, 403,
			&auditRecord{AgentTokenID: issued.ID, SecretName: "github", Delivery: "proxy", Upstream: "api", UpstreamHost: host, Decision: "denied", Reason: "no Policy allows it"}},
		{"unknown Upstream", func() int { return send(http.MethodGet, "/proxy/openai/nope/v1/models", bearer(issued.Token)) }, 403,
			func() *auditRecord {
				r := proxied("nope", "")
				r.Decision, r.Reason = "denied", "unknown Upstream"
				return &r
			}()},
		{"dot segment", func() int { return send(http.MethodGet, "/proxy/openai/api/v1/%2e%2e/admin", bearer(issued.Token)) }, 400,
			func() *auditRecord {
				r := proxied("api", host)
				r.Decision, r.Reason = "denied", "the path contains a dot segment"
				return &r
			}()},
		{"protocol upgrade", func() int { return send(http.MethodGet, "/proxy/openai/api/v1/models", withUpgrade) }, 400,
			func() *auditRecord {
				r := proxied("api", host)
				r.Decision, r.Reason = "denied", "protocol upgrade"
				return &r
			}()},
		{"Reveal Delivery the Policy does not allow", func() int { return send(http.MethodGet, "/v1/reveal/openai", bearer(issued.Token)) }, 403,
			&auditRecord{AgentTokenID: issued.ID, SecretName: "openai", Delivery: "reveal", Decision: "denied", Reason: "no Policy allows it"}},
		{"unknown Secret Name", func() int { return send(http.MethodGet, "/v1/reveal/no-such-secret", bearer(issued.Token)) }, 403,
			&auditRecord{AgentTokenID: issued.ID, SecretName: "no-such-secret", Delivery: "reveal", Decision: "denied", Reason: "unknown Secret Name"}},
		{"Secret missing from its Backend", func() int {
			tc.SetBackendSecrets(path, map[string]string{"kv/github": "test-value-2"})
			return send(http.MethodGet, "/proxy/openai/api/v1/models", bearer(issued.Token))
		}, 502,
			&auditRecord{AgentTokenID: issued.ID, SecretName: "openai", Delivery: "proxy", Upstream: "api", UpstreamHost: host, Decision: "allowed", Failure: "the Secret could not be fetched"}},
	}

	// Attempts run one at a time and each record is matched to its attempt
	// by position, so an attempt with a second record, or a record where
	// none belongs, shifts every later record.
	n := 0
	for _, a := range attempts {
		if got := a.do(); got != a.wantStatus && a.wantStatus != -1 {
			t.Fatalf("%s: status %d, want %d\nstderr:\n%s", a.name, got, a.wantStatus, srv.Stderr())
		}
		if a.want == nil {
			continue
		}
		n++
		records := auditRecords(t, srv, n)
		if len(records) != n {
			t.Fatalf("%s: %d Audit Records, want %d: %+v", a.name, len(records), n, records)
		}
		got := records[n-1]
		a.want.Seq = int64(n)
		if !sameRecord(got, *a.want) {
			t.Errorf("%s: Audit Record = %+v (status %v), want %+v (status %v)", a.name, got, got.UpstreamStatus, *a.want, a.want.UpstreamStatus)
		}
	}
	if records := auditRecords(t, srv, n); len(records) != n {
		t.Fatalf("%d Audit Records, want %d: %+v", len(records), n, records)
	}
}

type auditVerification struct {
	Intact      bool `json:"intact"`
	Records     int  `json:"records"`
	Checkpoints int  `json:"checkpoints"`
	Break       *struct {
		Seq     int    `json:"seq"`
		Problem string `json:"problem"`
	} `json:"break"`
}

// verifyAudit runs tc audit verify --json and returns its result and exit
// code.
func verifyAudit(t *testing.T, srv *harness.Server) (auditVerification, harness.Result) {
	t.Helper()
	res := srv.TC("audit", "verify", "--json")
	var v auditVerification
	if err := json.Unmarshal([]byte(res.Stdout), &v); err != nil {
		t.Fatalf("tc audit verify --json: exit %d, %v\nstdout:\n%s\nstderr:\n%s", res.ExitCode, err, res.Stdout, res.Stderr)
	}
	return v, res
}

func TestAuditRecordsAreHashChainedAcrossRestarts(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	token := "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token

	// Agents choose the bytes of a denied Secret Name, including ones JSON
	// encoders disagree on.
	for _, name := range []string{"github", "openai", "%3Cx%3E%26", "a%FFb", "github"} {
		reveal(t, srv, token, name)
	}
	records := auditRecords(t, srv, 5)
	lines := srv.AuditRecords(5)

	// A restart picks the chain up where it ended.
	srv.Stop()
	credential := srv.Credential
	srv = tc.Start(revealConfig)
	srv.Credential = credential
	waitForPlugin(t, srv, "fake", running)
	reveal(t, srv, token, "github")
	records = append(records, auditRecords(t, srv, 1)...)
	lines = append(lines, srv.AuditRecords(1)...)

	prev := strings.Repeat("0", 64)
	seen := map[string]bool{}
	for i, rec := range records {
		if rec.Seq != int64(i+1) || rec.PrevHash != prev {
			t.Errorf("record %d: seq %d, prev_hash %s; want seq %d chained to %s", i+1, rec.Seq, rec.PrevHash, i+1, prev)
		}
		if len(rec.Hash) != 64 || strings.Trim(rec.Hash, "0123456789abcdef") != "" || seen[rec.Hash] {
			t.Errorf("record %d: hash %q is not a distinct SHA-256 in hex", i+1, rec.Hash)
		}
		if got := lineHash(t, lines[i]); got != rec.Hash {
			t.Errorf("record %d: the line without its hash hashes to %s, want %s: %s", i+1, got, rec.Hash, lines[i])
		}
		seen[rec.Hash] = true
		prev = rec.Hash
	}

	res := srv.TC("audit", "verify")
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "intact") || !strings.Contains(res.Stdout, "6 Audit Records") {
		t.Fatalf("tc audit verify: exit %d, want 0 reporting 6 intact Audit Records\nstdout:\n%s\nstderr:\n%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	if v, res := verifyAudit(t, srv); res.ExitCode != 0 || !v.Intact || v.Records != 6 || v.Break != nil {
		t.Fatalf("tc audit verify --json = %+v, exit %d; want intact with 6 records", v, res.ExitCode)
	}
}

// lineHash is how a stream consumer checks a record without re-encoding it
// (ADR-0016): the SHA-256 of the line with its final hash member removed.
func lineHash(t *testing.T, line string) string {
	t.Helper()
	i := strings.LastIndex(line, `,"hash":"`)
	if i < 0 || !strings.HasSuffix(line, `"}`) {
		t.Fatalf("Audit Record does not end with its hash: %s", line)
	}
	sum := sha256.Sum256([]byte(line[:i] + "}"))
	return hex.EncodeToString(sum[:])
}

// A record someone writes after the chain's end chains correctly, but
// TrustedCourier did not append it, and it would block the next record.
func TestAuditVerifyReportsARecordTrustedCourierDidNotAppend(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	token := "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token
	for _, name := range []string{"github", "openai", "github"} {
		reveal(t, srv, token, name)
	}
	records := auditRecords(t, srv, 3)
	last := srv.AuditRecords(3)[2]

	// Forge record 4 from record 3 in the documented format.
	forged := strings.Replace(last, `"seq":3,`, `"seq":4,`, 1)
	forged = strings.Replace(forged, `"prev_hash":"`+records[2].PrevHash+`"`, `"prev_hash":"`+records[2].Hash+`"`, 1)
	hash := lineHash(t, forged)
	tc.TamperDatabase(fmt.Sprintf(`INSERT INTO audit_records
		SELECT 4, time, agent_token_id, secret_name, delivery, upstream, upstream_host, decision,
		reason, upstream_status, failure, hash, X'%s' FROM audit_records WHERE seq = 3`, hash))

	v, res := verifyAudit(t, srv)
	if res.ExitCode != 1 || v.Intact || v.Break == nil || v.Break.Seq != 4 || !strings.Contains(v.Break.Problem, "not appended by TrustedCourier") || v.Records != 3 {
		t.Fatalf("tc audit verify --json = %+v (break %+v), exit %d; want a break at record 4, not appended by TrustedCourier", v, v.Break, res.ExitCode)
	}
}

func TestProxyDeliveryCutOffByShutdownIsAudited(t *testing.T) {
	_, srv, token := startProxy(t, "openai-proxy")

	req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = bearer(token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if line, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil || line != "data: first\n" {
		t.Fatalf("first event = %q, %v", line, err)
	}

	// The Upstream holds the stream open past the shutdown grace period.
	srv.Stop()

	records := auditRecords(t, srv, 1)
	if len(records) != 1 {
		t.Fatalf("%d Audit Records, want 1: %+v", len(records), records)
	}
	if rec := records[0]; rec.Decision != "allowed" || rec.UpstreamStatus == nil || *rec.UpstreamStatus != 200 ||
		rec.Failure != "cut off by server shutdown" {
		t.Fatalf("Audit Record = %+v, want allowed with status 200, cut off by server shutdown", rec)
	}
}

func TestAuditVerifyReportsTheFirstBreak(t *testing.T) {
	cases := []struct {
		name, tamper string
		wantSeq      int
		wantProblem  string
	}{
		{"record altered", "UPDATE audit_records SET decision = 'allowed', reason = '' WHERE seq = 2", 2, "does not match its hash"},
		{"record deleted", "DELETE FROM audit_records WHERE seq = 2", 2, "missing"},
		{"first record deleted", "DELETE FROM audit_records WHERE seq = 1", 1, "missing"},
		{"last record deleted", "DELETE FROM audit_records WHERE seq = 3", 3, "missing"},
		{"record replaced by the next", "DELETE FROM audit_records WHERE seq = 2; UPDATE audit_records SET seq = 2 WHERE seq = 3", 2, "does not match its hash"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			srv := tc.Start(revealConfig)
			waitForPlugin(t, srv, "fake", running)
			token := "Bearer " + issueAgentToken(t, srv, "github-reveal", "1h").Token
			for _, name := range []string{"github", "openai", "github"} {
				reveal(t, srv, token, name)
			}
			auditRecords(t, srv, 3)
			if v, res := verifyAudit(t, srv); res.ExitCode != 0 || !v.Intact {
				t.Fatalf("before tampering: tc audit verify = %+v, exit %d; want intact", v, res.ExitCode)
			}

			tc.TamperDatabase(c.tamper)

			v, res := verifyAudit(t, srv)
			if res.ExitCode != 1 || v.Intact || v.Break == nil || v.Break.Seq != c.wantSeq ||
				!strings.Contains(v.Break.Problem, c.wantProblem) || v.Records != int(c.wantSeq-1) {
				t.Fatalf("tc audit verify --json = %+v (break %+v), exit %d; want a break at record %d that is %q, after %d intact",
					v, v.Break, res.ExitCode, c.wantSeq, c.wantProblem, c.wantSeq-1)
			}
			text := srv.TC("audit", "verify")
			if want := fmt.Sprintf("broken at record %d", c.wantSeq); text.ExitCode != 1 || !strings.Contains(text.Stdout, want) {
				t.Fatalf("tc audit verify: exit %d, want 1 reporting %q\nstdout:\n%s\nstderr:\n%s", text.ExitCode, want, text.Stdout, text.Stderr)
			}
		})
	}
}

func TestRevealDeliveryProducesAnAuditRecord(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	issued := issueAgentToken(t, srv, "github-reveal", "1h")

	if got := reveal(t, srv, "Bearer "+issued.Token, "github"); got.Status != http.StatusOK {
		t.Fatalf("reveal github = %d %q, want 200", got.Status, got.Body)
	}
	records := auditRecords(t, srv, 1)
	if len(records) != 1 {
		t.Fatalf("got %d Audit Records, want 1: %+v", len(records), records)
	}
	rec := records[0]
	want := auditRecord{
		Seq:          1,
		Time:         rec.Time,
		AgentTokenID: issued.ID,
		SecretName:   "github",
		Delivery:     "reveal",
		Decision:     "allowed",
		PrevHash:     rec.PrevHash,
		Hash:         rec.Hash,
	}
	if rec != want {
		t.Errorf("Audit Record = %+v, want %+v", rec, want)
	}
	if time.Since(rec.Time) > time.Minute || time.Until(rec.Time) > time.Second {
		t.Errorf("Audit Record time = %v, want about now", rec.Time)
	}
}

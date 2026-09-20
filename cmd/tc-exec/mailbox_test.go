package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testMailboxBroker(t *testing.T) *broker {
	t.Helper()
	workspace, mailbox := t.TempDir(), t.TempDir()
	if err := os.Chmod(mailbox, 0700); err != nil {
		t.Fatal(err)
	}
	b := &broker{cfg: config{Workspace: workspace, Mailbox: mailbox}, jobs: make(map[string]job), workers: make(chan struct{}, maxWorkers)}
	if err := b.openMailbox(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.closeMailbox)
	return b
}

func submitMailbox(t *testing.T, b *broker, command string) reply {
	t.Helper()
	r := b.process(message{Action: "submit", Command: command, Workdir: b.cfg.Workspace})
	if r.Error != "" || r.Mailbox == nil {
		t.Fatalf("submit: %+v", r)
	}
	return r
}

func TestMailboxDispatchSingleUseAndBoundedOutput(t *testing.T) {
	b := testMailboxBroker(t)
	submitted := submitMailbox(t, b, "printf hello")
	r, err := dispatchMailbox(context.Background(), *submitted.Mailbox, submitted.Job)
	if err != nil || r.Status != 0 || r.Output != "hello" {
		t.Fatalf("dispatch: %+v %v", r, err)
	}
	if _, err := dispatchMailbox(context.Background(), *submitted.Mailbox, submitted.Job); err == nil {
		t.Fatal("replay accepted")
	}
	if r := b.process(message{Action: "dispatch", Job: submitted.Job}); r.Error == "" {
		t.Fatal("socket replay accepted")
	}
	submitted = submitMailbox(t, b, "python3 -c 'print(\"x\"*1100000)'")
	r, err = dispatchMailbox(context.Background(), *submitted.Mailbox, submitted.Job)
	if err != nil || len(r.Output) != outputLimit || !r.Truncated {
		t.Fatalf("output bounds: length=%d truncated=%v error=%v", len(r.Output), r.Truncated, err)
	}
}

func TestMailboxRejectsReplacementsAndTraversal(t *testing.T) {
	for _, kind := range []string{"symlink", "regular", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			b := testMailboxBroker(t)
			submitted := submitMailbox(t, b, "echo should-not-run > executed")
			path := filepath.Join(submitted.Mailbox.Path, "request")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink("response", path); err != nil {
					t.Fatal(err)
				}
			case "regular":
				if err := os.WriteFile(path, []byte("D"), 0600); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(path)
			}
			if _, err := dispatchMailbox(context.Background(), *submitted.Mailbox, submitted.Job); err == nil {
				t.Fatal("replacement accepted")
			}
			if _, err := dispatchMailbox(context.Background(), *submitted.Mailbox, "../request"); err == nil {
				t.Fatal("traversal accepted")
			}
			if _, err := os.Stat(filepath.Join(b.cfg.Workspace, "executed")); !os.IsNotExist(err) {
				t.Fatal("replacement executed a command")
			}
		})
	}
}

func TestMailboxCancellationAndRestart(t *testing.T) {
	b := testMailboxBroker(t)
	submitted := submitMailbox(t, b, "echo started > started; sleep 2; echo escaped > escaped")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := dispatchMailbox(ctx, *submitted.Mailbox, submitted.Job); done <- err }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(filepath.Join(b.cfg.Workspace, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancel succeeded unexpectedly")
	}
	time.Sleep(100 * time.Millisecond)
	if len(b.workers) != 0 {
		t.Fatal("cancelled worker not reaped")
	}
	if _, err := os.Stat(filepath.Join(b.cfg.Workspace, "escaped")); !os.IsNotExist(err) {
		t.Fatal("cancelled command continued")
	}
	submitted = submitMailbox(t, b, "echo restart")
	b.mailboxCancel()
	b.mailboxWG.Wait()
	if _, err := dispatchMailbox(context.Background(), *submitted.Mailbox, submitted.Job); err == nil {
		t.Fatal("stopped broker accepted dispatch")
	}
}

func TestCodexSandboxConfigKeepsCredentialsOutsideAllowlist(t *testing.T) {
	c := string(codexSandboxConfig("/project", "/profile/mailbox", "/bin/tc-exec", "/bin/codex", "/private/token"))
	for _, want := range []string{`":root" = "deny"`, `":minimal" = "read"`, `enabled = false`, `"/profile/mailbox" = "write"`} {
		if !strings.Contains(c, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, bad := range []string{"network_access", `"/profile" = "write"`, `"/profile" = "read"`, "danger-full-access"} {
		if strings.Contains(c, bad) {
			t.Fatalf("unexpected %s", bad)
		}
	}
}

func TestMailboxReplyDoesNotContainCommand(t *testing.T) {
	b := testMailboxBroker(t)
	r := submitMailbox(t, b, "echo command-not-in-mailbox")
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "command-not-in-mailbox") {
		t.Fatal("command persisted in mailbox reference")
	}
	entries, err := os.ReadDir(r.Mailbox.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("unexpected mailbox entries")
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeNamedPipe == 0 {
			t.Fatal("mailbox contains regular payload file")
		}
	}
}

func TestMailboxExpiryAdmissionAndShutdown(t *testing.T) {
	b := testMailboxBroker(t)
	r := submitMailbox(t, b, "echo unexpected > executed")
	b.mu.Lock()
	j := b.jobs[r.Job]
	j.created = time.Now().Add(-jobTTL - time.Second)
	b.jobs[r.Job] = j
	b.mu.Unlock()
	got, err := dispatchMailbox(context.Background(), *r.Mailbox, r.Job)
	if err != nil || got.Error != "unknown or expired job" {
		t.Fatalf("expired job: %+v %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(b.cfg.Workspace, "executed")); !os.IsNotExist(err) {
		t.Fatal("expired command ran")
	}
	b.mu.Lock()
	for i := 0; i < maxJobs; i++ {
		b.jobs[fmt.Sprint(i)] = job{"true", b.cfg.Workspace, time.Now()}
	}
	b.mu.Unlock()
	got = b.process(message{Action: "submit", Command: "true", Workdir: b.cfg.Workspace})
	if got.Error != "broker busy" {
		t.Fatalf("admission: %+v", got)
	}
}

func TestMailboxRejectsPublicAndSymlinkRoots(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0755)
	if _, err := openDir(root); err == nil {
		t.Fatal("public mailbox accepted")
	}
	os.Chmod(root, 0700)
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openDir(link); err == nil {
		t.Fatal("symlink mailbox accepted")
	}
}

func TestBrokerEventsExcludePayloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	events, err := openBrokerEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	events.record("end", message{Action: "request", Command: "private-command", Path: "/private-path", Job: "not-a-job"}, reply{Error: "private-error", Output: "private-output"})
	events.file.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") || strings.Contains(string(data), "not-a-job") {
		t.Fatal("diagnostics logged payload")
	}
	if _, err := openBrokerEvents(path); err == nil {
		t.Fatal("existing event log overwritten")
	}
}

func TestMailboxLegacySocketDispatchReleasesEndpoints(t *testing.T) {
	b := testMailboxBroker(t)
	r := submitMailbox(t, b, "printf legacy")
	result := b.process(message{Action: "dispatch", Job: r.Job})
	if result.Output != "legacy" || result.Status != 0 {
		t.Fatalf("legacy dispatch: %+v", result)
	}
	deadline := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		active := b.mailboxActive
		b.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("legacy socket consumed job retained FIFO admission")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := dispatchMailbox(context.Background(), *r.Mailbox, r.Job); err == nil {
		t.Fatal("legacy job replay accepted")
	}
}

func TestSetupCodexRejectsTokenInMailbox(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	profile := filepath.Join(root, "profile")
	mailbox := filepath.Join(profile, "mailbox")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mailbox, 0700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(mailbox, "agent-token")
	if err := os.WriteFile(token, []byte("synthetic-only"), 0600); err != nil {
		t.Fatal(err)
	}
	err := setup([]string{"--codex-sandbox", "--codex-binary", "/usr/bin/true", "--dir", profile, "--workspace", workspace, "--agent-url", "http://127.0.0.1:8200", "--agent-token-file", token, "--resource", "demo", "--secret-name", "demo", "--upstream", "api", "--path-prefix", "/allowed"})
	if err == nil || !strings.Contains(err.Error(), "outside mailbox") {
		t.Fatalf("unsafe token placement: %v", err)
	}
	if _, err := os.Stat(filepath.Join(profile, "config.toml")); !os.IsNotExist(err) {
		t.Fatal("unsafe profile was published")
	}
}

func TestProfilePreflightAndNoFollow(t *testing.T) {
	for _, kind := range []string{"conflict", "symlink", "dangling"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			os.Chmod(root, 0700)
			target := filepath.Join(t.TempDir(), "outside")
			conflict := filepath.Join(root, "hooks.json")
			switch kind {
			case "conflict":
				os.WriteFile(conflict, []byte("different"), 0600)
			case "symlink":
				os.WriteFile(target, []byte("outside"), 0600)
				os.Symlink(target, conflict)
			case "dangling":
				os.Symlink(target, conflict)
			}
			if err := publishProfile(root, map[string][]byte{"config.toml": []byte("policy"), "hooks.json": []byte("hooks")}); err == nil {
				t.Fatal("unsafe profile accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "config.toml")); !os.IsNotExist(err) {
				t.Fatal("preflight failure published a policy")
			}
			data, err := os.ReadFile(target)
			if kind == "dangling" && !os.IsNotExist(err) {
				t.Fatal("dangling symlink target created")
			}
			if kind == "symlink" && string(data) != "outside" {
				t.Fatal("symlink target changed")
			}
		})
	}
	root := t.TempDir()
	os.Chmod(root, 0700)
	files := map[string][]byte{"config.toml": []byte("complete policy"), "hooks.json": []byte("complete hooks")}
	if err := publishProfile(root, files); err != nil {
		t.Fatal(err)
	}
	if err := publishProfile(root, files); err != nil {
		t.Fatal("idempotent setup:", err)
	}
}

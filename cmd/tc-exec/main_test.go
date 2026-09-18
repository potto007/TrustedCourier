package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBrokerShellAndHTTP(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap unavailable")
	}
	workspace := t.TempDir()
	secret := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(secret, []byte("synthetic-host-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy/demo/api/allowed" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("X-TC-Agent-Token") != "synthetic-agent-token" {
			t.Errorf("missing Agent Token")
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	b := &broker{cfg: config{Workspace: workspace, AgentURL: srv.URL, Resources: map[string]resource{"demo": {SecretName: "demo", Upstream: "api", Methods: []string{"GET"}, PathPrefixes: []string{"/allowed"}}}}, token: "synthetic-agent-token", jobs: make(map[string]job), workers: make(chan struct{}, maxWorkers)}
	submitted := b.process(message{Action: "submit", Command: "printf ordinary", Workdir: workspace})
	if submitted.Job == "" {
		t.Fatal(submitted.Error)
	}
	got := b.process(message{Action: "dispatch", Job: submitted.Job})
	if got.Status != 0 || got.Output != "ordinary" {
		t.Fatalf("ordinary = %+v", got)
	}
	if again := b.process(message{Action: "dispatch", Job: submitted.Job}); again.Error == "" {
		t.Fatal("job replay accepted")
	}
	for _, cmd := range []string{"cat " + secret, "python3 -c 'open(\"" + secret + "\").read()'", "/usr/bin/curl -fsS " + srv.URL, "env", "sh -c 'cat " + secret + "'"} {
		got = b.shell(job{command: cmd, workdir: workspace})
		if strings.Contains(got.Output, "synthetic-host-secret") || strings.Contains(got.Output, "synthetic-agent-token") || strings.Contains(got.Output, `{"ok":true}`) {
			t.Fatalf("shell escaped via %q: %+v", cmd, got)
		}
	}
	if got := b.process(message{Action: "submit", Command: "pwd", Workdir: filepath.Dir(workspace)}); got.Error == "" {
		t.Fatal("outside workdir accepted")
	}
	if got := b.process(message{Action: "request", Resource: "demo", Method: "POST", Path: "/allowed"}); got.Error == "" {
		t.Fatal("POST accepted")
	}
	if got := b.process(message{Action: "request", Resource: "demo", Method: "GET", Path: "/forbidden"}); got.Error == "" {
		t.Fatal("path accepted")
	}
	if got := b.process(message{Action: "request", Resource: "demo", Method: "GET", Path: "/allowed"}); got.Status != 200 || got.Output != `{"ok":true}` {
		t.Fatalf("HTTP = %+v", got)
	}
}

func TestHookPreservesInputFields(t *testing.T) {
	dir := t.TempDir()
	workspace := t.TempDir()
	socket := filepath.Join(dir, "broker.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var m message
		json.NewDecoder(conn).Decode(&m)
		if m.Action != "submit" || m.Command != "echo hello" {
			t.Errorf("submit = %+v", m)
		}
		json.NewEncoder(conn).Encode(reply{Job: "abc"})
	}()
	path := filepath.Join(dir, "config.json")
	tokenFile := filepath.Join(dir, "agent-token")
	if err := os.WriteFile(tokenFile, []byte("synthetic-token"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config{Workspace: workspace, Socket: socket, AgentURL: "http://127.0.0.1:9999", AgentTokenFile: tokenFile}
	data, _ := json.Marshal(cfg)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	in, err := os.CreateTemp(dir, "input")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { os.Stdin = old }()
	in.WriteString(`{"tool_name":"Bash","cwd":"` + workspace + `","tool_input":{"command":"echo hello","timeout":12345}}`)
	in.Seek(0, 0)
	os.Stdin = in
	oldOut := os.Stdout
	out, err := os.CreateTemp(dir, "output")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = out
	defer func() { os.Stdout = oldOut }()
	if err = hook([]string{"--config", path}); err != nil {
		t.Fatal(err)
	}
	out.Seek(0, 0)
	var value struct {
		HookSpecificOutput struct {
			PermissionDecision string                     `json:"permissionDecision"`
			UpdatedInput       map[string]json.RawMessage `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err = json.NewDecoder(out).Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value.HookSpecificOutput.PermissionDecision != "allow" || string(value.HookSpecificOutput.UpdatedInput["timeout"]) != "12345" {
		t.Fatalf("hook output %+v", value)
	}
}

func TestSandboxCanReachOnlyBrokerSocket(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap unavailable")
	}
	workspace := t.TempDir()
	dir := t.TempDir()
	socket := filepath.Join(dir, "broker.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	configPath := filepath.Join(dir, "config.json")
	if err = os.WriteFile(configPath, []byte(`{"demo":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var m message
		json.NewDecoder(c).Decode(&m)
		if m.Action != "request" {
			t.Errorf("action = %q", m.Action)
		}
		json.NewEncoder(c).Encode(reply{Status: 200, Output: "broker-ok"})
	}()
	b := &broker{cfg: config{Workspace: workspace, Socket: socket}, configPath: configPath}
	cmd := `python3 -c 'import json,socket,os; s=socket.socket(socket.AF_UNIX); s.connect(os.environ["TC_EXEC_SOCKET"]); s.sendall(b"{\"action\":\"request\"}\n"); print(json.loads(s.recv(4096))["output"])'`
	got := b.shell(job{command: cmd, workdir: workspace})
	if got.Status != 0 || !strings.Contains(got.Output, "broker-ok") {
		t.Fatalf("sandbox broker call = %+v", got)
	}
	<-done
}

func TestSandboxDeniesInternetSocketFamilies(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap unavailable")
	}
	workspace := t.TempDir()
	b := &broker{cfg: config{Workspace: workspace}}
	for _, family := range []string{"AF_INET", "AF_INET6", "AF_PACKET"} {
		command := `python3 -c 'import socket,errno; s=None
try: s=socket.socket(socket.` + family + `,socket.SOCK_STREAM)
except OSError as e: print("denied" if e.errno==errno.EPERM else "wrong-error")
else: print("socket-opened"); s.close()'`
		got := b.shell(job{command: command, workdir: workspace})
		if got.Status != 0 || got.Output != "denied\n" {
			t.Fatalf("%s socket policy = %+v", family, got)
		}
	}
}

func TestLoadRejectsWorkspaceAliases(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "real")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(workspace, alias); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(workspace, "token")
	if err := os.WriteFile(token, []byte("synthetic-token"), 0600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "profile")
	if err := os.Mkdir(profile, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, ws, token string }{
		{"workspace alias", alias, token},
		{"token alias", workspace, filepath.Join(alias, "token")},
		{"profile alias", workspace, filepath.Join(root, "outside-token")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "profile alias" {
				if err := os.WriteFile(tc.token, []byte("synthetic-token"), 0600); err != nil {
					t.Fatal(err)
				}
				profile = filepath.Join(alias, "profile")
				if err := os.Mkdir(profile, 0700); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(profile, "config.json")
			data, _ := json.Marshal(config{Workspace: tc.ws, Socket: filepath.Join(root, "broker.sock"), AgentURL: "http://127.0.0.1:9999", AgentTokenFile: tc.token})
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := load(path); err == nil {
				t.Fatal("workspace alias exposed protected file")
			}
		})
	}
}

func TestBoundedOutputAndBash(t *testing.T) {
	w := &boundedOutput{}
	chunk := []byte(strings.Repeat("x", 4096))
	for i := 0; i < 1024; i++ {
		if n, err := w.Write(chunk); n != len(chunk) || err != nil {
			t.Fatal(n, err)
		}
	}
	if w.buf.Len() != outputLimit || !w.truncated {
		t.Fatalf("output len=%d truncated=%t", w.buf.Len(), w.truncated)
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap unavailable")
	}
	workspace := t.TempDir()
	b := &broker{cfg: config{Workspace: workspace}}
	got := b.shell(job{command: "[[ 1 == 1 ]] && a=(ok) && echo ${a[0]}", workdir: workspace})
	if got.Status != 0 || got.Output != "ok\n" {
		t.Fatalf("Bash = %+v", got)
	}
	got = b.shell(job{command: "for ((i=0;i<700000;i++)); do echo x; done", workdir: workspace})
	if got.Status != 0 || !got.Truncated || len(got.Output) != outputLimit {
		t.Fatalf("continued output = status %d len %d truncated %t", got.Status, len(got.Output), got.Truncated)
	}
}

func TestWorkspaceReplacementDoesNotRedirectMount(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap unavailable")
	}
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "marker"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err := os.Rename(workspace, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "marker"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	b := &broker{cfg: config{Workspace: workspace}, workspaceDir: fd}
	got := b.shell(job{command: "cat marker", workdir: workspace})
	if got.Status != 0 || got.Output != "original" {
		t.Fatalf("mount redirected after workspace replacement: %+v", got)
	}
}

func TestJobExpiryAndAdmission(t *testing.T) {
	workspace := t.TempDir()
	b := &broker{cfg: config{Workspace: workspace}, jobs: map[string]job{"old": {"echo old", workspace, time.Now().Add(-jobTTL - time.Second)}}, workers: make(chan struct{}, maxWorkers)}
	if r := b.process(message{Action: "submit", Command: "echo new", Workdir: workspace}); r.Job == "" {
		t.Fatal(r.Error)
	}
	if _, ok := b.jobs["old"]; ok {
		t.Fatal("expired job retained")
	}
	for i := len(b.jobs); i < maxJobs; i++ {
		b.jobs[strings.Repeat("x", i+1)] = job{"echo", workspace, time.Now()}
	}
	if r := b.process(message{Action: "submit", Command: "echo busy", Workdir: workspace}); r.Error != "broker busy" {
		t.Fatalf("admission = %+v", r)
	}
	for i := 0; i < maxWorkers; i++ {
		b.workers <- struct{}{}
	}
	if r := b.process(message{Action: "dispatch", Job: "old"}); r.Error != "broker busy" {
		t.Fatalf("dispatch admission = %+v", r)
	}
	for i := 0; i < maxWorkers; i++ {
		<-b.workers
	}
}

func TestConcurrentSubmitRespectsJobCap(t *testing.T) {
	workspace := t.TempDir()
	b := &broker{cfg: config{Workspace: workspace}, jobs: make(map[string]job)}
	var wg sync.WaitGroup
	for i := 0; i < maxJobs*2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.process(message{Action: "submit", Command: "echo ok", Workdir: workspace}) }()
	}
	wg.Wait()
	if len(b.jobs) != maxJobs {
		t.Fatalf("admitted %d jobs, cap %d", len(b.jobs), maxJobs)
	}
}

func TestHTTPRequestPreservesEscapedPath(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.EscapedPath())
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	b := &broker{cfg: config{AgentURL: srv.URL, Resources: map[string]resource{"demo": {SecretName: "demo", Upstream: "api", Methods: []string{"GET"}, PathPrefixes: []string{"/allowed"}}}}, token: "synthetic-token"}
	for _, path := range []string{"/allowed/a%20b", "/allowed/%E2%9C%93", "/allowed/a%25b", "/allowed/a%2Fb"} {
		if r := b.httpRequest(message{Resource: "demo", Method: "GET", Path: path}); r.Status != 200 {
			t.Fatalf("%s = %+v", path, r)
		}
		if got, want := seen[len(seen)-1], "/proxy/demo/api"+path; got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestGeneratedHookCommandQuotesConfigPath(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "tc-exec")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build tc-exec: %v\n%s", err, out)
	}
	workspace := filepath.Join(root, "workspace")
	profile := filepath.Join(root, "profile with ' quote")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "agent-token")
	if err := os.WriteFile(token, []byte("synthetic-token"), 0600); err != nil {
		t.Fatal(err)
	}
	setup := exec.Command(binary, "setup", "--dir", profile, "--workspace", workspace, "--agent-url", "http://127.0.0.1:9999", "--agent-token-file", token, "--resource", "demo", "--secret-name", "demo", "--upstream", "api", "--path-prefix", "/allowed")
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(profile, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks struct {
		Hooks struct {
			PreToolUse []struct {
				Hooks []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}
	cmd := hooks.Hooks.PreToolUse[0].Hooks[0].Command
	sh := exec.Command("/bin/sh", "-c", cmd)
	sh.Stdin = strings.NewReader(`{"tool_name":"Bash","cwd":"` + workspace + `","tool_input":{"command":"echo ok"}}`)
	out, err := sh.CombinedOutput()
	if err == nil || strings.Contains(string(out), "open "+strings.Split(profile, " ")[0]) {
		t.Fatalf("quoted hook command failed at path parsing: %v %s", err, out)
	}
}

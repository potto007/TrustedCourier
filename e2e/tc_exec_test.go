package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This uses the normal e2e fake Backend Plugin and TLS Upstream. All values
// are synthetic; the Agent Token is kept outside the brokered workspace.
func TestTCExecAuthenticatedReadThroughProxyDelivery(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")
	dir := t.TempDir()
	binary := filepath.Join(dir, "tc-exec")
	build := exec.Command("go", "build", "-o", binary, "./cmd/tc-exec")
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("bubblewrap is required for broker e2e test: ", err)
	}
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build tc-exec: %v\n%s", err, out)
	}
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "agent-token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "profile")
	codexBinary := os.Getenv("TC_CODEX_BINARY")
	configBinary := codexBinary
	if configBinary == "" {
		configBinary = "/usr/bin/true"
	}
	setup := exec.Command(binary, "setup", "--codex-sandbox", "--codex-binary", configBinary, "--dir", profile, "--workspace", workspace, "--agent-url", srv.AgentURL(), "--agent-token-file", tokenFile, "--resource", "demo", "--secret-name", "openai", "--upstream", "api", "--path-prefix", "/v1/models")
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	cfg := filepath.Join(profile, "tc-exec.json")
	broker := exec.Command(binary, "serve", "--config", cfg)
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { broker.Process.Kill(); broker.Wait() }()
	socket := filepath.Join(profile, "broker.sock")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker socket did not appear")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Exercise the Codex adapter's actual rewrite and dispatcher for Bash
	// syntax that /bin/sh would reject.
	hook := exec.Command(binary, "hook", "--config", cfg)
	hook.Stdin = strings.NewReader(`{"tool_name":"Bash","cwd":"` + workspace + `","tool_input":{"command":"[[ 1 == 1 ]] && a=(ok) && echo ${a[0]}","timeout":120000}}`)
	hookOutput, err := hook.Output()
	if err != nil {
		t.Fatal(err)
	}
	var rewritten struct {
		HookSpecificOutput struct {
			UpdatedInput struct {
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(hookOutput, &rewritten); err != nil {
		t.Fatal(err)
	}
	if rewritten.HookSpecificOutput.UpdatedInput.Timeout != 120000 {
		t.Fatal("Codex timeout field was lost")
	}
	if !strings.Contains(rewritten.HookSpecificOutput.UpdatedInput.Command, " dispatch --mailbox ") {
		t.Fatal("Codex did not use filesystem dispatch")
	}
	dispatchedCommand := exec.Command("/bin/sh", "-c", rewritten.HookSpecificOutput.UpdatedInput.Command)
	if codexBinary != "" {
		// The hook itself runs on the host. Test its rewritten command inside the
		// actual Codex sandbox, including read restrictions before FIFO dispatch.
		outer := filepath.Join(workspace, "outer-boundary.py")
		source := fmt.Sprintf(`import os,socket
for path in [%q,%q,%q]:
 try:
  with open(path, "rb") as f: f.read(1)
 except OSError: pass
 else: raise SystemExit("protected file readable")
s=socket.socket(socket.AF_UNIX)
try: s.connect(%q)
except OSError: pass
else: raise SystemExit("broker socket reachable from outer sandbox")
`, tokenFile, cfg, filepath.Join(workspace, "token-alias"), socket)
		if err := os.Symlink(tokenFile, filepath.Join(workspace, "token-alias")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(outer, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		dispatchedCommand = exec.Command(codexBinary, "sandbox", "-P", "trustedcourier", "-C", workspace, "/bin/sh", "-c", "python3 ./outer-boundary.py && "+rewritten.HookSpecificOutput.UpdatedInput.Command)
		dispatchedCommand.Env = append(os.Environ(), "CODEX_HOME="+profile)
	}
	if out, err := dispatchedCommand.Output(); err != nil || string(out) != "ok\n" {
		t.Fatalf("Codex Bash rewrite: %v %q", err, out)
	}
	call := exec.Command(binary, "request", "--config", cfg, "--resource", "demo", "--method", "GET", "--path", "/v1/models")
	out, err := call.CombinedOutput()
	if err != nil {
		t.Fatalf("request: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "upstream saw GET /v1/models") {
		t.Fatalf("unexpected response %q", out)
	}
	// The same operation is reachable from an ordinary shell job. Its only
	// network path is the mounted broker socket.
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var submitted struct {
		Job   string `json:"job"`
		Error string `json:"error"`
	}
	if err = json.NewEncoder(conn).Encode(map[string]string{"action": "submit", "command": "/tc-exec request --resource demo --method GET --path /v1/models", "workdir": workspace}); err != nil {
		t.Fatal(err)
	}
	if err = json.NewDecoder(conn).Decode(&submitted); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if submitted.Job == "" {
		t.Fatal(submitted.Error)
	}
	conn, err = net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var dispatched struct {
		Status int    `json:"status"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err = json.NewEncoder(conn).Encode(map[string]string{"action": "dispatch", "job": submitted.Job}); err != nil {
		t.Fatal(err)
	}
	if err = json.NewDecoder(conn).Decode(&dispatched); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if dispatched.Status != 0 || !strings.Contains(dispatched.Output, "upstream saw GET /v1/models") {
		t.Fatalf("sandbox request = %+v", dispatched)
	}
	requests := tc.Upstream().Requests()
	if len(requests) != 2 || requests[0].Header.Get("Authorization") != "Bearer test-value-1" || requests[1].Header.Get("Authorization") != "Bearer test-value-1" {
		t.Fatalf("proxy did not inject synthetic Secret: %+v", requests)
	}
	if strings.Contains(string(out), token) || strings.Contains(string(out), "test-value-1") {
		t.Fatal("Agent Token or Secret reached client output")
	}
	records := srv.AuditRecords(1)
	var record map[string]any
	if err = json.Unmarshal([]byte(records[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record["decision"] != "allowed" || record["delivery"] != "proxy" {
		t.Fatalf("Audit Record = %+v", record)
	}
}

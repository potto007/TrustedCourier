package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test the public Claude hook's actual rewrite against a disposable TC
// instance and a synthetic Secret. Claude itself is not launched here.
func TestClaudeHookBrokerProxyDelivery(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")
	dir := t.TempDir()
	build := func(name, pkg string) string {
		binary := filepath.Join(dir, name)
		cmd := exec.Command("/usr/local/go/bin/go", "build", "-o", binary, pkg)
		cmd.Dir = ".."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", pkg, err, out)
		}
		return binary
	}
	brokerBin := build("tc-exec", "./cmd/tc-exec")
	hookBin := build("tc-claude-hook", "./cmd/tc-claude-hook")
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "agent-token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "profile")
	setup := exec.Command(brokerBin, "setup", "--dir", profile, "--workspace", workspace, "--agent-url", srv.AgentURL(), "--agent-token-file", tokenFile, "--resource", "demo", "--secret-name", "openai", "--upstream", "api", "--path-prefix", "/v1/models")
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	cfg := filepath.Join(profile, "tc-exec.json")
	broker := exec.Command(brokerBin, "serve", "--config", cfg)
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Process.Kill(); _ = broker.Wait() }()
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
	adapter := exec.Command(hookBin)
	adapter.Env = append(os.Environ(), "TC_EXEC_CONFIG="+cfg, "TC_EXEC_BINARY="+brokerBin)
	adapter.Stdin = strings.NewReader(`{"tool_name":"Bash","cwd":"` + workspace + `","tool_input":{"command":"/tc-exec request --resource demo --method GET --path /v1/models","timeout":5000,"description":"synthetic read"}}`)
	adapterOutput, err := adapter.CombinedOutput()
	if err != nil {
		t.Fatalf("Claude adapter: %v\n%s", err, adapterOutput)
	}
	var rewritten struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
			UpdatedInput       struct {
				Command     string `json:"command"`
				Timeout     int    `json:"timeout"`
				Description string `json:"description"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(adapterOutput, &rewritten); err != nil {
		t.Fatal(err)
	}
	if rewritten.HookSpecificOutput.PermissionDecision != "" || rewritten.HookSpecificOutput.UpdatedInput.Timeout != 5000 || rewritten.HookSpecificOutput.UpdatedInput.Description != "synthetic read" {
		t.Fatalf("Claude permission or fields changed: %s", adapterOutput)
	}
	dispatch := exec.Command("/bin/sh", "-c", rewritten.HookSpecificOutput.UpdatedInput.Command)
	output, err := dispatch.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "upstream saw GET /v1/models") {
		t.Fatalf("dispatch: %v\n%s", err, output)
	}
	if strings.Contains(string(output), token) || strings.Contains(string(output), "test-value-1") {
		t.Fatal("Agent Token or synthetic Secret reached tool output")
	}
	requests := tc.Upstream().Requests()
	if len(requests) != 1 || requests[0].Header.Get("Authorization") != "Bearer test-value-1" {
		t.Fatalf("proxy request = %+v", requests)
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewritePreservesBashInputAndNormalPermission(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "tc-exec.json")
	if err := os.WriteFile(profile, []byte(`{"socket":"/tmp/tc-test.sock"}`), 0600); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == "TC_EXEC_CONFIG" {
			return profile
		}
		if k == "TC_EXEC_BINARY" {
			return "/usr/bin/tc-exec"
		}
		return ""
	}
	var output bytes.Buffer
	event := `{"tool_name":"Bash","cwd":"/workspace","tool_input":{"command":"printf 'hello'\n","timeout":1234,"run_in_background":false,"description":"test"}}`
	err := run(strings.NewReader(event), &output, getenv, func(_ context.Context, socket, command, workdir string) (string, error) {
		if socket != "/tmp/tc-test.sock" || command != "printf 'hello'\n" || workdir != "/workspace" {
			t.Fatalf("unexpected request: %q %q %q", socket, command, workdir)
		}
		return "job-1", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		HookSpecificOutput struct {
			HookEventName      string                     `json:"hookEventName"`
			PermissionDecision string                     `json:"permissionDecision"`
			UpdatedInput       map[string]json.RawMessage `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.HookSpecificOutput.HookEventName != "PreToolUse" || result.HookSpecificOutput.PermissionDecision != "" {
		t.Fatalf("bad decision: %s", output.String())
	}
	var cmd string
	if err := json.Unmarshal(result.HookSpecificOutput.UpdatedInput["command"], &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd != "'/usr/bin/tc-exec' dispatch --config '"+profile+"' --job 'job-1'" {
		t.Fatalf("unexpected dispatcher: %q", cmd)
	}
	for _, field := range []string{"timeout", "run_in_background", "description"} {
		if _, ok := result.HookSpecificOutput.UpdatedInput[field]; !ok {
			t.Errorf("lost %s", field)
		}
	}
}

func TestNoRewriteOnInvalidInput(t *testing.T) {
	var output bytes.Buffer
	err := run(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"echo x"}}`), &output, func(string) string { return "" }, func(context.Context, string, string, string) (string, error) {
		t.Fatal("called submit")
		return "", nil
	})
	if err == nil || output.Len() != 0 {
		t.Fatalf("want error without rewrite: %v %s", err, output.String())
	}
}

func TestBackgroundCallDeniedWithoutSubmit(t *testing.T) {
	var output bytes.Buffer
	err := run(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"sleep 3","run_in_background":true}}`), &output, func(string) string { return "" }, func(context.Context, string, string, string) (string, error) {
		t.Fatal("called submit")
		return "", nil
	})
	if err != nil || !strings.Contains(output.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("want denial: %v %s", err, output.String())
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Fatal(got)
	}
}

func TestSubmitSocketProtocol(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var req struct {
			Action  string `json:"action"`
			Command string `json:"command"`
			Workdir string `json:"workdir"`
		}
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			done <- err
			return
		}
		if req.Action != "submit" || req.Command != "echo one\necho two" || req.Workdir != "/workspace" {
			done <- fmt.Errorf("bad request: %+v", req)
			return
		}
		_, err = conn.Write([]byte("{\"job\":\"abc\"}\n"))
		done <- err
	}()
	job, err := submit(context.Background(), socket, "echo one\necho two", "/workspace")
	if err != nil || job != "abc" {
		t.Fatalf("job %q: %v", job, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// tc-claude-hook translates Claude Code's documented PreToolUse Bash payload
// into a TrustedCourier execution job. It does not grant tool permission.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxInput = 1 << 20

type input struct {
	ToolName  string                     `json:"tool_name"`
	ToolInput map[string]json.RawMessage `json:"tool_input"`
	CWD       string                     `json:"cwd"`
}

type config struct {
	Socket string `json:"socket"`
}

type brokerResponse struct {
	Job   string `json:"job"`
	Error string `json:"error"`
}

func main() {
	if err := run(os.Stdin, os.Stdout, os.Getenv, submit); err != nil {
		// A malformed or unavailable hook is not a security boundary. The
		// protected launcher must confine the process independently.
		fmt.Fprintln(os.Stderr, "tc-claude-hook:", err)
		os.Exit(1)
	}
}

type submitFunc func(context.Context, string, string, string) (string, error)

func run(stdin io.Reader, stdout io.Writer, getenv func(string) string, submitJob submitFunc) error {
	data, err := io.ReadAll(io.LimitReader(stdin, maxInput+1))
	if err != nil || len(data) > maxInput {
		return errors.New("invalid or oversized hook input")
	}
	var event input
	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("decode hook input: %w", err)
	}
	if event.ToolName != "Bash" {
		return errors.New("expected Bash PreToolUse event")
	}
	var command string
	if err := json.Unmarshal(event.ToolInput["command"], &command); err != nil || command == "" {
		return errors.New("Bash command is missing")
	}
	profile := getenv("TC_EXEC_CONFIG")
	if !filepath.IsAbs(profile) {
		return errors.New("TC_EXEC_CONFIG must be an absolute path in a protected launch")
	}
	bin := getenv("TC_EXEC_BINARY")
	if bin == "" {
		bin = "tc-exec"
	}
	if !filepath.IsAbs(bin) {
		return errors.New("TC_EXEC_BINARY must be an absolute path in a protected launch")
	}
	profileData, err := os.ReadFile(profile)
	if err != nil {
		return fmt.Errorf("read execution profile: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(profileData, &cfg); err != nil || !filepath.IsAbs(cfg.Socket) {
		return errors.New("execution profile has no absolute socket path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	job, err := submitJob(ctx, cfg.Socket, command, event.CWD)
	if err != nil {
		return fmt.Errorf("submit confined job: %w", err)
	}
	if job == "" || strings.ContainsAny(job, "\r\n\x00") {
		return errors.New("broker returned invalid job identifier")
	}
	// updatedInput replaces the entire input. Retain every other Bash field,
	// including timeout, background mode, and caller-provided metadata.
	event.ToolInput["command"], _ = json.Marshal(shellQuote(bin) + " dispatch --config " + shellQuote(profile) + " --job " + shellQuote(job))
	decision := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PreToolUse", "updatedInput": event.ToolInput,
	}}
	return json.NewEncoder(stdout).Encode(decision)
}

func submit(ctx context.Context, socket, command, workdir string) (string, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	request := map[string]string{"action": "submit", "command": command, "workdir": workdir}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxInput+1)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(line) > maxInput {
		return "", errors.New("broker response too large")
	}
	var response brokerResponse
	if err := json.NewDecoder(bytes.NewReader(line)).Decode(&response); err != nil {
		return "", err
	}
	if response.Error != "" {
		return "", errors.New(response.Error)
	}
	return response.Job, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Package harness is the Seam 1 process harness: it builds the real tc
// binary, starts TrustedCourier from a config file, and drives the tc CLI.
// Tests built on it assert only externally visible behavior.
package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"
)

var tcBinary string

// Main builds the tc binary once for the test package, runs the tests, and
// removes the build. Call it from TestMain.
func Main(m *testing.M) {
	dir, err := os.MkdirTemp("", "tc-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
	code, err := buildAndRun(m, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		code = 1
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func buildAndRun(m *testing.M, dir string) (int, error) {
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return 0, fmt.Errorf("locate module root: %w", err)
	}
	root := filepath.Dir(strings.TrimSpace(string(gomod)))
	tcBinary = filepath.Join(dir, "tc")
	args := []string{"build", "-o", tcBinary}
	if raceEnabled {
		args = append(args, "-race")
	}
	args = append(args, "./cmd/tc")
	build := exec.Command("go", args...)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("build tc: %w\n%s", err, out)
	}
	return m.Run(), nil
}

// Installation is one TrustedCourier data directory and admin socket that
// survives server restarts.
type Installation struct {
	t       *testing.T
	DataDir string
	Socket  string
	dir     string
}

// New creates an empty installation cleaned up when the test ends.
func New(t *testing.T) *Installation {
	t.Helper()
	// Unix socket paths are limited to ~108 bytes, so keep the base short.
	dir, err := os.MkdirTemp("/tmp", "tc-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return &Installation{
		t:       t,
		dir:     dir,
		DataDir: filepath.Join(dir, "data"),
		Socket:  filepath.Join(dir, "admin.sock"),
	}
}

// ConfigVars are available to config templates as {{.DataDir}}, {{.Socket}}
// and {{.UID}}.
type ConfigVars struct {
	DataDir string
	Socket  string
	UID     int
}

// BaseConfig is a minimal valid config with one Policy.
const BaseConfig = `
data_dir: {{.DataDir}}
admin:
  socket: {{.Socket}}
policies:
  openai-proxy:
    secrets:
      - name: openai
        delivery: [proxy]
  github-reveal:
    secrets:
      - name: github
        delivery: [proxy, reveal]
`

func (in *Installation) writeConfig(tmpl string) string {
	in.t.Helper()
	parsed, err := template.New("config").Parse(tmpl)
	if err != nil {
		in.t.Fatalf("parse config template: %v", err)
	}
	var buf bytes.Buffer
	vars := ConfigVars{DataDir: in.DataDir, Socket: in.Socket, UID: os.Getuid()}
	if err := parsed.Execute(&buf, vars); err != nil {
		in.t.Fatalf("render config template: %v", err)
	}
	path := filepath.Join(in.dir, "config.yaml")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		in.t.Fatal(err)
	}
	return path
}

// Server is a running TrustedCourier process.
type Server struct {
	in     *Installation
	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer
	done   chan struct{}
	err    error
	// Credential is the Operator Credential the test uses for tc commands.
	// It is set from the first boot's output and may be overwritten by tests.
	Credential string
}

var operatorCredentialPattern = regexp.MustCompile(`tcoc_[a-z2-7]+`)

// Start launches TrustedCourier with the rendered config and waits until the
// admin socket accepts connections. The server is stopped when the test ends.
func (in *Installation) Start(configTemplate string) *Server {
	in.t.Helper()
	s := in.launch(configTemplate)
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case <-s.done:
			in.t.Fatalf("TrustedCourier exited during startup: %v\nstdout:\n%s\nstderr:\n%s",
				s.err, s.stdout.String(), s.stderr.String())
		default:
		}
		if conn, err := net.Dial("unix", in.Socket); err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			in.t.Fatalf("admin socket not ready\nstderr:\n%s", s.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.Credential = operatorCredentialPattern.FindString(s.stdout.String())
	in.t.Cleanup(s.Stop)
	return s
}

// Refused runs TrustedCourier with the rendered config, expects it to exit
// without serving, and returns its exit code and stderr.
func (in *Installation) Refused(configTemplate string) (int, string) {
	in.t.Helper()
	s := in.launch(configTemplate)
	select {
	case <-s.done:
	case <-time.After(15 * time.Second):
		s.Stop()
		in.t.Fatalf("TrustedCourier kept running; stderr:\n%s", s.stderr.String())
	}
	return exitCode(s.err), s.stderr.String()
}

func (in *Installation) launch(configTemplate string) *Server {
	in.t.Helper()
	path := in.writeConfig(configTemplate)
	s := &Server{
		in:     in,
		stdout: &syncBuffer{},
		stderr: &syncBuffer{},
		done:   make(chan struct{}),
	}
	s.cmd = exec.Command(tcBinary, "server", "run", "--config", path)
	s.cmd.Stdout = s.stdout
	s.cmd.Stderr = s.stderr
	s.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + in.dir}
	if err := s.cmd.Start(); err != nil {
		in.t.Fatalf("start TrustedCourier: %v", err)
	}
	go func() {
		s.err = s.cmd.Wait()
		close(s.done)
	}()
	return s
}

// Stop sends SIGTERM and waits for the process to exit. It is safe to call
// more than once.
func (s *Server) Stop() {
	select {
	case <-s.done:
		return
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
		s.in.t.Errorf("TrustedCourier did not stop on SIGTERM; stderr:\n%s", s.stderr.String())
	}
}

// Stdout returns everything the server wrote to stdout so far.
func (s *Server) Stdout() string { return s.stdout.String() }

// Stderr returns everything the server wrote to stderr so far.
func (s *Server) Stderr() string { return s.stderr.String() }

// Result is the outcome of one tc CLI invocation.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// TC runs the tc CLI against this server's admin socket with its Operator
// Credential.
func (s *Server) TC(args ...string) Result {
	s.in.t.Helper()
	return s.in.TC([]string{"TC_OPERATOR_CREDENTIAL=" + s.Credential}, args...)
}

// TC runs the tc CLI against the installation's admin socket with only the
// given extra environment.
func (in *Installation) TC(env []string, args ...string) Result {
	in.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tcBinary, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "TC_ADMIN_SOCKET=" + in.Socket}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		in.t.Fatalf("tc %v timed out", args)
	}
	return Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode(err)}
}

// FilesContain reports whether any file under the installation's data
// directory contains needle.
func (in *Installation) FilesContain(needle string) bool {
	in.t.Helper()
	found := false
	err := filepath.WalkDir(in.DataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(needle)) {
			found = true
		}
		return nil
	})
	if err != nil {
		in.t.Fatalf("scan data directory: %v", err)
	}
	return found
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

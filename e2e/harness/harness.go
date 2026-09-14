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
	"net/http"
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

// childEnv is the environment every tc process gets: a clean base plus the
// runtime settings the test run was invoked with, so a GODEBUG=fips140=on
// test run exercises tc in FIPS mode.
func childEnv(extra ...string) []string {
	env := []string{"PATH=" + os.Getenv("PATH")}
	for _, name := range []string{"GODEBUG", "GORACE"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return append(env, extra...)
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
// and {{.UID}}. The config file lives in the parent of DataDir.
type ConfigVars struct {
	DataDir string
	Socket  string
	UID     int
}

// BaseConfig is a minimal valid config with two Policies.
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

// Server is a TrustedCourier process.
type Server struct {
	in        *Installation
	cmd       *exec.Cmd
	stdout    string // file receiving the process's stdout
	stderr    string // file receiving the process's stderr
	done      chan struct{}
	err       error
	checkOnce sync.Once
	// Credential is the Operator Credential the test uses for tc commands.
	// It is set from the first boot's output and may be overwritten by tests.
	Credential string
}

var operatorCredentialPattern = regexp.MustCompile(`tcoc_[a-z2-7]+`)

// Start launches TrustedCourier with the rendered config and waits until the
// admin API answers requests. The server is stopped when the test ends.
func (in *Installation) Start(configTemplate string) *Server {
	in.t.Helper()
	s := in.launch(configTemplate)
	deadline := time.Now().Add(15 * time.Second)
	for !in.adminAnswers() {
		select {
		case <-s.done:
			in.t.Fatalf("TrustedCourier exited during startup: %v\nstdout:\n%s\nstderr:\n%s",
				s.err, s.Stdout(), s.Stderr())
		default:
		}
		if time.Now().After(deadline) {
			in.t.Fatalf("admin API not ready\nstderr:\n%s", s.Stderr())
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.Credential = operatorCredentialPattern.FindString(s.Stdout())
	return s
}

// adminAnswers reports whether the admin API returns any HTTP response. A
// bound socket alone is not enough: the server may still be booting.
func (in *Installation) adminAnswers() bool {
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", in.Socket)
			},
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://trustedcourier/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
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
		in.t.Fatalf("TrustedCourier kept running; stderr:\n%s", s.Stderr())
	}
	s.checkOutput()
	return exitCode(s.err), s.Stderr()
}

func (in *Installation) launch(configTemplate string) *Server {
	in.t.Helper()
	path := in.writeConfig(configTemplate)
	s := &Server{in: in, done: make(chan struct{})}
	// Files, not pipes: the process's writes are visible as soon as they
	// return, with no copying goroutine to race. They live outside DataDir so
	// the one-time credential in stdout never counts as stored data.
	stdout, err := os.CreateTemp(in.dir, "stdout-")
	if err != nil {
		in.t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	stderr, err := os.CreateTemp(in.dir, "stderr-")
	if err != nil {
		in.t.Fatal(err)
	}
	defer func() { _ = stderr.Close() }()
	s.stdout, s.stderr = stdout.Name(), stderr.Name()

	s.cmd = exec.Command(tcBinary, "server", "run", "--config", path)
	s.cmd.Stdout = stdout
	s.cmd.Stderr = stderr
	s.cmd.Env = childEnv("HOME=" + in.dir)
	if err := s.cmd.Start(); err != nil {
		in.t.Fatalf("start TrustedCourier: %v", err)
	}
	go func() {
		s.err = s.cmd.Wait()
		close(s.done)
	}()
	in.t.Cleanup(s.Stop)
	return s
}

// Stop sends SIGTERM, waits for the process to exit, and fails the test if it
// did not exit cleanly. It is safe to call more than once.
func (s *Server) Stop() {
	select {
	case <-s.done:
		s.checkOutput()
		return
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
		if s.err != nil {
			s.in.t.Errorf("TrustedCourier exited uncleanly on SIGTERM: %v\nstderr:\n%s", s.err, s.Stderr())
		}
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
		s.in.t.Errorf("TrustedCourier did not stop on SIGTERM; stderr:\n%s", s.Stderr())
	}
	s.checkOutput()
}

// checkOutput fails the test if the race detector reported a race.
func (s *Server) checkOutput() {
	s.checkOnce.Do(func() {
		if strings.Contains(s.Stderr(), "WARNING: DATA RACE") {
			s.in.t.Errorf("race detected in TrustedCourier:\n%s", s.Stderr())
		}
	})
}

// Stdout returns everything the server wrote to stdout so far.
func (s *Server) Stdout() string { return readFile(s.stdout) }

// Stderr returns everything the server wrote to stderr so far.
func (s *Server) Stderr() string { return readFile(s.stderr) }

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("<read %s: %v>", path, err)
	}
	return string(data)
}

// Result is the outcome of one tc CLI invocation.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// cliTimeout bounds one tc CLI invocation.
const cliTimeout = 15 * time.Second

// TC runs the tc CLI against this server's admin socket with its Operator
// Credential.
func (s *Server) TC(args ...string) Result {
	return s.in.TC([]string{"TC_OPERATOR_CREDENTIAL=" + s.Credential}, args...)
}

// TC runs the tc CLI against the installation's admin socket with only the
// given extra environment. It never fails the test itself, so it is safe to
// call from subtests; a timeout is reported as exit code -1.
func (in *Installation) TC(env []string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tcBinary, args...)
	cmd.Env = childEnv(append([]string{"TC_ADMIN_SOCKET=" + in.Socket}, env...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode(err)}
	if ctx.Err() != nil {
		res.ExitCode = -1
		res.Stderr += fmt.Sprintf("\nharness: tc %v timed out after %v", args, cliTimeout)
	}
	if strings.Contains(res.Stderr, "WARNING: DATA RACE") {
		res.ExitCode = -1
		res.Stderr += "\nharness: race detected in the tc CLI"
	}
	return res
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

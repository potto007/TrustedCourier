// Package harness is the Seam 1 process harness: it builds the real tc
// binary, starts TrustedCourier from a config file, and drives the tc CLI.
// Tests built on it assert only externally visible behavior.
package harness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"

	"github.com/potto007/TrustedCourier/sdk/plugin/client"
	_ "modernc.org/sqlite" // registers the "sqlite" driver for TamperDatabase
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
	for _, p := range []struct {
		bin         *PluginBinary
		name, flags string
	}{
		{&FakePlugin, "fake", ""},
		{&ReplacementPlugin, "replacement", "-X main.label=replacement"},
		{&UnhealthyPlugin, "unhealthy", "-X main.mode=unhealthy"},
		{&ReadOnlyPlugin, "readonly", "-X main.mode=readonly"},
		{&CrashingPlugin, "crashing", "-X main.mode=crash"},
		{&MalformedPlugin, "malformed", "-X main.mode=malformed"},
		{&NoFIPSPlugin, "nofips", "-X main.mode=nofips"},
		{&FIPSOnPlugin, "fipson", "-X main.mode=fipson"},
	} {
		var err error
		if *p.bin, err = buildPlugin(filepath.Join(root, "sdk", "plugin"), filepath.Join(dir, p.name), p.flags); err != nil {
			return 0, err
		}
	}
	return m.Run(), nil
}

// PluginBinary is a Backend Plugin binary and its SHA-256 as the config
// pins it.
type PluginBinary struct {
	Path   string
	SHA256 string
}

// Variants of the fake Backend Plugin built on the plugin SDK, each with its
// own hash. FakePlugin is well behaved and reports its uid in its health
// detail; ReplacementPlugin is the same with "replacement" in the detail;
// UnhealthyPlugin reports "Backend sealed" alongside that detail;
// ReadOnlyPlugin cannot store Courier Keys; CrashingPlugin exits before the
// handshake; MalformedPlugin breaks the protocol contract in every response
// and writes a forged log line; NoFIPSPlugin reports itself outside FIPS
// 140-3 mode whatever mode it runs in, and FIPSOnPlugin reports mode "on"
// (never "only") likewise.
var FakePlugin, ReplacementPlugin, UnhealthyPlugin, ReadOnlyPlugin, CrashingPlugin, MalformedPlugin, NoFIPSPlugin, FIPSOnPlugin PluginBinary

func buildPlugin(sdkDir, out, ldflags string) (PluginBinary, error) {
	build := exec.Command("go", "build", "-ldflags", ldflags, "-o", out, "./internal/fakebackend")
	build.Dir = sdkDir
	if b, err := build.CombinedOutput(); err != nil {
		return PluginBinary{}, fmt.Errorf("build fake Backend Plugin: %w\n%s", err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return PluginBinary{}, err
	}
	return PluginBinary{Path: out, SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}, nil
}

// childEnv is the environment every tc process gets: a clean base plus the
// runtime settings the test run was invoked with, so a GODEBUG=fips140=on
// test run exercises tc in FIPS mode. The FIPS 140-3 mode is always spelled
// out, since tc defaults it off while a test binary built with GOFIPS140
// defaults it on.
func childEnv(extra ...string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "GODEBUG=" + client.GODEBUG()}
	if v, ok := os.LookupEnv("GORACE"); ok {
		env = append(env, "GORACE="+v)
	}
	return append(env, extra...)
}

// Installation is one TrustedCourier data directory and admin socket that
// survives server restarts.
type Installation struct {
	t       *testing.T
	DataDir string
	Socket  string
	// ConfigMode is the file mode the config file is written with.
	ConfigMode os.FileMode
	// Env is added to every server process's environment, after the
	// settings inherited from the test run, so a test can force a runtime
	// mode such as GODEBUG=fips140=on.
	Env []string
	dir string

	// upstream is the fake Upstream BaseConfig pins its Secret Names to, once
	// started.
	upstream *Upstream

	mu sync.Mutex
	// secretValues are the Secret values tests gave the fake Backend Plugin.
	secretValues []string
}

// FakeSecretValues are the values the fake Backend Plugin holds at start,
// mirroring sdk/plugin/internal/fakebackend. None may appear in
// TrustedCourier's output.
var FakeSecretValues = []string{"test-value-1", "test-value-2", "test-value-3", AuditSigningKey}

// AuditSigningKeyLocation is where the fake Backend Plugin holds
// AuditSigningKey.
const AuditSigningKeyLocation = "courier/audit-signing-key"

// AuditSigningKey is the test-only Ed25519 audit signing key the fake Backend
// Plugin holds, as PKCS #8 PEM, and AuditSigningPublicKey its public key.
var AuditSigningKey, AuditSigningPublicKey = fakeAuditSigningKey()

// fakeAuditSigningKey mirrors the derivation in
// sdk/plugin/internal/fakebackend.
func fakeAuditSigningKey() (string, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("TrustedCourier fake audit signing key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), private.Public().(ed25519.PublicKey)
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
	in := &Installation{
		t:          t,
		dir:        dir,
		DataDir:    filepath.Join(dir, "data"),
		Socket:     filepath.Join(dir, "admin.sock"),
		ConfigMode: 0o600,
	}
	return in
}

// Upstream returns the fake Upstream BaseConfig pins its Secret Names to,
// starting it on the first call, so tests that never proxy start none.
func (in *Installation) Upstream() *Upstream {
	in.t.Helper()
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.upstream == nil {
		in.upstream = in.StartUpstream(true)
	}
	return in.upstream
}

// ConfigVars are available to config templates as {{.DataDir}}, {{.Socket}},
// {{.UID}}, the fake Backend Plugins as {{.Fake.Path}}, {{.Fake.SHA256}} and
// so on, and the installation's fake Upstream as {{.Upstream.URL}} and
// {{.Upstream.CABundle}}. The config file lives in the parent of DataDir.
type ConfigVars struct {
	DataDir   string
	Socket    string
	UID       int
	Fake      PluginBinary
	Unhealthy PluginBinary
	ReadOnly  PluginBinary
	Crashing  PluginBinary
	Malformed PluginBinary
	NoFIPS    PluginBinary
	FIPSOn    PluginBinary

	in *Installation
}

// Upstream is the installation's fake Upstream, started only when a config
// template uses it.
func (v ConfigVars) Upstream() *Upstream { return v.in.Upstream() }

// InstallPlugin copies bin into dir with the given mode and returns its path,
// so a test can later replace it.
func (in *Installation) InstallPlugin(bin PluginBinary, dir string, mode os.FileMode) string {
	in.t.Helper()
	path := filepath.Join(dir, filepath.Base(bin.Path))
	in.copyFile(bin.Path, path, mode)
	return path
}

// SetBackendSecrets replaces what the fake Backend Plugin installed at
// pluginPath holds with secrets, by location. The plugin reads them on every
// Get, so a test can rotate a Secret while TrustedCourier runs.
func (in *Installation) SetBackendSecrets(pluginPath string, secrets map[string]string) {
	in.t.Helper()
	data, err := json.Marshal(secrets)
	if err != nil {
		in.t.Fatal(err)
	}
	in.mu.Lock()
	for _, v := range secrets {
		in.secretValues = append(in.secretValues, v)
	}
	in.mu.Unlock()
	tmp := pluginPath + ".secrets.json.new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		in.t.Fatal(err)
	}
	if err := os.Rename(tmp, pluginPath+".secrets.json"); err != nil {
		in.t.Fatal(err)
	}
}

// BackendSecrets returns what the fake Backend Plugin installed at pluginPath
// holds, by location, including the Courier Keys TrustedCourier stored in it.
// SetBackendSecrets must have been called for the plugin first.
func (in *Installation) BackendSecrets(pluginPath string) map[string]string {
	in.t.Helper()
	data, err := os.ReadFile(pluginPath + ".secrets.json")
	if err != nil {
		in.t.Fatal(err)
	}
	secrets := map[string]string{}
	if err := json.Unmarshal(data, &secrets); err != nil {
		in.t.Fatal(err)
	}
	return secrets
}

// FreePort returns a TCP port that was free when it was checked, for a
// listener whose port another process must know before it binds.
func FreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// ReplacePlugin atomically replaces the binary at path with bin, as an
// attacker or a careless upgrade might while TrustedCourier runs.
func (in *Installation) ReplacePlugin(path string, bin PluginBinary) {
	in.t.Helper()
	tmp := path + ".new"
	in.copyFile(bin.Path, tmp, 0o755)
	if err := os.Rename(tmp, path); err != nil {
		in.t.Fatal(err)
	}
}

func (in *Installation) copyFile(from, to string, mode os.FileMode) {
	in.t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		in.t.Fatal(err)
	}
	if err := os.WriteFile(to, data, mode); err != nil {
		in.t.Fatal(err)
	}
	if err := os.Chmod(to, mode); err != nil {
		in.t.Fatal(err)
	}
}

// Dir is the installation's private directory, holding the config file.
func (in *Installation) Dir() string { return in.dir }

// AdminConfig is the smallest valid config: a data directory and the admin
// socket, with no Policies, Secret Names, or Backend Plugins.
const AdminConfig = `
data_dir: {{.DataDir}}
admin:
  socket: {{.Socket}}
`

// BaseConfig is AdminConfig plus two Policies, the Secret Names they grant,
// and the well-behaved fake Backend Plugin, named fake, sharing the server's
// OS user. Both Secret Names are pinned to the installation's fake Upstream
// as the Upstream named api: openai with an "Authorization: Bearer" header
// Injection Template, github with "Authorization: token". It ends inside
// backend_plugins, so a test can append more Backend Plugins, or top-level
// keys.
const BaseConfig = AdminConfig + `
policies:
  openai-proxy:
    secrets:
      - name: openai
        delivery: [proxy]
  github-reveal:
    secrets:
      - name: github
        delivery: [proxy, reveal]
secrets:
  openai:
    backend: fake
    location: kv/openai
    injection_template:
      header:
        name: Authorization
        value: Bearer {secret}
    upstreams:
      api:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
  github:
    backend: fake
    location: kv/github
    injection_template:
      header:
        name: Authorization
        value: token {secret}
    upstreams:
      api:
        url: {{.Upstream.URL}}
        ca_bundle: {{.Upstream.CABundle}}
backend_plugins:
  fake:
    path: {{.Fake.Path}}
    sha256: {{.Fake.SHA256}}
    insecure_share_core_user: true
`

func (in *Installation) writeConfig(tmpl string) string {
	in.t.Helper()
	parsed, err := template.New("config").Parse(tmpl)
	if err != nil {
		in.t.Fatalf("parse config template: %v", err)
	}
	var buf bytes.Buffer
	vars := ConfigVars{
		DataDir:   in.DataDir,
		Socket:    in.Socket,
		UID:       os.Getuid(),
		Fake:      FakePlugin,
		Unhealthy: UnhealthyPlugin,
		ReadOnly:  ReadOnlyPlugin,
		Crashing:  CrashingPlugin,
		Malformed: MalformedPlugin,
		NoFIPS:    NoFIPSPlugin,
		FIPSOn:    FIPSOnPlugin,
		in:        in,
	}
	if err := parsed.Execute(&buf, vars); err != nil {
		in.t.Fatalf("render config template: %v", err)
	}
	path := filepath.Join(in.dir, "config.yaml")
	if err := os.WriteFile(path, buf.Bytes(), in.ConfigMode); err != nil {
		in.t.Fatal(err)
	}
	if err := os.Chmod(path, in.ConfigMode); err != nil {
		in.t.Fatal(err)
	}
	return path
}

// RewriteConfig replaces the running server's config file with the rendered
// configTemplate, for a later reload.
func (s *Server) RewriteConfig(configTemplate string) {
	s.in.t.Helper()
	s.in.writeConfig(configTemplate)
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
	s.cmd.Env = childEnv(append([]string{"HOME=" + in.dir}, in.Env...)...)
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

// PID returns the server process's ID.
func (s *Server) PID() int { return s.cmd.Process.Pid }

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

// checkOutput fails the test if the race detector reported a race, or if a
// Secret value the fake Backend Plugin could hold appears in the server's
// output.
func (s *Server) checkOutput() {
	s.checkOnce.Do(func() {
		output := s.Stdout() + s.Stderr()
		if strings.Contains(output, "WARNING: DATA RACE") {
			s.in.t.Errorf("race detected in TrustedCourier:\n%s", s.Stderr())
		}
		s.in.mu.Lock()
		values := append(slices.Clone(FakeSecretValues), s.in.secretValues...)
		s.in.mu.Unlock()
		for _, v := range values {
			if strings.Contains(output, v) {
				s.in.t.Errorf("a Secret value appears in TrustedCourier's own output:\n%s", output)
			}
		}
	})
}

var (
	agentAPIURL       = regexp.MustCompile(`msg="Agent API listening" url=(\S+)`)
	agentAPISocket    = regexp.MustCompile(`msg="Agent API listening" socket=(\S+)`)
	signingKeyReady   = regexp.MustCompile(`msg="audit signing key loaded"`)
	certificateLoaded = regexp.MustCompile(`msg="TLS certificate loaded" listener="the Agent API"`)
	adminCertLoaded   = regexp.MustCompile(`msg="TLS certificate loaded" listener="the remote admin listener"`)
	remoteAdminURL    = regexp.MustCompile(`msg="remote admin API listening" url=(\S+)`)
)

// AdminURL waits for the server to log the remote admin listener's URL and
// to load its TLS certificate (its own, or the Agent API's when shared), and
// returns the URL, such as https://127.0.0.1:41235.
func (s *Server) AdminURL(shared bool) string {
	s.in.t.Helper()
	loaded := adminCertLoaded
	if shared {
		loaded = certificateLoaded
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		stderr := s.Stderr()
		if m := remoteAdminURL.FindStringSubmatch(stderr); m != nil && loaded.MatchString(stderr) {
			return m[1]
		}
		if time.Now().After(deadline) {
			s.in.t.Fatalf("the remote admin listener never started serving; stderr:\n%s", stderr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// AgentURL waits for the server to log the Agent API's URL and to load the
// audit signing key and, when the URL is https, the TLS certificate, so it
// serves Deliveries, and returns the Agent API's base URL, such as
// http://127.0.0.1:41234.
func (s *Server) AgentURL() string {
	s.in.t.Helper()
	return s.agentURL(true)
}

// ListeningAgentURL is AgentURL without waiting for the audit signing key or
// the TLS certificate.
func (s *Server) ListeningAgentURL() string {
	s.in.t.Helper()
	return s.agentURL(false)
}

func (s *Server) agentURL(ready bool) string {
	s.in.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		stderr := s.Stderr()
		if m := agentAPIURL.FindStringSubmatch(stderr); m != nil {
			url := m[1]
			if !ready || (signingKeyReady.MatchString(stderr) &&
				(!strings.HasPrefix(url, "https://") || certificateLoaded.MatchString(stderr))) {
				return url
			}
		}
		if time.Now().After(deadline) {
			s.in.t.Fatalf("the Agent API never started serving Deliveries; stderr:\n%s", stderr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// AgentSocket waits for the server to log the Agent API's unix socket and to
// load the audit signing key, and returns the socket path.
func (s *Server) AgentSocket() string {
	s.in.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		stderr := s.Stderr()
		if m := agentAPISocket.FindStringSubmatch(stderr); m != nil && signingKeyReady.MatchString(stderr) {
			return m[1]
		}
		if time.Now().After(deadline) {
			s.in.t.Fatalf("the Agent API never started serving Deliveries on a unix socket; stderr:\n%s", stderr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// AuditRecords waits until the server has streamed at least n Audit Records
// and returns every one streamed so far, one JSON object per element. The
// stream is the complete stdout lines holding a JSON object; the Operator
// Credential banner is not one.
func (s *Server) AuditRecords(n int) []string {
	s.in.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var records []string
		for line := range strings.Lines(s.Stdout()) {
			if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "\n") {
				records = append(records, strings.TrimSuffix(line, "\n"))
			}
		}
		if len(records) >= n {
			return records
		}
		if time.Now().After(deadline) {
			s.in.t.Fatalf("the server streamed %d Audit Records, want %d\nstdout:\n%s\nstderr:\n%s", len(records), n, s.Stdout(), s.Stderr())
		}
		time.Sleep(20 * time.Millisecond)
	}
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

// TamperDatabase runs statement against the installation's SQLite database
// directly, as anyone with write access to the data directory could.
func (in *Installation) TamperDatabase(statement string) {
	in.t.Helper()
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(in.DataDir, "trustedcourier.db"), RawQuery: "_pragma=busy_timeout(5000)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		in.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(statement); err != nil {
		in.t.Fatalf("tamper with the database: %v", err)
	}
}

// QueryDatabase runs query against the installation's SQLite database
// directly, as anyone with read access to the data directory could, and calls
// scan for each row.
func (in *Installation) QueryDatabase(query string, scan func(*sql.Rows) error) {
	in.t.Helper()
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(in.DataDir, "trustedcourier.db"), RawQuery: "_pragma=busy_timeout(5000)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		in.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(query)
	if err != nil {
		in.t.Fatalf("query the database: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := scan(rows); err != nil {
			in.t.Fatalf("read a database row: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		in.t.Fatalf("query the database: %v", err)
	}
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

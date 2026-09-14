package e2e

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

type pluginStatus struct {
	Name         string   `json:"name"`
	State        string   `json:"state"`
	PID          int      `json:"pid"`
	Healthy      bool     `json:"healthy"`
	Detail       string   `json:"detail"`
	Capabilities []string `json:"capabilities"`
	Restarts     int      `json:"restarts"`
}

// backendPlugins returns tc status --json's Backend Plugins by name.
func backendPlugins(t *testing.T, srv *harness.Server) map[string]pluginStatus {
	t.Helper()
	res := srv.TC("status", "--json")
	var status struct {
		BackendPlugins []pluginStatus `json:"backend_plugins"`
	}
	if res.ExitCode != 0 {
		t.Fatalf("tc status --json: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	if err := json.Unmarshal([]byte(res.Stdout), &status); err != nil {
		t.Fatalf("tc status --json: %v\n%s", err, res.Stdout)
	}
	plugins := make(map[string]pluginStatus, len(status.BackendPlugins))
	for _, p := range status.BackendPlugins {
		plugins[p.Name] = p
	}
	return plugins
}

// waitForPlugin polls tc status until the named Backend Plugin satisfies ok.
func waitForPlugin(t *testing.T, srv *harness.Server, name string, ok func(pluginStatus) bool) pluginStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		p := backendPlugins(t, srv)[name]
		if ok(p) {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("Backend Plugin %q never reached the expected state; last status: %+v\nserver stderr:\n%s", name, p, srv.Stderr())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func running(p pluginStatus) bool { return p.State == "running" && p.PID > 0 }

func TestStatusReportsBackendPluginHealthAndCapabilities(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.PluginConfig)

	p := waitForPlugin(t, srv, "fake", running)
	if !p.Healthy || !strings.Contains(p.Detail, "fake Backend") {
		t.Errorf("fake Backend Plugin health = %v %q, want healthy with its detail", p.Healthy, p.Detail)
	}
	if strings.Join(p.Capabilities, ",") != "courier-key-write" {
		t.Errorf("capabilities = %v, want [courier-key-write]", p.Capabilities)
	}

	res := srv.TC("status")
	if res.ExitCode != 0 {
		t.Fatalf("tc status: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	for _, want := range []string{"BACKEND PLUGIN", "fake", "running", "healthy", "courier-key-write"} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("tc status is missing %q:\n%s", want, res.Stdout)
		}
	}
}

func TestStatusRequiresOperatorCredential(t *testing.T) {
	tc := harness.New(t)
	tc.Start(harness.PluginConfig)

	res := tc.TC(nil, "status")
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "Operator Credential") {
		t.Fatalf("tc status without the Operator Credential: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestPluginSHA256PrintsConfigLine(t *testing.T) {
	tc := harness.New(t)

	res := tc.TC(nil, "plugin", "sha256", harness.FakePlugin.Path)
	if res.ExitCode != 0 {
		t.Fatalf("tc plugin sha256: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	if want := "sha256: " + harness.FakePlugin.SHA256 + "\n"; res.Stdout != want {
		t.Fatalf("tc plugin sha256 printed %q, want %q", res.Stdout, want)
	}

	// The printed line is what the config takes.
	srv := tc.Start(fmt.Sprintf(harness.BaseConfig+`
backend_plugins:
  fake:
    path: {{.Fake.Path}}
    %s
    insecure_share_core_user: true
`, strings.TrimSpace(res.Stdout)))
	waitForPlugin(t, srv, "fake", running)

	missing := tc.TC(nil, "plugin", "sha256", filepath.Join(tc.Dir(), "no-such-plugin"))
	if missing.ExitCode != 1 || !strings.Contains(missing.Stderr, "no-such-plugin") {
		t.Fatalf("tc plugin sha256 on a missing file: exit %d\n%s", missing.ExitCode, missing.Stderr)
	}
}

func TestBackendPluginWithMismatchedHashIsRefused(t *testing.T) {
	tc := harness.New(t)
	config := strings.Replace(harness.PluginConfig, "{{.Fake.SHA256}}", "{{.Crashing.SHA256}}", 1)

	code, stderr := tc.Refused(config)
	if code == 0 {
		t.Fatal("TrustedCourier started with a Backend Plugin whose hash does not match")
	}
	for _, want := range []string{`Backend Plugin "fake"`, "SHA-256", harness.FakePlugin.SHA256} {
		if !strings.Contains(stderr, want) {
			t.Errorf("error is missing %q:\n%s", want, stderr)
		}
	}
	if _, err := os.Stat(tc.Socket); err == nil {
		t.Error("admin socket exists after refusing the Backend Plugin")
	}
}

func TestReplacedBackendPluginIsNotRelaunched(t *testing.T) {
	tc := harness.New(t)
	dir := t.TempDir()
	path := tc.InstallPlugin(harness.FakePlugin, dir, 0o755)
	srv := tc.Start(strings.Replace(harness.PluginConfig, "{{.Fake.Path}}", path, 1))
	first := waitForPlugin(t, srv, "fake", running)

	tc.ReplacePlugin(path, harness.ReplacementPlugin)
	if err := syscall.Kill(first.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}

	p := waitForPlugin(t, srv, "fake", func(p pluginStatus) bool {
		return p.Restarts >= 1 && strings.Contains(p.Detail, "SHA-256")
	})
	if p.State == "running" || p.Healthy || strings.Contains(p.Detail, "replacement") {
		t.Fatalf("the replaced Backend Plugin binary was run: %+v", p)
	}
	if res := srv.TC("token", "list"); res.ExitCode != 0 {
		t.Fatalf("admin API stopped answering: exit %d\n%s", res.ExitCode, res.Stderr)
	}
}

func TestCrashedBackendPluginIsRestarted(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.PluginConfig)
	first := waitForPlugin(t, srv, "fake", running)

	if err := syscall.Kill(first.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}

	p := waitForPlugin(t, srv, "fake", func(p pluginStatus) bool {
		return running(p) && p.PID != first.PID
	})
	if p.Restarts != 1 || !p.Healthy {
		t.Fatalf("restarted Backend Plugin = %+v, want healthy after 1 restart", p)
	}
	if res := srv.TC("token", "list"); res.ExitCode != 0 {
		t.Fatalf("admin API stopped answering: exit %d\n%s", res.ExitCode, res.Stderr)
	}
}

func TestCrashingBackendPluginDoesNotAffectOthers(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.PluginConfig + `
  crashing:
    path: {{.Crashing.Path}}
    sha256: {{.Crashing.SHA256}}
    insecure_share_core_user: true
`)

	crashing := waitForPlugin(t, srv, "crashing", func(p pluginStatus) bool { return p.Restarts >= 2 })
	if crashing.State == "running" || crashing.Healthy || crashing.Detail == "" {
		t.Errorf("crashing Backend Plugin status = %+v, want not running, unhealthy, with a reason", crashing)
	}
	fake := waitForPlugin(t, srv, "fake", running)
	if !fake.Healthy || fake.Restarts != 0 {
		t.Errorf("well-behaved Backend Plugin status = %+v, want healthy with no restarts", fake)
	}
	if res := srv.TC("token", "issue", "--policy", "openai-proxy", "--expires-in", "1h"); res.ExitCode != 0 {
		t.Fatalf("token issue: exit %d\n%s", res.ExitCode, res.Stderr)
	}
}

func TestMalformedBackendPluginResponsesAreErrors(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig + `
backend_plugins:
  malformed:
    path: {{.Malformed.Path}}
    sha256: {{.Malformed.SHA256}}
    insecure_share_core_user: true
`)

	p := waitForPlugin(t, srv, "malformed", running)
	if p.Healthy || !strings.Contains(p.Detail, "malformed") {
		t.Errorf("malformed health response reported as %v %q, want unhealthy and malformed", p.Healthy, p.Detail)
	}
	res := srv.TC("status")
	if strings.ContainsAny(res.Stdout+res.Stderr, "\x1b\x00") {
		t.Errorf("tc status relayed control characters from the Backend Plugin:\n%q", res.Stdout)
	}
	if strings.Contains(srv.Stderr(), "panic") {
		t.Errorf("TrustedCourier panicked:\n%s", srv.Stderr())
	}
	// The plugin's log message tried to start a line of its own.
	waitFor(t, func() bool { return strings.Contains(srv.Stderr(), "forged entry") })
	for line := range strings.Lines(srv.Stderr()) {
		if strings.HasPrefix(line, "[FORGED]") {
			t.Errorf("a Backend Plugin forged a server log line: %q", line)
		}
		if strings.ContainsRune(line, '\u009b') {
			t.Errorf("server log relayed a C1 control character from a Backend Plugin: %q", line)
		}
	}
	if again := backendPlugins(t, srv)["malformed"]; again.PID != p.PID || again.Restarts != 0 {
		t.Errorf("malformed responses restarted the Backend Plugin: %+v, then %+v", p, again)
	}
}

func TestUnhealthyBackendPluginKeepsItsDetail(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig + `
backend_plugins:
  unhealthy:
    path: {{.Unhealthy.Path}}
    sha256: {{.Unhealthy.SHA256}}
    insecure_share_core_user: true
`)

	p := waitForPlugin(t, srv, "unhealthy", running)
	if p.Healthy || !strings.Contains(p.Detail, "Backend sealed") || !strings.Contains(p.Detail, "fake Backend, uid=") {
		t.Fatalf("unhealthy Backend Plugin reported as %v %q, want unhealthy with its error and detail", p.Healthy, p.Detail)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestBackendPluginsStopWithServer(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.PluginConfig)
	pid := waitForPlugin(t, srv, "fake", running).PID

	srv.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		if time.Now().After(deadline) {
			t.Fatalf("Backend Plugin process %d still exists after the server stopped", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestBackendPluginMustRunAsSeparateUser(t *testing.T) {
	const plugin = `
backend_plugins:
  fake:
    path: {{.Fake.Path}}
    sha256: {{.Fake.SHA256}}
`
	cases := []struct {
		name       string
		config     string
		configMode os.FileMode
		wantErr    string
		skip       bool
	}{
		{
			name:    "no user",
			config:  harness.BaseConfig + plugin,
			wantErr: `Backend Plugin "fake": user is required`,
		},
		{
			name:    "server's own user",
			config:  harness.BaseConfig + plugin + "    user: \"{{.UID}}\"\n",
			wantErr: "insecure_share_core_user",
		},
		{
			name:       "config readable by the plugin user",
			config:     harness.BaseConfig + plugin + "    user: nobody\n",
			configMode: 0o644,
			wantErr:    "readable",
		},
		{
			name:    "other user without root",
			config:  harness.BaseConfig + plugin + "    user: nobody\n",
			wantErr: "root",
			skip:    os.Geteuid() == 0,
		},
		{
			name:    "unknown user",
			config:  harness.BaseConfig + plugin + "    user: tc-no-such-user\n",
			wantErr: "tc-no-such-user",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.skip {
				t.Skip("needs a non-root server")
			}
			tc := harness.New(t)
			if c.configMode != 0 {
				tc.ConfigMode = c.configMode
			}
			code, stderr := tc.Refused(c.config)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

// TestBackendPluginRunsAsSeparateUser needs root, so the server can switch
// the plugin to another user. Run it with sudo.
func TestBackendPluginRunsAsSeparateUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	tc := harness.New(t)
	// The plugin user must be able to reach its binary.
	dir, err := os.MkdirTemp("", "tc-plugin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := tc.InstallPlugin(harness.FakePlugin, dir, 0o755)
	srv := tc.Start(harness.BaseConfig + `
backend_plugins:
  fake:
    path: ` + path + `
    sha256: {{.Fake.SHA256}}
    user: nobody
`)

	p := waitForPlugin(t, srv, "fake", running)
	if !strings.Contains(p.Detail, "uid=65534") {
		t.Fatalf("Backend Plugin health detail %q does not show it running as nobody (65534)", p.Detail)
	}
	for _, file := range []string{filepath.Join(tc.Dir(), "config.yaml"), filepath.Join(tc.DataDir, "trustedcourier.db")} {
		cat := exec.Command("cat", file)
		cat.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if out, err := cat.CombinedOutput(); err == nil {
			t.Errorf("the Backend Plugin user can read %s:\n%s", file, out)
		}
	}
}

func TestPluginConfigIsValidated(t *testing.T) {
	cases := []struct {
		name    string
		plugin  string
		wantErr string
	}{
		{"missing path", "    sha256: {{.Fake.SHA256}}\n    insecure_share_core_user: true\n", "path is required"},
		{"missing sha256", "    path: {{.Fake.Path}}\n    insecure_share_core_user: true\n", "sha256 is required"},
		{"malformed sha256", "    path: {{.Fake.Path}}\n    sha256: abc123\n    insecure_share_core_user: true\n", "64 hexadecimal"},
		{"user and insecure_share_core_user", "    path: {{.Fake.Path}}\n    sha256: {{.Fake.SHA256}}\n    user: nobody\n    insecure_share_core_user: true\n", "not both"},
		{"missing binary", "    path: /nonexistent/plugin\n    sha256: {{.Fake.SHA256}}\n    insecure_share_core_user: true\n", "/nonexistent/plugin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.BaseConfig + "backend_plugins:\n  fake:\n" + c.plugin)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
	t.Run("invalid name", func(t *testing.T) {
		tc := harness.New(t)
		code, stderr := tc.Refused(harness.BaseConfig + `
backend_plugins:
  "bad name":
    path: {{.Fake.Path}}
    sha256: {{.Fake.SHA256}}
    insecure_share_core_user: true
`)
		if code == 0 || !strings.Contains(stderr, `invalid Backend Plugin name "bad name"`) {
			t.Fatalf("exit %d, stderr:\n%s", code, stderr)
		}
	})
}

func TestUppercaseSHA256IsAccepted(t *testing.T) {
	tc := harness.New(t)
	sum := sha256.Sum256(mustRead(t, harness.FakePlugin.Path))
	srv := tc.Start(strings.Replace(harness.PluginConfig, "{{.Fake.SHA256}}", fmt.Sprintf("%X", sum), 1))
	waitForPlugin(t, srv, "fake", running)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

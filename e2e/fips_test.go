package e2e

import (
	"crypto/fips140"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// fipsStatus is tc status --json's FIPS 140-3 report for the server.
type fipsStatus struct {
	Mode   string `json:"mode"`
	Module string `json:"module"`
}

func serverFIPS(t *testing.T, srv *harness.Server) fipsStatus {
	t.Helper()
	res := srv.TC("status", "--json")
	if res.ExitCode != 0 {
		t.Fatalf("tc status --json: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	var status struct {
		FIPS140 fipsStatus `json:"fips140"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &status); err != nil {
		t.Fatalf("tc status --json: %v\n%s", err, res.Stdout)
	}
	return status.FIPS140
}

// testMode is the FIPS 140-3 mode this test process runs in, which the
// harness passes to every server it starts.
func testMode() string {
	switch {
	case fips140.Enforced():
		return "only"
	case fips140.Enabled():
		return "on"
	}
	return "off"
}

// TestStatusReportsFIPSMode checks the server runs in the FIPS 140-3 mode
// the test run was invoked with, and that a plugin built on the SDK
// follows it.
func TestStatusReportsFIPSMode(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	plugin := waitForPlugin(t, srv, "fake", running)

	server := serverFIPS(t, srv)
	if server.Mode != testMode() {
		t.Errorf("server FIPS 140-3 mode = %q, want %q (the test run's mode)", server.Mode, testMode())
	}
	if server.Module != fips140.Version() {
		t.Errorf("server FIPS 140-3 module = %q, want %q (the test run's)", server.Module, fips140.Version())
	}
	if plugin.FIPS140 != server.Mode {
		t.Errorf("Backend Plugin FIPS 140-3 mode = %q, want the server's %q", plugin.FIPS140, server.Mode)
	}
	if want := fmt.Sprintf("FIPS 140-3 mode: %s (module %s)", server.Mode, server.Module); !strings.Contains(srv.TC("status").Stdout, want) {
		t.Errorf("tc status does not show %q:\n%s", want, srv.TC("status").Stdout)
	}
	if want := "fips140=" + server.Mode; !strings.Contains(srv.Stderr(), want) {
		t.Errorf("server did not log its FIPS 140-3 mode (%q):\n%s", want, srv.Stderr())
	}
}

// TestFIPSModeIsChosenAtRuntime sets each mode through GODEBUG, as an
// Operator does on the standard binary, and checks the server and its
// plugin are in it.
func TestFIPSModeIsChosenAtRuntime(t *testing.T) {
	for _, mode := range []string{"off", "on", "only"} {
		t.Run(mode, func(t *testing.T) {
			tc := harness.New(t)
			tc.Env = []string{"GODEBUG=fips140=" + mode}
			srv := tc.Start(harness.BaseConfig)
			plugin := waitForPlugin(t, srv, "fake", running)
			if got := serverFIPS(t, srv).Mode; got != mode {
				t.Errorf("server FIPS 140-3 mode = %q with GODEBUG=fips140=%s", got, mode)
			}
			if plugin.FIPS140 != mode {
				t.Errorf("Backend Plugin FIPS 140-3 mode = %q, want the server's %q", plugin.FIPS140, mode)
			}
		})
	}
}

// TestFIPSOnlyModeServes runs the server with fips140=only, where any
// non-approved algorithm panics, through a Delivery.
func TestFIPSOnlyModeServes(t *testing.T) {
	tc := harness.New(t)
	tc.Env = []string{"GODEBUG=fips140=only"}
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	if got := reveal(t, srv, "Bearer "+token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Errorf("Reveal Delivery in fips140=only mode = %d %q, want 200 with the Secret\nserver stderr:\n%s",
			got.Status, got.Body, srv.Stderr())
	}
}

// refused is a Backend Plugin the server will not run.
func refused(p pluginStatus) bool { return p.State == "refused" }

// TestWeakerBackendPluginIsRefusedInFIPSMode: a server in FIPS mode refuses
// a plugin that reports a weaker mode, once and for all, and keeps serving
// the plugins in its mode (ADR-0027).
func TestWeakerBackendPluginIsRefusedInFIPSMode(t *testing.T) {
	for _, c := range []struct {
		mode, plugin, template string
	}{
		{"on", "nofips", "{{.NoFIPS.Path}}\n    sha256: {{.NoFIPS.SHA256}}"},
		{"only", "nofips", "{{.NoFIPS.Path}}\n    sha256: {{.NoFIPS.SHA256}}"},
		{"only", "fipson", "{{.FIPSOn.Path}}\n    sha256: {{.FIPSOn.SHA256}}"},
	} {
		t.Run(c.mode+"/"+c.plugin, func(t *testing.T) {
			tc := harness.New(t)
			tc.Env = []string{"GODEBUG=fips140=" + c.mode}
			srv := tc.Start(harness.BaseConfig + "  weak:\n    path: " + c.template + "\n    insecure_share_core_user: true\n")
			weak := waitForPlugin(t, srv, "weak", refused)
			if weak.PID != 0 || weak.Healthy || weak.Restarts != 0 || !strings.Contains(weak.Detail, "rebuild it") {
				t.Errorf("refused Backend Plugin status = %+v, want not running, never restarted, with the remedy", weak)
			}
			if !strings.Contains(srv.Stderr(), "will not be relaunched") {
				t.Errorf("server did not log the refusal:\n%s", srv.Stderr())
			}
			fake := waitForPlugin(t, srv, "fake", running)
			if !fake.Healthy || fake.FIPS140 != c.mode {
				t.Errorf("FIPS Backend Plugin status = %+v, want healthy in mode %s", fake, c.mode)
			}
		})
	}
}

// TestFIPSBackendPluginRunsOutsideFIPSMode: a plugin in a stronger mode
// than the server's is accepted, and a server outside FIPS mode accepts a
// plugin outside it.
func TestFIPSBackendPluginRunsOutsideFIPSMode(t *testing.T) {
	for _, c := range []struct {
		mode, plugin, template, want string
	}{
		{"off", "nofips", "{{.NoFIPS.Path}}\n    sha256: {{.NoFIPS.SHA256}}", "off"},
		{"off", "fipson", "{{.FIPSOn.Path}}\n    sha256: {{.FIPSOn.SHA256}}", "on"},
		{"on", "fipson", "{{.FIPSOn.Path}}\n    sha256: {{.FIPSOn.SHA256}}", "on"},
	} {
		t.Run(c.mode+"/"+c.plugin, func(t *testing.T) {
			tc := harness.New(t)
			tc.Env = []string{"GODEBUG=fips140=" + c.mode}
			srv := tc.Start(harness.AdminConfig + "\nbackend_plugins:\n  plugin:\n    path: " + c.template + "\n    insecure_share_core_user: true\n")
			p := waitForPlugin(t, srv, "plugin", running)
			if !p.Healthy || p.FIPS140 != c.want {
				t.Errorf("Backend Plugin status = %+v, want healthy in mode %s", p, c.want)
			}
		})
	}
}

// TestCoreDumpsAreDisabled reads the core file size limit of the server and
// of a Backend Plugin from /proc: both must be zero, hard and soft.
func TestCoreDumpsAreDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	plugin := waitForPlugin(t, srv, "fake", running)
	for name, pid := range map[string]int{"server": srv.PID(), "Backend Plugin": plugin.PID} {
		limits, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for line := range strings.Lines(string(limits)) {
			if !strings.HasPrefix(line, "Max core file size") {
				continue
			}
			found = true
			if f := strings.Fields(line); len(f) < 6 || f[4] != "0" || f[5] != "0" {
				t.Errorf("%s core file size limit is not 0/0: %s", name, strings.TrimSpace(line))
			}
		}
		if !found {
			t.Errorf("%s: no core file size limit in /proc/%d/limits", name, pid)
		}
	}
}

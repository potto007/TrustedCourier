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

// fipsStatus is tc status --json's FIPS 140-3 report for the core.
type fipsStatus struct {
	Enabled bool   `json:"enabled"`
	Module  string `json:"module"`
}

func statusFIPS(t *testing.T, srv *harness.Server) (fipsStatus, map[string]bool) {
	t.Helper()
	res := srv.TC("status", "--json")
	if res.ExitCode != 0 {
		t.Fatalf("tc status --json: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	var status struct {
		FIPS140        fipsStatus `json:"fips140"`
		BackendPlugins []struct {
			Name    string `json:"name"`
			FIPS140 bool   `json:"fips140"`
		} `json:"backend_plugins"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &status); err != nil {
		t.Fatalf("tc status --json: %v\n%s", err, res.Stdout)
	}
	plugins := map[string]bool{}
	for _, p := range status.BackendPlugins {
		plugins[p.Name] = p.FIPS140
	}
	return status.FIPS140, plugins
}

// TestStatusReportsFIPSMode checks the server runs in the FIPS 140-3 mode
// the test run was invoked with (the harness passes GODEBUG through), and
// that a plugin built on the SDK follows it.
func TestStatusReportsFIPSMode(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	waitForPlugin(t, srv, "fake", running)

	core, plugins := statusFIPS(t, srv)
	if core.Enabled != fips140.Enabled() {
		t.Errorf("core FIPS 140-3 mode = %v, want %v (the test run's mode)", core.Enabled, fips140.Enabled())
	}
	if core.Module != fips140.Version() {
		t.Errorf("core FIPS 140-3 module = %q, want %q (the test run's)", core.Module, fips140.Version())
	}
	if plugins["fake"] != core.Enabled {
		t.Errorf("Backend Plugin FIPS 140-3 mode = %v, want the core's %v", plugins["fake"], core.Enabled)
	}
	mode := "off"
	if core.Enabled {
		mode = "on"
	}
	if want := fmt.Sprintf("FIPS 140-3 mode: %s (module %s)", mode, core.Module); !strings.Contains(srv.TC("status").Stdout, want) {
		t.Errorf("tc status does not show %q:\n%s", want, srv.TC("status").Stdout)
	}
	if want := "fips140=" + mode; !strings.Contains(srv.Stderr(), want) {
		t.Errorf("server did not log its FIPS 140-3 mode (%q):\n%s", want, srv.Stderr())
	}
}

// TestFIPSModeIsEnabledAtRuntime forces FIPS mode on through GODEBUG, as an
// Operator does on the standard binary, and checks the plugin follows.
func TestFIPSModeIsEnabledAtRuntime(t *testing.T) {
	tc := harness.New(t)
	tc.Env = []string{"GODEBUG=fips140=on"}
	srv := tc.Start(harness.BaseConfig)
	waitForPlugin(t, srv, "fake", running)

	core, plugins := statusFIPS(t, srv)
	if !core.Enabled {
		t.Error("core is not in FIPS 140-3 mode with GODEBUG=fips140=on")
	}
	if !plugins["fake"] {
		t.Error("Backend Plugin did not follow the core into FIPS 140-3 mode")
	}
	if res := srv.TC("token", "issue", "--policy", "openai-proxy", "--expires-in", "1h"); res.ExitCode != 0 {
		t.Fatalf("token issue in FIPS mode: exit %d\n%s", res.ExitCode, res.Stderr)
	}
}

// TestFIPSOnlyModeServes runs the server with fips140=only, where any
// non-approved algorithm panics, through a Delivery.
func TestFIPSOnlyModeServes(t *testing.T) {
	tc := harness.New(t)
	tc.Env = []string{"GODEBUG=fips140=only"}
	srv := tc.Start(revealConfig)
	waitForPlugin(t, srv, "fake", running)
	if core, _ := statusFIPS(t, srv); !core.Enabled {
		t.Error("core is not in FIPS 140-3 mode with GODEBUG=fips140=only")
	}
	token := issueAgentToken(t, srv, "github-reveal", "1h").Token
	if got := reveal(t, srv, "Bearer "+token, "github"); got.Status != http.StatusOK || got.Body != "test-value-2" {
		t.Errorf("Reveal Delivery in fips140=only mode = %d %q, want 200 with the Secret\nserver stderr:\n%s",
			got.Status, got.Body, srv.Stderr())
	}
}

// TestNonFIPSBackendPluginIsRefusedInFIPSMode: a core in FIPS mode refuses
// a plugin whose handshake does not report FIPS mode, and keeps serving the
// plugins that do (ADR-0004).
func TestNonFIPSBackendPluginIsRefusedInFIPSMode(t *testing.T) {
	tc := harness.New(t)
	tc.Env = []string{"GODEBUG=fips140=on"}
	srv := tc.Start(harness.BaseConfig + `
  nofips:
    path: {{.NoFIPS.Path}}
    sha256: {{.NoFIPS.SHA256}}
    insecure_share_core_user: true
`)
	refused := waitForPlugin(t, srv, "nofips", func(p pluginStatus) bool {
		return p.State == "restarting" && strings.Contains(p.Detail, "FIPS")
	})
	if refused.PID != 0 || refused.Healthy {
		t.Errorf("refused Backend Plugin status = %+v, want not running", refused)
	}
	if !strings.Contains(srv.Stderr(), "not in FIPS 140-3 mode") {
		t.Errorf("server did not log the refusal:\n%s", srv.Stderr())
	}
	fake := waitForPlugin(t, srv, "fake", running)
	if !fake.Healthy {
		t.Errorf("FIPS Backend Plugin status = %+v, want healthy", fake)
	}
}

// TestNonFIPSBackendPluginRunsOutsideFIPSMode: the same plugin is accepted
// by a core that is not in FIPS mode.
func TestNonFIPSBackendPluginRunsOutsideFIPSMode(t *testing.T) {
	tc := harness.New(t)
	tc.Env = []string{"GODEBUG=fips140=off"}
	srv := tc.Start(harness.AdminConfig + `
backend_plugins:
  nofips:
    path: {{.NoFIPS.Path}}
    sha256: {{.NoFIPS.SHA256}}
    insecure_share_core_user: true
`)
	if p := waitForPlugin(t, srv, "nofips", running); !p.Healthy {
		t.Errorf("Backend Plugin status = %+v, want healthy", p)
	}
	if _, plugins := statusFIPS(t, srv); plugins["nofips"] {
		t.Error("status reports the plugin in FIPS 140-3 mode")
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

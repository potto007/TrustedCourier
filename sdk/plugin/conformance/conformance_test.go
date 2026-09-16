package conformance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/sdk/plugin/conformance"
)

// buildFake builds the fake Backend Plugin in the given mode.
func buildFake(t *testing.T, mode string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fakebackend")
	cmd := exec.Command("go", "build", "-ldflags", "-X main.mode="+mode, "-o", bin, "../internal/fakebackend")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake plugin: %v\n%s", err, out)
	}
	return bin
}

var fakeFixture = conformance.Fixture{
	Secrets: map[string][]byte{
		"kv/openai": []byte("test-value-1"),
		"kv/github": []byte("test-value-2"),
		"kv/üabc":   []byte("test-value-3"),
	},
	Missing:            "kv/missing",
	Malformed:          []string{"kv/empty"},
	CourierKeyLocation: "courier/tls-key",
}

func TestFakePluginPassesConformance(t *testing.T) {
	conformance.Run(t, buildFake(t, ""), fakeFixture)
}

// TestKitCoversEveryCheck runs the kit against the fake plugin in a child
// test process and checks every conformance check ran and passed, so a
// check cannot silently drop out of the kit.
func TestKitCoversEveryCheck(t *testing.T) {
	if bin := os.Getenv("CONFORMANCE_FAKE_PLUGIN"); bin != "" {
		conformance.Run(t, bin, fakeFixture)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKitCoversEveryCheck$", "-test.v")
	cmd.Env = append(os.Environ(), "CONFORMANCE_FAKE_PLUGIN="+buildFake(t, ""))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kit failed the fake plugin:\n%s", out)
	}
	for _, check := range []string{
		"FIPS140", "FIPS140Follows", "Capabilities", "Health", "Get", "GetMissing",
		"GetMalformed", "List", "ListNoMatch", "Concurrent", "CourierKeyWrite",
	} {
		if !strings.Contains(string(out), "--- PASS: TestKitCoversEveryCheck/"+check+" ") {
			t.Errorf("kit output does not show check %s passing:\n%s", check, out)
		}
	}
}

// TestKitFailsPluginWithoutMalformedHandling runs the kit against a plugin
// that serves a value at a malformed location, bypassing the SDK's checks.
func TestKitFailsPluginWithoutMalformedHandling(t *testing.T) {
	if bin := os.Getenv("CONFORMANCE_LENIENT_PLUGIN"); bin != "" {
		conformance.Run(t, bin, fakeFixture)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKitFailsPluginWithoutMalformedHandling$", "-test.v")
	cmd.Env = append(os.Environ(), "CONFORMANCE_LENIENT_PLUGIN="+buildFake(t, "lenient"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("conformance kit passed a plugin that serves a malformed Secret:\n%s", out)
	}
	for _, want := range []string{
		"--- FAIL: TestKitFailsPluginWithoutMalformedHandling/GetMalformed",
		"--- PASS: TestKitFailsPluginWithoutMalformedHandling/Get ",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("kit output is missing %q:\n%s", want, out)
		}
	}
}

// TestConformanceFailsMalformedPlugin runs the kit against a plugin that
// breaks the contract in a child test process, since a kit failure fails
// the test that runs it.
func TestConformanceFailsMalformedPlugin(t *testing.T) {
	if bin := os.Getenv("CONFORMANCE_MALFORMED_PLUGIN"); bin != "" {
		conformance.Run(t, bin, fakeFixture)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConformanceFailsMalformedPlugin$", "-test.v")
	cmd.Env = append(os.Environ(), "CONFORMANCE_MALFORMED_PLUGIN="+buildFake(t, "malformed"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("conformance kit passed a malformed plugin:\n%s", out)
	}
	for _, want := range []string{
		"--- FAIL: TestConformanceFailsMalformedPlugin/Health",
		"--- FAIL: TestConformanceFailsMalformedPlugin/Get ",
		"--- FAIL: TestConformanceFailsMalformedPlugin/GetMissing",
		"--- FAIL: TestConformanceFailsMalformedPlugin/List",
		"malformed response",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("kit output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "panic:") {
		t.Errorf("kit panicked on a malformed plugin:\n%s", out)
	}
}

// TestConformanceFailsNonFIPSPluginInFIPSMode runs the kit in FIPS mode
// against a plugin that reports itself outside FIPS mode, in a child test
// process as above.
func TestConformanceFailsNonFIPSPluginInFIPSMode(t *testing.T) {
	if bin := os.Getenv("CONFORMANCE_NOFIPS_PLUGIN"); bin != "" {
		conformance.Run(t, bin, fakeFixture)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConformanceFailsNonFIPSPluginInFIPSMode$", "-test.v")
	cmd.Env = append(os.Environ(), "CONFORMANCE_NOFIPS_PLUGIN="+buildFake(t, "nofips"), "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("conformance kit in FIPS mode passed a plugin outside FIPS mode:\n%s", out)
	}
	for _, want := range []string{
		"--- FAIL: TestConformanceFailsNonFIPSPluginInFIPSMode/FIPS140",
		"kit runs in FIPS 140-3 mode on but the plugin reports off",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("kit output is missing %q:\n%s", want, out)
		}
	}
}

func TestPluginDoesNotDependOnCore(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../internal/fakebackend").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	const core = "github.com/potto007/TrustedCourier/"
	for dep := range strings.Lines(string(out)) {
		dep = strings.TrimSpace(dep)
		if strings.HasPrefix(dep, core) && !strings.HasPrefix(dep, core+"sdk/plugin") {
			t.Errorf("a plugin built on the SDK depends on core package %s", dep)
		}
	}
}

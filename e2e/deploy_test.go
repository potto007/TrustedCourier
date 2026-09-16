package e2e

import (
	"debug/elf"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// repoRoot is the repository root, the parent of the e2e package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestReleaseBinariesAreStatic(t *testing.T) {
	out := t.TempDir()
	build := exec.Command(filepath.Join(repoRoot(t), "scripts", "build-release.sh"), out)
	// Built against the in-tree FIPS module here, as go test is; the
	// script defaults to the certified snapshot, as CI does.
	build.Env = append(os.Environ(), "GOFIPS140=off")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build-release.sh: %v\n%s", err, b)
	}
	for _, name := range []string{"tc", "openbao-plugin"} {
		path := filepath.Join(out, name)
		f, err := elf.Open(path)
		if err != nil {
			t.Fatalf("%s is not an ELF binary: %v", name, err)
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				t.Errorf("%s asks for a dynamic loader; it is not static", name)
			}
		}
		if needed, _ := f.ImportedLibraries(); len(needed) > 0 {
			t.Errorf("%s needs shared libraries %v; it is not static", name, needed)
		}
		if f.Section(".symtab") != nil {
			t.Errorf("%s is not stripped", name)
		}
		_ = f.Close()
	}
	sums, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^[0-9a-f]{64}  tc$`).Match(sums) || !regexp.MustCompile(`(?m)^[0-9a-f]{64}  openbao-plugin$`).Match(sums) {
		t.Errorf("SHA256SUMS does not list both binaries:\n%s", sums)
	}
	res := runBinary(t, filepath.Join(out, "tc"), "--help")
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "tc init") {
		t.Errorf("the static tc does not run: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func runBinary(t *testing.T, path string, args ...string) harness.Result {
	t.Helper()
	cmd := exec.Command(path, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	return harness.Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}
}

// composeOrSkip returns the compose command for the deploy directory, or
// skips without docker compose.
func composeOrSkip(t *testing.T, files ...string) func(env []string, args ...string) harness.Result {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		if os.Getenv("TC_REQUIRE_OPENBAO") != "" {
			t.Fatal("TC_REQUIRE_OPENBAO is set but docker is not on PATH")
		}
		t.Skip("no docker on PATH")
	}
	if out, err := exec.Command(docker, "compose", "version").CombinedOutput(); err != nil {
		t.Skipf("docker compose is not available: %v\n%s", err, out)
	}
	dir := filepath.Join(repoRoot(t), "deploy")
	return func(env []string, args ...string) harness.Result {
		t.Helper()
		all := []string{"compose"}
		for _, f := range files {
			all = append(all, "-f", f)
		}
		cmd := exec.Command(docker, append(all, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			code = -1
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			}
		}
		return harness.Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}
	}
}

type composeConfig struct {
	Services map[string]struct {
		Image       string   `json:"image"`
		Command     []string `json:"command"`
		NetworkMode string   `json:"network_mode"`
	} `json:"services"`
}

func renderCompose(t *testing.T, files ...string) composeConfig {
	t.Helper()
	compose := composeOrSkip(t, files...)
	res := compose([]string{"BAO_DEV_ROOT_TOKEN_ID=test"}, "config", "--format", "json")
	if res.ExitCode != 0 {
		t.Fatalf("docker compose config: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	var cfg composeConfig
	if err := json.Unmarshal([]byte(res.Stdout), &cfg); err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, res.Stdout)
	}
	return cfg
}

func TestComposeFilesMatchTheHarness(t *testing.T) {
	cfg := renderCompose(t, "compose.yaml")
	bao := cfg.Services["openbao"]
	if bao.Image != harness.OpenBaoImage {
		t.Errorf("compose.yaml runs %s, the tests %s", bao.Image, harness.OpenBaoImage)
	}
	// Compose keeps $$ in the rendered command; the shell sees $.
	if len(bao.Command) != 3 || strings.ReplaceAll(bao.Command[2], "$$", "$") != harness.OpenBaoWaitForSealKey {
		t.Errorf("compose.yaml starts OpenBao with %q, the tests with %q", bao.Command, harness.OpenBaoWaitForSealKey)
	}
	if _, ok := cfg.Services["trustedcourier"]; !ok {
		t.Errorf("compose.yaml has no trustedcourier service")
	}

	dev := renderCompose(t, "compose.yaml", "compose.dev.yaml")
	if cmd := dev.Services["openbao"].Command; len(cmd) != 2 || cmd[1] != "-dev" {
		t.Errorf("compose.dev.yaml starts OpenBao with %q, not in dev mode", cmd)
	}
	if mode := dev.Services["trustedcourier"].NetworkMode; mode != "host" {
		t.Errorf("compose.dev.yaml puts trustedcourier on network %q; Agents on the host need loopback", mode)
	}
}

// TestComposeStackBootstraps builds the image and runs the compose file's
// steps: pin the plugin, tc init, up, and administer the running server.
// It takes minutes and needs the network, so it runs only with
// TC_COMPOSE_TEST set. It uses its own compose project and removes it.
func TestComposeStackBootstraps(t *testing.T) {
	if os.Getenv("TC_COMPOSE_TEST") == "" {
		t.Skip("set TC_COMPOSE_TEST to build the image and run the compose stack")
	}
	compose := composeOrSkip(t, "compose.yaml", "compose.test.yaml")
	dir := t.TempDir()
	project := "tc-e2e-" + strings.ToLower(regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(filepath.Base(dir), ""))
	env := []string{"COMPOSE_PROJECT_NAME=" + project, "TC_TEST_CONFIG=" + filepath.Join(dir, "trustedcourier.yaml")}
	t.Cleanup(func() {
		if res := compose(env, "down", "--volumes", "--timeout", "10"); res.ExitCode != 0 {
			t.Logf("docker compose down: %s", res.Stderr)
		}
	})
	// The config must exist before compose mounts it, and must not be
	// readable by the plugin user.
	if err := os.WriteFile(filepath.Join(dir, "trustedcourier.yaml"), []byte("data_dir: /var/lib/trustedcourier/data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := compose(env, "build"); res.ExitCode != 0 {
		t.Fatalf("docker compose build: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	res := compose(env, "run", "--rm", "--no-deps", "trustedcourier", "tc", "plugin", "sha256", "/usr/local/lib/trustedcourier/plugins/openbao")
	if res.ExitCode != 0 {
		t.Fatalf("tc plugin sha256: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	sum := strings.TrimSpace(strings.TrimPrefix(res.Stdout, "sha256: "))
	shipped, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "trustedcourier.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The shipped config with the plugin pinned and no Agent API, whose
	// TLS needs a domain.
	config := strings.Replace(string(shipped), "sha256: CHANGE-ME", "sha256: "+sum, 1)
	config = regexp.MustCompile(`(?s)\nagent_api:.*?\naudit:`).ReplaceAllString(config, "\naudit:")
	if err := os.WriteFile(filepath.Join(dir, "trustedcourier.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	res = compose(env, "run", "--rm", "trustedcourier", "tc", "init",
		"--config", "/etc/trustedcourier/trustedcourier.yaml", "--seal-key-file", "/openbao/seal/unseal.key", "--recovery-shares", "1", "--recovery-threshold", "1")
	if res.ExitCode != 0 {
		t.Fatalf("tc init in compose: exit %d\n%s%s\n%s", res.ExitCode, res.Stdout, res.Stderr, compose(env, "logs", "openbao").Stdout)
	}
	out := initOutput(res.Stdout)
	credential := out.one(t, operatorCredentialLabel)
	rootToken := out.one(t, rootTokenLabel)

	if res := compose(env, "up", "--detach", "--wait", "--wait-timeout", "60"); res.ExitCode != 0 {
		t.Fatalf("docker compose up: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	adminEnv := append(env, "TC_OPERATOR_CREDENTIAL="+credential)
	deadline := time.Now().Add(60 * time.Second)
	for {
		res = compose(adminEnv, "exec", "-e", "TC_OPERATOR_CREDENTIAL", "trustedcourier", "tc", "status")
		if res.ExitCode == 0 && strings.Contains(res.Stdout, "healthy") && !strings.Contains(res.Stdout, "unhealthy") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the plugin never became healthy in compose: exit %d\n%s%s\n%s", res.ExitCode, res.Stdout, res.Stderr, compose(env, "logs").Stdout)
		}
		time.Sleep(time.Second)
	}
	if !strings.Contains(res.Stdout, "Audit signing key: loaded") {
		t.Errorf("tc status in compose:\n%s", res.Stdout)
	}
	res = compose(adminEnv, "exec", "-e", "TC_OPERATOR_CREDENTIAL", "trustedcourier", "tc", "token", "issue", "--policy", "openai-proxy", "--expires-in", "1h")
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "tcat_") {
		t.Errorf("tc token issue in compose: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	// The root token works against OpenBao from inside its container, as
	// the docs say to store Secrets.
	res = compose(append(env, "BAO_TOKEN="+rootToken), "exec", "-e", "BAO_TOKEN", "openbao", "bao", "kv", "put", "-mount=secret", "openai", "key=sk-compose-test")
	if res.ExitCode != 0 {
		t.Errorf("bao kv put in compose: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
}

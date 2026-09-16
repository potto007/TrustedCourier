package e2e

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// initConfig is a config for the bundled OpenBao: the OpenBao Backend
// Plugin sharing the server's user, pointed at an OpenBao by BAO_ADDR with
// its token in BAO_TOKEN_FILE, the audit signing key and one Secret Name
// in its KV mount, and a Policy that reveals the Secret Name. It ends
// inside the plugin's env.
const initConfig = `
data_dir: {{.DataDir}}
admin:
  socket: {{.Socket}}
agent_api:
  listen: 127.0.0.1:0
audit:
  signing_key:
    backend: openbao
    location: secret/data/trustedcourier#audit-signing-key
secrets:
  openai:
    backend: openbao
    location: secret/data/openai#key
policies:
  openai-reveal:
    secrets:
      - name: openai
        delivery: [reveal]
backend_plugins:
  openbao:
    path: {{.OpenBao.Path}}
    sha256: {{.OpenBao.SHA256}}
    insecure_share_core_user: true
    env:
      BAO_ADDR: %s
      BAO_TOKEN_FILE: %s
`

// initOutput is what tc init printed, by labelled section: the lines after
// a line starting with the label, up to the next blank line.
type initOutput string

func (o initOutput) section(label string) []string {
	var lines []string
	found := false
	for line := range strings.SplitSeq(string(o), "\n") {
		switch {
		case found && line == "":
			return lines
		case found:
			lines = append(lines, line)
		case strings.HasPrefix(line, label):
			found = true
		}
	}
	return lines
}

func (o initOutput) one(t *testing.T, label string) string {
	t.Helper()
	lines := o.section(label)
	if len(lines) != 1 {
		t.Fatalf("tc init printed %d lines under %q, want 1:\n%s", len(lines), label, string(o))
	}
	return lines[0]
}

const (
	sealKeyLabel            = "Static seal key"
	recoveryKeysLabel       = "Recovery keys"
	rootTokenLabel          = "Root token"
	operatorCredentialLabel = "Operator Credential"
)

// runInit runs tc init against the installation's config file with the
// extra flags, and returns its output.
func runInit(t *testing.T, tc *harness.Installation, env []string, flags ...string) (harness.Result, initOutput) {
	t.Helper()
	args := append([]string{"init", "--config", filepath.Join(tc.Dir(), "config.yaml")}, flags...)
	// tc init waits for OpenBao (up to --wait) and the plugin's health; a
	// runner under load needs more than a plain command's limit.
	res := tc.TCTimeout(3*time.Minute, env, args...)
	return res, initOutput(res.Stdout)
}

func TestInitBootstrapsOpenBaoWithStaticSeal(t *testing.T) {
	tc := harness.New(t)
	sealDir := filepath.Join(tc.Dir(), "seal")
	if err := os.Mkdir(sealDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// OpenBao boots waiting for the seal key tc init writes, as the compose
	// file's does.
	bao := harness.StartOpenBao(t, sealDir)
	tokenFile := filepath.Join(tc.Dir(), "openbao-token")
	config := fmt.Sprintf(initConfig, bao.Address, tokenFile)
	tc.WriteConfig(config)
	sealKeyFile := filepath.Join(sealDir, harness.SealKeyFile)

	res, out := runInit(t, tc, nil, "--seal-key-file", sealKeyFile, "--recovery-shares", "3", "--recovery-threshold", "2")
	if res.ExitCode != 0 {
		t.Fatalf("tc init: exit %d\n%s%s\nOpenBao:\n%s", res.ExitCode, res.Stdout, res.Stderr, bao.Logs())
	}

	// The seal key is OpenBao's: written where the Operator said, shown once.
	sealKey, err := os.ReadFile(sealKeyFile)
	if err != nil {
		t.Fatalf("tc init did not write the seal key: %v", err)
	}
	if len(sealKey) != 32 {
		t.Errorf("seal key is %d bytes, want 32", len(sealKey))
	}
	if shown := out.one(t, sealKeyLabel); shown != base64.StdEncoding.EncodeToString(sealKey) {
		t.Errorf("tc init showed seal key %q, which is not the file's contents in base64", shown)
	}
	recovery := out.section(recoveryKeysLabel)
	if len(recovery) != 3 {
		t.Fatalf("tc init showed %d recovery keys, want 3:\n%s", len(recovery), res.Stdout)
	}
	if !strings.Contains(res.Stdout, "any 2 of the 3") {
		t.Errorf("tc init does not say how many recovery keys are needed:\n%s", res.Stdout)
	}
	rootToken := out.one(t, rootTokenLabel)
	credential := out.one(t, operatorCredentialLabel)
	if !strings.HasPrefix(credential, "tcoc_") {
		t.Fatalf("Operator Credential %q has no tcoc_ prefix", credential)
	}
	if initialized, sealed := bao.Health(); !initialized || sealed {
		t.Fatalf("after tc init OpenBao is initialized=%v sealed=%v", initialized, sealed)
	}
	bao.Must(rootToken, http.MethodGet, "auth/token/lookup-self", nil, http.StatusOK)

	// TrustedCourier keeps none of the material it showed (ADR-0001,
	// ADR-0008). The seal key file is OpenBao's, outside the data directory.
	for _, needle := range append(append([]string{rootToken, base64.StdEncoding.EncodeToString(sealKey), credential}, recovery...), string(sealKey)) {
		if tc.FilesContain(needle) {
			t.Errorf("a value tc init showed is stored in the data directory")
		}
	}
	tokenInfo, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("tc init did not write the Backend Plugin's token file: %v", err)
	}
	if perm := tokenInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode is %v, want 0600", perm)
	}
	pluginToken, _ := os.ReadFile(tokenFile)
	if strings.TrimSpace(string(pluginToken)) == rootToken {
		t.Errorf("the Backend Plugin was given the root token")
	}
	if key := bao.KVField(rootToken, "trustedcourier", "audit-signing-key"); !strings.Contains(key, "PRIVATE KEY") {
		t.Errorf("tc init did not store an audit signing key: %q", key)
	}
	// The shipped OpenBao config lets the plugin's token live the year tc
	// init asks for; the default cap would cut it to 32 days.
	m := regexp.MustCompile(`Backend Plugin openbao: .*expires (\S+);`).FindStringSubmatch(res.Stdout)
	if m == nil {
		t.Fatalf("tc init did not print the plugin token's expiry:\n%s", res.Stdout)
	}
	if expiry, err := time.Parse(time.RFC3339, m[1]); err != nil || time.Until(expiry) < 360*24*time.Hour {
		t.Errorf("plugin token expires %s, want about a year out", m[1])
	}

	// The static seal unseals OpenBao on its own after a restart.
	bao.Restart()
	if initialized, sealed := bao.Health(); !initialized || sealed {
		t.Fatalf("after a restart OpenBao is initialized=%v sealed=%v\n%s", initialized, sealed, bao.Logs())
	}

	// A second tc init changes nothing.
	res, _ = runInit(t, tc, nil, "--seal-key-file", sealKeyFile)
	if res.ExitCode == 0 {
		t.Fatalf("a second tc init succeeded:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "already initialized") {
		t.Errorf("second tc init does not say OpenBao is initialized:\n%s", res.Stderr)
	}
	if after, _ := os.ReadFile(sealKeyFile); string(after) != string(sealKey) {
		t.Errorf("a second tc init changed the seal key")
	}

	// The server uses what tc init set up: the Operator Credential, the
	// Backend Plugin's token, and the audit signing key.
	bao.PutKV(rootToken, "openai", map[string]any{"key": "sk-init-test"})
	srv := tc.Start(config)
	if strings.Contains(srv.Stdout(), "tcoc_") {
		t.Errorf("the server showed an Operator Credential after tc init created one:\n%s", srv.Stdout())
	}
	srv.Credential = credential
	if res := srv.TC("token", "list"); res.ExitCode != 0 {
		t.Fatalf("the Operator Credential tc init showed is rejected: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	p := waitForPlugin(t, srv, "openbao", func(p pluginStatus) bool { return p.State == "running" && p.Healthy })
	if !strings.Contains(p.Detail, "OpenBao 2.") {
		t.Errorf("plugin detail %q does not name the OpenBao version", p.Detail)
	}
	token := issueAgentToken(t, srv, "openai-reveal", "1h").Token
	if resp := reveal(t, srv, "Bearer "+token, "openai"); resp.Status != http.StatusOK || resp.Body != "sk-init-test" {
		t.Fatalf("Reveal Delivery after tc init: status %d body %q", resp.Status, resp.Body)
	}
}

func TestInitDevUsesDevModeOpenBao(t *testing.T) {
	tc := harness.New(t)
	bao := harness.StartDevOpenBao(t)
	tokenFile := filepath.Join(tc.Dir(), "openbao-token")
	config := fmt.Sprintf(initConfig, bao.Address, tokenFile)
	tc.WriteConfig(config)
	env := []string{"BAO_DEV_ROOT_TOKEN_ID=" + bao.RootToken}

	res, _ := runInit(t, tc, nil, "--dev")
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "BAO_DEV_ROOT_TOKEN_ID") {
		t.Fatalf("tc init --dev without the dev root token: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	res, _ = runInit(t, tc, env, "--dev", "--seal-key-file", filepath.Join(tc.Dir(), "unseal.key"))
	if res.ExitCode != 2 {
		t.Fatalf("tc init --dev with --seal-key-file: exit %d, want a usage error\n%s", res.ExitCode, res.Stderr)
	}

	res, out := runInit(t, tc, env, "--dev")
	if res.ExitCode != 0 {
		t.Fatalf("tc init --dev: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	for _, label := range []string{sealKeyLabel, recoveryKeysLabel, rootTokenLabel} {
		if len(out.section(label)) > 0 {
			t.Errorf("tc init --dev printed %q, which dev mode has none of:\n%s", label, res.Stdout)
		}
	}
	credential := out.one(t, operatorCredentialLabel)
	signingKey := bao.KVField(bao.RootToken, "trustedcourier", "audit-signing-key")
	if !strings.Contains(signingKey, "PRIVATE KEY") {
		t.Fatalf("tc init --dev did not store an audit signing key: %q", signingKey)
	}

	// Dev mode may be initialized again, for a fresh in-memory OpenBao; on
	// the same one, what exists is kept.
	res, out = runInit(t, tc, env, "--dev")
	if res.ExitCode != 0 {
		t.Fatalf("second tc init --dev: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	if len(out.section(operatorCredentialLabel)) > 0 {
		t.Errorf("second tc init --dev showed an Operator Credential again:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "Operator Credential: already created") {
		t.Errorf("second tc init --dev does not say the Operator Credential exists:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "token in "+tokenFile+" kept") {
		t.Errorf("second tc init --dev issued the plugin a new token instead of keeping the working one:\n%s", res.Stdout)
	}
	if again := bao.KVField(bao.RootToken, "trustedcourier", "audit-signing-key"); again != signingKey {
		t.Errorf("second tc init --dev replaced the audit signing key")
	}

	bao.PutKV(bao.RootToken, "openai", map[string]any{"key": "sk-dev-test"})
	srv := tc.Start(config)
	srv.Credential = credential
	waitForPlugin(t, srv, "openbao", func(p pluginStatus) bool { return p.State == "running" && p.Healthy })
	token := issueAgentToken(t, srv, "openai-reveal", "1h").Token
	if resp := reveal(t, srv, "Bearer "+token, "openai"); resp.Status != http.StatusOK || resp.Body != "sk-dev-test" {
		t.Fatalf("Reveal Delivery after tc init --dev: status %d body %q", resp.Status, resp.Body)
	}
}

func TestInitRefusesBadConfigBeforeTouchingOpenBao(t *testing.T) {
	tc := harness.New(t)
	cases := []struct {
		name, config, wantErr string
		flags                 []string
	}{
		{
			name:    "no OpenBao Backend Plugin",
			config:  harness.BaseConfig,
			wantErr: "no Backend Plugin sets BAO_ADDR",
			flags:   []string{"--seal-key-file", filepath.Join(tc.Dir(), "unseal.key")},
		},
		{
			name: "wrong plugin hash",
			config: strings.Replace(fmt.Sprintf(initConfig, "http://127.0.0.1:1", filepath.Join(tc.Dir(), "openbao-token")),
				"{{.OpenBao.SHA256}}", "{{.Fake.SHA256}}", 1),
			wantErr: "SHA-256",
			flags:   []string{"--seal-key-file", filepath.Join(tc.Dir(), "unseal.key")},
		},
		{
			name:    "no BAO_TOKEN_FILE",
			config:  strings.Replace(fmt.Sprintf(initConfig, "http://127.0.0.1:1", "x"), "BAO_TOKEN_FILE: x", "BAO_TOKEN: x", 1),
			wantErr: "BAO_TOKEN_FILE",
			flags:   []string{"--seal-key-file", filepath.Join(tc.Dir(), "unseal.key")},
		},
		{
			name:    "no seal key file",
			config:  fmt.Sprintf(initConfig, "http://127.0.0.1:1", filepath.Join(tc.Dir(), "openbao-token")),
			wantErr: "--seal-key-file",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc.WriteConfig(c.config)
			res, _ := runInit(t, tc, nil, c.flags...)
			if res.ExitCode == 0 {
				t.Fatalf("tc init succeeded:\n%s", res.Stdout)
			}
			if !strings.Contains(res.Stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, res.Stderr)
			}
			if _, err := os.Stat(filepath.Join(tc.Dir(), "unseal.key")); err == nil {
				t.Errorf("tc init wrote a seal key before refusing")
			}
		})
	}
}

// TestInitGivesTokenFileToPluginUser needs root, so tc init can hand the
// Backend Plugin's token file to the plugin's user. Run it with sudo.
func TestInitGivesTokenFileToPluginUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	tc := harness.New(t)
	bao := harness.StartDevOpenBao(t)
	// The plugin user must be able to reach its binary and its token file.
	dir, err := os.MkdirTemp("", "tc-plugin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := tc.InstallPlugin(harness.OpenBaoPlugin, dir, 0o755)
	tokenFile := filepath.Join(dir, "openbao-token")
	config := strings.Replace(fmt.Sprintf(initConfig, bao.Address, tokenFile),
		"    path: {{.OpenBao.Path}}\n", "    path: "+path+"\n", 1)
	config = strings.Replace(config, "    insecure_share_core_user: true\n", "    user: nobody\n", 1)
	tc.WriteConfig(config)

	res, out := runInit(t, tc, []string{"BAO_DEV_ROOT_TOKEN_ID=" + bao.RootToken}, "--dev")
	if res.ExitCode != 0 {
		t.Fatalf("tc init --dev: exit %d\n%s%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if uid := info.Sys().(*syscall.Stat_t).Uid; uid != 65534 {
		t.Errorf("token file is owned by uid %d, want nobody (65534)", uid)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode is %v, want 0600", perm)
	}

	srv := tc.Start(config)
	srv.Credential = out.one(t, operatorCredentialLabel)
	p := waitForPlugin(t, srv, "openbao", func(p pluginStatus) bool { return p.State == "running" && p.Healthy })
	if !p.Healthy {
		t.Fatalf("plugin running as nobody is not healthy: %s", p.Detail)
	}
}

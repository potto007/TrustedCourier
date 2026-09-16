package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/potto007/TrustedCourier/sdk/plugin/conformance"
)

// Image is the OpenBao container the tests run, pinned so a test failure is
// never a surprise upgrade.
const Image = "openbao/openbao:2.4.4"

// openBao is a running OpenBao the tests seed and the plugin is pointed at.
type openBao struct {
	Address   string
	RootToken string
	t         *testing.T
}

// startOpenBao returns an OpenBao to test against: the one at
// TC_OPENBAO_ADDR with the root token TC_OPENBAO_TOKEN when set, else a
// dev-mode container started with docker, stopped when the test ends. With
// neither, the test skips, or fails when TC_REQUIRE_OPENBAO is set, as it
// is in CI.
func startOpenBao(t *testing.T) *openBao {
	t.Helper()
	if addr := os.Getenv("TC_OPENBAO_ADDR"); addr != "" {
		return &openBao{Address: addr, RootToken: os.Getenv("TC_OPENBAO_TOKEN"), t: t}
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		if os.Getenv("TC_REQUIRE_OPENBAO") != "" {
			t.Fatal("TC_REQUIRE_OPENBAO is set but neither docker nor TC_OPENBAO_ADDR is available")
		}
		t.Skip("no docker on PATH and no TC_OPENBAO_ADDR; set one to run the OpenBao conformance test")
	}
	token := "root-" + hex.EncodeToString(randomBytes(t, 8))
	out, err := exec.Command(docker, "run", "--detach", "--rm", "--cap-add=IPC_LOCK",
		"--publish", "127.0.0.1::8200",
		"--env", "BAO_DEV_ROOT_TOKEN_ID="+token,
		"--env", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		Image, "server", "-dev").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", Image, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if out, err := exec.Command(docker, "rm", "--force", id).CombinedOutput(); err != nil {
			t.Logf("docker rm: %v\n%s", err, out)
		}
	})
	out, err = exec.Command(docker, "port", id, "8200/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, out)
	}
	// One line per address family; the first is the IPv4 one.
	hostPort, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	b := &openBao{Address: "http://" + hostPort, RootToken: token, t: t}
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, _ := b.call(http.MethodGet, "sys/health", nil)
		if status == http.StatusOK {
			return b
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command(docker, "logs", id).CombinedOutput()
			t.Fatalf("OpenBao at %s did not become healthy; last status %d\n%s", b.Address, status, logs)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// call makes one API call as root and returns the status and the decoded
// body, if any.
func (b *openBao) call(method, path string, body any) (int, map[string]any) {
	b.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			b.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, b.Address+"/v1/"+path, reader)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", b.RootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

// must makes a call that must return one of the given statuses.
func (b *openBao) must(method, path string, body any, ok ...int) map[string]any {
	b.t.Helper()
	status, decoded := b.call(method, path, body)
	for _, want := range ok {
		if status == want {
			return decoded
		}
	}
	b.t.Fatalf("%s %s: status %d, want %v: %v", method, path, status, ok, decoded)
	return nil
}

// buildPlugin builds the OpenBao Backend Plugin.
func buildPlugin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openbao-plugin")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, out)
	}
	return bin
}

// seed puts the Fixture's records in a KV v2 mount at secret/ and a KV v1
// mount at kv1/, and issues a token whose policy covers only those mounts,
// as an Operator's token would.
func seed(t *testing.T, b *openBao) (token string, fixture conformance.Fixture) {
	t.Helper()
	b.must(http.MethodPost, "sys/mounts/kv1", map[string]any{"type": "kv", "options": map[string]any{"version": "1"}}, http.StatusNoContent)
	b.must(http.MethodPost, "secret/data/openai", map[string]any{"data": map[string]any{"key": "sk-test-openai"}}, http.StatusOK)
	b.must(http.MethodPost, "secret/data/github", map[string]any{"data": map[string]any{
		"token":  "ghp_test_github",
		"empty":  "",
		"number": 42,
		"object": map[string]any{"nested": "x"},
	}}, http.StatusOK)
	b.must(http.MethodPost, "secret/data/team/üabc", map[string]any{"data": map[string]any{"key": "test-value-3"}}, http.StatusOK)
	b.must(http.MethodPost, "kv1/app", map[string]any{"password": "kv1-password", "blank": ""}, http.StatusNoContent)
	// A record with a field beside the Courier Key, which the write must
	// keep.
	b.must(http.MethodPost, "secret/data/trustedcourier", map[string]any{"data": map[string]any{"audit-signing-key": "keep-me"}}, http.StatusOK)

	b.must(http.MethodPut, "sys/policies/acl/trustedcourier", map[string]any{"policy": `
path "secret/data/*"     { capabilities = ["read", "create", "update"] }
path "secret/metadata/*" { capabilities = ["list", "read"] }
path "kv1/*"             { capabilities = ["read", "list", "create", "update"] }
`}, http.StatusNoContent)
	resp := b.must(http.MethodPost, "auth/token/create", map[string]any{"policies": []string{"trustedcourier"}, "ttl": "2h"}, http.StatusOK)
	token, _ = resp["auth"].(map[string]any)["client_token"].(string)
	if token == "" {
		t.Fatalf("auth/token/create returned no token: %v", resp)
	}
	return token, conformance.Fixture{
		Secrets: map[string][]byte{
			"secret/data/openai#key":    []byte("sk-test-openai"),
			"secret/data/github#token":  []byte("ghp_test_github"),
			"secret/data/team/üabc#key": []byte("test-value-3"),
			"kv1/app#password":          []byte("kv1-password"),
		},
		Missing:            "secret/data/nothing#key",
		Malformed:          []string{"secret/data/github#empty", "secret/data/github#number", "secret/data/github#object", "kv1/app#blank"},
		CourierKeyLocation: "secret/data/trustedcourier#tls-key",
	}
}

func TestOpenBaoPluginPassesConformance(t *testing.T) {
	b := startOpenBao(t)
	token, fixture := seed(t, b)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.Env = []string{"BAO_ADDR=" + b.Address, "BAO_TOKEN_FILE=" + tokenFile}
	conformance.Run(t, buildPlugin(t), fixture)

	// The Courier Key write kept the record's other field, and each write
	// made a new version rather than replacing the record.
	resp := b.must(http.MethodGet, "secret/data/trustedcourier", nil, http.StatusOK)
	data := resp["data"].(map[string]any)
	if fields := data["data"].(map[string]any); fields["audit-signing-key"] != "keep-me" {
		t.Errorf("after Courier Key writes, secret/data/trustedcourier fields = %v, want audit-signing-key kept", fields)
	}
	if version := data["metadata"].(map[string]any)["version"]; fmt.Sprint(version) != "3" {
		t.Errorf("after two Courier Key writes, version = %v, want 3", version)
	}
}

func TestOpenBaoPluginRefusesBadEnv(t *testing.T) {
	bin := buildPlugin(t)
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"no address", nil, "BAO_ADDR is required"},
		{"no token", []string{"BAO_ADDR=http://127.0.0.1:1"}, "BAO_TOKEN or BAO_TOKEN_FILE is required"},
		{"both tokens", []string{"BAO_ADDR=http://127.0.0.1:1", "BAO_TOKEN=x", "BAO_TOKEN_FILE=/nonexistent"}, "not both"},
		{"missing token file", []string{"BAO_ADDR=http://127.0.0.1:1", "BAO_TOKEN_FILE=/nonexistent"}, "BAO_TOKEN_FILE"},
		{"bad address", []string{"BAO_ADDR=openbao:8200", "BAO_TOKEN=x"}, "BAO_ADDR"},
		{"address with path", []string{"BAO_ADDR=http://127.0.0.1:1/v1", "BAO_TOKEN=x"}, "only a scheme, host, and port"},
		{"missing CA file", []string{"BAO_ADDR=https://127.0.0.1:1", "BAO_TOKEN=x", "BAO_CACERT=/nonexistent"}, "BAO_CACERT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(bin)
			cmd.Env = c.env
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("plugin started with env %q", c.env)
			}
			if !strings.Contains(string(out), c.want) {
				t.Errorf("stderr does not contain %q:\n%s", c.want, out)
			}
		})
	}
}

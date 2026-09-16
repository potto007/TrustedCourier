package harness

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
)

// OpenBaoImage is the OpenBao container the tests run, pinned so a test
// failure is never a surprise upgrade. deploy/compose.yaml pins the same.
const OpenBaoImage = "openbao/openbao:2.4.4"

// OpenBaoPlugin is the bundled OpenBao Backend Plugin, built from
// plugins/openbao, as {{.OpenBao.Path}} and {{.OpenBao.SHA256}} in config
// templates.
var OpenBaoPlugin PluginBinary

// SealKeyFile is the seal key's name inside the directory tc init and
// OpenBao share.
const SealKeyFile = "unseal.key"

// OpenBaoWaitForSealKey is what the OpenBao container runs when it boots
// with the static seal: it waits for tc init to write the seal key, hands
// it to OpenBao in its environment, and starts OpenBao as OpenBao's user.
// The file stays owner-only on the shared volume. deploy/compose.yaml runs
// the same command.
const OpenBaoWaitForSealKey = `while [ ! -s /openbao/seal/` + SealKeyFile + ` ]; do sleep 1; done; ` +
	`BAO_SEAL_KEY=$(base64 -w0 /openbao/seal/` + SealKeyFile + `) exec docker-entrypoint.sh server`

// OpenBaoConfigFile is the OpenBao config the compose stack ships, which
// the static-seal tests run OpenBao with, so the two cannot drift.
const OpenBaoConfigFile = "deploy/openbao/openbao.hcl"

// OpenBao is an OpenBao container a test runs.
type OpenBao struct {
	// Address is OpenBao's URL from the host, such as http://127.0.0.1:41235.
	Address string
	// RootToken is the dev-mode root token; empty for a static-seal OpenBao
	// until the test learns it from tc init.
	RootToken string
	t         *testing.T
	docker    string
	id        string
}

// dockerOrSkip returns the docker binary, or skips the test when there is
// none, unless TC_REQUIRE_OPENBAO is set, as it is in CI, in which case it
// fails.
func dockerOrSkip(t *testing.T) string {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		if os.Getenv("TC_REQUIRE_OPENBAO") != "" {
			t.Fatal("TC_REQUIRE_OPENBAO is set but docker is not on PATH")
		}
		t.Skip("no docker on PATH; the test needs an OpenBao container")
	}
	return docker
}

// StartOpenBao runs OpenBao with the static seal, reading its key from
// sealDir, which it waits for as the compose file's OpenBao does. sealDir
// must be absolute. The container is removed when the test ends.
func StartOpenBao(t *testing.T, sealDir string) *OpenBao {
	t.Helper()
	docker := dockerOrSkip(t)
	configDir := t.TempDir()
	if err := os.Chmod(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	shipped, err := os.ReadFile(filepath.Join(repoRoot, OpenBaoConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "openbao.hcl"), shipped, 0o644); err != nil {
		t.Fatal(err)
	}
	return runOpenBao(t, docker, "",
		"--env", "SKIP_CHOWN=1",
		"--volume", configDir+":/openbao/config:ro",
		"--volume", sealDir+":/openbao/seal:ro",
		OpenBaoImage, "sh", "-c", OpenBaoWaitForSealKey)
}

// StartDevOpenBao runs OpenBao in in-memory dev mode with a random root
// token, as deploy/compose.dev.yaml does.
func StartDevOpenBao(t *testing.T) *OpenBao {
	t.Helper()
	docker := dockerOrSkip(t)
	token := "root-" + hex.EncodeToString(randomBytes(t, 8))
	b := runOpenBao(t, docker, token,
		"--env", "BAO_DEV_ROOT_TOKEN_ID="+token,
		"--env", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		OpenBaoImage, "server", "-dev")
	b.WaitReachable()
	return b
}

func runOpenBao(t *testing.T, docker, rootToken string, args ...string) *OpenBao {
	t.Helper()
	// A fixed port, so the address in a config file survives a restart.
	address := fmt.Sprintf("127.0.0.1:%d", FreePort(t))
	// Only stdout holds the container ID; a pull, when the image is not
	// present, reports on stderr.
	var stderr strings.Builder
	run := exec.Command(docker, append([]string{"run", "--detach", "--rm", "--cap-add=IPC_LOCK",
		"--publish", address + ":8200"}, args...)...)
	run.Stderr = &stderr
	out, err := run.Output()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", OpenBaoImage, err, stderr.String())
	}
	b := &OpenBao{Address: "http://" + address, RootToken: rootToken, t: t, docker: docker, id: strings.TrimSpace(string(out))}
	t.Cleanup(func() {
		if out, err := exec.Command(docker, "rm", "--force", b.id).CombinedOutput(); err != nil {
			t.Logf("docker rm: %v\n%s", err, out)
		}
	})
	return b
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// Logs returns the container's output so far.
func (b *OpenBao) Logs() string {
	out, _ := exec.Command(b.docker, "logs", b.id).CombinedOutput()
	return string(out)
}

// Restart restarts the container, as a host reboot would, and waits for
// OpenBao to answer again.
func (b *OpenBao) Restart() {
	b.t.Helper()
	if out, err := exec.Command(b.docker, "restart", b.id).CombinedOutput(); err != nil {
		b.t.Fatalf("docker restart: %v\n%s", err, out)
	}
	b.WaitReachable()
}

// WaitReachable waits until OpenBao answers sys/health, whatever it says.
func (b *OpenBao) WaitReachable() {
	b.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if status, _ := b.Call("", http.MethodGet, "sys/health?uninitcode=200&sealedcode=200", nil); status == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("OpenBao at %s did not answer\n%s", b.Address, b.Logs())
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Health reports whether OpenBao is initialized and whether it is sealed.
func (b *OpenBao) Health() (initialized, sealed bool) {
	b.t.Helper()
	status, body := b.Call("", http.MethodGet, "sys/health?uninitcode=200&sealedcode=200", nil)
	if status != http.StatusOK {
		b.t.Fatalf("sys/health: status %d: %v", status, body)
	}
	initialized, _ = body["initialized"].(bool)
	sealed, _ = body["sealed"].(bool)
	return initialized, sealed
}

// Call makes one API call with token and returns the status and the decoded
// body, if any. A status of 0 means OpenBao did not answer.
func (b *OpenBao) Call(token, method, path string, body any) (int, map[string]any) {
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
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

// Must makes a call with token that must return one of the given statuses.
func (b *OpenBao) Must(token, method, path string, body any, ok ...int) map[string]any {
	b.t.Helper()
	status, decoded := b.Call(token, method, path, body)
	for _, want := range ok {
		if status == want {
			return decoded
		}
	}
	b.t.Fatalf("%s %s: status %d, want %v: %v", method, path, status, ok, decoded)
	return nil
}

// KVField returns the string field of the KV v2 record at path under the
// secret/ mount, or "" when the record or field is absent.
func (b *OpenBao) KVField(token, path, field string) string {
	b.t.Helper()
	status, body := b.Call(token, http.MethodGet, "secret/data/"+path, nil)
	if status == http.StatusNotFound {
		return ""
	}
	if status != http.StatusOK {
		b.t.Fatalf("read secret/data/%s: status %d: %v", path, status, body)
	}
	data, _ := body["data"].(map[string]any)
	fields, _ := data["data"].(map[string]any)
	value, _ := fields[field].(string)
	return value
}

// PutKV writes fields as the KV v2 record at path under the secret/ mount.
func (b *OpenBao) PutKV(token, path string, fields map[string]any) {
	b.t.Helper()
	b.Must(token, http.MethodPost, "secret/data/"+path, map[string]any{"data": fields}, http.StatusOK)
}

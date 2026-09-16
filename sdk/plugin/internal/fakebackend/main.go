// Command fakebackend is a fake Backend Plugin for TrustedCourier's own
// tests: the conformance kit's, and the Seam 1 process harness's.
//
// Its behavior is fixed at build time, so each variant has its own SHA-256:
//
//	go build -ldflags "-X main.mode=crash" ./internal/fakebackend
//
// Modes: "" is a well-behaved Backend built on the SDK; "unhealthy" is the
// same but reports itself unhealthy; "readonly" is the same but cannot store
// Courier Keys; "crash" exits before the handshake; "malformed" bypasses the
// SDK, breaks the protocol contract in every response, and writes a forged
// log line; "nofips" bypasses the SDK and reports itself outside FIPS
// 140-3 mode whatever mode it runs in, as a plugin built without the SDK
// or on an old one would; "fipson" likewise reports FIPS mode "on", never
// "only". label, when set, appears in the health detail.
//
// When a file named after the binary plus ".secrets.json" exists, Get serves
// the JSON object of locations to values in it instead of the built-in
// Secrets, and WriteCourierKey stores into that file, so a test can see what
// TrustedCourier stored and a restarted server finds it again.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/potto007/TrustedCourier/sdk/plugin"
	"github.com/potto007/TrustedCourier/sdk/plugin/protocol"
)

var (
	mode  string
	label string
)

func main() {
	switch mode {
	case "", "unhealthy", "readonly":
		plugin.Serve(newBackend())
	case "crash":
		fmt.Fprintln(os.Stderr, "fakebackend: crashing on purpose")
		os.Exit(3)
	case "malformed":
		// A log line whose message tries to forge a second server log line
		// and drive the terminal with an 8-bit CSI.
		fmt.Fprintln(os.Stderr, `{"@level":"error","@message":"ok\n[FORGED] admin: forged entry \u009b2J"}`)
		protocol.Serve(malformedBackend{})
	case "nofips":
		protocol.Serve(noFIPSBackend{})
	case "fipson":
		protocol.Serve(noFIPSBackend{claimOn: true})
	default:
		fmt.Fprintf(os.Stderr, "fakebackend: unknown mode %q\n", mode)
		os.Exit(2)
	}
}

// Secrets the fake Backend holds at start.
var Secrets = map[string]string{
	"kv/openai": "test-value-1",
	"kv/github": "test-value-2",
	// Non-ASCII, with a multi-byte character across its midpoint.
	"kv/üabc": "test-value-3",
	// The audit signing key the e2e harness configures.
	"courier/audit-signing-key": auditSigningKey(),
}

// auditSigningKey is a test-only Ed25519 key as PKCS #8 PEM, derived from a
// fixed seed so the e2e harness can derive the same key. The harness keeps a
// copy of this derivation.
func auditSigningKey() string {
	seed := sha256.Sum256([]byte("TrustedCourier fake audit signing key"))
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

type backend struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

func newBackend() *backend {
	b := &backend{secrets: map[string][]byte{}}
	for loc, v := range Secrets {
		b.secrets[loc] = []byte(v)
	}
	return b
}

func (b *backend) Get(_ context.Context, location string) ([]byte, error) {
	if secrets, err := secretsFile(); err != nil {
		return nil, err
	} else if secrets != nil {
		v, ok := secrets[location]
		if !ok {
			return nil, plugin.ErrNotFound
		}
		return []byte(v), nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.secrets[location]
	if !ok {
		return nil, plugin.ErrNotFound
	}
	return slices.Clone(v), nil
}

// secretsFile returns the Secrets in <executable>.secrets.json, read afresh
// on every call so tests can rotate a Secret, or nil when there is no such
// file.
func secretsFile() (map[string]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(exe + ".secrets.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	secrets := map[string]string{}
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func (b *backend) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var locs []string
	for loc := range b.secrets {
		if strings.HasPrefix(loc, prefix) {
			locs = append(locs, loc)
		}
	}
	slices.Sort(locs)
	return locs, nil
}

// Health reports the process's user so tests can see which OS user the
// core ran the plugin as.
func (b *backend) Health(context.Context) (string, error) {
	detail := fmt.Sprintf("fake Backend, uid=%d gid=%d", os.Getuid(), os.Getgid())
	if label != "" {
		detail += ", " + label
	}
	if mode == "unhealthy" {
		return detail, errors.New("Backend sealed")
	}
	return detail, nil
}

func (b *backend) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{CourierKeyWrite: mode != "readonly"}
}

func (b *backend) WriteCourierKey(_ context.Context, location string, value []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if secrets, err := secretsFile(); err != nil {
		return err
	} else if secrets != nil {
		secrets[location] = string(value)
		return writeSecretsFile(secrets)
	}
	b.secrets[location] = slices.Clone(value)
	return nil
}

// writeSecretsFile replaces <executable>.secrets.json with secrets.
func writeSecretsFile(secrets map[string]string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	tmp := exe + ".secrets.json.write"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, exe+".secrets.json")
}

// malformedBackend answers every call with a response that breaks the
// protocol contract, as a compromised or buggy plugin might.
type malformedBackend struct {
	protocol.UnimplementedBackendServer
}

// Capabilities reports the process's real FIPS mode, so a core in FIPS mode
// admits the plugin and the malformed responses are what it sees.
func (malformedBackend) Capabilities(context.Context, *protocol.CapabilitiesRequest) (*protocol.CapabilitiesResponse, error) {
	return &protocol.CapabilitiesResponse{
		Fips140Enabled: fips140.Enabled(),
		Fips140Only:    fips140.Enforced(),
		Fips140Version: fips140.Version(),
	}, nil
}

func (malformedBackend) Health(context.Context, *protocol.HealthRequest) (*protocol.HealthResponse, error) {
	return &protocol.HealthResponse{Healthy: true, Detail: "\x1b[2Jall good\x07"}, nil
}

func (malformedBackend) Get(context.Context, *protocol.GetRequest) (*protocol.GetResponse, error) {
	return &protocol.GetResponse{}, nil
}

func (malformedBackend) List(context.Context, *protocol.ListRequest) (*protocol.ListResponse, error) {
	return &protocol.ListResponse{Locations: []string{"\x00", "elsewhere/secret", "elsewhere/secret"}}, nil
}

// noFIPSBackend is well formed but reports a fixed FIPS 140-3 state
// whatever mode its process runs in: "off" in the nofips mode, "on" (never
// "only") in the fipson mode.
type noFIPSBackend struct {
	protocol.UnimplementedBackendServer
	claimOn bool
}

func (b noFIPSBackend) Capabilities(context.Context, *protocol.CapabilitiesRequest) (*protocol.CapabilitiesResponse, error) {
	return &protocol.CapabilitiesResponse{Fips140Enabled: b.claimOn, Fips140Version: "latest"}, nil
}

func (noFIPSBackend) Health(context.Context, *protocol.HealthRequest) (*protocol.HealthResponse, error) {
	return &protocol.HealthResponse{Healthy: true, Detail: "fake Backend with a fixed FIPS mode"}, nil
}

package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/access"
	"github.com/potto007/TrustedCourier/internal/bootstrap"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/pemkey"
	"github.com/potto007/TrustedCourier/internal/pluginhost"
	"github.com/potto007/TrustedCourier/internal/store"
	"github.com/potto007/TrustedCourier/sdk/plugin"
)

// Environment variables tc init reads for a root token.
const (
	// devRootTokenEnv is the dev-mode root token, the variable OpenBao's
	// own dev server takes, so a compose file sets it once for both.
	devRootTokenEnv = "BAO_DEV_ROOT_TOKEN_ID"
	// rootTokenEnv lets tc init finish setting up an OpenBao that is
	// already initialized, after an earlier run stopped part way.
	rootTokenEnv = "BAO_TOKEN"
)

// initOptions are tc init's flags.
type initOptions struct {
	configPath, sealKeyFile, backend string
	dev                              bool
	recoveryShares, recoveryThresh   int
	pluginTokenTTL, wait             time.Duration
}

// initCommand runs tc init: it bootstraps the bundled OpenBao with the
// static seal (ADR-0008), issues the OpenBao Backend Plugin its token,
// stores the audit signing key, and creates the Operator Credential. What
// it shows, it shows once; TrustedCourier keeps none of it (ADR-0001).
func initCommand(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("init")
	var o initOptions
	fs.StringVar(&o.configPath, "config", "", "config file path")
	fs.StringVar(&o.sealKeyFile, "seal-key-file", "", "the static seal key file OpenBao reads; created when absent")
	fs.StringVar(&o.backend, "backend", "", "the OpenBao Backend Plugin's name, when several set BAO_ADDR")
	fs.BoolVar(&o.dev, "dev", false, "OpenBao runs in dev mode; its root token is in "+devRootTokenEnv)
	fs.IntVar(&o.recoveryShares, "recovery-shares", 5, "recovery key shares")
	fs.IntVar(&o.recoveryThresh, "recovery-threshold", 3, "recovery key shares needed")
	fs.DurationVar(&o.pluginTokenTTL, "plugin-token-ttl", 8760*time.Hour, "the Backend Plugin token's lifetime; OpenBao caps it at its maximum lease")
	fs.DurationVar(&o.wait, "wait", 2*time.Minute, "how long to wait for OpenBao to answer")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	switch {
	case fs.NArg() > 0:
		return fmt.Errorf("%w: init: unexpected argument %q", errUsage, fs.Arg(0))
	case o.configPath == "":
		return fmt.Errorf("%w: init: --config is required", errUsage)
	case o.dev && o.sealKeyFile != "":
		return fmt.Errorf("%w: init: --dev runs OpenBao without a seal; drop --seal-key-file", errUsage)
	case !o.dev && o.sealKeyFile == "":
		return fmt.Errorf("%w: init: --seal-key-file is required: the static seal key OpenBao reads (or --dev for an in-memory OpenBao)", errUsage)
	case o.recoveryShares < 1 || o.recoveryThresh < 1 || o.recoveryThresh > o.recoveryShares:
		return fmt.Errorf("%w: init: --recovery-threshold must be between 1 and --recovery-shares", errUsage)
	}
	ctx := context.Background()
	return (&initializer{o: o, stdout: stdout, stderr: stderr}).run(ctx)
}

type initializer struct {
	o      initOptions
	stdout io.Writer
	stderr io.Writer
	cfg    *config.Config
	plugin config.BackendPlugin
	// env is the plugin's BAO_* settings.
	env map[string]string
}

func (in *initializer) run(ctx context.Context) error {
	cfg, err := config.Load(in.o.configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	in.cfg = cfg
	if err := in.selectPlugin(); err != nil {
		return err
	}
	tokenFile := in.env["BAO_TOKEN_FILE"]
	if tokenFile == "" {
		return fmt.Errorf("Backend Plugin %q sets no BAO_TOKEN_FILE; tc init writes the plugin's token there", in.plugin.Name)
	}
	// Nothing is touched until the plugin can be run as configured: its
	// binary matches the pinned SHA-256 and its user is separate.
	log := slog.New(slog.NewTextHandler(in.stderr, nil))
	host, err := pluginhost.New(cfg, in.stderr, log)
	if err != nil {
		return err
	}
	client, err := bootstrap.NewClient(in.env["BAO_ADDR"], in.env["BAO_CACERT"])
	if err != nil {
		return err
	}

	var sealKey []byte
	var sealKeyCreated bool
	if !in.o.dev {
		if sealKey, sealKeyCreated, err = bootstrap.EnsureSealKey(in.o.sealKeyFile); err != nil {
			return err
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, in.o.wait)
	health, err := client.WaitHealth(waitCtx, func(err error) {
		fmt.Fprintf(in.stderr, "Waiting for OpenBao at %s (%v)", client.Address, err)
		if sealKeyCreated {
			fmt.Fprintf(in.stderr, "; start it now, with the seal key at %s", in.o.sealKeyFile)
		}
		fmt.Fprintln(in.stderr)
	})
	cancel()
	if err != nil {
		// The key file stays: an OpenBao that is starting slowly may have
		// read it already, and the next tc init reuses it.
		if sealKeyCreated {
			return fmt.Errorf("%w; the seal key written to %s is kept for the next run", err, in.o.sealKeyFile)
		}
		return err
	}

	switch {
	case in.o.dev:
		client.Token = os.Getenv(devRootTokenEnv)
		if client.Token == "" {
			return fmt.Errorf("--dev needs OpenBao's dev root token in %s", devRootTokenEnv)
		}
		if !health.Initialized || health.Sealed {
			return fmt.Errorf("OpenBao at %s is not an initialized, unsealed dev server (initialized=%v sealed=%v)", client.Address, health.Initialized, health.Sealed)
		}
	case health.Initialized:
		// The key file is never removed: an OpenBao that just booted may
		// hold it, and a restart would wait for it.
		if health.Sealed {
			if sealKeyCreated {
				return fmt.Errorf("OpenBao at %s is initialized but sealed: it was initialized with another seal key than the one just written to %s. Restore the key it was initialized with there, and remove this one", client.Address, in.o.sealKeyFile)
			}
			return fmt.Errorf("OpenBao at %s is initialized but sealed: the seal key at %s is not the one it was initialized with", client.Address, in.o.sealKeyFile)
		}
		client.Token = os.Getenv(rootTokenEnv)
		if client.Token == "" {
			return fmt.Errorf("OpenBao at %s is already initialized; tc init initializes it once. To finish setting TrustedCourier up against it, rerun with a root token in %s", client.Address, rootTokenEnv)
		}
		fmt.Fprintf(in.stdout, "OpenBao at %s is already initialized; continuing with the token in %s.\n\n", client.Address, rootTokenEnv)
	default:
		// Show the seal key before anything that can still fail: OpenBao
		// cannot start without it, and TrustedCourier does not keep it.
		fmt.Fprintf(in.stdout, "Static seal key (base64 of %s; back it up, OpenBao cannot start without it; TrustedCourier does not keep it):\n%s\n\n",
			in.o.sealKeyFile, base64.StdEncoding.EncodeToString(sealKey))
		result, err := client.Init(ctx, in.o.recoveryShares, in.o.recoveryThresh)
		if err != nil {
			return fmt.Errorf("initialize OpenBao at %s: %w", client.Address, err)
		}
		client.Token = result.RootToken
		fmt.Fprintf(in.stdout, "OpenBao at %s initialized with the static seal.\n\n", client.Address)
		fmt.Fprintf(in.stdout, "Recovery keys (any %d of the %d regenerate the root token; shown once, TrustedCourier does not keep them):\n%s\n\n",
			in.o.recoveryThresh, in.o.recoveryShares, strings.Join(result.RecoveryKeys, "\n"))
		fmt.Fprintf(in.stdout, "Root token (shown once, TrustedCourier does not keep it; store Secrets with it, then keep it offline):\n%s\n\n", result.RootToken)
	}

	if err := in.setUpPlugin(ctx, client, host, tokenFile); err != nil {
		return err
	}
	return in.operatorCredential(ctx)
}

// selectPlugin picks the OpenBao Backend Plugin: the one whose env sets
// BAO_ADDR, or the one --backend names.
func (in *initializer) selectPlugin() error {
	var candidates []string
	for name, pc := range in.cfg.BackendPlugins {
		if _, ok := pluginEnv(pc)["BAO_ADDR"]; ok {
			candidates = append(candidates, name)
		}
	}
	name := in.o.backend
	switch {
	case name != "":
		if _, ok := in.cfg.BackendPlugins[name]; !ok {
			return fmt.Errorf("--backend %q is not in backend_plugins", name)
		}
	case len(candidates) == 0:
		return errors.New("no Backend Plugin sets BAO_ADDR in its env; tc init needs the OpenBao Backend Plugin in backend_plugins")
	case len(candidates) > 1:
		return fmt.Errorf("Backend Plugins %s all set BAO_ADDR; pick one with --backend", strings.Join(candidates, ", "))
	default:
		name = candidates[0]
	}
	in.plugin = in.cfg.BackendPlugins[name]
	in.env = pluginEnv(in.plugin)
	if in.env["BAO_ADDR"] == "" {
		return fmt.Errorf("Backend Plugin %q sets no BAO_ADDR", name)
	}
	return nil
}

func pluginEnv(pc config.BackendPlugin) map[string]string {
	env := make(map[string]string, len(pc.Env))
	for _, entry := range pc.Env {
		name, value, _ := strings.Cut(entry, "=")
		env[name] = value
	}
	return env
}

// setUpPlugin gives the Backend Plugin what it needs in OpenBao and on
// disk, then runs it once to store the audit signing key through it.
func (in *initializer) setUpPlugin(ctx context.Context, client *bootstrap.Client, host *pluginhost.Host, tokenFile string) error {
	created, err := client.EnsureKVMount(ctx)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(in.stdout, "KV v2 secrets engine mounted at %s/.\n", bootstrap.KVMount)
	}
	if err := client.WritePluginPolicy(ctx); err != nil {
		return err
	}
	// A rerun keeps a token that still works rather than leaving a live one
	// behind unrecorded.
	if existing, err := os.ReadFile(tokenFile); err == nil {
		if ttl, err := client.CheckPluginToken(ctx, strings.TrimSpace(string(existing))); err == nil {
			fmt.Fprintf(in.stdout, "Backend Plugin %s: token in %s kept (%s).\n", in.plugin.Name, tokenFile, tokenExpiry(ttl))
			return in.runPlugin(ctx, host)
		}
	}
	token, err := client.CreatePluginToken(ctx, in.o.pluginTokenTTL)
	if err != nil {
		return fmt.Errorf("issue the Backend Plugin's token: %w", err)
	}
	if err := writeTokenFile(tokenFile, token.Token, in.plugin); err != nil {
		return err
	}
	fmt.Fprintf(in.stdout, "Backend Plugin %s: token with policy %s written to %s (%s).\n", in.plugin.Name, bootstrap.PolicyName, tokenFile, tokenExpiry(token.TTL))
	return in.runPlugin(ctx, host)
}

func tokenExpiry(ttl time.Duration) string {
	if ttl <= 0 {
		return "does not expire"
	}
	return fmt.Sprintf("expires %s; the plugin does not renew it", time.Now().Add(ttl).UTC().Format(time.RFC3339))
}

// writeTokenFile writes token to path, readable by the plugin's user only.
// The file is created, never reused, and handed over by descriptor, so a
// plugin user who owns the directory cannot redirect the write.
func writeTokenFile(path, token string, pc config.BackendPlugin) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create the token file's directory: %w", err)
	}
	tmp := path + ".new"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear the Backend Plugin's stale token file: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write the Backend Plugin's token file: %w", err)
	}
	err = func() error {
		if _, err := f.WriteString(token + "\n"); err != nil {
			return err
		}
		if err := f.Chmod(0o600); err != nil {
			return err
		}
		if err := pluginhost.GiveFile(f, pc); err != nil {
			return err
		}
		return f.Sync()
	}()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write the Backend Plugin's token file: %w", err)
	}
	return nil
}

// runPlugin runs the Backend Plugin once, as the server will, proving it
// launches and reaches its Backend with the token, and stores the audit
// signing key through it when the config keeps that key there.
func (in *initializer) runPlugin(ctx context.Context, host *pluginhost.Host) error {
	pluginCtx, stop := context.WithCancel(ctx)
	defer host.Wait()
	defer stop()
	host.Start(pluginCtx)
	name := in.plugin.Name
	deadline := time.Now().Add(30 * time.Second)
	for {
		var status pluginhost.Status
		for _, s := range host.Status(ctx) {
			if s.Name == name {
				status = s
			}
		}
		if status.State == pluginhost.StateRunning && status.Healthy {
			break
		}
		if status.State == pluginhost.StateRefused || time.Now().After(deadline) {
			return fmt.Errorf("Backend Plugin %s is %s and not healthy: %s", name, status.State, status.Detail)
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Fprintf(in.stdout, "Backend Plugin %s: launched and healthy.\n", name)
	key := in.cfg.Audit.SigningKey
	if key == nil || key.Backend != name {
		return nil
	}
	return in.storeSigningKey(ctx, host, *key)
}

// storeSigningKey stores a new Ed25519 audit signing key at key through the
// running Backend Plugin, unless one is there.
func (in *initializer) storeSigningKey(ctx context.Context, host *pluginhost.Host, key config.CourierKey) error {
	existing, err := host.Get(ctx, key.Backend, key.Location)
	switch {
	case err == nil:
		existing.Release()
		fmt.Fprintf(in.stdout, "Audit signing key: kept at %s.\n", key.Location)
		return nil
	case !errors.Is(err, plugin.ErrNotFound):
		return fmt.Errorf("read the audit signing key at %s: %w", key.Location, err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pem, err := pemkey.MarshalSigner(private)
	if err != nil {
		return err
	}
	if err := host.WriteCourierKey(ctx, key.Backend, key.Location, pem); err != nil {
		return fmt.Errorf("store the audit signing key at %s: %w", key.Location, err)
	}
	stored, err := host.Get(ctx, key.Backend, key.Location)
	if err != nil {
		return fmt.Errorf("read back the audit signing key at %s: %w", key.Location, err)
	}
	stored.Release()
	fmt.Fprintf(in.stdout, "Audit signing key: generated and stored at %s.\n", key.Location)
	return nil
}

// operatorCredential creates the Operator Credential unless the server or
// an earlier tc init did, and shows it once.
func (in *initializer) operatorCredential(ctx context.Context) error {
	db, err := store.Open(ctx, in.cfg.DataDir)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = db.Close() }()
	shown := false
	err = access.New(db, config.NewRunning(in.cfg)).EnsureOperatorCredential(ctx, func(credential string) error {
		shown = true
		_, err := fmt.Fprintf(in.stdout, "\nOperator Credential (shown once; store it now, it cannot be shown again):\n%s\n", credential)
		return err
	})
	if err != nil {
		return err
	}
	if !shown {
		fmt.Fprintln(in.stdout, "\nOperator Credential: already created; it was shown when it was.")
	}
	return nil
}

// Package cli implements the tc command line.
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/potto007/TrustedCourier/internal/admin"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/harden"
	"github.com/potto007/TrustedCourier/internal/pluginhost"
	"github.com/potto007/TrustedCourier/internal/server"
)

const usage = `Usage:
  tc server run --config <path>
  tc token issue --policy <name> [--policy <name>...] (--expires-in <lifetime> | --expires-at <RFC 3339>) [--json]
  tc token list [--json]
  tc token revoke <id>
  tc env <secret-name> [--upstream <name>] [--json]
  tc reload [--json]
  tc status [--json]
  tc audit verify [--json]
  tc plugin sha256 <path>

Environment:
  TC_ADMIN_SOCKET         admin socket path (default ` + config.DefaultAdminSocket + `)
  TC_OPERATOR_CREDENTIAL  Operator Credential for admin commands
  TC_ADMIN_URL            remote admin listener, https://host:port, instead of the socket
  TC_ADMIN_CLIENT_CERT    client certificate PEM file for TC_ADMIN_URL
  TC_ADMIN_CLIENT_KEY     its private key PEM file
  TC_ADMIN_CA_BUNDLE      CA PEM file that verifies TC_ADMIN_URL (default: system roots)
`

// errUsage reports a command line the user must fix.
var errUsage = errors.New("usage")

// Main runs tc with args (without the program name) and returns the exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	// Every tc process may hold a Secret or a credential: the server holds
	// Secrets, tc env prints them, and the other commands carry the Operator
	// Credential. None of them may ever write a core dump (ADR-0001).
	err := harden.DisableCoreDumps()
	if err != nil {
		err = fmt.Errorf("disable core dumps: %w", err)
	} else {
		err = run(args, stdout, stderr)
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(stdout, usage)
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "tc: %v\n\n%s", err, usage)
		return 2
	default:
		fmt.Fprintf(stderr, "tc: %v\n", err)
		return 1
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && slices.Contains([]string{"-h", "--help", "help"}, args[0]) {
		return flag.ErrHelp
	}
	if len(args) >= 1 && args[0] == "status" {
		return status(args[1:], stdout)
	}
	if len(args) >= 1 && args[0] == "env" {
		return env(args[1:], stdout)
	}
	if len(args) >= 1 && args[0] == "reload" {
		return reload(args[1:], stdout)
	}
	if len(args) < 2 {
		return fmt.Errorf("%w: missing command", errUsage)
	}
	cmd, rest := args[0]+" "+args[1], args[2:]
	switch cmd {
	case "audit verify":
		return auditVerify(rest, stdout)
	case "plugin sha256":
		return pluginSHA256(rest, stdout)
	case "server run":
		return serverRun(rest, stdout, stderr)
	case "token issue":
		return tokenIssue(rest, stdout)
	case "token list":
		return tokenList(rest, stdout)
	case "token revoke":
		return tokenRevoke(rest, stdout)
	default:
		return fmt.Errorf("%w: unknown command %q", errUsage, cmd)
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %s: %v", errUsage, fs.Name(), err)
	}
	return nil
}

func serverRun(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("server run")
	configPath := fs.String("config", "", "config file path")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: server run: unexpected argument %q", errUsage, fs.Arg(0))
	}
	if *configPath == "" {
		return fmt.Errorf("%w: server run: --config is required", errUsage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, *configPath, stdout, stderr)
}

// adminClient returns a client for the admin API: the remote admin listener
// when TC_ADMIN_URL is set, otherwise the admin socket.
func adminClient() (*admin.Client, error) {
	credential := os.Getenv("TC_OPERATOR_CREDENTIAL")
	if credential == "" {
		return nil, errors.New("TC_OPERATOR_CREDENTIAL is not set; admin commands require the Operator Credential")
	}
	if remote := os.Getenv("TC_ADMIN_URL"); remote != "" {
		return remoteAdminClient(remote, credential)
	}
	socket := os.Getenv("TC_ADMIN_SOCKET")
	if socket == "" {
		socket = config.DefaultAdminSocket
	}
	return admin.NewClient(socket, credential), nil
}

func remoteAdminClient(remote, credential string) (*admin.Client, error) {
	certFile, keyFile := os.Getenv("TC_ADMIN_CLIENT_CERT"), os.Getenv("TC_ADMIN_CLIENT_KEY")
	switch {
	case certFile == "" && keyFile == "":
		return nil, errors.New("TC_ADMIN_URL is set but TC_ADMIN_CLIENT_CERT and TC_ADMIN_CLIENT_KEY are not; the remote admin listener requires a client certificate")
	case certFile == "":
		return nil, errors.New("TC_ADMIN_CLIENT_KEY is set but TC_ADMIN_CLIENT_CERT is not")
	case keyFile == "":
		return nil, errors.New("TC_ADMIN_CLIENT_CERT is set but TC_ADMIN_CLIENT_KEY is not")
	}
	client, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load the client certificate from TC_ADMIN_CLIENT_CERT and TC_ADMIN_CLIENT_KEY: %w", err)
	}
	var rootCAs *x509.CertPool
	if bundle := os.Getenv("TC_ADMIN_CA_BUNDLE"); bundle != "" {
		if rootCAs, err = config.LoadCABundle(bundle); err != nil {
			return nil, fmt.Errorf("TC_ADMIN_CA_BUNDLE: %w", err)
		}
	}
	return admin.NewRemoteClient(remote, client, rootCAs, credential)
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func tokenIssue(args []string, stdout io.Writer) error {
	fs := newFlagSet("token issue")
	var policies stringList
	fs.Var(&policies, "policy", "Policy name to attach (repeatable)")
	expiresIn := fs.String("expires-in", "", "lifetime, such as 12h or 30d")
	expiresAt := fs.String("expires-at", "", "expiry as an RFC 3339 timestamp")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: token issue: unexpected argument %q", errUsage, fs.Arg(0))
	}
	if len(policies) == 0 {
		return fmt.Errorf("%w: token issue: at least one --policy is required", errUsage)
	}
	expiry, err := parseExpiry(*expiresIn, *expiresAt, time.Now())
	if err != nil {
		return err
	}

	client, err := adminClient()
	if err != nil {
		return err
	}
	issued, err := client.IssueAgentToken(context.Background(), admin.IssueAgentTokenRequest{
		Policies:  policies,
		ExpiresAt: expiry,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, issued)
	}
	fmt.Fprintf(stdout, "Agent Token (shown once; store it now, it cannot be shown again):\n%s\n\n", issued.Token)
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "ID:\t%s\n", issued.ID)
	fmt.Fprintf(tw, "Policies:\t%s\n", strings.Join(issued.Policies, ", "))
	fmt.Fprintf(tw, "Expires:\t%s\n", issued.ExpiresAt.Format(time.RFC3339))
	return tw.Flush()
}

// parseExpiry turns exactly one of --expires-in and --expires-at into an
// absolute expiry.
func parseExpiry(expiresIn, expiresAt string, now time.Time) (time.Time, error) {
	switch {
	case expiresIn == "" && expiresAt == "":
		return time.Time{}, fmt.Errorf("%w: token issue: an expiry is required (--expires-in or --expires-at)", errUsage)
	case expiresIn != "" && expiresAt != "":
		return time.Time{}, fmt.Errorf("%w: token issue: use only one of --expires-in and --expires-at", errUsage)
	case expiresAt != "":
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: token issue: --expires-at: %v", errUsage, err)
		}
		return t, nil
	}
	d, err := parseLifetime(expiresIn)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: token issue: --expires-in: %v", errUsage, err)
	}
	return now.Add(d), nil
}

// parseLifetime accepts Go durations plus whole days, such as 30d.
func parseLifetime(s string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid lifetime %q", s)
		}
		if n > int64(math.MaxInt64/(24*time.Hour)) {
			return 0, fmt.Errorf("lifetime %q is too long", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid lifetime %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("lifetime %q must be positive", s)
	}
	return d, nil
}

func tokenList(args []string, stdout io.Writer) error {
	fs := newFlagSet("token list")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: token list: unexpected argument %q", errUsage, fs.Arg(0))
	}
	client, err := adminClient()
	if err != nil {
		return err
	}
	tokens, err := client.ListAgentTokens(context.Background())
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, tokens)
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPOLICIES\tEXPIRES\tLAST USED\tSTATUS")
	for _, t := range tokens {
		lastUsed := "never"
		if t.LastUsedAt != nil {
			lastUsed = t.LastUsedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			t.ID, strings.Join(t.Policies, ","), t.ExpiresAt.Format(time.RFC3339), lastUsed, t.Status)
	}
	return tw.Flush()
}

func tokenRevoke(args []string, stdout io.Writer) error {
	fs := newFlagSet("token revoke")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: token revoke: exactly one Agent Token ID is required", errUsage)
	}
	client, err := adminClient()
	if err != nil {
		return err
	}
	id := fs.Arg(0)
	if err := client.RevokeAgentToken(context.Background(), id); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Agent Token %s revoked\n", id)
	return nil
}

func status(args []string, stdout io.Writer) error {
	fs := newFlagSet("status")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: status: unexpected argument %q", errUsage, fs.Arg(0))
	}
	client, err := adminClient()
	if err != nil {
		return err
	}
	st, err := client.Status(context.Background())
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, st)
	}
	fmt.Fprintf(stdout, "FIPS 140-3 mode: %s (module %s)\n\n", st.FIPS140.Mode, st.FIPS140.Module)
	if len(st.BackendPlugins) == 0 {
		fmt.Fprintln(stdout, "No Backend Plugins configured.")
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "BACKEND PLUGIN\tSTATE\tHEALTH\tCAPABILITIES\tRESTARTS\tDETAIL")
		for _, p := range st.BackendPlugins {
			health := "unhealthy"
			if p.Healthy {
				health = "healthy"
			}
			caps := strings.Join(p.Capabilities, ",")
			if caps == "" {
				caps = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", p.Name, p.State, health, caps, p.Restarts, p.Detail)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	key := st.AuditSigningKey
	if key.Loaded {
		_, err = fmt.Fprintln(stdout, "\nAudit signing key: loaded")
	} else {
		_, err = fmt.Fprintf(stdout, "\nAudit signing key: not loaded (%s)\n", key.Detail)
	}
	if err != nil {
		return err
	}
	if cert := st.TLSCertificate; cert != nil {
		if cert.Loaded {
			line := "TLS certificate: loaded"
			if cert.NotAfter != "" {
				line += " (expires " + cert.NotAfter
				if cert.RenewAt != "" {
					line += ", renews " + cert.RenewAt
				}
				line += ")"
			}
			if cert.RenewalError != "" {
				line += "; renewal failing: " + cert.RenewalError
			}
			_, err = fmt.Fprintln(stdout, line)
		} else {
			_, err = fmt.Fprintf(stdout, "TLS certificate: not loaded (%s); the Agent API completes no TLS handshake until it is\n", cert.Detail)
		}
		if err != nil {
			return err
		}
	}
	if cert := st.RemoteAdminTLSCertificate; cert != nil {
		if cert.Loaded {
			line := "Remote admin TLS certificate: loaded"
			if cert.NotAfter != "" {
				line += " (expires " + cert.NotAfter + ")"
			}
			_, err = fmt.Fprintln(stdout, line)
		} else {
			_, err = fmt.Fprintf(stdout, "Remote admin TLS certificate: not loaded (%s); the remote admin listener completes no TLS handshake until it is\n", cert.Detail)
		}
		if err != nil {
			return err
		}
	}
	if st.AuditRecords.Pending == 0 {
		return nil
	}
	_, err = fmt.Fprintf(stdout, "Audit Records: %d waiting to be stored; Deliveries are refused (%s)\n",
		st.AuditRecords.Pending, st.AuditRecords.Detail)
	return err
}

// reload has the server reload its config file.
func reload(args []string, stdout io.Writer) error {
	fs := newFlagSet("reload")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: reload: unexpected argument %q", errUsage, fs.Arg(0))
	}
	client, err := adminClient()
	if err != nil {
		return err
	}
	reloaded, err := client.ReloadConfig(context.Background())
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, reloaded)
	}
	_, err = fmt.Fprintf(stdout, "Config reloaded from %s (Policies: %d, Secret Names: %d)\n",
		reloaded.Path, reloaded.Policies, reloaded.SecretNames)
	return err
}

// env prints the environment variables an Agent needs to use a Secret Name
// through Proxy Delivery, one NAME=value per line.
func env(args []string, stdout io.Writer) error {
	fs := newFlagSet("env")
	upstream := fs.String("upstream", "", "Upstream name, when the Secret Name has several")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// Flags may also follow the Secret Name.
	var positional []string
	for fs.NArg() > 0 {
		positional = append(positional, fs.Arg(0))
		if err := parseFlags(fs, fs.Args()[1:]); err != nil {
			return err
		}
	}
	if len(positional) != 1 {
		return fmt.Errorf("%w: env: exactly one Secret Name is required", errUsage)
	}
	client, err := adminClient()
	if err != nil {
		return err
	}
	e, err := client.SecretNameEnv(context.Background(), positional[0], *upstream)
	if err != nil {
		return err
	}
	if *asJSON {
		vars := make(map[string]string, len(e.Env))
		for _, v := range e.Env {
			vars[v.Name] = v.Value
		}
		return writeJSON(stdout, vars)
	}
	for _, v := range e.Env {
		if _, err := fmt.Fprintf(stdout, "%s=%s\n", v.Name, v.Value); err != nil {
			return err
		}
	}
	return nil
}

// errAuditBroken fails tc audit verify after it has reported the break.
var errAuditBroken = errors.New("the audit chain is broken")

func auditVerify(args []string, stdout io.Writer) error {
	fs := newFlagSet("audit verify")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: audit verify: unexpected argument %q", errUsage, fs.Arg(0))
	}
	client, err := adminClient()
	if err != nil {
		return err
	}
	v, err := client.VerifyAudit(context.Background())
	if err != nil {
		return err
	}
	switch {
	case *asJSON:
		err = writeJSON(stdout, v)
	case v.Break == nil:
		_, err = fmt.Fprintf(stdout, "Audit chain intact: %s, %s\n", auditRecords(v.Records), plural(v.Checkpoints, "signed checkpoint"))
	default:
		_, err = fmt.Fprintf(stdout, "Audit chain broken at record %d: %s\n%s before it intact\n",
			v.Break.Seq, v.Break.Problem, auditRecords(v.Records))
	}
	if err != nil {
		return err
	}
	if !v.Intact {
		return errAuditBroken
	}
	return nil
}

func auditRecords(n int64) string { return plural(n, "Audit Record") }

func plural(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func pluginSHA256(args []string, stdout io.Writer) error {
	fs := newFlagSet("plugin sha256")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: plugin sha256: exactly one Backend Plugin binary path is required", errUsage)
	}
	sum, err := pluginhost.FileSHA256(fs.Arg(0))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "sha256: %s\n", sum)
	return err
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

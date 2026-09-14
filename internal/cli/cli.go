// Package cli implements the tc command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/potto007/TrustedCourier/internal/admin"
	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/server"
)

const usage = `Usage:
  tc server run --config <path>
  tc token issue --policy <name> [--policy <name>...] (--expires-in <lifetime> | --expires-at <RFC 3339>) [--json]
  tc token list [--json]

Environment:
  TC_ADMIN_SOCKET         admin socket path (default ` + config.DefaultAdminSocket + `)
  TC_OPERATOR_CREDENTIAL  Operator Credential for admin commands
`

// errUsage reports a command line the user must fix.
var errUsage = errors.New("usage")

// Main runs tc with args (without the program name) and returns the exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	err := run(args, stdout, stderr)
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
	if len(args) < 2 {
		return fmt.Errorf("%w: missing command", errUsage)
	}
	cmd, rest := args[0]+" "+args[1], args[2:]
	switch cmd {
	case "server run":
		return serverRun(rest, stdout, stderr)
	case "token issue":
		return tokenIssue(rest, stdout)
	case "token list":
		return tokenList(rest, stdout)
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
	if *configPath == "" {
		return fmt.Errorf("%w: server run: --config is required", errUsage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, *configPath, stdout, stderr)
}

func adminClient() (*admin.Client, error) {
	credential := os.Getenv("TC_OPERATOR_CREDENTIAL")
	if credential == "" {
		return nil, errors.New("TC_OPERATOR_CREDENTIAL is not set; admin commands require the Operator Credential")
	}
	socket := os.Getenv("TC_ADMIN_SOCKET")
	if socket == "" {
		socket = config.DefaultAdminSocket
	}
	return admin.NewClient(socket, credential), nil
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
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid lifetime %q", s)
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

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

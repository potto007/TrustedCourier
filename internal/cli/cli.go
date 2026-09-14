// Package cli implements the tc command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
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
  tc token list

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

func tokenList(args []string, stdout io.Writer) error {
	fs := newFlagSet("token list")
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
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPOLICIES\tEXPIRES\tLAST USED\tSTATUS")
	now := time.Now()
	for _, t := range tokens {
		lastUsed := "never"
		if t.LastUsedAt != nil {
			lastUsed = t.LastUsedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			t.ID, strings.Join(t.Policies, ","), t.ExpiresAt.Format(time.RFC3339), lastUsed, status(t, now))
	}
	return tw.Flush()
}

func status(t admin.AgentToken, now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case !now.Before(t.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}

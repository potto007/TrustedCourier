package e2e

import (
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

func TestHelpSucceeds(t *testing.T) {
	tc := harness.New(t)
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}} {
		res := tc.TC(nil, args...)
		if res.ExitCode != 0 {
			t.Errorf("tc %v: exit %d\n%s", args, res.ExitCode, res.Stderr)
		}
		if !strings.Contains(res.Stdout, "tc token issue") {
			t.Errorf("tc %v does not print usage:\n%s", args, res.Stdout)
		}
	}
}

func TestUnexpectedArgumentsAreRejected(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	for _, args := range [][]string{
		{"token", "list", "bogus"},
		{"server", "run", "--config", "config.yaml", "bogus"},
	} {
		res := srv.TC(args...)
		if res.ExitCode == 0 {
			t.Errorf("tc %v ignored an unexpected argument; stdout:\n%s", args, res.Stdout)
		}
		if !strings.Contains(res.Stderr, `unexpected argument "bogus"`) {
			t.Errorf("tc %v error does not name the argument:\n%s", args, res.Stderr)
		}
	}
}

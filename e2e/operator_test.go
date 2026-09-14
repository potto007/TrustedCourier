package e2e

import (
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

func TestFirstBootShowsOperatorCredentialOnce(t *testing.T) {
	tc := harness.New(t)

	first := tc.Start(harness.BaseConfig)
	if first.Credential == "" {
		t.Fatalf("first boot did not show an Operator Credential; stdout:\n%s", first.Stdout())
	}
	credential := first.Credential
	first.Stop()

	second := tc.Start(harness.BaseConfig)
	if strings.Contains(second.Stdout(), "tcoc_") {
		t.Fatalf("second boot showed an Operator Credential again; stdout:\n%s", second.Stdout())
	}
	second.Credential = credential
	if res := second.TC("token", "list"); res.ExitCode != 0 {
		t.Fatalf("first-boot credential rejected after restart: exit %d\n%s", res.ExitCode, res.Stderr)
	}
}

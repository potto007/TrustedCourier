package e2e

import (
	"fmt"
	"os"
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

func TestOperatorCredentialIsNotStoredOnDisk(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)
	if res := srv.TC("token", "list"); res.ExitCode != 0 {
		t.Fatalf("token list: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	srv.Stop()

	if tc.FilesContain(srv.Credential) {
		t.Fatal("the Operator Credential value is stored in the data directory")
	}
}

func TestAdminOperationsRequireOperatorCredential(t *testing.T) {
	tc := harness.New(t)
	srv := tc.Start(harness.BaseConfig)

	cases := map[string][]string{
		"missing":             nil,
		"wrong":               {"TC_OPERATOR_CREDENTIAL=tcoc_" + strings.Repeat("a", 52)},
		"agent token instead": {"TC_OPERATOR_CREDENTIAL=tcat_" + strings.Repeat("a", 52)},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			res := tc.TC(env, "token", "list")
			if res.ExitCode == 0 {
				t.Fatalf("token list succeeded without the Operator Credential; stdout:\n%s", res.Stdout)
			}
			if !strings.Contains(res.Stderr, "Operator Credential") {
				t.Fatalf("error does not mention the Operator Credential:\n%s", res.Stderr)
			}
		})
	}

	if res := srv.TC("token", "list"); res.ExitCode != 0 {
		t.Fatalf("token list with the Operator Credential: exit %d\n%s", res.ExitCode, res.Stderr)
	}
}

func TestAdminSocketRejectsOtherLocalUsers(t *testing.T) {
	tc := harness.New(t)
	// Only a different local user may administer this server, so the test
	// process, holding the right Operator Credential, is the other user.
	srv := tc.Start(fmt.Sprintf(`
data_dir: {{.DataDir}}
admin:
  socket: {{.Socket}}
  allowed_uids: [%d]
policies:
  openai-proxy:
    secrets:
      - name: openai
        delivery: [proxy]
`, os.Getuid()+1))

	res := srv.TC("token", "list")
	if res.ExitCode == 0 {
		t.Fatalf("token list succeeded from a local user that is not allowed; stdout:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "not allowed") {
		t.Fatalf("error does not say the user is not allowed:\n%s", res.Stderr)
	}
}

func TestAdminSocketIsOwnerOnly(t *testing.T) {
	tc := harness.New(t)
	tc.Start(harness.BaseConfig)

	info, err := os.Stat(tc.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("admin socket mode is %v, want no group or other access", perm)
	}
}

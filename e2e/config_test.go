package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

func TestInvalidConfigIsRefused(t *testing.T) {
	const header = `
data_dir: {{.DataDir}}
admin:
  socket: {{.Socket}}
`
	cases := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "missing data_dir",
			config:  "admin:\n  socket: {{.Socket}}\n",
			wantErr: "data_dir is required",
		},
		{
			name:    "unknown field",
			config:  header + "polices: {}\n",
			wantErr: "polices",
		},
		{
			name: "unknown Delivery mode",
			config: header + `
policies:
  p:
    secrets:
      - name: openai
        delivery: [fetch]
`,
			wantErr: `Delivery mode "fetch"`,
		},
		{
			name: "no Delivery modes",
			config: header + `
policies:
  p:
    secrets:
      - name: openai
`,
			wantErr: "at least one Delivery mode",
		},
		{
			name: "Policy without Secret Names",
			config: header + `
policies:
  empty: {}
`,
			wantErr: `Policy "empty"`,
		},
		{
			name: "Secret Name missing",
			config: header + `
policies:
  p:
    secrets:
      - delivery: [proxy]
`,
			wantErr: "Secret Name",
		},
		{
			name: "Secret Name listed twice",
			config: header + `
policies:
  p:
    secrets:
      - name: openai
        delivery: [proxy]
      - name: openai
        delivery: [reveal]
`,
			wantErr: `"openai" more than once`,
		},
		{
			name: "Policy defined twice",
			config: header + `
policies:
  p:
    secrets:
      - name: openai
        delivery: [proxy]
  p:
    secrets:
      - name: github
        delivery: [reveal]
`,
			wantErr: `"p" already defined`,
		},
		{
			name: "invalid Policy name",
			config: header + `
policies:
  "bad name":
    secrets:
      - name: openai
        delivery: [proxy]
`,
			wantErr: `invalid Policy name "bad name"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(c.config)
			if code == 0 {
				t.Fatalf("TrustedCourier exited 0 with an invalid config")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
			if _, err := os.Stat(tc.Socket); err == nil {
				t.Fatalf("admin socket exists after refusing the config")
			}
		})
	}
}

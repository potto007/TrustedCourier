package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

// presets are the built-in Presets, with the credential slot an SDK fills and
// the Upstream host each pins.
var presets = []struct {
	name, slot, prefix, host string
}{
	{"openai", "Authorization", "Bearer ", "api.openai.com"},
	{"anthropic", "X-Api-Key", "", "api.anthropic.com"},
	{"github", "Authorization", "token ", "api.github.com"},
}

// TestPresetsSupplyTheInjectionTemplate applies each Preset with its
// Upstreams replaced by the fake Upstream, so the template it supplies can be
// seen end to end without reaching the real service.
func TestPresetsSupplyTheInjectionTemplate(t *testing.T) {
	var secretNames, policy strings.Builder
	policy.WriteString("  presets-proxy:\n    secrets:\n")
	for _, p := range presets {
		secretNames.WriteString("  preset-" + p.name + ":\n    backend: fake\n    location: kv/openai\n    preset: " + p.name +
			"\n    upstreams:\n      api:\n        url: {{.Upstream.URL}}\n        ca_bundle: {{.Upstream.CABundle}}\n")
		policy.WriteString("      - name: preset-" + p.name + "\n        delivery: [proxy]\n")
	}
	tc, srv := startTemplates(t, secretNames.String(), policy.String())
	token := issueAgentToken(t, srv, "presets-proxy", "1h").Token

	for _, p := range presets {
		t.Run(p.name, func(t *testing.T) {
			before := len(tc.Upstream().Requests())
			got := proxy(t, srv, http.MethodGet, "/proxy/preset-"+p.name+"/api/v1/x", http.Header{p.slot: {p.prefix + token}}, "")
			if got.Status != http.StatusOK {
				t.Fatalf("proxy = %d %q, want 200\nserver stderr:\n%s", got.Status, got.Body, srv.Stderr())
			}
			reqs := tc.Upstream().Requests()
			if len(reqs) != before+1 {
				t.Fatalf("the Upstream received %d requests, want 1", len(reqs)-before)
			}
			up := reqs[before]
			if v := up.Header.Values(p.slot); len(v) != 1 || v[0] != p.prefix+"test-value-1" {
				t.Errorf("the Upstream received %s %q, want %q", p.slot, v, p.prefix+"test-value-1")
			}
			assertNoAgentToken(t, up, token)
		})
	}
}

// TestPresetsPinTheirUpstream applies each Preset as is. A Policy that allows
// only Reveal Delivery denies the proxied request before anything leaves
// TrustedCourier, and the Audit Record names the Upstream host it would have
// gone to.
func TestPresetsPinTheirUpstream(t *testing.T) {
	var secretNames, policy strings.Builder
	policy.WriteString("  presets-reveal:\n    secrets:\n")
	for _, p := range presets {
		secretNames.WriteString("  pinned-" + p.name + ":\n    backend: fake\n    location: kv/openai\n    preset: " + p.name + "\n")
		policy.WriteString("      - name: pinned-" + p.name + "\n        delivery: [reveal]\n")
	}
	_, srv := startTemplates(t, secretNames.String(), policy.String())
	token := issueAgentToken(t, srv, "presets-reveal", "1h").Token

	for i, p := range presets {
		got := proxy(t, srv, http.MethodGet, "/proxy/pinned-"+p.name+"/api/v1/x", bearer(token), "")
		if got.Status != http.StatusForbidden {
			t.Fatalf("%s: proxy = %d %q, want 403", p.name, got.Status, got.Body)
		}
		records := auditRecords(t, srv, i+1)
		if rec := records[len(records)-1]; rec.SecretName != "pinned-"+p.name || rec.Upstream != "api" || rec.UpstreamHost != p.host {
			t.Errorf("%s: Audit Record %+v, want Upstream api pinned to %s", p.name, rec, p.host)
		}
	}
}

func TestPresetConfigIsValidated(t *testing.T) {
	const name = "secrets:\n  openai:\n    backend: fake\n    location: kv/openai\n"
	cases := []struct{ name, config, wantErr string }{
		{"unknown Preset", name + "    preset: no-such-preset\n", `unknown preset "no-such-preset"; use one of anthropic, github, openai`},
		{"Preset and Injection Template", name + "    preset: openai\n    injection_template:\n      query:\n        name: key\n", "not both"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := harness.New(t)
			code, stderr := tc.Refused(harness.AdminConfig + fakePluginConfig + c.config)
			if code == 0 {
				t.Fatal("TrustedCourier started")
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
		})
	}
}

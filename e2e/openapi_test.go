package e2e

import (
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
	"go.yaml.in/yaml/v3"
)

// TestOpenAPISpecMatchesTheAgentAPI checks every operation the Agent API's
// OpenAPI spec describes against a running server: each must reach a handler
// that asks for an Agent Token, not 404 or 405.
func TestOpenAPISpecMatchesTheAgentAPI(t *testing.T) {
	data, err := os.ReadFile("../docs/api/agent-api.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		OpenAPI string                    `yaml:"openapi"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.1.") {
		t.Errorf("openapi = %q, want 3.1.x", spec.OpenAPI)
	}
	wantPaths := []string{"/v1/reveal/{secret_name}", "/proxy/{secret_name}/{upstream}", "/proxy/{secret_name}/{upstream}/{path}"}
	for _, p := range wantPaths {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("the spec does not describe %s", p)
		}
	}

	tc := harness.New(t)
	srv := tc.Start(proxyConfig)
	fill := strings.NewReplacer("{secret_name}", "openai", "{upstream}", "api", "{path}", "v1/models")
	methods := []string{"get", "head", "post", "put", "patch", "delete", "options"}
	for path, item := range spec.Paths {
		if !slices.Contains(wantPaths, path) {
			t.Errorf("the spec describes %s, which the Agent API does not serve", path)
		}
		for method, op := range item {
			if !slices.Contains(methods, method) {
				continue
			}
			operation, _ := op.(map[string]any)
			responses, _ := operation["responses"].(map[string]any)
			if _, ok := responses["401"]; !ok {
				t.Errorf("%s %s: the spec lists no 401", method, path)
			}
			req, err := http.NewRequest(strings.ToUpper(method), srv.AgentURL()+fill.Replace(path), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := agentDo(t, req); got.Status != http.StatusUnauthorized {
				t.Errorf("%s %s = %d %q, want 401", method, path, got.Status, got.Body)
			}
		}
	}
}

package e2e

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/e2e/harness"
)

func TestProxyDeliveryDoesNotLogSecretsInUpstreamErrors(t *testing.T) {
	cases := []struct {
		name, response, wantLog string
		bodyError               bool
		wantStatus              int
	}{
		{
			name:     "content encoding",
			response: "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\nContent-Length: 0\r\n\r\n",
			wantLog:  "Redaction cannot read the Upstream's response",
		},
		{
			name:     "content length",
			response: "HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n",
			wantLog:  "Upstream not reached",
		},
		{
			name:     "status line",
			response: "HTTP/1.1 %s invalid\r\n\r\n",
			wantLog:  "Upstream not reached",
		},
		{
			name:     "protocol upgrade",
			response: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n",
			wantLog:  "Upstream not reached",
		},
		{
			// net/http logs unsolicited bytes through the process's default
			// logger, bypassing ReverseProxy entirely.
			name:       "unsolicited response",
			response:   "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n%s",
			wantLog:    "Delivery allowed",
			wantStatus: http.StatusOK,
		},
		{
			// A malformed trailer fails during body copy, which uses
			// ReverseProxy's own logger instead of its ErrorHandler.
			name:      "trailer",
			response:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n0123456789abcdef0123456789abcdef\r\n0\r\n%s\r\n\r\n",
			wantLog:   "the Upstream's response broke off",
			bodyError: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.wantStatus == 0 {
				c.wantStatus = http.StatusBadGateway
			}
			tc := harness.New(t)
			up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				value := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if value != fakeSecret {
					t.Errorf("Upstream did not receive the injected Secret")
				}
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = conn.Close() }()
				_, _ = fmt.Fprintf(buf, c.response, value)
				_ = buf.Flush()
			}))
			t.Cleanup(up.Close)
			ca := filepath.Join(tc.Dir(), "upstream-ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := strings.NewReplacer("{{.Upstream.URL}}", up.URL, "{{.Upstream.CABundle}}", ca).Replace(proxyConfig)
			srv := tc.Start(cfg)
			waitForPlugin(t, srv, "fake", running)
			token := issueAgentToken(t, srv, "openai-proxy", "1h").Token
			req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/test", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = bearer(token)
			res, requestErr := http.DefaultClient.Do(req)
			var body []byte
			var readErr error
			if res != nil {
				body, readErr = io.ReadAll(res.Body)
				_ = res.Body.Close()
				assertNoSecret(t, agentResponse{Status: res.StatusCode, Header: res.Header, Body: string(body)})
			}
			if c.bodyError {
				if requestErr == nil && readErr == nil {
					t.Error("malformed trailer reached the Agent as a complete response")
				}
			} else if requestErr != nil || res.StatusCode != c.wantStatus {
				t.Fatalf("want status %d, got response %v, error %v", c.wantStatus, res, requestErr)
			}
			// Stop also checks all core output for every fake Secret value.
			srv.Stop()
			if !strings.Contains(srv.Stderr(), c.wantLog) {
				t.Errorf("missing safe failure message %q:\n%s", c.wantLog, srv.Stderr())
			}
		})
	}
}

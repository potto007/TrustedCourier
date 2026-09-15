package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The Agent write stall limit bounds writes to an Agent that stops reading,
// not an Upstream's silence: a stream that pauses longer than that limit, then
// ends, must reach the Agent whole, trailers included.
func TestProxyDeliveryStreamSurvivesAPauseBeforeItEnds(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the Agent write stall limit")
	}
	_, srv, token := startProxy(t, "openai-proxy")

	h2c := &http.Transport{Protocols: new(http.Protocols)}
	h2c.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(h2c.CloseIdleConnections)
	clients := map[string]*http.Client{"HTTP/1.1": http.DefaultClient, "HTTP/2": {Transport: h2c}}
	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/pause-end?pause=35s", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = bearer(token)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != "data: first\n\n" {
				t.Fatalf("stream = %q, %v, want the whole event and a clean end", body, err)
			}
			if v := resp.Trailer.Get("X-Done"); v != "yes" {
				t.Errorf("X-Done trailer = %q, want yes", v)
			}
		})
	}
}

func TestProxyDeliveryLogsAResponseCutOff(t *testing.T) {
	_, srv, token := startProxy(t, "openai-proxy")

	req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/cut", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = bearer(token)
	// The cut may come before or after the response's headers reach the Agent.
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("the Agent read a whole body from a response the Upstream cut off")
	}
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(srv.Stderr(), "Delivery cut off"); {
		if time.Now().After(deadline) {
			t.Fatalf("server log does not record the cut-off Delivery:\n%s", srv.Stderr())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ReverseProxy drops query parameters it cannot parse, such as ones split by
// ';', which some servers read as a separator; building the Upstream URL must
// not bring them back.
func TestProxyDeliveryDropsQueryParametersItCannotParse(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")

	if got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/v1/models?model=a;model=b&ok=1", bearer(token), ""); got.Status != http.StatusOK {
		t.Fatalf("proxy = %d %q, want 200", got.Status, got.Body)
	}
	reqs := tc.Upstream().Requests()
	if len(reqs) != 1 || reqs[0].RawQuery != "ok=1" {
		t.Fatalf("the Upstream received %+v, want only the query ok=1", reqs)
	}
}

package e2e

import (
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSecret is the value the fake Backend Plugin holds for openai.
const fakeSecret = "test-value-1"

// assertNoSecret fails if the Secret reached the Agent anywhere in res.
func assertNoSecret(t *testing.T, res agentResponse) {
	t.Helper()
	for name, values := range res.Header {
		for _, v := range values {
			// Header names reach the Agent in any case: HTTP/2 lowercases them.
			if strings.Contains(strings.ToLower(name), fakeSecret) || strings.Contains(strings.ToLower(v), fakeSecret) {
				t.Errorf("the Agent received the Secret in %s: %q", name, v)
			}
		}
	}
	if strings.Contains(res.Body, fakeSecret) {
		t.Errorf("the Agent received the Secret in the body: %q", res.Body)
	}
}

func TestProxyDeliveryRedactsTheSecretFromResponses(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")

	t.Run("echoed in a 401 body and header", func(t *testing.T) {
		got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/echo?status=401&header=Authorization&text=invalid+key:+", bearer(token), "")
		const want = "invalid key: Bearer ************"
		if got.Status != http.StatusUnauthorized || got.Body != want {
			t.Fatalf("proxy = %d %q, want 401 %q", got.Status, got.Body, want)
		}
		if v := got.Header.Get("X-Echo"); v != want {
			t.Errorf("X-Echo = %q, want %q", v, want)
		}
		if v := got.Header.Get("Content-Length"); v != strconv.Itoa(len(want)) {
			t.Errorf("Content-Length = %q, want %d", v, len(want))
		}
		assertNoSecret(t, got)
	})

	t.Run("echoed in 103 Early Hints", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/echo?early=1&header=Authorization", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = bearer(token)
		var early []textproto.MIMEHeader
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
				if code == http.StatusEarlyHints {
					early = append(early, header)
				}
				return nil
			},
		}))
		got := agentDo(t, req)
		const want = "Bearer ************"
		if got.Status != http.StatusOK || got.Body != want {
			t.Fatalf("proxy = %d %q, want 200 %q", got.Status, got.Body, want)
		}
		if len(early) != 1 || early[0].Get("X-Echo") != want {
			t.Fatalf("103 responses = %v, want one with X-Echo %q", early, want)
		}
		if v := got.Header.Values("Cache-Control"); len(v) != 1 || v[0] != "no-store" {
			t.Errorf("Cache-Control after 103 = %q, want no-store", v)
		}
		assertNoSecret(t, got)
	})

	t.Run("echoed in a gzip body", func(t *testing.T) {
		header := bearer(token)
		header.Set("Accept-Encoding", "gzip")
		got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/echo?encoding=gzip&header=Authorization", header, "")
		if got.Status != http.StatusOK || got.Body != "Bearer ************" || got.Header.Get("Content-Encoding") != "" {
			t.Fatalf("proxy = %d %q %v, want 200 with the plain, masked body", got.Status, got.Body, got.Header)
		}
		assertNoSecret(t, got)
	})

	t.Run("echoed in a header name", func(t *testing.T) {
		got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/echo?name=1&header=Authorization", bearer(token), "")
		if got.Status != http.StatusOK {
			t.Fatalf("proxy = %d %q, want 200", got.Status, got.Body)
		}
		assertNoSecret(t, got)
	})

	t.Run("in an encoding Redaction cannot read", func(t *testing.T) {
		header := bearer(token)
		header.Set("Accept-Encoding", "gzip")
		for _, enc := range []string{"br", "gzip-twice"} {
			// The 103 clears the response's headers, which a 502 must still carry.
			got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/echo?early=1&header=Authorization&encoding="+enc, header, "")
			if got.Status != http.StatusBadGateway || got.Header.Get("Content-Encoding") != "" {
				t.Fatalf("%s: proxy = %d %q %v, want 502", enc, got.Status, got.Body, got.Header)
			}
			if got.Header.Get("Cache-Control") != "no-store" || got.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("%s: 502 headers %v, want Cache-Control no-store and nosniff", enc, got.Header)
			}
			assertNoSecret(t, got)
		}
		if !strings.Contains(srv.Stderr(), "Redaction cannot read") {
			t.Errorf("server log does not record the refused encoding:\n%s", srv.Stderr())
		}
	})

	t.Run("requested as a range", func(t *testing.T) {
		header := bearer(token)
		header.Set("Range", "bytes=10-13")
		header.Set("If-Range", `"etag"`)
		before := len(tc.Upstream.Requests())
		got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/echo?header=Authorization", header, "")
		if got.Status != http.StatusOK || got.Body != "Bearer ************" {
			t.Fatalf("proxy = %d %q, want 200 with the whole masked body", got.Status, got.Body)
		}
		reqs := tc.Upstream.Requests()
		if len(reqs) != before+1 {
			t.Fatalf("the Upstream received %d requests, want 1", len(reqs)-before)
		}
		if up := reqs[before]; up.Header.Get("Range") != "" || up.Header.Get("If-Range") != "" {
			t.Errorf("the Upstream received Range %q and If-Range %q, want neither", up.Header.Get("Range"), up.Header.Get("If-Range"))
		}
		assertNoSecret(t, got)
	})

	t.Run("without the Secret", func(t *testing.T) {
		// Ends with a partial match, which must still arrive.
		const want = "near test-value-2, test-value-"
		got := proxy(t, srv, http.MethodGet, "/proxy/openai/api/echo?text="+url.QueryEscape(want), bearer(token), "")
		if got.Status != http.StatusOK || got.Body != want || got.Header.Get("X-Echo") != want ||
			got.Header.Get("Content-Length") != strconv.Itoa(len(want)) || got.Header.Get("Content-Type") != "text/plain" {
			t.Fatalf("proxy = %d %q %v, want 200 with the Upstream's response unchanged", got.Status, got.Body, got.Header)
		}
	})
}

func TestProxyDeliveryRedactsTheSecretSplitAcrossAStream(t *testing.T) {
	tc, srv, token := startProxy(t, "openai-proxy")

	req, err := http.NewRequest(http.MethodGet, srv.AgentURL()+"/proxy/openai/api/echo-events?header=Authorization", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = bearer(token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy echo-events = %d, want 200", resp.StatusCode)
	}

	chunks := make(chan string)
	go func() {
		defer close(chunks)
		buf := make([]byte, 1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				chunks <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// The Upstream sends "data: first", then "data: key Bearer te", and holds
	// back the rest. All but "te", which could begin the Secret, reaches the
	// Agent while the stream is held.
	const early = "data: first\n\ndata: key Bearer "
	var got string
	for got != early {
		select {
		case c := <-chunks:
			got += c
			if !strings.HasPrefix(early, got) {
				t.Fatalf("while the stream is held, the Agent received %q, want %q", got, early)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("while the stream is held, the Agent received %q, want %q", got, early)
		}
	}
	tc.Upstream.ReleaseEvents()
	for c := range chunks {
		got += c
	}
	if want := "data: first\n\ndata: key Bearer ************\n\n"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	if v := resp.Trailer.Get("X-Echo"); v != "Bearer ************" {
		t.Errorf("X-Echo trailer = %q, want the masked value", v)
	}
}

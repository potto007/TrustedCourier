package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/potto007/TrustedCourier/sdk/plugin"
)

// fakeBao is the least of OpenBao's API the plugin needs, with knobs for
// the states a dev-mode container cannot easily show.
type fakeBao struct {
	sealed       bool
	tokenValid   bool
	forbidden    bool
	casConflicts atomic.Int32
	version      atomic.Int64
	written      chan map[string]any
}

func newFakeBao() *fakeBao {
	f := &fakeBao{tokenValid: true, written: make(chan map[string]any, 8)}
	f.version.Store(1)
	return f
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	write := func(status int, body any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	errors := func(status int, msg string) { write(status, map[string]any{"errors": []string{msg}}) }
	switch {
	case r.URL.Path == "/v1/sys/health":
		if f.sealed {
			write(http.StatusServiceUnavailable, map[string]any{"initialized": true, "sealed": true, "version": "2.4.4"})
			return
		}
		write(http.StatusOK, map[string]any{"initialized": true, "sealed": false, "version": "2.4.4"})
	case r.Header.Get("X-Vault-Token") != "good" || !f.tokenValid:
		errors(http.StatusForbidden, "permission denied")
	case r.URL.Path == "/v1/auth/token/lookup-self":
		write(http.StatusOK, map[string]any{"data": map[string]any{"ttl": 0}})
	case r.URL.Path == "/v1/elsewhere/data/x":
		// A record somewhere the token must never be sent.
		w.Header().Set("Location", "http://127.0.0.1:1/v1/secret/data/x")
		w.WriteHeader(http.StatusTemporaryRedirect)
	case f.forbidden:
		errors(http.StatusForbidden, "permission denied")
	case r.URL.Path == "/v1/sys/internal/ui/mounts/secret/data/x":
		write(http.StatusOK, map[string]any{"data": map[string]any{"type": "kv", "path": "secret/", "options": map[string]any{"version": "2"}}})
	case r.URL.Path == "/v1/secret/data/x" && r.Method == http.MethodGet:
		write(http.StatusOK, map[string]any{"data": map[string]any{
			"data":     map[string]any{"key": "value"},
			"metadata": map[string]any{"version": f.version.Load()},
		}})
	case r.URL.Path == "/v1/secret/data/x" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cas, _ := body["options"].(map[string]any)["cas"].(float64)
		if f.casConflicts.Load() > 0 {
			f.casConflicts.Add(-1)
			f.version.Add(1)
			errors(http.StatusBadRequest, "check-and-set parameter did not match the current version")
			return
		}
		if int64(cas) != f.version.Load() {
			errors(http.StatusBadRequest, "check-and-set parameter did not match the current version")
			return
		}
		f.written <- body
		write(http.StatusOK, map[string]any{"data": map[string]any{"version": f.version.Load() + 1}})
	default:
		errors(http.StatusNotFound, "")
	}
}

func newBackend(t *testing.T, f *fakeBao) *Backend {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	b, err := New(Config{Address: srv.URL, Token: "good"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHealthReportsSealed(t *testing.T) {
	f := newFakeBao()
	f.sealed = true
	detail, err := newBackend(t, f).Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Errorf("Health = %q, %v; want a sealed error", detail, err)
	}
	if !strings.Contains(detail, "OpenBao 2.4.4") {
		t.Errorf("detail = %q, want the version", detail)
	}
}

func TestHealthReportsInvalidToken(t *testing.T) {
	f := newFakeBao()
	f.tokenValid = false
	_, err := newBackend(t, f).Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "token is invalid") {
		t.Errorf("Health error = %v; want an invalid token error", err)
	}
}

func TestGetReportsPermissionDenied(t *testing.T) {
	f := newFakeBao()
	f.forbidden = true
	_, err := newBackend(t, f).Get(context.Background(), "secret/data/x#key")
	if err == nil || errors.Is(err, plugin.ErrNotFound) || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("Get = %v; want a permission denied error that is not not-found", err)
	}
}

func TestGetDoesNotFollowRedirects(t *testing.T) {
	_, err := newBackend(t, newFakeBao()).Get(context.Background(), "elsewhere/data/x#key")
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Errorf("Get = %v; want the redirect status reported, not followed", err)
	}
}

func TestGetRejectsBadLocations(t *testing.T) {
	b := newBackend(t, newFakeBao())
	for _, loc := range []string{"secret/data/x", "#key", "secret/data/x#", "/secret/data/x#key", "secret/data/x/#key", "secret//x#key", "secret/data/x?a=b#key"} {
		if _, err := b.Get(context.Background(), loc); err == nil || errors.Is(err, plugin.ErrNotFound) {
			t.Errorf("Get(%q) = %v; want a location error", loc, err)
		}
	}
}

func TestWriteCourierKeyRetriesCheckAndSet(t *testing.T) {
	f := newFakeBao()
	f.casConflicts.Store(2)
	if err := newBackend(t, f).WriteCourierKey(context.Background(), "secret/data/x#tls-key", []byte("pem")); err != nil {
		t.Fatalf("WriteCourierKey: %v", err)
	}
	body := <-f.written
	data := body["data"].(map[string]any)
	if data["key"] != "value" || data["tls-key"] != "pem" {
		t.Errorf("written data = %v; want the existing field kept and the key added", data)
	}
	if cas := body["options"].(map[string]any)["cas"]; cas != float64(3) {
		t.Errorf("cas = %v; want the version after the conflicts, 3", cas)
	}
}

func TestWriteCourierKeyGivesUpOnEndlessConflicts(t *testing.T) {
	f := newFakeBao()
	f.casConflicts.Store(100)
	err := newBackend(t, f).WriteCourierKey(context.Background(), "secret/data/x#tls-key", []byte("pem"))
	if err == nil || !strings.Contains(err.Error(), "check-and-set") {
		t.Errorf("WriteCourierKey = %v; want a check-and-set error", err)
	}
}

func TestWriteCourierKeyRefusesBinary(t *testing.T) {
	err := newBackend(t, newFakeBao()).WriteCourierKey(context.Background(), "secret/data/x#tls-key", []byte{0xff, 0xfe})
	if err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("WriteCourierKey = %v; want a UTF-8 error", err)
	}
}

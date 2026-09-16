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
// the states a dev-mode container cannot easily show. It mounts secret/
// as KV v2 and kv1/ as KV v1; the record x on each holds key=value.
type fakeBao struct {
	sealed       bool
	tokenValid   bool
	forbidden    bool
	deleted      bool
	version      string
	casConflicts atomic.Int32
	recordVer    atomic.Int64
	written      chan map[string]any
}

func newFakeBao() *fakeBao {
	f := &fakeBao{tokenValid: true, version: "2.4.4", written: make(chan map[string]any, 8)}
	f.recordVer.Store(1)
	return f
}

func (f *fakeBao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	write := func(status int, body any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	fail := func(status int, msgs ...string) { write(status, map[string]any{"errors": msgs}) }
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case path == "sys/health":
		if f.sealed {
			write(http.StatusServiceUnavailable, map[string]any{"initialized": true, "sealed": true, "version": f.version})
			return
		}
		write(http.StatusOK, map[string]any{"initialized": true, "sealed": false, "version": f.version})
	case r.Header.Get("X-Vault-Token") != "good" || !f.tokenValid:
		fail(http.StatusForbidden, "permission denied")
	case path == "auth/token/lookup-self":
		write(http.StatusOK, map[string]any{"data": map[string]any{"ttl": 0}})
	case strings.HasPrefix(path, "sys/internal/ui/mounts/"):
		mnt, _, _ := strings.Cut(strings.TrimPrefix(path, "sys/internal/ui/mounts/"), "/")
		switch mnt {
		case "secret":
			write(http.StatusOK, map[string]any{"data": map[string]any{"type": "kv", "path": "secret/", "options": map[string]any{"version": "2"}}})
		case "kv1", "elsewhere":
			write(http.StatusOK, map[string]any{"data": map[string]any{"type": "kv", "path": mnt + "/", "options": map[string]any{"version": "1"}}})
		case "pki":
			write(http.StatusOK, map[string]any{"data": map[string]any{"type": "pki", "path": "pki/"}})
		default:
			fail(http.StatusForbidden, "preflight capability check returned 403")
		}
	case path == "elsewhere/x":
		// A record somewhere the token must never be sent.
		w.Header().Set("Location", "http://127.0.0.1:1/v1/secret/data/x")
		w.WriteHeader(http.StatusTemporaryRedirect)
	case f.forbidden:
		fail(http.StatusForbidden, "permission denied")
	case path == "secret/x":
		fail(http.StatusNotFound, "Invalid path for a versioned K/V secrets engine. See the API docs for the appropriate API endpoints to use.")
	case path == "kv1/x" && r.Method == http.MethodGet:
		// A KV v1 record whose fields happen to be named like a KV v2
		// envelope.
		write(http.StatusOK, map[string]any{"data": map[string]any{
			"key": "value", "data": map[string]any{"inner": "x"}, "metadata": "meta",
		}})
	case path == "kv1/x" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.written <- body
		w.WriteHeader(http.StatusNoContent)
	case path == "secret/data/big" && r.Method == http.MethodGet:
		write(http.StatusOK, map[string]any{"data": map[string]any{
			"data":     map[string]any{"key": strings.Repeat("x", maxValueBytes+1)},
			"metadata": map[string]any{"version": 1},
		}})
	case path == "secret/data/x" && r.Method == http.MethodGet:
		if f.deleted {
			write(http.StatusNotFound, map[string]any{"errors": []string{}, "data": map[string]any{
				"data": nil, "metadata": map[string]any{"version": f.recordVer.Load(), "deletion_time": "2026-09-16T00:00:00Z"},
			}})
			return
		}
		write(http.StatusOK, map[string]any{"data": map[string]any{
			"data":     map[string]any{"key": "value"},
			"metadata": map[string]any{"version": f.recordVer.Load()},
		}})
	case path == "secret/data/x" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cas, _ := body["options"].(map[string]any)["cas"].(float64)
		if f.casConflicts.Load() > 0 {
			f.casConflicts.Add(-1)
			f.recordVer.Add(1)
			fail(http.StatusBadRequest, "check-and-set parameter did not match the current version")
			return
		}
		if int64(cas) != f.recordVer.Load() {
			fail(http.StatusBadRequest, "check-and-set parameter did not match the current version")
			return
		}
		f.written <- body
		write(http.StatusOK, map[string]any{"data": map[string]any{"version": f.recordVer.Load() + 1}})
	default:
		fail(http.StatusNotFound)
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

func TestHealthDetailIsPrintableAndBounded(t *testing.T) {
	f := newFakeBao()
	f.version = "2.4.4\x1b[2J" + strings.Repeat("v", 200)
	detail, err := newBackend(t, f).Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if strings.ContainsRune(detail, '\x1b') || len(detail) > 100 {
		t.Errorf("detail = %q; want the version sanitized and cut", detail)
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
	_, err := newBackend(t, newFakeBao()).Get(context.Background(), "elsewhere/x#key")
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Errorf("Get = %v; want the redirect status reported, not followed", err)
	}
}

func TestGetRejectsBadLocations(t *testing.T) {
	b := newBackend(t, newFakeBao())
	for _, loc := range []string{"secret/data/x", "#key", "secret/data/x#", "/secret/data/x#key", "secret/data/x/#key", "secret//x#key", "secret/data/x?a=b#key", "secret/data/50%off#key", "secret/data/a b#key"} {
		_, err := b.Get(context.Background(), loc)
		if err == nil || errors.Is(err, plugin.ErrNotFound) || !strings.Contains(err.Error(), "location") {
			t.Errorf("Get(%q) = %v; want a location error", loc, err)
		}
	}
}

func TestGetNamesAMissingDataSegment(t *testing.T) {
	_, err := newBackend(t, newFakeBao()).Get(context.Background(), "secret/x#key")
	if err == nil || errors.Is(err, plugin.ErrNotFound) || !strings.Contains(err.Error(), "secret/data/") {
		t.Errorf("Get on a KV v2 path without data/ = %v; want an error naming the data segment, not not-found", err)
	}
}

func TestGetOnANonKVMountIsAnError(t *testing.T) {
	_, err := newBackend(t, newFakeBao()).Get(context.Background(), "pki/cert/ca#certificate")
	if err == nil || errors.Is(err, plugin.ErrNotFound) || !strings.Contains(err.Error(), "not KV") {
		t.Errorf("Get on a pki mount = %v; want a not-KV error", err)
	}
}

func TestGetReadsKVv1ByMountVersion(t *testing.T) {
	b := newBackend(t, newFakeBao())
	got, err := b.Get(context.Background(), "kv1/x#key")
	if err != nil || string(got) != "value" {
		t.Errorf("Get(kv1/x#key) = %q, %v; want the record's own field", got, err)
	}
	if _, err := b.Get(context.Background(), "kv1/x#data"); err == nil || errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("Get(kv1/x#data) = %v; want a not-a-string error for the object field, not not-found", err)
	}
}

func TestGetRefusesOversizedValue(t *testing.T) {
	_, err := newBackend(t, newFakeBao()).Get(context.Background(), "secret/data/big#key")
	if err == nil || errors.Is(err, plugin.ErrNotFound) || !strings.Contains(err.Error(), "byte limit") {
		t.Errorf("Get of an oversized field = %v; want the plugin's own size error", err)
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

func TestWriteCourierKeyToADeletedRecordUsesItsVersion(t *testing.T) {
	f := newFakeBao()
	f.deleted = true
	f.recordVer.Store(7)
	if err := newBackend(t, f).WriteCourierKey(context.Background(), "secret/data/x#tls-key", []byte("pem")); err != nil {
		t.Fatalf("WriteCourierKey: %v", err)
	}
	body := <-f.written
	if cas := body["options"].(map[string]any)["cas"]; cas != float64(7) {
		t.Errorf("cas = %v; want the deleted record's version, 7", cas)
	}
	if data := body["data"].(map[string]any); len(data) != 1 || data["tls-key"] != "pem" {
		t.Errorf("written data = %v; want only the key", data)
	}
}

func TestWriteCourierKeyOnKVv1KeepsTheRecord(t *testing.T) {
	f := newFakeBao()
	if err := newBackend(t, f).WriteCourierKey(context.Background(), "kv1/x#tls-key", []byte("pem")); err != nil {
		t.Fatalf("WriteCourierKey: %v", err)
	}
	body := <-f.written
	if body["key"] != "value" || body["tls-key"] != "pem" || body["metadata"] != "meta" || body["options"] != nil {
		t.Errorf("written record = %v; want every field kept, the key added, and no KV v2 envelope", body)
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

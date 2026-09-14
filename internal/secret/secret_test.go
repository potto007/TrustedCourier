package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
)

const value = "sk-live-0123456789"

func newSecret(t *testing.T) *Secret {
	t.Helper()
	s, err := New([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Release)
	return s
}

func TestWriteToWritesTheValue(t *testing.T) {
	s := newSecret(t)
	var buf bytes.Buffer
	n, err := s.WriteTo(&buf)
	if err != nil || n != int64(len(value)) || buf.String() != value {
		t.Fatalf("WriteTo = %d, %v, %q; want %d, nil, %q", n, err, buf.String(), len(value), value)
	}
	if s.Len() != len(value) {
		t.Fatalf("Len = %d, want %d", s.Len(), len(value))
	}
}

func TestNewWipesTheSource(t *testing.T) {
	src := []byte(value)
	s, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Release()
	if !bytes.Equal(src, make([]byte, len(value))) {
		t.Fatalf("source after New = %q, want zeroed", src)
	}
}

func TestFormattingNeverShowsTheValue(t *testing.T) {
	s := newSecret(t)
	var out []string
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X", "%d", "%T"} {
		out = append(out, fmt.Sprintf(verb, s), fmt.Sprintf(verb, *s))
	}
	out = append(out, fmt.Sprint(s), fmt.Sprintln(s), s.String(), fmt.Sprintf("%v", struct{ S *Secret }{s}))
	for _, got := range out {
		assertHidden(t, got)
	}
}

func TestLoggingNeverShowsTheValue(t *testing.T) {
	s := newSecret(t)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("text", "secret", s, "copy", *s)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("json", "secret", s, "group", slog.Group("g", "secret", s))
	assertHidden(t, buf.String())
	if !strings.Contains(buf.String(), "json") {
		t.Fatalf("JSON handler wrote nothing:\n%s", buf.String())
	}
}

func TestMarshalingIsRefused(t *testing.T) {
	s := newSecret(t)
	if out, err := json.Marshal(s); err == nil {
		t.Fatalf("json.Marshal succeeded: %s", out)
	}
	if out, err := json.Marshal(struct{ S Secret }{*s}); err == nil {
		t.Fatalf("json.Marshal of a copy succeeded: %s", out)
	}
}

func TestReleaseWipesTheBuffer(t *testing.T) {
	var unmapped []byte
	realMunmap := munmap
	munmap = func(b []byte) error { unmapped = b; return nil }
	t.Cleanup(func() { munmap = realMunmap })

	s, err := New([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	s.Release()
	if unmapped == nil {
		t.Fatal("Release did not unmap the buffer")
	}
	if !bytes.Equal(unmapped, make([]byte, len(unmapped))) {
		t.Fatalf("buffer after Release = %q, want zeroed", unmapped)
	}
	_ = realMunmap(unmapped)
}

func TestReleasedSecretIsUnusable(t *testing.T) {
	s, err := New([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	copied := *s
	s.Release()
	s.Release() // idempotent

	var buf bytes.Buffer
	if _, err := copied.WriteTo(&buf); err == nil || buf.Len() != 0 {
		t.Fatalf("WriteTo on a released Secret's copy = %v, wrote %q", err, buf.String())
	}
	if s.Len() != 0 {
		t.Fatalf("Len after Release = %d, want 0", s.Len())
	}
}

func TestBufferIsLocked(t *testing.T) {
	before, ok := lockedKB(t)
	if !ok {
		t.Skip("/proc/self/status VmLck not available")
	}
	s, err := New(bytes.Repeat([]byte("x"), 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	during, _ := lockedKB(t)
	s.Release()
	after, _ := lockedKB(t)
	if during-before < 64 {
		t.Fatalf("locked memory grew by %d kB for a 64 kB Secret, want at least 64", during-before)
	}
	if after != before {
		t.Fatalf("locked memory after Release = %d kB, want %d", after, before)
	}
}

func lockedKB(t *testing.T) (int, bool) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for line := range strings.Lines(string(data)) {
		if rest, ok := strings.CutPrefix(line, "VmLck:"); ok {
			n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(rest), " kB"))
			if err != nil {
				t.Fatalf("parse VmLck %q: %v", line, err)
			}
			return n, true
		}
	}
	return 0, false
}

func assertHidden(t *testing.T, got string) {
	t.Helper()
	for _, leak := range []string{value, fmt.Sprintf("%x", value), fmt.Sprintf("%X", value), "115 107 45"} {
		if strings.Contains(got, leak) {
			t.Fatalf("output reveals the Secret: %q", got)
		}
	}
}

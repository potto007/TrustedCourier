package redact_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/potto007/TrustedCourier/internal/redact"
)

const needle = "test-value-1"

// write writes each chunk to a Writer over needle, closes it, and returns
// everything that reached the underlying writer.
func write(t *testing.T, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	w := redact.NewWriter(&out, needle)
	for _, c := range chunks {
		if n, err := w.Write([]byte(c)); err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v, want %d, nil", c, n, err, len(c))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	return out.String()
}

func TestWriterMasksTheNeedle(t *testing.T) {
	got := write(t, `{"error":"invalid key: Bearer test-value-1, again test-value-1"}`)
	if want := `{"error":"invalid key: Bearer ************, again ************"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriterHoldsBackOnlyAPartialMatch(t *testing.T) {
	var out bytes.Buffer
	w := redact.NewWriter(&out, needle)
	steps := []struct{ write, want string }{
		{"data: first\n\n", "data: first\n\n"},
		{"data: key test-", "data: first\n\ndata: key "},
		{"val", "data: first\n\ndata: key "},
		// "test-valx" cannot begin a match, so all of it goes.
		{"x", "data: first\n\ndata: key test-valx"},
		{" te", "data: first\n\ndata: key test-valx "},
	}
	for _, s := range steps {
		if _, err := w.Write([]byte(s.write)); err != nil {
			t.Fatal(err)
		}
		if got := out.String(); got != s.want {
			t.Fatalf("after Write(%q): got %q, want %q", s.write, got, s.want)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "data: first\n\ndata: key test-valx te"; got != want {
		t.Fatalf("after Close: got %q, want %q", got, want)
	}
}

func TestWriterPassesThroughWithoutTheNeedle(t *testing.T) {
	const body = "near miss: test-value-2, test-value-, test-value-"
	if got := write(t, body[:20], body[20:]); got != body {
		t.Fatalf("got %q, want %q unchanged", got, body)
	}
}

func TestWriterMasksEveryByteOfOverlappingMatches(t *testing.T) {
	var out bytes.Buffer
	w := redact.NewWriter(&out, "aa")
	_, _ = w.Write([]byte("xaaay"))
	_ = w.Close()
	if got, want := out.String(), "x***y"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// writeNeedles writes each chunk to a Writer over needles, closes it, and
// returns everything that reached the underlying writer.
func writeNeedles(t *testing.T, needles []string, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	w := redact.NewWriter(&out, needles...)
	for _, c := range chunks {
		if n, err := w.Write([]byte(c)); err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v, want %d, nil", c, n, err, len(c))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	return out.String()
}

func TestWriterMasksEveryNeedle(t *testing.T) {
	// The Secret, and the basic auth credential that encodes it.
	needles := []string{"test-value-1", "dXNlcjp0ZXN0LXZhbHVlLTE="}
	const stream = "raw test-value-1, encoded Basic dXNlcjp0ZXN0LXZhbHVlLTE=\n"
	const want = "raw ************, encoded Basic ************************\n"
	for i := 1; i < len(stream); i++ {
		if got := writeNeedles(t, needles, stream[:i], stream[i:]); got != want {
			t.Fatalf("split at %d: got %q, want %q", i, got, want)
		}
	}
}

func TestWriterMasksNeedlesThatOverlap(t *testing.T) {
	needles := []string{"abcd", "cdef"}
	if got, want := writeNeedles(t, needles, "xabcdefy"), "x******y"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A match of one needle that ends where a partial match of the other
	// begins: the held-back bytes stay masked, and the completed match is
	// masked too.
	if got, want := writeNeedles(t, []string{"ab", "bc"}, "xab", "c"), "x***"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriterMasksWithAByteNoNeedleContains(t *testing.T) {
	got := writeNeedles(t, []string{"k*y", "x-z"}, "[k*y|x-z]")
	if len(got) != 9 || got[0] != '[' || got[4] != '|' || got[8] != ']' ||
		strings.Count(got, got[1:2]) != 6 || strings.ContainsAny(got[1:2], "k*yx-z") {
		t.Fatalf("got %q, want both needles masked with one byte neither contains", got)
	}
}

func TestWriterIgnoresEmptyNeedles(t *testing.T) {
	if got, want := writeNeedles(t, []string{"", needle, ""}, "key test-value-1"), "key ************"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriterMasksWithAByteTheNeedleDoesNotContain(t *testing.T) {
	var out bytes.Buffer
	w := redact.NewWriter(&out, "k*y")
	_, _ = w.Write([]byte("[k*y]"))
	_ = w.Close()
	if got := out.String(); len(got) != 5 || got[0] != '[' || got[4] != ']' || got[1] != got[2] || got[2] != got[3] ||
		bytes.ContainsAny([]byte(got[1:4]), "k*y") {
		t.Fatalf("got %q, want [ and ] around three copies of one byte not in the needle", got)
	}
}

func TestWriterMaskKeepsJSONAndHTMLIntact(t *testing.T) {
	var out bytes.Buffer
	w := redact.NewWriter(&out, `Pa*ss!word`)
	_, _ = w.Write([]byte(`{"error":"invalid key Pa*ss!word"}`))
	_ = w.Close()
	got := out.String()
	masked := got[len(`{"error":"invalid key `) : len(got)-len(`"}`)]
	if len(masked) != len(`Pa*ss!word`) || bytes.ContainsAny([]byte(masked), "Pa*ss!word\"\\<>&'") ||
		bytes.Count([]byte(masked), []byte(masked[:1])) != len(masked) {
		t.Fatalf("got %q, want one repeated byte that is not in the needle and not JSON- or HTML-significant", got)
	}
}

func TestWriterWithAnEmptyNeedlePassesThrough(t *testing.T) {
	var out bytes.Buffer
	w := redact.NewWriter(&out, "")
	_, _ = w.Write([]byte("body"))
	_ = w.Close()
	if got := out.String(); got != "body" {
		t.Fatalf("got %q, want body", got)
	}
}

func TestString(t *testing.T) {
	cases := map[string]string{
		"Bearer test-value-1":        "Bearer ************",
		"test-value-1, test-value-1": "************, ************",
		"no match; test-value-":      "no match; test-value-",
		"":                           "",
	}
	for in, want := range cases {
		if got := redact.String(in, needle); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
	if got, want := redact.String("a test-value-1 b dGVzdA== c", needle, "dGVzdA=="), "a ************ b ******** c"; got != want {
		t.Errorf("String with two needles = %q, want %q", got, want)
	}
}

func TestWriterMasksTheNeedleSplitAcrossWrites(t *testing.T) {
	const stream, want = "data: Bearer test-value-1\n\n", "data: Bearer ************\n\n"
	for i := 1; i < len(stream); i++ {
		for j := i; j < len(stream); j++ {
			if got := write(t, stream[:i], stream[i:j], stream[j:]); got != want {
				t.Fatalf("split at %d and %d: got %q, want %q", i, j, got, want)
			}
		}
	}
	bytewise := make([]string, len(stream))
	for i := range stream {
		bytewise[i] = stream[i : i+1]
	}
	if got := write(t, bytewise...); got != want {
		t.Fatalf("one byte at a time: got %q, want %q", got, want)
	}
}

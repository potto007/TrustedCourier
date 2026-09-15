package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// events is recorded `go test -json` output: p1 runs TestA (with a subtest),
// TestB fails, TestC is skipped, p2 fails to build, and p3 fails without a
// failing test, as when TestMain exits or the package times out. One line is
// not JSON, as when go test writes to stderr. Times step so progress appends
// are rate limited to one a second.
const events = `{"Time":"2026-09-15T10:00:00Z","Action":"start","Package":"example.com/m/p1"}
{"Time":"2026-09-15T10:00:00Z","Action":"run","Package":"example.com/m/p1","Test":"TestA"}
{"Time":"2026-09-15T10:00:00.2Z","Action":"output","Package":"example.com/m/p1","Test":"TestA","Output":"=== RUN   TestA\n"}
{"Time":"2026-09-15T10:00:00.3Z","Action":"run","Package":"example.com/m/p1","Test":"TestA/sub"}
{"Time":"2026-09-15T10:00:00.4Z","Action":"pass","Package":"example.com/m/p1","Test":"TestA/sub"}
{"Time":"2026-09-15T10:00:00.5Z","Action":"pass","Package":"example.com/m/p1","Test":"TestA"}
go: downloading example.com/dep v1.0.0
{"Time":"2026-09-15T10:00:01.5Z","Action":"run","Package":"example.com/m/p1","Test":"TestB"}
{"Time":"2026-09-15T10:00:01.6Z","Action":"output","Package":"example.com/m/p1","Test":"TestB","Output":"    b_test.go:9: boom\n"}
{"Time":"2026-09-15T10:00:01.7Z","Action":"fail","Package":"example.com/m/p1","Test":"TestB"}
{"Time":"2026-09-15T10:00:01.8Z","Action":"run","Package":"example.com/m/p1","Test":"TestC"}
{"Time":"2026-09-15T10:00:01.9Z","Action":"skip","Package":"example.com/m/p1","Test":"TestC"}
{"Time":"2026-09-15T10:00:02Z","Action":"fail","Package":"example.com/m/p1"}
{"ImportPath":"example.com/m/p2","Action":"build-output","Output":"# example.com/m/p2\n"}
{"ImportPath":"example.com/m/p2","Action":"build-fail"}
{"Time":"2026-09-15T10:00:03Z","Action":"start","Package":"example.com/m/p3"}
{"Time":"2026-09-15T10:00:03.1Z","Action":"output","Package":"example.com/m/p3","Output":"panic: boom\n"}
{"Time":"2026-09-15T10:00:03.2Z","Action":"fail","Package":"example.com/m/p3"}
`

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	for s := bufio.NewScanner(f); s.Scan(); {
		lines = append(lines, s.Text())
	}
	return lines
}

// start leaves a previous run's log and progress sidecar behind.
func start(t *testing.T) string {
	t.Helper()
	log := filepath.Join(t.TempDir(), "e2e.log")
	for _, path := range []string{log, log + ".progress.jsonl"} {
		if err := os.WriteFile(path, []byte("from the previous run\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return log
}

func TestRunWritesTheLogProgressAndFailedSentinel(t *testing.T) {
	log := start(t)
	failure := errors.New("exit status 1")

	if err := run(strings.NewReader(events), func() error { return failure }, log, "TrustedCourier e2e"); !errors.Is(err, failure) {
		t.Fatalf("run = %v, want the command's error", err)
	}

	wantLog := []string{
		"=== RUN   TestA",
		"go: downloading example.com/dep v1.0.0",
		"    b_test.go:9: boom",
		"# example.com/m/p2",
		"panic: boom",
		"FAILED",
	}
	if got := readLines(t, log); !reflect.DeepEqual(got, wantLog) {
		t.Errorf("log = %q, want %q", got, wantLog)
	}

	line := func(done, pass, fail, skip int, current string, ts float64) map[string]any {
		return map[string]any{
			"v": 1.0, "phase": "test", "label": "TrustedCourier e2e",
			"done": float64(done), "pass": float64(pass), "fail": float64(fail), "skip": float64(skip),
			"current": current, "ts": ts,
		}
	}
	const t0 = 1789466400.0 // 2026-09-15T10:00:00Z
	wantProgress := []map[string]any{
		// The first change is written at once; later ones at most once a
		// second, and the last is flushed when the stream ends. Subtests are
		// not counted. A package that fails without a failing test, or fails
		// to build, counts as one failure so the counts never read as clean
		// when the run is not. p1's package failure is TestB's, so it does
		// not count again.
		line(0, 0, 0, 0, "p1.TestA", t0),
		line(1, 1, 0, 0, "p1.TestB", t0+1),
		line(4, 1, 2, 1, "p2 (build)", t0+2),
		line(5, 1, 3, 1, "p3 (package)", t0+3),
	}
	var gotProgress []map[string]any
	for _, l := range readLines(t, log+".progress.jsonl") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("progress line %q: %v", l, err)
		}
		gotProgress = append(gotProgress, m)
	}
	if !reflect.DeepEqual(gotProgress, wantProgress) {
		t.Errorf("progress =\n%v\nwant\n%v", gotProgress, wantProgress)
	}
}

func TestRunEndsTheLogWithDoneWhenTheCommandSucceeds(t *testing.T) {
	log := start(t)
	const passing = `{"Time":"2026-09-15T10:00:00Z","Action":"run","Package":"example.com/m/p1","Test":"TestA"}
{"Time":"2026-09-15T10:00:00.1Z","Action":"output","Package":"example.com/m/p1","Test":"TestA","Output":"ok\n"}
{"Time":"2026-09-15T10:00:00.2Z","Action":"pass","Package":"example.com/m/p1","Test":"TestA"}
`
	if err := run(strings.NewReader(passing), func() error { return nil }, log, ""); err != nil {
		t.Fatalf("run = %v", err)
	}
	if got, want := readLines(t, log), []string{"ok", "DONE"}; !reflect.DeepEqual(got, want) {
		t.Errorf("log = %q, want %q", got, want)
	}
	progress := readLines(t, log+".progress.jsonl")
	if len(progress) == 0 || strings.Contains(strings.Join(progress, "\n"), "previous run") {
		t.Fatalf("progress = %q, want only this run's lines", progress)
	}
	var last map[string]any
	if err := json.Unmarshal([]byte(progress[len(progress)-1]), &last); err != nil {
		t.Fatal(err)
	}
	if last["done"] != 1.0 || last["pass"] != 1.0 || last["label"] != nil {
		t.Errorf("last progress line = %v, want done 1, pass 1, no label", last)
	}
}

// Command testprogress runs a `go test -json` command, writes its readable
// output to a log, and reports progress beside it for the work-band UI plugin:
// one JSON line per update in <log>.progress.jsonl, and DONE or FAILED as the
// log's last line. It exits with the command's exit code.
//
//	go run ./scripts/testprogress -log /tmp/e2e.log -label "TrustedCourier e2e" -- go test -race -json ./...
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

func main() {
	logPath := flag.String("log", "", "log file to write; progress goes to <log>.progress.jsonl")
	label := flag.String("label", "", "row label for the work-band UI plugin")
	flag.Parse()
	if *logPath == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: testprogress -log <file> [-label <text>] -- go test -json ...")
		os.Exit(2)
	}

	cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "testprogress:", err)
		os.Exit(1)
	}
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		done <- err
	}()

	err := run(pr, func() error { return <-done }, *logPath, *label)
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() > 0:
		os.Exit(exit.ExitCode())
	case err != nil:
		fmt.Fprintln(os.Stderr, "testprogress:", err)
		os.Exit(1)
	}
}

// event is one line of `go test -json` output.
type event struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
}

// progress is one line of the work-band progress sidecar (contract v1).
type progress struct {
	V       int    `json:"v"`
	Phase   string `json:"phase"`
	Label   string `json:"label,omitempty"`
	Done    int    `json:"done"`
	Pass    int    `json:"pass"`
	Fail    int    `json:"fail"`
	Skip    int    `json:"skip"`
	Current string `json:"current,omitempty"`
	TS      int64  `json:"ts,omitempty"`
}

// appendInterval rate-limits progress appends; the band polls every 5 s.
const appendInterval = time.Second

// run reads `go test -json` events, truncates and writes the log at logPath
// and its progress sidecar, and once events end, ends the log with DONE or
// FAILED by what wait returns. Only top-level tests are counted. Lines that
// are not events, such as go's own stderr, go to the log as they are. It
// returns wait's error joined with any write error.
func run(events io.Reader, wait func() error, logPath, label string) error {
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()
	sidecar, err := os.Create(logPath + ".progress.jsonl")
	if err != nil {
		return err
	}
	defer func() { _ = sidecar.Close() }()

	var (
		writeErr  error
		endsLine  = true
		p         = progress{V: 1, Phase: "test", Label: label}
		now, last time.Time
		appended  bool
		pending   bool
	)
	writeLog := func(s string) {
		if s == "" {
			return
		}
		if _, err := io.WriteString(logFile, s); err != nil && writeErr == nil {
			writeErr = err
		}
		endsLine = strings.HasSuffix(s, "\n")
	}
	appendProgress := func() {
		b, _ := json.Marshal(p) // progress always encodes
		if _, err := sidecar.Write(append(b, '\n')); err != nil && writeErr == nil {
			writeErr = err
		}
		appended, pending, last = true, false, now
	}

	r := bufio.NewReader(events)
	for {
		line, readErr := r.ReadString('\n')
		var e event
		switch {
		case line == "":
		case !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &e) != nil || e.Action == "":
			writeLog(line)
		default:
			if !e.Time.IsZero() {
				now, p.TS = e.Time, e.Time.Unix()
			}
			topLevel := e.Test != "" && !strings.Contains(e.Test, "/")
			switch e.Action {
			case "output", "build-output":
				writeLog(e.Output)
			case "run":
				if topLevel {
					p.Current, pending = path.Base(e.Package)+"."+e.Test, true
				}
			case "pass", "fail", "skip":
				if topLevel {
					p.Done++
					switch e.Action {
					case "pass":
						p.Pass++
					case "fail":
						p.Fail++
					default:
						p.Skip++
					}
					pending = true
				}
			}
			if pending && (!appended || now.Sub(last) >= appendInterval) {
				appendProgress()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return errors.Join(readErr, wait())
		}
	}
	if pending {
		appendProgress()
	}

	waitErr := wait()
	if !endsLine {
		writeLog("\n")
	}
	if waitErr != nil {
		writeLog("FAILED\n")
	} else {
		writeLog("DONE\n")
	}
	return errors.Join(waitErr, writeErr)
}

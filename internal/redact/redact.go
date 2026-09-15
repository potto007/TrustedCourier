// Package redact performs Redaction: it masks every exact match of a Secret
// in an Upstream's response before the response reaches the Agent.
//
// A match becomes a run of one mask byte of the same length, so a response's
// Content-Length stays true and a response without the Secret passes through
// byte for byte.
package redact

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"unsafe"
)

// Writer masks every exact match of any of its needles in what is written
// through it, including a match split across writes. It holds back only a
// trailing run of bytes that could begin a match, so a stream is delayed by
// less than the longest needle's length.
type Writer struct {
	w       io.Writer
	needles [][]byte
	mask    byte
	buf     []byte
	// masked marks the bytes of buf that belong to a match. Held-back bytes
	// keep their raw value, so a match they begin can still be found.
	masked  []bool
	pending int // bytes at the start of buf held back from the last Write
}

// NewWriter returns a Writer that masks every needle in everything written to
// w. Empty needles mask nothing.
func NewWriter(w io.Writer, needles ...string) *Writer {
	return &Writer{w: w, needles: views(needles), mask: maskFor(needles)}
}

// Write masks p and writes all of it to the underlying writer but for a
// trailing partial match, which it holds back until the next Write or Close.
// It never modifies p.
func (w *Writer) Write(p []byte) (int, error) {
	if len(w.needles) == 0 {
		return w.w.Write(p)
	}
	if w.pending == 0 && !containsAny(p, w.needles) {
		// Nothing to mask: write p itself, less any partial match.
		hold := partialMatch(p, w.needles)
		if _, err := w.w.Write(p[:len(p)-hold]); err != nil {
			return 0, err
		}
		w.buf = append(w.buf[:0], p[len(p)-hold:]...)
		w.masked = append(w.masked[:0], make([]bool, hold)...)
		w.pending = hold
		return len(p), nil
	}
	w.buf = append(w.buf[:w.pending], p...)
	w.masked = append(w.masked[:w.pending], make([]bool, len(p))...)
	markMatches(w.buf, w.needles, w.masked)
	hold := partialMatch(w.buf, w.needles)
	send := len(w.buf) - hold
	applyMask(w.buf[:send], w.masked, w.mask)
	if _, err := w.w.Write(w.buf[:send]); err != nil {
		return 0, err
	}
	w.pending = copy(w.buf, w.buf[send:])
	copy(w.masked, w.masked[send:])
	// The held bytes' old place may be past the next append's end.
	clear(w.buf[w.pending:])
	return len(p), nil
}

// Close writes the partial match the Writer holds back, which the stream
// ended before completing. It does not close the underlying writer.
func (w *Writer) Close() error {
	if w.pending == 0 {
		return nil
	}
	applyMask(w.buf[:w.pending], w.masked, w.mask)
	_, err := w.w.Write(w.buf[:w.pending])
	clear(w.buf[:w.pending])
	w.pending = 0
	return err
}

// String returns s with every exact match of any needle masked.
func String(s string, needles ...string) string {
	if !slices.ContainsFunc(needles, func(n string) bool { return n != "" && strings.Contains(s, n) }) {
		return s
	}
	b := []byte(s)
	masked := make([]bool, len(b))
	markMatches(b, views(needles), masked)
	applyMask(b, masked, maskFor(needles))
	return string(b)
}

// markMatches marks every byte of b inside a match of any needle, overlapping
// matches included.
func markMatches(b []byte, needles [][]byte, masked []bool) {
	for _, needle := range needles {
		for start := 0; ; start++ {
			i := bytes.Index(b[start:], needle)
			if i < 0 {
				break
			}
			start += i
			for k := range needle {
				masked[start+k] = true
			}
		}
	}
}

// applyMask replaces the marked bytes of b with m.
func applyMask(b []byte, masked []bool, m byte) {
	for i := range b {
		if masked[i] {
			b[i] = m
		}
	}
}

func containsAny(b []byte, needles [][]byte) bool {
	return slices.ContainsFunc(needles, func(n []byte) bool { return bytes.Contains(b, n) })
}

// partialMatch returns the length of the longest suffix of b that is a proper
// prefix of any needle.
func partialMatch(b []byte, needles [][]byte) int {
	longest := 0
	for _, needle := range needles {
		tail := b[max(0, len(b)-len(needle)+1):]
		for i := range len(tail) - longest {
			if bytes.HasPrefix(needle, tail[i:]) {
				longest = len(tail) - i
				break
			}
		}
	}
	return longest
}

// maskBytes are the bytes a mask may be made of, in order of preference. None
// means anything in JSON or HTML, so a masked document still parses.
const maskBytes = "*x-_.~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwyz"

// maskFor returns the first of maskBytes that no needle contains, so a mask
// cannot combine with the bytes around it into a new match. Needles holding
// every one of them between them get '*'.
func maskFor(needles []string) byte {
	for i := range len(maskBytes) {
		if !slices.ContainsFunc(needles, func(n string) bool { return strings.IndexByte(n, maskBytes[i]) >= 0 }) {
			return maskBytes[i]
		}
	}
	return '*'
}

// views returns the non-empty needles' bytes without copying them: the Secret
// already sits in the string Proxy Delivery built from the Injection
// Template, and a second heap copy would outlive it for no reason. The bytes
// are only ever read.
func views(needles []string) [][]byte {
	var out [][]byte
	for _, n := range needles {
		if n != "" {
			out = append(out, unsafe.Slice(unsafe.StringData(n), len(n)))
		}
	}
	return out
}

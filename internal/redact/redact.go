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
	"strings"
	"unsafe"
)

// Writer masks every exact match of a needle in what is written through it,
// including a match split across writes. It holds back only a trailing run
// of bytes that could begin a match, so a stream is delayed by no more than
// the needle's length.
type Writer struct {
	w       io.Writer
	needle  []byte
	mask    byte
	buf     []byte
	pending int // bytes at the start of buf held back from the last Write
}

// NewWriter returns a Writer that masks needle in everything written to w.
// An empty needle masks nothing.
func NewWriter(w io.Writer, needle string) *Writer {
	return &Writer{w: w, needle: view(needle), mask: maskFor(needle)}
}

// Write masks p and writes all of it to the underlying writer but for a
// trailing partial match, which it holds back until the next Write or Close.
// It never modifies p.
func (w *Writer) Write(p []byte) (int, error) {
	if len(w.needle) == 0 {
		return w.w.Write(p)
	}
	if w.pending == 0 && !bytes.Contains(p, w.needle) {
		// Nothing to mask: write p itself, less any partial match.
		hold := partialMatch(p[max(0, len(p)-len(w.needle)+1):], w.needle)
		if _, err := w.w.Write(p[:len(p)-hold]); err != nil {
			return 0, err
		}
		w.buf = append(w.buf[:0], p[len(p)-hold:]...)
		w.pending = hold
		return len(p), nil
	}
	w.buf = append(w.buf[:w.pending], p...)
	end := mask(w.buf, w.needle, w.mask)
	hold := partialMatch(w.buf[max(end, len(w.buf)-len(w.needle)+1):], w.needle)
	send := len(w.buf) - hold
	if _, err := w.w.Write(w.buf[:send]); err != nil {
		return 0, err
	}
	w.pending = copy(w.buf, w.buf[send:])
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
	_, err := w.w.Write(w.buf[:w.pending])
	clear(w.buf[:w.pending])
	w.pending = 0
	return err
}

// String returns s with every exact match of needle masked.
func String(s, needle string) string {
	if needle == "" || !strings.Contains(s, needle) {
		return s
	}
	b := []byte(s)
	mask(b, view(needle), maskFor(needle))
	return string(b)
}

// mask masks every match of needle in b, leftmost first, and returns the
// index just past the last one.
func mask(b, needle []byte, m byte) int {
	end := 0
	for {
		i := bytes.Index(b[end:], needle)
		if i < 0 {
			return end
		}
		end += i
		for k := range needle {
			b[end+k] = m
		}
		end += len(needle)
	}
}

// partialMatch returns the length of the longest suffix of b that is a
// prefix of needle.
func partialMatch(b, needle []byte) int {
	for i := range b {
		if bytes.HasPrefix(needle, b[i:]) {
			return len(b) - i
		}
	}
	return 0
}

// maskBytes are the bytes a mask may be made of, in order of preference. None
// means anything in JSON or HTML, so a masked document still parses.
const maskBytes = "*x-_.~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwyz"

// maskFor returns the first of maskBytes that needle does not contain, so a
// mask cannot combine with the bytes around it into a new match. A needle
// holding every one of them gets '*'.
func maskFor(needle string) byte {
	for i := range len(maskBytes) {
		if strings.IndexByte(needle, maskBytes[i]) < 0 {
			return maskBytes[i]
		}
	}
	return '*'
}

// view returns needle's bytes without copying them: the Secret already sits
// in the Injection Template's header string, and a second heap copy would
// outlive it for no reason. The bytes are only ever read.
func view(needle string) []byte {
	return unsafe.Slice(unsafe.StringData(needle), len(needle))
}

// Package secret holds plaintext Secret values in the core (ADR-0001). A
// Secret lives in locked memory outside the Go heap, cannot become a string,
// never formats, logs, or marshals its contents, and is wiped on Release.
//
// Copies the core cannot avoid still exist briefly: the gRPC buffer a value
// arrives in and the net/http buffer it leaves through. Memory hygiene in Go
// is a discipline; adopt runtime/secret once it leaves experiment.
package secret

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
)

// redacted is what a Secret shows instead of its contents.
const redacted = "[secret]"

// ErrReleased reports use of a Secret after Release.
var ErrReleased = errors.New("secret: use after Release")

// Secret is a plaintext Secret value. Copies of a Secret share one buffer, so
// releasing any copy releases them all.
type Secret struct {
	p *locked
}

type locked struct {
	mu      sync.Mutex
	buf     []byte // the whole mapping, nil once released
	n       int    // length of the value at the start of buf
	cleanup runtime.Cleanup
}

// New copies value into locked memory and wipes value. It fails rather than
// hold the value in memory that could be swapped out.
func New(value []byte) (*Secret, error) {
	defer clear(value)
	buf, err := allocate(max(len(value), 1))
	if err != nil {
		return nil, fmt.Errorf("secret: allocate locked memory: %w", err)
	}
	p := &locked{buf: buf, n: copy(buf, value)}
	// A Secret dropped without Release is still wiped once unreachable.
	p.cleanup = runtime.AddCleanup(p, free, buf)
	return &Secret{p: p}, nil
}

// Len returns the value's length in bytes, or 0 once released.
func (s Secret) Len() int {
	if s.p == nil {
		return 0
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	return s.p.n
}

// WriteTo writes the value to w. It is the only way the value leaves a
// Secret.
func (s Secret) WriteTo(w io.Writer) (int64, error) {
	if s.p == nil {
		return 0, ErrReleased
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if s.p.buf == nil {
		return 0, ErrReleased
	}
	n, err := w.Write(s.p.buf[:s.p.n])
	return int64(n), err
}

// Release wipes, unlocks, and unmaps the value. It is safe to call more than
// once.
func (s Secret) Release() {
	if s.p == nil {
		return
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if s.p.buf == nil {
		return
	}
	s.p.cleanup.Stop()
	free(s.p.buf)
	s.p.buf, s.p.n = nil, 0
}

// String returns a placeholder, never the value.
func (Secret) String() string { return redacted }

// GoString returns a placeholder, never the value.
func (Secret) GoString() string { return redacted }

// Format writes a placeholder for every verb, never the value.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue logs a placeholder, never the value.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

var errMarshal = errors.New("secret: a Secret cannot be marshaled")

// MarshalJSON refuses, so a Secret never lands in an encoded response or log.
func (Secret) MarshalJSON() ([]byte, error) { return nil, errMarshal }

// MarshalText refuses, so a Secret never lands in an encoded response or log.
func (Secret) MarshalText() ([]byte, error) { return nil, errMarshal }

func free(buf []byte) {
	clear(buf)
	_ = munlock(buf)
	_ = munmap(buf)
}

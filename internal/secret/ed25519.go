package secret

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
)

// Ed25519Key is an Ed25519 private key held like a Secret: in locked memory
// outside the Go heap, never formatted, logged, or marshaled, and wiped on
// Release. It signs; the private key never leaves it.
//
// Signing still copies the key to the heap for the length of each call:
// crypto/ed25519 caches an expanded key per key slice through a weak pointer,
// which memory outside the heap cannot have. That cached copy is not wiped;
// it is dropped once the garbage collector finds the call's copy unreachable.
type Ed25519Key struct {
	p      *locked
	public ed25519.PublicKey
}

// ParseEd25519Key reads an Ed25519 private key from s, which must hold one
// PKCS #8 PEM block of type PRIVATE KEY and nothing else, as
// `openssl genpkey -algorithm ed25519` writes. s is left unchanged.
//
// Parsing makes short-lived copies of the key on the heap; the ones this
// function holds are wiped before it returns.
func ParseEd25519Key(s *Secret) (*Ed25519Key, error) {
	if s == nil || s.p == nil {
		return nil, ErrReleased
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	if s.p.buf == nil {
		return nil, ErrReleased
	}

	data := s.p.buf[:s.p.n]
	// pem.Decode skips any text before the block; refuse it instead.
	if !bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN ")) {
		return nil, errors.New("the audit signing key is not PEM, or has data before the PEM block")
	}
	block, rest := pem.Decode(data)
	switch {
	case block == nil:
		return nil, errors.New("the audit signing key is not PEM")
	case block.Type != "PRIVATE KEY":
		clear(block.Bytes)
		return nil, fmt.Errorf("the audit signing key is a PEM %q block, want PRIVATE KEY (PKCS #8)", block.Type)
	case len(bytes.TrimSpace(rest)) > 0:
		clear(block.Bytes)
		return nil, errors.New("the audit signing key has data after the PEM block")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the audit signing key is not a valid PKCS #8 private key")
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the audit signing key is a %T, not an Ed25519 private key", parsed)
	}
	defer clear(private)

	buf, err := allocate(ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLockedMemory, err)
	}
	p := &locked{buf: buf, n: copy(buf, private)}
	p.cleanup = runtime.AddCleanup(p, free, buf)
	public := ed25519.PublicKey(bytes.Clone(private.Public().(ed25519.PublicKey)))
	return &Ed25519Key{p: p, public: public}, nil
}

// Public returns the public key.
func (k *Ed25519Key) Public() ed25519.PublicKey { return k.public }

// Sign returns the Ed25519 signature of msg.
func (k *Ed25519Key) Sign(msg []byte) ([]byte, error) {
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	if k.p.buf == nil {
		return nil, ErrReleased
	}
	private := make(ed25519.PrivateKey, k.p.n)
	defer clear(private)
	copy(private, k.p.buf[:k.p.n])
	return ed25519.Sign(private, msg), nil
}

// Release wipes, unlocks, and unmaps the private key. It is safe to call more
// than once.
func (k *Ed25519Key) Release() {
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	if k.p.buf == nil {
		return
	}
	k.p.cleanup.Stop()
	free(k.p.buf)
	k.p.buf, k.p.n = nil, 0
}

// String returns a placeholder, never the key.
func (Ed25519Key) String() string { return redacted }

// GoString returns a placeholder, never the key.
func (Ed25519Key) GoString() string { return redacted }

// Format writes a placeholder for every verb, never the key.
func (Ed25519Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue logs a placeholder, never the key.
func (Ed25519Key) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON refuses, so the key never lands in an encoded response or log.
func (Ed25519Key) MarshalJSON() ([]byte, error) { return nil, errMarshal }

// MarshalText refuses, so the key never lands in an encoded response or log.
func (Ed25519Key) MarshalText() ([]byte, error) { return nil, errMarshal }

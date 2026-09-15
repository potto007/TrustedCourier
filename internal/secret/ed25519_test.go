package secret

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// pkcs8PEM encodes key as a PKCS #8 PEM block.
func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newKeySecret(t *testing.T, value []byte) *Secret {
	t.Helper()
	s, err := New(value)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Release)
	return s
}

func TestParseEd25519KeySigns(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseEd25519Key(newKeySecret(t, pkcs8PEM(t, private)))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Release()

	if !key.Public().Equal(public) {
		t.Fatalf("Public = %x, want %x", key.Public(), public)
	}
	msg := []byte("audit checkpoint")
	sig, err := key.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, msg, sig) {
		t.Fatal("signature does not verify with the public key")
	}
}

func TestParseEd25519KeyRefusesOtherValues(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := pkcs8PEM(t, private)
	cases := []struct {
		name    string
		value   []byte
		wantErr string
	}{
		{"not PEM", []byte("not a key"), "PEM"},
		{"another block type", []byte(strings.Replace(string(good), "PRIVATE KEY", "PUBLIC KEY", 2)), "PRIVATE KEY"},
		{"trailing data", append(good, "trailing"...), "after the PEM block"},
		{"leading data", append([]byte("leading\n"), good...), "before the PEM block"},
		{"two keys", append(good, good...), "after the PEM block"},
		{"ECDSA key", pkcs8PEM(t, ecKey), "not an Ed25519"},
		{"bad DER", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x01}}), "PKCS #8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := ParseEd25519Key(newKeySecret(t, c.value))
			if err == nil {
				key.Release()
				t.Fatal("ParseEd25519Key succeeded")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not contain %q", err, c.wantErr)
			}
		})
	}
}

func TestEd25519KeyNeverShowsTheKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseEd25519Key(newKeySecret(t, pkcs8PEM(t, private)))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Release()

	seed := fmt.Sprintf("%x", private.Seed())
	for _, got := range []string{fmt.Sprintf("%v", key), fmt.Sprintf("%+v", *key), fmt.Sprintf("%#v", key), fmt.Sprintf("%x", key)} {
		if strings.Contains(got, seed) || got != redacted {
			t.Fatalf("formatted key = %q, want %q", got, redacted)
		}
	}
	if out, err := json.Marshal(key); err == nil {
		t.Fatalf("json.Marshal succeeded: %s", out)
	}
}

func TestReleasedEd25519KeyCannotSign(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseEd25519Key(newKeySecret(t, pkcs8PEM(t, private)))
	if err != nil {
		t.Fatal(err)
	}
	key.Release()
	key.Release() // idempotent
	if _, err := key.Sign([]byte("msg")); !errors.Is(err, ErrReleased) {
		t.Fatalf("Sign after Release = %v, want ErrReleased", err)
	}
}

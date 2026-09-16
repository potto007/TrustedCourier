// Package pemkey parses the PEM a Backend holds for a Courier Key: a
// certificate chain, or a private key. Every error names what was parsed, as
// the caller describes it, so the Operator reads which Courier Key is wrong.
package pemkey

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParseChain returns the DER certificates in data, leaf first. what
// describes the data, such as "the TLS certificate".
func ParseChain(data []byte, what string) ([][]byte, error) {
	if !IsPEM(data) {
		return nil, fmt.Errorf("%s is not PEM, or has data before the first PEM block", what)
	}
	var chain [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s has a PEM %q block, want only CERTIFICATE blocks", what, block.Type)
		}
		chain = append(chain, block.Bytes)
	}
	switch {
	case len(chain) == 0:
		return nil, fmt.Errorf("%s is not PEM", what)
	case len(bytes.TrimSpace(data)) > 0:
		return nil, fmt.Errorf("%s has data after the PEM blocks", what)
	}
	return chain, nil
}

// ParseSigner parses the private key PEM in data: PKCS #8, PKCS #1 (RSA), or
// SEC 1 (EC). The DER copy parsing needs is wiped before it returns; data is
// the caller's to wipe. what describes the data, such as "the TLS key".
func ParseSigner(data []byte, what string) (crypto.Signer, error) {
	if !IsPEM(data) {
		return nil, fmt.Errorf("%s is not PEM, or has data before the PEM block", what)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", what)
	}
	defer clear(block.Bytes)
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("%s has data after the PEM block", what)
	}
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%s is a PEM %q block, want PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY", what, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid private key", what)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s is a %T, which cannot sign", what, parsed)
	}
	return signer, nil
}

// MarshalSigner encodes key as PKCS #8 PEM.
func MarshalSigner(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalChain encodes the DER certificates in chain as PEM.
func MarshalChain(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// IsPEM reports whether data starts with a PEM block, after whitespace.
func IsPEM(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN "))
}

// KeyMatches reports whether private is the key of the certificate holding
// public.
func KeyMatches(public crypto.PublicKey, private crypto.Signer) error {
	p, ok := public.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !p.Equal(private.Public()) {
		return errors.New("the key does not match the certificate")
	}
	return nil
}

// Package contract holds the rules every Backend Plugin response must meet.
// The SDK applies them before a response leaves a plugin, so Plugin Authors
// see violations early, and the client applies them again on arrival,
// because the core cannot trust that a plugin used the SDK.
package contract

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on what crosses the plugin boundary.
const (
	MaxLocationBytes = 1024
	MaxValueBytes    = 1 << 20
	MaxListLength    = 10000
	MaxDetailBytes   = 1024
	// MaxMessageBytes bounds one gRPC message, above the largest List a
	// plugin may legitimately send.
	MaxMessageBytes = 16 << 20
	// maxErrorBytes bounds an error message relayed from a plugin.
	maxErrorBytes = 512
)

// Location checks a Backend location.
func Location(loc string) error {
	if loc == "" {
		return errors.New("location is empty")
	}
	if len(loc) > MaxLocationBytes {
		return fmt.Errorf("location is %d bytes, over the %d byte limit", len(loc), MaxLocationBytes)
	}
	return printable("location", loc)
}

// Prefix checks a List prefix, which may be empty.
func Prefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	return Location(prefix)
}

// Value checks a Secret or Courier Key value.
func Value(v []byte) error {
	if len(v) == 0 {
		return errors.New("value is empty")
	}
	if len(v) > MaxValueBytes {
		return fmt.Errorf("value is %d bytes, over the %d byte limit", len(v), MaxValueBytes)
	}
	return nil
}

// List checks the locations a List call for prefix returned.
func List(prefix string, locations []string) error {
	if len(locations) > MaxListLength {
		return fmt.Errorf("list has %d locations, over the %d limit", len(locations), MaxListLength)
	}
	seen := make(map[string]struct{}, len(locations))
	for i, loc := range locations {
		if err := Location(loc); err != nil {
			return fmt.Errorf("locations[%d]: %w", i, err)
		}
		if !strings.HasPrefix(loc, prefix) {
			return fmt.Errorf("locations[%d] does not start with the requested prefix", i)
		}
		if _, dup := seen[loc]; dup {
			return fmt.Errorf("locations[%d] is listed more than once", i)
		}
		seen[loc] = struct{}{}
	}
	return nil
}

// Detail checks a health detail.
func Detail(d string) error {
	if len(d) > MaxDetailBytes {
		return fmt.Errorf("health detail is %d bytes, over the %d byte limit", len(d), MaxDetailBytes)
	}
	return printable("health detail", d)
}

// MaxVersionBytes bounds the FIPS 140-3 module version a plugin reports,
// such as "v1.0.0" or "latest".
const MaxVersionBytes = 64

// FIPS140Version checks the module version a plugin reports.
func FIPS140Version(v string) error {
	if len(v) > MaxVersionBytes {
		return fmt.Errorf("fips140_version is %d bytes, over the %d byte limit", len(v), MaxVersionBytes)
	}
	return printable("fips140_version", v)
}

// printable rejects invalid UTF-8 and control characters, which could
// forge log lines or drive an Operator's terminal.
func printable(what, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8", what)
	}
	if i := strings.IndexFunc(s, unicode.IsControl); i >= 0 {
		return fmt.Errorf("%s contains a control character at byte %d", what, i)
	}
	return nil
}

// Sanitize makes untrusted text from a plugin safe to log or display: invalid
// UTF-8 and control characters become '?', and it is truncated.
func Sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxErrorBytes {
			b.WriteString("...")
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

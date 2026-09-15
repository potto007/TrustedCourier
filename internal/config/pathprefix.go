package config

import (
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// PathPrefix is a path prefix a Policy limits Proxy Delivery to. It matches
// the path after /proxy/{secret_name}/{upstream} by whole segments, after
// percent-decoding, so /repos/o/r allows /repos/o/r/issues but not
// /repos/o/rx.
type PathPrefix struct {
	text     string
	segments []string
}

// pathSegmentPattern is one escaped path segment made of RFC 3986 pchar
// bytes, without ';', which servlet containers read as starting parameters.
var pathSegmentPattern = regexp.MustCompile(`^(?:[A-Za-z0-9._~!$&'()*+,=:@-]|%[0-9A-Fa-f]{2})+$`)

// ParsePathPrefix parses an escaped path prefix such as /repos/o/r. A
// trailing slash is ignored.
func ParsePathPrefix(s string) (PathPrefix, error) {
	if !strings.HasPrefix(s, "/") {
		return PathPrefix{}, errors.New("must start with /")
	}
	if s == "/" {
		return PathPrefix{text: s}, nil
	}
	s = strings.TrimSuffix(s, "/")
	out := PathPrefix{text: s}
	for raw := range strings.SplitSeq(s[1:], "/") {
		if !pathSegmentPattern.MatchString(raw) {
			return PathPrefix{}, errors.New("must be a path of non-empty segments without '?', '#', ';', spaces, or invalid percent-encoding")
		}
		seg, err := url.PathUnescape(raw)
		switch {
		case err != nil:
			return PathPrefix{}, err
		case !utf8.ValidString(seg):
			return PathPrefix{}, errors.New("must decode to valid UTF-8")
		case hasControl(seg) || strings.ContainsAny(seg, `/\`):
			return PathPrefix{}, errors.New("must not encode a slash, backslash, or control character")
		case seg == "." || seg == "..":
			return PathPrefix{}, errors.New("must not contain dot segments")
		}
		out.segments = append(out.segments, seg)
	}
	return out, nil
}

// String returns the prefix as the Operator wrote it, without a trailing
// slash.
func (p PathPrefix) String() string { return p.text }

// Matches reports whether the escaped path starts with p's segments. A path
// that could reach something other than it appears to, with a dot segment,
// invalid percent-encoding, or invalid UTF-8, matches nothing.
func (p PathPrefix) Matches(escapedPath string) bool {
	segments, ok := decodePath(escapedPath)
	return ok && len(segments) >= len(p.segments) && slices.Equal(segments[:len(p.segments)], p.segments)
}

// decodePath returns the percent-decoded segments of an escaped path, or
// false if the path has a dot segment, including one behind an encoded slash
// or backslash or before ';' parameters, invalid percent-encoding, or invalid
// UTF-8. The empty path and "/" have no segments.
func decodePath(escaped string) ([]string, bool) {
	escaped = strings.TrimPrefix(escaped, "/")
	if escaped == "" {
		return nil, true
	}
	var segments []string
	for raw := range strings.SplitSeq(escaped, "/") {
		seg, err := url.PathUnescape(raw)
		if err != nil || !utf8.ValidString(seg) {
			return nil, false
		}
		for part := range strings.FieldsFuncSeq(seg, func(r rune) bool { return r == '/' || r == '\\' }) {
			if name, _, _ := strings.Cut(part, ";"); name == "." || name == ".." {
				return nil, false
			}
		}
		segments = append(segments, seg)
	}
	return segments, true
}

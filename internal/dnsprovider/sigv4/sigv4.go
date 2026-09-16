// Package sigv4 signs HTTP requests with AWS Signature Version 4, which is
// all Route 53 needs from an AWS SDK. It hashes and MACs with the standard
// library only, so FIPS mode covers it.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// Sign adds the Authorization and X-Amz-Date headers SigV4 needs to req,
// whose body is body. Every header req already carries is signed, and so is
// the host. secretAccessKey stays the caller's to wipe.
func Sign(req *http.Request, body []byte, accessKeyID string, secretAccessKey []byte, region, service string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payloadHash := sha256.Sum256(body)
	payload := hex.EncodeToString(payloadHash[:])
	req.Header.Set("X-Amz-Date", amzDate)

	// Canonical headers: lowercase names, trimmed values, sorted by name,
	// host included.
	names := []string{"host"}
	values := map[string]string{"host": req.Host}
	if values["host"] == "" {
		values["host"] = req.URL.Host
	}
	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "host" {
			continue
		}
		names = append(names, lower)
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = strings.Join(strings.Fields(v), " ")
		}
		values[lower] = strings.Join(trimmed, ",")
	}
	sort.Strings(names)
	names = slices.Compact(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + values[name] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath(req.URL),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		payload,
	}, "\n")
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(requestHash[:])}, "\n")

	kSecret := append([]byte("AWS4"), secretAccessKey...)
	defer clear(kSecret)
	kDate := hmacSHA256(kSecret, date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// canonicalPath is the URI-encoded path, each segment encoded once, or "/".
func canonicalPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, s := range segments {
		unescaped, err := url.PathUnescape(s)
		if err != nil {
			unescaped = s
		}
		segments[i] = awsEscape(unescaped)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery is the query sorted by name then value, each encoded as
// SigV4 wants.
func canonicalQuery(q url.Values) string {
	type pair struct{ k, v string }
	var pairs []pair
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, pair{awsEscape(k), awsEscape(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// awsEscape percent-encodes everything but the RFC 3986 unreserved
// characters, with uppercase hex digits.
func awsEscape(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

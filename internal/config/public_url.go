package config

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// validateAgentPublicURL accepts an origin, including a mapped public port.
// It does not resolve names or change the listener's TLS requirements.
func validateAgentPublicURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("agent_api.public_url must be an absolute http or https URL with a host")
	}
	if u.User != nil {
		return "", errors.New("agent_api.public_url must not contain credentials")
	}
	if (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", errors.New("agent_api.public_url must be an origin without a path, query, or fragment")
	}
	host := u.Hostname()
	addr, ipErr := netip.ParseAddr(host)
	if ipErr == nil {
		if addr.Zone() != "" || addr.Unmap().IsUnspecified() || addr.IsMulticast() {
			return "", errors.New("agent_api.public_url must name a reachable host, not a wildcard, multicast, or scoped address")
		}
	} else if strings.ContainsAny(u.Host, "[]") || !domainPattern.MatchString(strings.ToLower(strings.TrimSuffix(host, "."))) || len(host) > 253 {
		return "", errors.New("agent_api.public_url must name a valid DNS host or IP address")
	}
	// A colon in an IPv6 literal must be bracketed to be a URL authority.
	if ipErr == nil && addr.Is6() != strings.HasPrefix(u.Host, "[") {
		return "", errors.New("agent_api.public_url must bracket only IPv6 addresses")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("agent_api.public_url port must be from 1 to 65535")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("agent_api.public_url must not contain an empty port")
	}
	if u.Scheme == "http" && (ipErr != nil || !addr.Unmap().IsLoopback()) {
		return "", errors.New("agent_api.public_url requires https except for literal loopback IP addresses")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

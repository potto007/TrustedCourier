package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
)

// propagationPoll is how often the records are looked up while waiting.
var propagationPoll = 2 * time.Second

// Record is a TXT record DNS-01 validation looks for.
type Record struct {
	// Name is the record's name, such as _acme-challenge.example.com.
	Name string
	// Value is the TXT value.
	Value string
}

// WaitPropagated waits until every name server answers a TXT query for each
// record with its value, so the CA's validation is asked for only once it
// can succeed. One cfg.PropagationTimeout covers all the records. The
// servers are cfg.Resolvers, or each record's authoritative name servers found
// through the system resolver; the system resolver itself is never asked,
// since it caches a negative answer for longer than the wait.
func WaitPropagated(ctx context.Context, cfg config.DNS, records []Record) error {
	return waitPropagated(ctx, cfg, records, authoritativeServers)
}

// discover returns the authoritative servers for a record name. Tests supply
// local DNS servers so they exercise propagation without public DNS or port 53.
func waitPropagated(ctx context.Context, cfg config.DNS, records []Record, discover func(context.Context, string) ([]string, error)) error {
	if len(records) == 0 {
		return nil
	}
	timeout := cfg.PropagationTimeout
	if timeout <= 0 {
		timeout = config.DefaultDNSPropagationTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	serversByName := make(map[string][]string, len(records))
	for _, r := range records {
		if _, ok := serversByName[r.Name]; ok {
			continue
		}
		servers := cfg.Resolvers
		if len(servers) == 0 {
			var err error
			if servers, err = discover(ctx, r.Name); err != nil {
				return fmt.Errorf("%w; set agent_api.tls.acme.dns.resolvers to name servers to check the record on", err)
			}
		}
		serversByName[r.Name] = servers
	}
	for {
		var missing []string
		var lastErr error
		for _, r := range records {
			for _, server := range serversByName[r.Name] {
				values, err := lookupTXT(ctx, server, r.Name)
				if err != nil {
					lastErr = err
				}
				if err != nil || !slices.Contains(values, r.Value) {
					missing = append(missing, r.Name+" on "+server)
				}
			}
		}
		if len(missing) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			err := fmt.Errorf("the TXT record did not appear within %s: %s", timeout, strings.Join(missing, ", "))
			if lastErr != nil {
				err = fmt.Errorf("%w; the last lookup failed: %v", err, lastErr)
			}
			return err
		case <-time.After(propagationPoll):
		}
	}
}

// authoritativeServers finds the name servers of the zone that holds name,
// as IP address and port. The zone is the nearest parent of name with NS
// records; a top-level domain is never it, since its servers answer only
// referrals, and a failed NS lookup is an error rather than a step up to a
// parent that cannot be the zone.
func authoritativeServers(ctx context.Context, name string) ([]string, error) {
	candidates := zoneCandidates(config.DNS{}, name)
	for _, zone := range candidates[:max(len(candidates)-1, 0)] {
		records, err := net.DefaultResolver.LookupNS(ctx, zone)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue
			}
			return nil, fmt.Errorf("look up the name servers of %s: %w", zone, err)
		}
		if len(records) == 0 {
			continue
		}
		var servers []string
		for _, ns := range records {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, strings.TrimSuffix(ns.Host, "."))
			if err != nil {
				continue
			}
			for _, a := range addrs {
				servers = append(servers, net.JoinHostPort(a.IP.String(), "53"))
			}
		}
		if len(servers) == 0 {
			return nil, fmt.Errorf("none of the name servers of %s resolves to an address", zone)
		}
		return servers, nil
	}
	return nil, fmt.Errorf("no zone holding %s has name servers the system resolver knows", name)
}

// lookupTXT asks server for name's TXT records.
func lookupTXT(ctx context.Context, server, name string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return resolver.LookupTXT(ctx, name)
}

package dnsprovider

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
)

// propagationPoll is how often the record is looked up while waiting.
var propagationPoll = 2 * time.Second

// WaitPropagated waits until every name server answers a TXT query for name
// with value, so the CA's validation is asked for only once it can succeed.
// The servers are cfg.Resolvers, or the zone's authoritative name servers
// found through the system resolver, or the system resolver itself when
// they cannot be found. It gives up after cfg.PropagationTimeout.
func WaitPropagated(ctx context.Context, cfg config.DNS, name, value string) error {
	timeout := cfg.PropagationTimeout
	if timeout <= 0 {
		timeout = config.DefaultDNSPropagationTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	servers := cfg.Resolvers
	if len(servers) == 0 {
		servers = authoritativeServers(ctx, name)
	}
	if len(servers) == 0 {
		// The empty server is the system resolver.
		servers = []string{""}
	}
	for {
		var missing []string
		for _, server := range servers {
			values, err := lookupTXT(ctx, server, name)
			if err != nil || !slices.Contains(values, value) {
				missing = append(missing, server)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			where := "the system resolver"
			if missing[0] != "" {
				where = strings.Join(missing, ", ")
			}
			return fmt.Errorf("the TXT record at %s did not appear on %s within %s", name, where, timeout)
		case <-time.After(propagationPoll):
		}
	}
}

// authoritativeServers finds the name servers of the zone that holds name,
// as IP address and port, or nothing when the system resolver cannot say.
func authoritativeServers(ctx context.Context, name string) []string {
	for _, zone := range zoneCandidates(config.DNS{}, name) {
		records, err := net.DefaultResolver.LookupNS(ctx, zone)
		if err != nil || len(records) == 0 {
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
		return servers
	}
	return nil
}

// lookupTXT asks server, or the system resolver when server is empty, for
// name's TXT records.
func lookupTXT(ctx context.Context, server, name string) ([]string, error) {
	resolver := net.DefaultResolver
	if server != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, server)
			},
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return resolver.LookupTXT(ctx, name)
}

package dnsprovider

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/challtestsrv"
	"github.com/miekg/dns"
	"github.com/potto007/TrustedCourier/internal/config"
)

func TestWaitPropagatedUsesEachRecordsAuthoritativeServers(t *testing.T) {
	records := []Record{
		{Name: "_acme-challenge.first.test", Value: "first"},
		{Name: "_acme-challenge.second.test", Value: "second"},
		// An apex and its wildcard require different values at the same name.
		{Name: "_acme-challenge.first.test", Value: "wildcard"},
	}
	firstAddr := startIsolatedNameServer(t, map[string][]string{
		records[0].Name: {records[0].Value, records[2].Value},
	})
	secondAddr := startIsolatedNameServer(t, map[string][]string{
		records[1].Name: {records[1].Value},
	})
	var discovered []string
	discover := func(ctx context.Context, name string) ([]string, error) {
		discovered = append(discovered, name)
		if name == records[0].Name {
			return []string{firstAddr}, nil
		}
		if name == records[1].Name {
			return []string{secondAddr}, nil
		}
		t.Fatalf("unexpected discovery for %q", name)
		return nil, nil
	}
	cfg := config.DNS{PropagationTimeout: time.Second}
	if err := waitPropagated(context.Background(), cfg, records, discover); err != nil {
		t.Fatalf("WaitPropagated: %v", err)
	}
	if !slices.Equal(discovered, []string{records[0].Name, records[1].Name}) {
		t.Errorf("discovered %v, want each distinct record name once", discovered)
	}
}

func TestWaitPropagatedRequiresEveryServer(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, complete := range []bool{false, true} {
			t.Run(strconv.FormatBool(explicit)+"/"+strconv.FormatBool(complete), func(t *testing.T) {
				records := []Record{
					{Name: "_acme-challenge.first.test", Value: "first"},
					{Name: "_acme-challenge.second.test", Value: "second"},
				}
				firstAddr := startIsolatedNameServer(t, map[string][]string{
					records[0].Name: {records[0].Value},
					records[1].Name: {records[1].Value},
				})
				// Return a TXT answer even when the second value is missing.
				values := map[string][]string{
					records[0].Name: {records[0].Value},
					records[1].Name: {"unrelated"},
				}
				if complete {
					values[records[1].Name] = append(values[records[1].Name], records[1].Value)
				}
				secondAddr := startIsolatedNameServer(t, values)
				servers := []string{firstAddr, secondAddr}
				cfg := config.DNS{PropagationTimeout: 200 * time.Millisecond}
				if explicit {
					cfg.Resolvers = servers
				}
				discover := func(context.Context, string) ([]string, error) {
					if explicit {
						t.Fatal("explicit resolvers must bypass discovery")
					}
					return servers, nil
				}
				err := waitPropagated(context.Background(), cfg, records, discover)
				if complete {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), records[1].Name+" on "+secondAddr) {
					t.Fatalf("WaitPropagated = %v, want timeout for second record on second server", err)
				}
			})
		}
	}
}

// Each server has its own handler. challtestsrv registers a process-wide DNS
// handler, so multiple instances would all answer from the last one's records.
func startIsolatedNameServer(t *testing.T, records map[string][]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Authoritative = true
			for _, q := range req.Question {
				values, ok := records[strings.TrimSuffix(q.Name, ".")]
				if !ok {
					resp.Rcode = dns.RcodeRefused
					continue
				}
				if q.Qtype == dns.TypeTXT {
					for _, value := range values {
						resp.Answer = append(resp.Answer, &dns.TXT{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
							Txt: []string{value},
						})
					}
				}
			}
			_ = w.WriteMsg(resp)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- srv.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		_ = pc.Close()
		t.Fatalf("start DNS server: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return pc.LocalAddr().String()
}

func TestWaitPropagatedSharesDiscoveryDeadline(t *testing.T) {
	records := []Record{{Name: "_acme-challenge.first.test"}, {Name: "_acme-challenge.second.test"}}
	for _, parentTimeout := range []time.Duration{time.Hour, 100 * time.Millisecond} {
		t.Run(parentTimeout.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), parentTimeout)
			defer cancel()
			var firstDeadline time.Time
			discover := func(ctx context.Context, name string) ([]string, error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("discovery has no deadline")
				}
				if name == records[0].Name {
					firstDeadline = deadline
					return []string{"127.0.0.1:53"}, nil
				}
				if deadline != firstDeadline {
					t.Error("discovery reset the propagation deadline")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			cfg := config.DNS{PropagationTimeout: 200 * time.Millisecond}
			start := time.Now()
			err := waitPropagated(ctx, cfg, records, discover)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("WaitPropagated = %v, want discovery deadline exceeded", err)
			}
			if firstDeadline.After(start.Add(cfg.PropagationTimeout + 50*time.Millisecond)) {
				t.Error("discovery deadline exceeds the configured timeout")
			}
			parentDeadline, _ := ctx.Deadline()
			if firstDeadline.After(parentDeadline) {
				t.Error("discovery deadline exceeds the parent's deadline")
			}
		})
	}
}

// startNameServer runs a challtestsrv name server on a free port and returns
// its address.
func startNameServer(t *testing.T) (*challtestsrv.ChallSrv, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	srv, err := challtestsrv.New(challtestsrv.Config{DNSAddrs: []string{addr}, Log: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	srv.Run()
	t.Cleanup(srv.Shutdown)
	return srv, addr
}

func TestWaitPropagatedReturnsOnceTheResolversAnswer(t *testing.T) {
	ns, addr := startNameServer(t)
	propagationPoll = 50 * time.Millisecond
	t.Cleanup(func() { propagationPoll = 2 * time.Second })
	cfg := config.DNS{Resolvers: []string{addr}, PropagationTimeout: 5 * time.Second}

	go func() {
		time.Sleep(200 * time.Millisecond)
		ns.AddDNSTXTRecord("_acme-challenge.example.test", "other")
		ns.AddDNSTXTRecord("_acme-challenge.example.test", "wanted")
	}()
	start := time.Now()
	if err := WaitPropagated(context.Background(), cfg, []Record{{Name: "_acme-challenge.example.test", Value: "wanted"}}); err != nil {
		t.Fatalf("WaitPropagated: %v", err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Error("WaitPropagated returned before the record was set")
	}
}

func TestWaitPropagatedGivesUpAfterTheTimeout(t *testing.T) {
	ns, addr := startNameServer(t)
	propagationPoll = 50 * time.Millisecond
	t.Cleanup(func() { propagationPoll = 2 * time.Second })
	ns.AddDNSTXTRecord("_acme-challenge.example.test", "other")
	cfg := config.DNS{Resolvers: []string{addr}, PropagationTimeout: 300 * time.Millisecond}
	err := WaitPropagated(context.Background(), cfg, []Record{{Name: "_acme-challenge.example.test", Value: "wanted"}})
	if err == nil || !strings.Contains(err.Error(), "_acme-challenge.example.test on "+addr) {
		t.Fatalf("WaitPropagated = %v, want a timeout naming the record and the resolver", err)
	}
}

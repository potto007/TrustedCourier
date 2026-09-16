package dnsprovider

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/challtestsrv"
	"github.com/potto007/TrustedCourier/internal/config"
)

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
	srv, err := challtestsrv.New(challtestsrv.Config{DNSAddrs: []string{addr}})
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
	if err := WaitPropagated(context.Background(), cfg, "_acme-challenge.example.test", "wanted"); err != nil {
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
	err := WaitPropagated(context.Background(), cfg, "_acme-challenge.example.test", "wanted")
	if err == nil || !strings.Contains(err.Error(), addr) || !strings.Contains(err.Error(), "_acme-challenge.example.test") {
		t.Fatalf("WaitPropagated = %v, want a timeout naming the record and the resolver", err)
	}
}

package dnstt

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func waitGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		got := runtime.NumGoroutine()
		if got <= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not return to baseline: want <=%d, got %d", want, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDNSTTCloseStopsLeakOnFailingResolver reproduces the production leak: a
// DoH resolver whose dials always fail (as a parked NXDOMAIN domain does).
// dnstt.Close must stop every goroutine so the sender loops don't keep
// hammering the dead resolver forever.
func TestDNSTTCloseStopsLeakOnFailingResolver(t *testing.T) {
	base := runtime.NumGoroutine()

	failDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("dial failed: no such host")
	}

	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	d := &dnstt{
		domain:      domain,
		transport:   &dohDialer{url: "https://secure.avastdns.invalid/dns-query"},
		mtu:         135,
		dialContext: failDial,
	}
	if err := WithUTLSDistribution(defaultUTLSDistribution)(d); err != nil {
		t.Fatal(err)
	}
	pconn, err := d.transport.dial(d.clientHelloID, d.dialContext)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	d.pconn = NewDNSPacketConn(pconn, turbotunnel.DummyAddr{}, d.domain)

	rt, err := d.NewRoundTripper(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	// Drive a request so KCP starts polling through the failing resolver.
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "https://www.gstatic.com/generate_204", http.NoBody)
		client := &http.Client{Transport: rt, Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()

	time.Sleep(1 * time.Second) // let the poll/send loops spin
	if err := d.Close(); err != nil {
		t.Logf("Close returned: %v", err)
	}
	waitGoroutines(t, base)
}

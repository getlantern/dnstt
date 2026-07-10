package dnstt

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
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

// silentPacketConn accepts every write and never delivers a read until it is
// closed, modeling a reachable resolver whose tunnel server never answers. That
// case parks the Noise handshake read with no error, and before the fix it also
// deadlocked Close, which contends for the same sessAccess mutex.
type silentPacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func newSilentPacketConn() *silentPacketConn {
	return &silentPacketConn{closed: make(chan struct{})}
}

func (c *silentPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *silentPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *silentPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *silentPacketConn) LocalAddr() net.Addr              { return turbotunnel.DummyAddr{} }
func (c *silentPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *silentPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *silentPacketConn) SetWriteDeadline(time.Time) error { return nil }

// TestDNSTTCloseUnblocksSilentHandshake reproduces the production leak that
// TestDNSTTCloseStopsLeakOnFailingResolver does not: the resolver is reachable
// (writes succeed) but the tunnel never returns data, so the Noise handshake
// read blocks with no error. Close must return promptly (not wait on the
// handshake), and every goroutine must drain.
func TestDNSTTCloseUnblocksSilentHandshake(t *testing.T) {
	base := runtime.NumGoroutine()

	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile("server.pub")
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := noise.DecodeKey(string(bytes.TrimSpace(key)))
	if err != nil {
		t.Fatal(err)
	}
	d := &dnstt{domain: domain, mtu: 135, publicKey: pubkey}
	d.pconn = newSilentPacketConn()

	// A generous handshake bound backstops the drain assertion if closing the
	// packet conn does not itself unblock the KCP read; it is far longer than a
	// prompt Close, so it cannot mask a Close that waits on the handshake.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		_, _ = d.getStream(ctx) // enters the blocking handshake
	}()
	time.Sleep(200 * time.Millisecond) // let it reach the handshake read

	closeReturned := make(chan error, 1)
	go func() { closeReturned <- d.Close() }()
	select {
	case <-closeReturned:
	case <-time.After(1 * time.Second):
		t.Fatal("Close blocked on the in-flight handshake (deadlock not fixed)")
	}

	<-streamDone
	waitGoroutines(t, base)
}

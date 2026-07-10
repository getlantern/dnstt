package dnstt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for dependencies
type mockTransport struct {
	mock.Mock
}

func (m *mockTransport) dial(hello *utls.ClientHelloID) (net.PacketConn, error) {
	args := m.Called(hello)
	conn, _ := args.Get(0).(net.PacketConn)
	return conn, args.Error(1)
}

func (m *mockTransport) String() string {
	return "mockTransport"
}

func TestNewDNSTT(t *testing.T) {
	// Test missing transport
	_, err := NewDNSTT()
	assert.Error(t, err)

	// Test default ClientHelloID
	dtt, err := NewDNSTT(WithDoH("https://example.com"), WithTunnelDomain("t.iantem.io"))
	assert.NoError(t, err)
	assert.NotNil(t, dtt)
	assert.NotNil(t, dtt.(*dnstt).clientHelloID)
}

func TestDNSTT_NewRoundTripper(t *testing.T) {
	// NewRoundTripper is lazy — it does not dial eagerly. When the underlying
	// packet connection was never established (pconn == nil), the error surfaces
	// only when RoundTrip is called.
	d := &dnstt{}

	rt, err := d.NewRoundTripper(context.Background(), "example.com")
	require.NoError(t, err)
	require.NotNil(t, rt)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	require.NoError(t, err)
	_, err = rt.RoundTrip(req)
	assert.Error(t, err)
}

func TestRoundTripperE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DNS-tunnel E2E test in -short mode")
	}

	key, err := os.ReadFile("server.pub")
	require.NoError(t, err)
	pubKey := string(bytes.TrimSpace(key))

	const domain = "t.iantem.io"
	const url = "https://detectportal.firefox.com/success.txt"

	// Mirror radiance's config (/var/lib/lantern/dnstt.yml): try several major
	// DoH resolvers and accept the first that establishes. A single resolver may
	// be blocked or slow on a given network even when others work. Set
	// DNSTT_TEST_DOH to pin one.
	resolvers := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
	}
	if r := os.Getenv("DNSTT_TEST_DOH"); r != "" {
		resolvers = []string{r}
	}

	// dnstt establishment is flaky (frequent EOFs/resets/502s from the tunnel
	// front), so radiance races all resolvers concurrently and retries until one
	// succeeds. A single sequential attempt usually loses. Mirror that: run a
	// worker per resolver, each retrying, and take the first end-to-end 200.
	const overallBudget = 3 * time.Minute
	const perAttempt = 40 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), overallBudget)
	defer cancel()

	statusCh := make(chan int, len(resolvers))
	var lastErr atomic.Value
	for _, resolver := range resolvers {
		go func(resolver string) {
			for ctx.Err() == nil {
				status, err := dnsttRoundTrip(ctx, perAttempt, resolver, domain, pubKey, url)
				if err == nil {
					select {
					case statusCh <- status:
					case <-ctx.Done():
					}
					return
				}
				lastErr.Store(fmt.Errorf("%s: %w", resolver, err))
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second): // brief backoff before retrying this resolver
				}
			}
		}(resolver)
	}

	select {
	case status := <-statusCh:
		cancel() // stop the other workers
		require.Equal(t, http.StatusOK, status)
	case <-ctx.Done():
		err, _ := lastErr.Load().(error)
		t.Skipf("no DNS-tunnel resolver established within %s (tunnel degraded/unreachable): %v", overallBudget, err)
	}
}

// dnsttRoundTrip performs one full request through a freshly-built dnstt tunnel
// on the given resolver, tearing it down before returning. perAttempt caps a
// single try so a stalled tunnel is retried rather than consuming the budget.
func dnsttRoundTrip(ctx context.Context, perAttempt time.Duration, resolver, domain, pubKey, url string) (int, error) {
	dt, err := NewDNSTT(
		WithTunnelDomain(domain),
		WithDoH(resolver),
		WithPublicKey(pubKey),
	)
	if err != nil {
		return 0, err
	}
	defer dt.Close()

	rt, err := dt.NewRoundTripper(ctx, "")
	if err != nil {
		return 0, err
	}

	attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

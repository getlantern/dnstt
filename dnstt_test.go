package dnstt

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"testing"

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

func TestWithDialer_DoH(t *testing.T) {
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("custom dialer called")
	}
	dt, err := NewDNSTT(
		WithTunnelDomain("t.example.com"),
		WithDoH("https://example.com"),
		WithDialer(customDialer),
	)
	require.NoError(t, err)
	defer dt.Close()

	d := dt.(*dnstt)
	doh, ok := d.transport.(*dohDialer)
	require.True(t, ok)
	assert.NotNil(t, doh.dialContext, "dialContext should be set on dohDialer")

	// Verify the custom dialer is actually the one injected by calling it.
	_, err = doh.dialContext(context.Background(), "tcp", "example.com:443")
	assert.Error(t, err)
	assert.Equal(t, "custom dialer called", err.Error())
}

func TestWithDialer_DoT(t *testing.T) {
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("custom dialer called")
	}
	// For DoT, the dialer is called during NewDNSTT (transport.dial connects immediately),
	// so we expect NewDNSTT to fail with our custom dialer's error.
	_, err := NewDNSTT(
		WithTunnelDomain("t.example.com"),
		WithDoT("1.1.1.1:853"),
		WithDialer(customDialer),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "custom dialer called")
}

func TestWithDialer_DefaultFallback(t *testing.T) {
	// When no WithDialer is provided, a default dialer should still be injected.
	dt, err := NewDNSTT(
		WithTunnelDomain("t.example.com"),
		WithDoH("https://example.com"),
	)
	require.NoError(t, err)
	defer dt.Close()

	d := dt.(*dnstt)
	doh, ok := d.transport.(*dohDialer)
	require.True(t, ok)
	assert.NotNil(t, doh.dialContext, "dialContext should be set to default dialer")
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
	resolver := "https://dns.google/dns-query"
	domain := "t.iantem.io"

	key, err := os.ReadFile("server.pub")
	require.NoError(t, err)
	key = bytes.TrimSpace(key)

	dt, err := NewDNSTT(
		WithTunnelDomain(domain),
		WithDoH(resolver),
		WithPublicKey(string(key)),
	)
	require.NoError(t, err)
	defer dt.Close()
	rt, err := dt.NewRoundTripper(context.Background(), "")
	require.NoError(t, err)

	url := "https://mock.httpstatus.io/chain?count=2"
	// url := "https://detectportal.firefox.com/success.txt"
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	client := &http.Client{
		Transport: rt,
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

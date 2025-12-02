package dnstt

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	return args.Get(0).(net.PacketConn), args.Error(1)
}

func (m *mockTransport) String() string {
	return "mockTransport"
}

func TestNewDNSTT(t *testing.T) {
	// Test missing transport
	_, err := NewDNSTT()
	assert.Error(t, err)

	// Test default ClientHelloID
	dtt, err := NewDNSTT(WithDoH("https://example.com"))
	assert.NoError(t, err)
	assert.NotNil(t, dtt)
	assert.NotNil(t, dtt.(*dnstt).clientHelloID)
}

func TestDNSTT_WithConfigURL(t *testing.T) {
	config := `
dsntt:
  dohResolver: https://example.com
`
	var gzipped bytes.Buffer
	gz := gzip.NewWriter(&gzipped)
	_, err := gz.Write([]byte(config))
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == "http://localhost/dnstt_config.yaml.gz" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/gzip"}},
				Body:       io.NopCloser(bytes.NewReader(gzipped.Bytes())),
			}, nil
		}
		return nil, fmt.Errorf("unexpected URL: %s", req.URL.String())
	})

	d, err := NewDNSTT(
		WithDoH("https://fallback.example.com"),
		WithConfigURL("http://localhost/dnstt_config.yaml.gz"),
		WithHTTPClient(&http.Client{
			Transport: mockTransport,
		}),
	)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond) // Wait for config to be fetched
	assert.Equal(t, "DoH[https://example.com]", d.(*dnstt).transport.String())
}

// roundTripperFunc allows us to mock http.RoundTripper
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDNSTT_NewRoundTripper(t *testing.T) {
	mockTransport := &mockTransport{}
	mockTransport.On("dial", mock.Anything).Return(nil, errors.New("dial error"))

	dnstt := &dnstt{
		transport: mockTransport,
	}
	_, err := dnstt.NewRoundTripper(context.Background(), "example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dial error")
}

func TestRoundTripperE2E(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(
		os.Stdout,
		&slog.HandlerOptions{
			AddSource: true,
		},
	)))

	resolver := "https://cloudflare-dns.com/dns-query"
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
	rt, err := dt.NewRoundTripper(context.Background(), "")
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "https://detectportal.firefox.com/success.txt", nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	buf, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	defer resp.Body.Close()

	t.Logf("Response: %s", buf)
}

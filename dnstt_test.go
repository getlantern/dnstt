package dnstt

import (
	"bytes"
	"context"
	"errors"
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

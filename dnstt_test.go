package dnstt

import (
	"context"
	"errors"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

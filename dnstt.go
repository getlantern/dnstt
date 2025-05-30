// Package dnstt provides a DNS-based tunneling transport mechanism. It includes
// functionality for creating and managing DNS-based sessions, as well as options
// for configuring the transport.
package dnstt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// defaultUTLSDistribution is used to generate a `utls.ClientHelloID` when none is provided.
	defaultUTLSDistribution = "4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13"
)

// DNSTT defines the interface for a DNS-based tunneling transport.
// It provides methods for creating a new HTTP round tripper and closing the transport.
type DNSTT interface {
	// NewRoundTripper creates a new HTTP round tripper for the given address.
	// It manages session creation and reuse.
	NewRoundTripper(ctx context.Context, addr string) (http.RoundTripper, error)

	// Close releases resources and closes active sessions.
	Close() error
}

type dnstt struct {
	domain        dns.Name
	publicKey     []byte
	clientHelloID *utls.ClientHelloID
	transport     transport
	mtu           int

	sess       *smux.Session
	sessAccess sync.Mutex
	closed     atomic.Bool
}

// NewDNSTT creates a new DNSTT instance with the provided options. If no options are provided for
// ClientHelloID, one is generated using a default distribution. An error is returned if encountered
// while applying options or if an option to set the transport is not provided.
func NewDNSTT(options ...Option) (DNSTT, error) {
	dnstt := &dnstt{}
	for _, option := range options {
		if err := option(dnstt); err != nil {
			slog.Error("applying option", "option", option, "error", err)
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	if dnstt.clientHelloID == nil {
		slog.Info(
			"ClientHelloID not set, using default utls distribution to generate one",
			"distribution", defaultUTLSDistribution,
		)
		if err := WithUTLSDistribution(defaultUTLSDistribution)(dnstt); err != nil {
			return nil, fmt.Errorf("applying default utls distribution: %w", err)
		}
	}
	if dnstt.transport == nil {
		return nil, errors.New("a transport option (e.g., WithDoH or WithDoT) must be provided")
	}
	return dnstt, nil
}

// Close releases resources and closes active sessions for the dnstt instance.
func (d *dnstt) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	d.sessAccess.Lock()
	defer d.sessAccess.Unlock()
	if d.sess != nil {
		return d.sess.Close()
	}
	return nil
}

func (d *dnstt) isClosed() bool {
	return d.closed.Load()
}

// NewRoundTripper creates a new HTTP round tripper for the given address.
// It manages session creation and reuse.
func (d *dnstt) NewRoundTripper(ctx context.Context, addr string) (http.RoundTripper, error) {
	if d.isClosed() {
		return nil, errors.New("dnstt is closed")
	}

	d.sessAccess.Lock()
	defer d.sessAccess.Unlock()
	var err error
	if d.sess != nil {
		conn, err := d.sess.OpenStream()
		if err == nil {
			return &connectedRoundTripper{conn: conn}, nil
		}
		if !errors.Is(err, smux.ErrGoAway) {
			return nil, fmt.Errorf("opening stream: %w", err)
		}
		// the session stream id overflowed, so we need to create a new session
		slog.Debug("session stream id overflowed, closing current session")
		d.sess.Close()
	}

	slog.Info("creating new session", "transport", d.transport)
	pconn, err := d.transport.dial(d.clientHelloID)
	if err != nil {
		slog.Error("dial", "error", err, "transport", d.transport)
		return nil, fmt.Errorf("dial: %w", err)
	}
	pconn = NewDNSPacketConn(pconn, turbotunnel.DummyAddr{}, d.domain)
	sess, err := newSession(pconn, d.mtu, d.publicKey)
	if err != nil {
		pconn.Close()
		return nil, fmt.Errorf("creating session: %w", err)
	}
	conn, err := sess.OpenStream()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("opening stream: %w", err)
	}

	d.sess = sess
	return &connectedRoundTripper{conn: conn}, nil
}

// Option is a function type used to configure the dnstt instance.
type Option func(*dnstt) error

// WithDoH configures the client to send requests using DNS-over-HTTPS (DoH) through the specified
// public resolver URL.
//
// A list of public DNS servers that support DoH can be found at:
// https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers
func WithDoH(resolverURL string) Option {
	return func(d *dnstt) error {
		if d.transport != nil {
			return fmt.Errorf("transport already set to %s", d.transport)
		}
		_, err := url.Parse(resolverURL)
		if err != nil {
			return fmt.Errorf("invalid DoH URL: %w", err)
		}
		slog.Info("using DoH", "url", resolverURL)
		d.transport = &dohDialer{url: resolverURL}
		return nil
	}
}

// WithDoT configures the client to send requests using DNS-over-TLS (DoT) through the specified
// public resolver address ("host:port").
//
// A list of public DNS servers that support DoT can be found at:
// https://dnsprivacy.org/public_resolvers/#dns-over-tls-dot
func WithDoT(resolverAddr string) Option {
	return func(d *dnstt) error {
		if d.transport != nil {
			return fmt.Errorf("transport already set to %s", d.transport)
		}
		_, _, err := net.SplitHostPort(resolverAddr)
		if err != nil {
			return fmt.Errorf("invalid DoT address: %w", err)
		}
		slog.Info("using DoT", "addr", resolverAddr)
		d.transport = &dotDialer{addr: resolverAddr}
		return nil
	}
}

// WithTunnelDomain sets the base domain name used for the DNS tunnel.
//
// This should match the subdomain delegated to the tunnel server, as
// described in the DNS setup instructions.
func WithTunnelDomain(domain string) Option {
	return func(d *dnstt) error {
		domain, err := dns.ParseName(domain)
		if err != nil {
			return fmt.Errorf("invalid domain: %w", err)
		}

		d.domain = domain
		mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
		if mtu < 80 {
			return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
		}

		slog.Debug("effective MTU", "mtu", strconv.Itoa(mtu))
		d.mtu = mtu
		return nil
	}
}

// WithPublicKey sets the public key for the dnstt instance. key must be a hex-encoded and if
// provided, it is used to wrap the connection in a Noise channel.
func WithPublicKey(key string) Option {
	return func(d *dnstt) error {
		pubkey, err := noise.DecodeKey(key)
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		d.publicKey = pubkey
		return nil
	}
}

// WithUTLSDistribution uses the specified utls distribution to generate a ClientHelloID for the
// dnstt instance. If the ClientHelloID was already set by another option, an error is returned.
func WithUTLSDistribution(distribution string) Option {
	return func(d *dnstt) error {
		if d.clientHelloID != nil {
			return fmt.Errorf("ClientHelloID already set to %v", d.clientHelloID)
		}
		utlsClientHelloID, err := sampleUTLSDistribution(distribution)
		if err != nil {
			return fmt.Errorf("invalid utls distribution: %w", err)
		}
		d.clientHelloID = utlsClientHelloID
		return nil
	}
}

// WithUTLSClientHelloID sets a specific utls.ClientHelloID for the dnstt instance. If the
// ClientHelloID was already set by another option, an error is returned.
func WithUTLSClientHelloID(hello *utls.ClientHelloID) Option {
	return func(d *dnstt) error {
		if d.clientHelloID != nil {
			return fmt.Errorf("ClientHelloID already set to %v", d.clientHelloID)
		}
		d.clientHelloID = hello
		return nil
	}
}

// transport defines an interface for dialing a DNS-based connection.
type transport interface {
	// dial establishes a DNS-based connection using the provided ClientHelloID.
	dial(hello *utls.ClientHelloID) (net.PacketConn, error)
	// String returns a string representation of the transport.
	String() string
}

// dohDialer implements the transport interface for DNS-over-HTTPS.
type dohDialer struct {
	url string
}

func (d *dohDialer) dial(hello *utls.ClientHelloID) (net.PacketConn, error) {
	rt := NewUTLSRoundTripper(nil, hello)
	return NewHTTPPacketConn(rt, d.url, 32)
}

func (d *dohDialer) String() string { return "DoH[" + d.url + "]" }

// dotDialer implements the transport interface for DNS-over-TLS.
type dotDialer struct {
	addr string
}

func (d *dotDialer) dial(hello *utls.ClientHelloID) (net.PacketConn, error) {
	dialTLSContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return utlsDialContext(ctx, network, addr, nil, hello)
	}
	return NewTLSPacketConn(d.addr, dialTLSContext)
}

func (d *dotDialer) String() string { return "DoT[" + d.addr + "]" }

// connectedRoundTripper implements the http.RoundTripper interface for handling HTTP requests over
// a DNS-based connection.
type connectedRoundTripper struct {
	conn net.Conn
}

func (rt *connectedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	err := req.Write(rt.conn)
	if err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(rt.conn), req)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return resp, nil
}

///////////////////////////////////////////////////////////////////////
/////		Everything below is a direct copy from the original		/////
///////////////////////////////////////////////////////////////////////

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

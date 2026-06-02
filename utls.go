// Author: David Fifield
// david@bamsoftware.com
// https://www.bamsoftware.com/software/dnstt/
//
// package dnstt-client
// ///////////////////////////////////////////////////////////
// /////    This file is unmodified from the original    /////
// ///////////////////////////////////////////////////////////
package dnstt

// Support code for TLS camouflage using uTLS.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// utlsClientHelloIDMap is a correspondence between human-readable labels and
// supported utls.ClientHelloIDs.
var utlsClientHelloIDMap = []struct {
	Label string
	ID    *utls.ClientHelloID
}{
	{"random", &utls.HelloRandomizedALPN},
	{"Firefox", &utls.HelloFirefox_Auto},
	{"Firefox_55", &utls.HelloFirefox_55},
	{"Firefox_56", &utls.HelloFirefox_56},
	{"Firefox_63", &utls.HelloFirefox_63},
	{"Firefox_65", &utls.HelloFirefox_65},
	{"Firefox_99", &utls.HelloFirefox_99},
	{"Firefox_102", &utls.HelloFirefox_102},
	{"Firefox_105", &utls.HelloFirefox_105},
	{"Firefox_120", &utls.HelloFirefox_120},
	{"Chrome", &utls.HelloChrome_Auto},
	{"Chrome_58", &utls.HelloChrome_58},
	{"Chrome_62", &utls.HelloChrome_62},
	{"Chrome_70", &utls.HelloChrome_70},
	{"Chrome_72", &utls.HelloChrome_72},
	{"Chrome_83", &utls.HelloChrome_83},
	{"Chrome_87", &utls.HelloChrome_87},
	{"Chrome_96", &utls.HelloChrome_96},
	{"Chrome_100", &utls.HelloChrome_100},
	{"Chrome_102", &utls.HelloChrome_102},
	{"Chrome_120", &utls.HelloChrome_120},
	{"iOS", &utls.HelloIOS_Auto},
	{"iOS_11_1", &utls.HelloIOS_11_1},
	{"iOS_12_1", &utls.HelloIOS_12_1},
	{"iOS_13", &utls.HelloIOS_13},
	{"iOS_14", &utls.HelloIOS_14},
}

// utlsLookup returns a *utls.ClientHelloID from utlsClientHelloIDMap by a
// case-insensitive label match, or nil if there is no match.
func utlsLookup(label string) *utls.ClientHelloID {
	for _, entry := range utlsClientHelloIDMap {
		if strings.ToLower(label) == strings.ToLower(entry.Label) {
			return entry.ID
		}
	}
	return nil
}

// utlsDialContext connects to the given network address and initiates a TLS
// handshake with the provided ClientHelloID, and returns the resulting TLS
// connection.
func utlsDialContext(ctx context.Context, network, addr string, config *utls.Config, id *utls.ClientHelloID, dialFn func(context.Context, string, string) (net.Conn, error)) (*utls.UConn, error) {
	// Set the SNI from addr, if not already set.
	if config == nil {
		config = &utls.Config{}
	}
	if config.ServerName == "" {
		config = config.Clone()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		config.ServerName = host
	}
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}
	conn, err := dialFn(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, config, *id)
	// Must call before filtering curves: buildHandshakeState applies the
	// browser preset and overwrites CurvePreferences with the spec values.
	if err := uconn.BuildHandshakeState(); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("build handshake state: %w", err)
	}
	// Go 1.26's curveForCurveID only supports X25519, P256, P384, P521,
	// and X25519MLKEM768 (handled specially outside curveForCurveID).
	// Some uTLS presets include FFDHE group IDs (256, 257) and draft PQ
	// curves (X25519Kyber768Draft00 / 0x6399) that are not valid ECDHE
	// curves. Strip them so makeClientHello does not fail with
	// "tls: CurvePreferences includes unsupported curve".
	//
	// config shares the same *Config as uconn.Conn.config, so modifying
	// curvePreferences here also takes effect for makeClientHello later.
	if len(config.CurvePreferences) > 0 {
		filtered := make([]utls.CurveID, 0, len(config.CurvePreferences))
		for _, c := range config.CurvePreferences {
			switch c {
			case utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
				utls.X25519MLKEM768:
				filtered = append(filtered, c)
			}
		}
		config.CurvePreferences = filtered
	}
	uconn.HandshakeState.Hello.SupportedCurves = config.CurvePreferences
	// We must call Handshake before returning, or else the UConn may not
	// actually use the selected ClientHelloID. It depends on whether a Read
	// or a Write happens first. If a Read happens first, the connection
	// will use the normal crypto/tls fingerprint. If a Write happens first,
	// it will use the selected fingerprint as expected.
	// https://github.com/refraction-networking/utls/issues/75
	//
	// Use Conn.Handshake() to bypass UConn.handshakeContext() which would
	// call BuildHandshakeState again and re-apply the spec's curves.
	err = uconn.Conn.Handshake()
	if err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// The goal of utlsRoundTripper is: provide an http.RoundTripper abstraction
// that retains the features of http.Transport (e.g., persistent connections and
// HTTP/2 support), while making TLS connections using uTLS in place of
// crypto/tls. The challenge is: while http.Transport provides a DialTLSContext
// hook, setting it to non-nil disables automatic HTTP/2 support in the client.
// Most of the uTLS fingerprints contain an ALPN extension containing "h2";
// i.e., they declare support for HTTP/2. If the server also supports HTTP/2,
// then uTLS may negotiate an HTTP/2 connection without the http.Transport
// knowing it, which leads to an HTTP/1.1 client speaking to an HTTP/2 server, a
// protocol error.
//
// The code here uses an idea adapted from meek_lite in obfs4proxy:
// https://gitlab.com/yawning/obfs4/commit/4d453dab2120082b00bf6e63ab4aaeeda6b8d8a3
// Instead of setting DialTLSContext on an http.Transport and exposing it
// directly, we expose a wrapper type, utlsRoundTripper, which contains within
// it either an http.Transport or an http2.Transport. The first time a caller
// calls RoundTrip on the wrapper, we initiate a uTLS connection
// (bootstrapConn), then peek at the ALPN-negotiated protocol: if "h2", create
// an internal http2.Transport; otherwise, create an internal http.Transport. In
// either case, set DialTLSContext (or DialTLS for http2.Transport) on the
// created Transport to a function that dials using uTLS. As a special case, the
// first time the DialTLS callback is called, it reuses bootstrapConn (the one
// made to peek at the ALPN), rather than make a new connection.
//
// Subsequent calls to RoundTripper on the wrapper just pass the requests though
// the previously created http.Transport or http2.Transport. We assume that in
// future RoundTrips, the ALPN-negotiated protocol will remain the same as it
// was in the initial RoundTrip. At this point it is the http.Transport or
// http2.Transport calling DialTLSContext, not us, so we cannot dynamically swap
// the underlying transport based on the ALPN.
//
// https://bugs.torproject.org/tpo/anti-censorship/pluggable-transports/meek/29077
// https://github.com/refraction-networking/utls/issues/16

// utlsRoundTripper is an http.RoundTripper that uses uTLS (with a specified
// ClientHelloID) to make TLS connections.
//
// Can only be reused among servers which negotiate the same ALPN.
type utlsRoundTripper struct {
	clientHelloID *utls.ClientHelloID
	config        *utls.Config
	dialFn        func(context.Context, string, string) (net.Conn, error)
	innerLock     sync.Mutex
	inner         http.RoundTripper
}

// NewUTLSRoundTripper creates a utlsRoundTripper with the given TLS
// configuration and ClientHelloID.
func NewUTLSRoundTripper(config *utls.Config, id *utls.ClientHelloID) *utlsRoundTripper {
	return &utlsRoundTripper{
		clientHelloID: id,
		config:        config,
		// inner will be set in the first call to RoundTrip.
	}
}

// NewUTLSRoundTripperWithDialer creates a utlsRoundTripper that uses dialFn for
// all outbound TCP connections. Pass nil to use the default net.Dialer.
func NewUTLSRoundTripperWithDialer(config *utls.Config, id *utls.ClientHelloID, dialFn func(context.Context, string, string) (net.Conn, error)) *utlsRoundTripper {
	return &utlsRoundTripper{
		clientHelloID: id,
		config:        config,
		dialFn:        dialFn,
	}
}

func (rt *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "http":
		// If http, don't invoke uTLS; just pass it to an ordinary http.Transport.
		return http.DefaultTransport.RoundTrip(req)
	case "https":
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q", req.URL.Scheme)
	}

	var err error
	rt.innerLock.Lock()
	if rt.inner == nil {
		// On the first call, make an http.Transport or http2.Transport
		// as appropriate.
		rt.inner, err = makeRoundTripper(req, rt.config, rt.clientHelloID, rt.dialFn)
	}
	rt.innerLock.Unlock()
	if err != nil {
		return nil, err
	}

	// Forward the request to the inner http.Transport or http2.Transport.
	return rt.inner.RoundTrip(req)
}

// makeRoundTripper makes a bootstrap TLS configuration using the given TLS
// configuration and ClientHelloID, and creates an http.Transport or
// http2.Transport, depending on the negotated ALPN. The Transport is set up to
// make future TLS connections using the same TLS configuration and
// ClientHelloID.
func makeRoundTripper(req *http.Request, config *utls.Config, id *utls.ClientHelloID, dialFn func(context.Context, string, string) (net.Conn, error)) (http.RoundTripper, error) {
	addr, err := addrForDial(req.URL)
	if err != nil {
		return nil, err
	}

	bootstrapConn, err := utlsDialContext(req.Context(), "tcp", addr, config, id, dialFn)
	if err != nil {
		return nil, err
	}

	// Peek at the ALPN-negotiated protocol.
	protocol := bootstrapConn.ConnectionState().NegotiatedProtocol

	// Protects bootstrapConn.
	var lock sync.Mutex
	// This is the callback for future dials done by the inner
	// http.Transport or http2.Transport.
	dialTLSContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		lock.Lock()
		defer lock.Unlock()

		// On the first dial, reuse bootstrapConn.
		if bootstrapConn != nil {
			uconn := bootstrapConn
			bootstrapConn = nil
			return uconn, nil
		}

		// Later dials make a new connection.
		uconn, err := utlsDialContext(ctx, "tcp", addr, config, id, dialFn)
		if err != nil {
			return nil, err
		}
		if uconn.ConnectionState().NegotiatedProtocol != protocol {
			return nil, fmt.Errorf("unexpected switch from ALPN %q to %q",
				protocol, uconn.ConnectionState().NegotiatedProtocol)
		}

		return uconn, nil
	}

	// Construct an http.Transport or http2.Transport depending on ALPN.
	switch protocol {
	case http2.NextProtoTLS:
		// Unfortunately http2.Transport does not expose the same
		// configuration options as http.Transport with regard to
		// timeouts, etc., so we are at the mercy of the defaults.
		// https://github.com/golang/go/issues/16581
		return &http2.Transport{
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				// Ignore the *tls.Config parameter; use our
				// static config instead.
				return dialTLSContext(context.Background(), network, addr)
			},
		}, nil
	default:
		// With http.Transport, copy important default fields from
		// http.DefaultTransport, such as TLSHandshakeTimeout and
		// IdleConnTimeout, before overriding DialTLSContext.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialTLSContext = dialTLSContext
		return tr, nil
	}
}

// addrForDial extracts a host:port address from a URL, suitable for dialing.
func addrForDial(url *url.URL) (string, error) {
	host := url.Hostname()
	// net/http would use golang.org/x/net/idna here, to convert a possible
	// internationalized domain name to ASCII.
	port := url.Port()
	if port == "" {
		// No port? Use the default for the scheme.
		switch url.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported URL scheme %q", url.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

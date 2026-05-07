// Package dnstt provides a DNS-based tunneling transport mechanism. It includes
// functionality for creating and managing DNS-based sessions, as well as options
// for configuring the transport.
package dnstt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// defaultUTLSDistribution is used to generate a `utls.ClientHelloID` when none is provided.
	defaultUTLSDistribution = "4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13"

	tracerName = "github.com/getlantern/dnstt"
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

	pconn  net.PacketConn
	convID uint32

	// sessCancel cancels the context passed to the session span goroutine.
	// Protected by sessAccess.
	sessCancel context.CancelFunc
}

// NewDNSTT creates a new DNSTT instance with the provided options. If no options are provided for
// ClientHelloID, one is generated using a default distribution. An error is returned if encountered
// while applying options or if an option to set the transport is not provided.
func NewDNSTT(options ...Option) (DNSTT, error) {
	dnstt := &dnstt{}
	for _, option := range options {
		if err := option(dnstt); err != nil {
			slog.Error("applying option", "error", err)
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	if len(dnstt.domain) == 0 {
		return nil, errors.New("tunnel domain must be set using WithTunnelDomain")
	}
	if dnstt.transport == nil {
		return nil, errors.New("a transport option (e.g., WithDoH or WithDoT) must be provided")
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

	slog.Info("creating new session", "transport", dnstt.transport)
	pconn, err := dnstt.transport.dial(dnstt.clientHelloID)
	if err != nil {
		slog.Error("dial", "error", err, "transport", dnstt.transport)
		return nil, fmt.Errorf("dial: %w", err)
	}
	pconn = NewDNSPacketConn(pconn, turbotunnel.DummyAddr{}, dnstt.domain)
	dnstt.pconn = pconn
	return dnstt, nil
}

// Close releases resources and closes active sessions for the dnstt instance.
func (d *dnstt) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	d.sessAccess.Lock()
	defer d.sessAccess.Unlock()
	if d.sessCancel != nil {
		d.sessCancel()
		d.sessCancel = nil
	}
	if d.sess != nil {
		return d.sess.Close()
	}
	return nil
}

func (d *dnstt) isClosed() bool {
	return d.closed.Load()
}

func (d *dnstt) maybeCreateSession() (err error) {
	d.sessAccess.Lock()
	defer d.sessAccess.Unlock()
	if d.sess != nil && !d.sess.IsClosed() {
		return nil
	}
	if d.sessCancel != nil {
		d.sessCancel()
		d.sessCancel = nil
	}
	if d.pconn == nil {
		return errors.New("no packet connection: transport dial may have failed")
	}

	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(turbotunnel.DummyAddr{}, nil, 0, 0, d.pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %w", err)
	}
	defer func() {
		if err != nil {
			d.convID = 0
			conn.Close()
		}
	}()

	d.convID = conn.GetConv()
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Tune KCP for low-latency interactive use over a high-delay DNS tunnel:
	//   nodelay=1  → minimum RTO 30 ms (vs 100 ms default)
	//   interval=10 → flush/retransmit tick every 10 ms
	//   resend=2   → fast-retransmit after 2 duplicate ACKs
	//   nc=1       → disable congestion window (window limited only by
	//                the static send/recv window sizes set below)
	conn.SetNoDelay(1, 10, 2, 1)
	// Send ACKs immediately rather than batching them with the next
	// 10 ms tick; this lets the remote side open its send window sooner.
	conn.SetACKNoDelay(true)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !conn.SetMtu(d.mtu) {
		return fmt.Errorf("setting MTU to %d", d.mtu)
	}

	// Put a Noise channel on top of the KCP conn.
	var rw io.ReadWriteCloser = conn
	if d.publicKey != nil {
		// Put a Noise channel on top of the KCP conn.
		rw, err = noise.NewClient(conn, d.publicKey)
		if err != nil {
			return fmt.Errorf("opening Noise channel: %w", err)
		}
	}

	// Start a smux session
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	d.sess, err = smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}

	// check if dnstt is closed again before assigning the new session
	if d.isClosed() {
		d.sess.Close()
		return errors.New("dnstt is closed")
	}

	convID := d.convID
	sessCtx, cancel := context.WithCancel(context.Background())
	d.sessCancel = cancel
	go func() {
		_, span := otel.Tracer(tracerName).Start(sessCtx, "dnstt.session",
			trace.WithAttributes(attribute.String("conv_id", fmt.Sprintf("%08x", convID))))
		defer span.End()
		<-sessCtx.Done()
	}()
	slog.Debug("begin session", "sessionID", fmt.Sprintf("%08x", d.convID))
	return nil
}

func (d *dnstt) getStream() (*smux.Stream, error) {
	err := d.maybeCreateSession()
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	if !d.sess.IsClosed() {
		stream, err := d.sess.OpenStream()
		if err == nil {
			return stream, nil
		}
		if !errors.Is(err, smux.ErrGoAway) {
			return nil, fmt.Errorf("opening stream: %w", err)
		}
		// the session stream id overflowed, so we need to create a new session
		slog.Debug("session stream id overflowed, closing current session")
		d.sess.Close()
	}
	err = d.maybeCreateSession()
	if err != nil {
		return nil, fmt.Errorf("creating new session: %w", err)
	}

	stream, err := d.sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("opening stream: %w", err)
	}
	return stream, nil
}

// maxRoundTripRetries is the number of times a request is retried when the
// tunnel returns a premature EOF (e.g. when the upstream server times out
// the TLS handshake before the DNS tunnel completes it).
const maxRoundTripRetries = 5

// retryBaseDelay is the starting backoff duration before the first retry.
// Each subsequent retry doubles the delay (capped at retryMaxDelay), with
// ±25% random jitter applied to avoid synchronized retries.
const retryBaseDelay = 500 * time.Millisecond

// retryMaxDelay caps the exponential backoff to avoid very long waits.
const retryMaxDelay = 5 * time.Second

// NewRoundTripper creates a new HTTP round tripper for the given address.
// It manages session creation and reuse.
func (d *dnstt) NewRoundTripper(ctx context.Context, addr string) (http.RoundTripper, error) {
	if d.isClosed() {
		return nil, errors.New("dnstt is closed")
	}
	inner := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, streamSpan := otel.Tracer(tracerName).Start(ctx, "dnstt.stream")
			stream, err := d.getStream()
			if err != nil {
				streamSpan.RecordError(err)
				streamSpan.SetStatus(codes.Error, err.Error())
				streamSpan.End()
				return nil, fmt.Errorf("creating stream: %w", err)
			}
			streamSpan.SetAttributes(
				attribute.String("conv_id", fmt.Sprintf("%08x", d.convID)),
				attribute.Int("stream_id", int(stream.ID())),
			)
			slog.DebugContext(ctx, "begin stream", slog.String("convID", fmt.Sprintf("%08x", d.convID)), slog.Uint64("streamID", uint64(stream.ID())))
			return &conn{Stream: stream, sessID: d.convID, span: streamSpan}, nil
		},
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:8080") // dummy to force request to be sent correctly
		},
		// A persistent TLS session cache allows session resumption (TLS 1.3
		// PSK / TLS 1.2 session tickets) for subsequent connections to the
		// same host. Without this, every smux stream requires a full TLS
		// handshake (~7-9 DNS round trips for the server Certificate alone at
		// 135-byte MTU). With session resumption, subsequent handshakes are
		// 1-RTT (~200ms) instead of ~8s, which is critical for redirect chains
		// where each hop to the same host otherwise triggers a fresh handshake
		// that exceeds many upstream servers' TLS negotiation timeouts.
		TLSClientConfig: &tls.Config{
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		},
	}
	// resetSession closes the current smux session so that the next
	// getStream call creates a new one with a clean KCP state.
	resetSession := func() {
		d.sessAccess.Lock()
		if d.sessCancel != nil {
			d.sessCancel()
			d.sessCancel = nil
		}
		if d.sess != nil {
			d.sess.Close()
		}
		d.sessAccess.Unlock()
	}
	return &retryRoundTripper{
		inner:            inner,
		maxRetries:       maxRoundTripRetries,
		resetSession:     resetSession,
	}, nil
}

// retryRoundTripper wraps an http.Transport and retries requests that fail with
// a premature EOF or tunnel timeout. This can happen when an upstream server
// (e.g. Cloudflare) times out a slow TLS handshake before the DNS tunnel has
// finished delivering all the data. On retry the DoH connection is already
// warm, so the tunnel is faster and the handshake succeeds.
//
// When a context deadline or timeout fires (degraded KCP session), resetSession
// is called before the retry so the next attempt gets a fresh KCP/Noise session.
type retryRoundTripper struct {
	inner        *http.Transport
	maxRetries   int
	resetSession func() // closes the current session; next retry creates a fresh one
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, span := otel.Tracer(tracerName).Start(req.Context(), "dnstt.request",
		trace.WithAttributes(
			attribute.String("http.request.method", req.Method),
			attribute.String("url.full", req.URL.String()),
		),
	)
	defer span.End()
	req = req.WithContext(ctx)

	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			if req.Body != nil && req.GetBody == nil {
				// Cannot replay a streaming request body; give up.
				return nil, lastErr
			}

			// Exponential backoff with ±25% jitter: gives the DoH
			// connections time to warm up before the next attempt.
			delay := retryBaseDelay * (1 << (attempt - 1))
			if delay > retryMaxDelay {
				delay = retryMaxDelay
			}
			jitter := time.Duration(rand.Int63n(int64(delay) / 2))
			if rand.Intn(2) == 0 {
				delay += jitter
			} else {
				delay -= jitter
			}
			slog.Debug("retrying request after tunnel EOF", "attempt", attempt, "error", lastErr, "backoff", delay)
			select {
			case <-time.After(delay):
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}

			r.inner.CloseIdleConnections()
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("retrying request body: %w", err)
				}
				req.Body = body
			}
		}
		resp, err := r.inner.RoundTrip(req)
		if err == nil {
			span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
			if resp.StatusCode >= 400 {
				span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
			}
			return resp, nil
		}
		// A deadline or cancellation on the caller's context must not be
		// treated as a tunnel failure: *url.Error wrapping
		// context.DeadlineExceeded satisfies net.Error.Timeout(), which
		// would otherwise trigger resetSession() and disrupt every
		// concurrent RoundTrip sharing the same smux session.
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		if !isTunnelEOF(err) {
			return nil, err
		}
		// If the stream timed out, the KCP session may be degraded.
		// Reset it so the next retry gets a fresh session with a clean state.
		if isNetTimeout(err) && r.resetSession != nil {
			slog.Debug("stream timeout — resetting KCP session before retry", "attempt", attempt)
			r.resetSession()
		}
		lastErr = err
	}
	span.RecordError(lastErr)
	span.SetStatus(codes.Error, lastErr.Error())
	return nil, lastErr
}

// isTunnelEOF returns true when err represents a retryable tunnel failure:
// a premature EOF (upstream server closed the connection before the DNS tunnel
// finished delivering all data) or a net timeout (e.g. context deadline).
func isTunnelEOF(err error) bool {
	return errors.Is(err, io.EOF) || isNetTimeout(err)
}

// isNetTimeout returns true when err is (or wraps) a net.Error with Timeout.
func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
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
			return fmt.Errorf("[WithDoH] transport already set to %s", d.transport)
		}
		_, err := url.Parse(resolverURL)
		if err != nil {
			return fmt.Errorf("[WithDoH] invalid URL: %w", err)
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
			return fmt.Errorf("[WithDoT] transport already set to %s", d.transport)
		}
		_, _, err := net.SplitHostPort(resolverAddr)
		if err != nil {
			return fmt.Errorf("[WithDoT] invalid address: %w", err)
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
			return fmt.Errorf("[WithTunnelDomain] invalid domain: %w", err)
		}

		d.domain = domain
		mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
		if mtu < 80 {
			return fmt.Errorf("[WithTunnelDomain] domain %s leaves only %d bytes for payload", domain, mtu)
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
			return fmt.Errorf("[WithPublicKey] invalid public key: %w", err)
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
			return fmt.Errorf("[WithUTLSDistribution] ClientHelloID already set to %v", d.clientHelloID)
		}
		utlsClientHelloID, err := sampleUTLSDistribution(distribution)
		if err != nil {
			return fmt.Errorf("[WithUTLSDistribution] invalid utls distribution: %w", err)
		}
		d.clientHelloID = utlsClientHelloID
		slog.Debug("uTLS fingerprint",
			"client", utlsClientHelloID.Client,
			"version", utlsClientHelloID.Version,
		)
		return nil
	}
}

// WithUTLSClientHelloID sets a specific utls.ClientHelloID for the dnstt instance. If the
// ClientHelloID was already set by another option, an error is returned.
func WithUTLSClientHelloID(hello *utls.ClientHelloID) Option {
	return func(d *dnstt) error {
		if d.clientHelloID != nil {
			return fmt.Errorf("[WithUTLSClientHelloID] ClientHelloID already set to %v", d.clientHelloID)
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
	var rt http.RoundTripper
	if hello == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// Disable DefaultTransport's default Proxy =
		// ProxyFromEnvironment setting, for conformity
		// with utlsRoundTripper and with DoT mode,
		// which do not take a proxy from the
		// environment.
		transport.Proxy = nil
		rt = transport
	} else {
		rt = NewUTLSRoundTripper(nil, hello)
	}
	return NewHTTPPacketConn(rt, d.url, 32)
}

func (d *dohDialer) String() string { return "DoH[" + d.url + "]" }

// dotDialer implements the transport interface for DNS-over-TLS.
type dotDialer struct {
	addr string
}

func (d *dotDialer) dial(hello *utls.ClientHelloID) (net.PacketConn, error) {
	var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if hello == nil {
		dialTLSContext = (&tls.Dialer{}).DialContext
	} else {
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utlsDialContext(ctx, network, addr, nil, hello)
		}
	}
	return NewTLSPacketConn(d.addr, dialTLSContext)
}

func (d *dotDialer) String() string { return "DoT[" + d.addr + "]" }

type conn struct {
	*smux.Stream
	sessID uint32
	span   trace.Span
}

func (c *conn) Write(b []byte) (int, error) {
	n, err := c.Stream.Write(b)
	if err == io.EOF {
		// smux Stream.Write may return io.EOF.
		err = nil
	}
	if err != nil {
		id := fmt.Sprintf("%08x:%d", c.sessID, c.Stream.ID())
		slog.Error("stream write error", "stream", id, "error", err)
	}
	return n, err
}

func (c *conn) Read(b []byte) (int, error) {
	n, err := c.Stream.Read(b)
	if err != nil && err != io.EOF {
		id := fmt.Sprintf("%08x:%d", c.sessID, c.Stream.ID())
		slog.Error("stream read error", "stream", id, "error", err)
	}
	return n, err
}

func (c *conn) Close() error {
	defer c.span.End()
	slog.Debug("closing conn", "streamID", c.Stream.ID())
	return c.Stream.Close()
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

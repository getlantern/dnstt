// Package dnstt provides a DNS-based tunneling transport mechanism. It includes
// functionality for creating and managing DNS-based sessions, as well as options
// for configuring the transport.
package dnstt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/keepcurrent"
	"github.com/goccy/go-yaml"
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

	httpClient   *http.Client
	configURL    string
	pollInterval time.Duration

	sess       *smux.Session
	sessAccess sync.Mutex
	closed     atomic.Bool
}

// NewDNSTT creates a new DNSTT instance with the provided options. If no options are provided for
// ClientHelloID, one is generated using a default distribution. An error is returned if encountered
// while applying options or if an option to set the transport is not provided.
func NewDNSTT(options ...Option) (DNSTT, error) {
	dnstt := &dnstt{pollInterval: 12 * time.Hour}
	for _, option := range options {
		if err := option(dnstt); err != nil {
			slog.Error("applying option", "error", err)
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
	dnstt.keepCurrent()

	return dnstt, nil
}

// WithHTTPClient sets the HTTP client to use for fetching the dnstt configuration. For example, the client
// could be censorship-resistant in some way.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(d *dnstt) error {
		d.httpClient = httpClient
		return nil
	}
}

// WithConfigURL sets the URL from which to continually fetch updated dnstt configurations.
func WithConfigURL(configURL string) Option {
	return func(d *dnstt) error {
		d.configURL = configURL
		return nil
	}
}

// WithPollInterval sets the interval at which to poll for updated dnstt configurations.
func WithPollInterval(interval time.Duration) Option {
	return func(d *dnstt) error {
		d.pollInterval = interval
		return nil
	}
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

func (d *dnstt) onNewConfig(gzippedYML []byte) error {
	cfg, err := processYaml(gzippedYML)
	if err != nil {
		return fmt.Errorf("failed to process dnstt config: %w", err)
	}

	opts := make([]Option, 0)
	if cfg.Domain != "" {
		opts = append(opts, WithTunnelDomain(cfg.Domain))
	}
	if cfg.PublicKey != "" {
		opts = append(opts, WithPublicKey(cfg.PublicKey))
	}
	if cfg.DoHResolver != nil {
		opts = append(opts, WithDoH(*cfg.DoHResolver))
	}
	if cfg.DoTResolver != nil {
		opts = append(opts, WithDoT(*cfg.DoTResolver))
	}
	if cfg.UTLSDistribution != nil {
		opts = append(opts, WithUTLSDistribution(*cfg.UTLSDistribution))
	}

	for _, option := range opts {
		if err := option(d); err != nil {
			return fmt.Errorf("applying option: %w", err)
		}
	}
	return nil
}

type config struct {
	Domain           string  `yaml:"domain"`    // DNS tunnel domain, e.g., "t.iantem.io"
	PublicKey        string  `yaml:"publicKey"` // DNSTT server public key
	DoHResolver      *string `yaml:"dohResolver,omitempty"`
	DoTResolver      *string `yaml:"dotResolver,omitempty"`
	UTLSDistribution *string `yaml:"utlsDistribution,omitempty"`
}

func processYaml(gzippedYaml []byte) (config, error) {
	r, gzipErr := gzip.NewReader(bytes.NewReader(gzippedYaml))
	if gzipErr != nil {
		return config{}, fmt.Errorf("failed to create gzip reader: %w", gzipErr)
	}
	yml, err := io.ReadAll(r)
	if err != nil {
		return config{}, fmt.Errorf("failed to read gzipped file: %w", err)
	}
	path, err := yaml.PathString("$.dsntt")
	if err != nil {
		return config{}, fmt.Errorf("failed to create config path: %w", err)
	}
	var cfg config
	if err = path.Read(bytes.NewReader(yml), &cfg); err != nil {
		return config{}, fmt.Errorf("failed to read config: %w", err)
	}

	return cfg, nil
}

// keepCurrent fetches the dnstt configuration from the given URL and keeps it up
// to date by fetching it periodically.
func (d *dnstt) keepCurrent() {
	if d.configURL == "" {
		slog.Debug("No config URL provided -- not updating fronting configuration")
		return
	}

	slog.Debug("Updating dnstt configuration", slog.String("url", d.configURL))
	source := keepcurrent.FromWebWithClient(d.configURL, d.httpClient)
	chDB := make(chan []byte)
	dest := keepcurrent.ToChannel(chDB)

	runner := keepcurrent.NewWithValidator(
		d.validator(),
		source,
		dest,
	)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("panicked while waiting for dnstt config",
					slog.Any("recover", r),
					slog.String("stack", string(debug.Stack())))
			}
		}()
		for data := range chDB {
			slog.Debug("received new dnstt configuration")
			if err := d.onNewConfig(data); err != nil {
				slog.Error("failed to apply new dnstt configuration", "error", err)
			} else {
				slog.Info("applied new dnstt configuration",
					"domain", d.domain,
					"transport", d.transport,
				)
			}
		}
	}()

	runner.Start(d.pollInterval)
}

func (d *dnstt) validator() func([]byte) error {
	return func(data []byte) error {
		if _, err := processYaml(data); err != nil {
			slog.Error("failed to validate dnstt configuration", "error", err)
			return err
		}
		return nil
	}
}

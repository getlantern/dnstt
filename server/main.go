// This is a slightly modified version of [dnstt-server](https://www.bamsoftware.com/software/dnstt/dnstt-server).
// This version is modified to proxy the HTTP requests received over the tunnel directly, instead of
// forwarding them to a predefined upstream proxy.
package main

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	responseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	maxResponseDelay = 1 * time.Second

	// Number of sendLoop goroutines to run concurrently. Each goroutine
	// holds one DNS response open (for up to maxResponseDelay) to bundle
	// downstream packets into it before sending. More goroutines allow
	// more queries to be served in parallel: each active client sends up
	// to 16 concurrent polls (client-side pollLimit), so this value should
	// comfortably exceed the expected number of simultaneous clients × 16.
	// Goroutine overhead is negligible (~8 KB stack each).
	numSendLoops = 100

	// Size of the channel that feeds records from recvLoop to the sendLoop
	// goroutines. Sized well above numSendLoops so that recvLoop's
	// non-blocking send (default: drop) does not lose records during bursts
	// where all numSendLoops goroutines are busy holding a response open for
	// up to maxResponseDelay. A drop means the client's DNS query goes
	// unanswered, slowing downstream delivery until the next poll.
	sendLoopChanSize = numSendLoops * 10

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second

	// How frequently to send TCP keepalive probes to upstream targets. The OS
	// closes the connection after a system-dependent number of missed probes
	// (typically ~9 on Linux with the default 75 s probe interval, so ~11 min
	// total). A short period here means a hung upstream is detected and the
	// pipeData goroutines unblocked much sooner.
	upstreamKeepalivePeriod = 30 * time.Second

	// How long a single KCP write may block before the session is considered
	// dead. Writes stall when the remote client stops ACKing (KCP send-window
	// full), which is the main symptom of a silently-disappeared client. With
	// this deadline enforced on every write, the smux keepalive goroutine —
	// which writes a ping every 10 s — will fail fast rather than blocking
	// indefinitely, allowing smux to detect and close the dead session.
	// kcpWriteTimeout is the per-op write deadline on the KCP session. It
	// must be large enough to survive a full KCP send window filling up
	// while the client is busy doing a slow TLS handshake over DNS. DNS
	// round trips are ~200ms and a TLS Certificate can be 3-8KB, so
	// ~22+ DNS trips for the cert alone ≈ 4-5s. With KCP congestion window
	// disabled (nc=1) and smux keepalives at 10s, 120s gives plenty of
	// margin for the application data phase without pinning zombie sessions.
	kcpWriteTimeout = 120 * time.Second
	// kcpReadTimeout is the per-op read deadline on the KCP session. If no
	// data arrives for this long, the client has silently disappeared. Must
	// be larger than the longest possible idle gap (client-side poll
	// backs off to maxPollDelay=10s, so 120s is comfortably above that).
	kcpReadTimeout = 120 * time.Second
)

var (
	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// Control this value with the -mtu command-line option.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload = 1280 - 40 - 8
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateKeypair generates a private key and the corresponding public key. If
// privkeyFilename and pubkeyFilename are respectively empty, it prints the
// corresponding key to standard output; otherwise it saves the key to the given
// file name. The private key is saved with mode 0400 and the public key is
// saved with 0666 (before umask). In case of any error, it attempts to delete
// any files it has created before returning.
func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	// Filenames to delete in case of error (avoid leaving partially written
	// files).
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			fmt.Fprintf(os.Stderr, "deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				fmt.Fprintf(os.Stderr, "cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)

	if privkeyFilename != "" {
		// Save the privkey to a file.
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		err = noise.WriteKey(f, privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		// Save the pubkey to a file.
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		err = noise.WriteKey(f, pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	// All good, allow the written files to remain.
	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// handleStream acts as a basic HTTP proxy, connecting a client stream to the requested HTTP target.
func handleStream(stream *smux.Stream, conv uint32) error {
	// Set the deadline now (inside the goroutine) so the clock starts
	// when the goroutine is actually running, not before it is scheduled.
	if err := stream.SetDeadline(time.Now().Add(kcpReadTimeout)); err != nil {
		slog.Warn("failed to set stream deadline", slog.Any("err", err))
	}

	// Use a single bufio.Reader for the entire lifetime of this stream.
	// http.ReadRequest may pre-fetch bytes beyond the request headers into
	// the buffer; we must pass the same reader to pipeData so those bytes
	// are not silently dropped when we copy client→target data.
	br := bufio.NewReader(stream)
	req, err := http.ReadRequest(br)
	if err != nil {
		return fmt.Errorf("stream %08x:%d HTTP request read: %v", conv, stream.ID(), err)
	}

	targetAddr := req.Host
	if !strings.Contains(targetAddr, ":") {
		if req.URL.Scheme == "https" || req.Method == "CONNECT" {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	targetConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		if req.Method == "CONNECT" {
			fmt.Fprintf(stream, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		} else {
			resp := &http.Response{
				StatusCode: http.StatusBadGateway,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Request:    req,
			}
			resp.Write(stream)
		}
		return fmt.Errorf("stream %08x:%d connect target %s: %v", conv, stream.ID(), targetAddr, err)
	}
	defer targetConn.Close()
	// Enable TCP keepalives so the OS can detect and close connections to
	// upstream targets that stop responding without sending FIN/RST. Without
	// this, a hung server holds the pipeData goroutines open indefinitely.
	// Keepalives are best-effort: log failures but do not abort the stream,
	// since the proxy still works correctly; it just loses the early-detection
	// safety net on platforms where these syscalls are unsupported.
	if tc, ok := targetConn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			slog.Warn("SetKeepAlive failed", slog.String("conv", fmt.Sprintf("%08x", conv)), slog.Any("stream_id", stream.ID()), slog.Any("err", err))
		} else if err := tc.SetKeepAlivePeriod(upstreamKeepalivePeriod); err != nil {
			slog.Warn("SetKeepAlivePeriod failed", slog.String("conv", fmt.Sprintf("%08x", conv)), slog.Any("stream_id", stream.ID()), slog.Any("err", err))
		}
	}

	if req.Method == "CONNECT" {
		// HTTP tunnel
		fmt.Fprintf(stream, "HTTP/1.1 200 Connection Established\r\n\r\n")
	} else {
		// For regular HTTP requests, rewrite the request line to origin-form and forward
		req.RequestURI = "" // Required by http.Request.Write
		err = req.Write(targetConn)
		if err != nil {
			return fmt.Errorf("stream %08x:%d forward HTTP request: %v", conv, stream.ID(), err)
		}
	}

	// Clear the stream deadline before piping: the request phase is done, so
	// pipeData can run for as long as the upstream connection is alive.
	stream.SetDeadline(time.Time{})
	pipeData(stream, br, targetConn)
	return nil
}

// pipeData bidirectionally copies between the smux stream and the upstream TCP
// connection. br must be the same bufio.Reader used by http.ReadRequest so that
// any bytes pre-fetched into its buffer are not lost.
//
// We drain br's internal buffer first (via io.CopyN), then copy the raw stream
// directly. We deliberately avoid io.Copy(targetConn, br) because
// bufio.Reader implements io.WriterTo, and WriteTo unconditionally calls
// targetConn.Write(empty) before filling its buffer — a 0-byte write that
// blocks forever on net.Pipe connections and stalls in production.
func pipeData(stream io.ReadWriteCloser, br *bufio.Reader, targetConn io.ReadWriteCloser) {
	done := make(chan struct{})
	go func() {
		io.Copy(stream, targetConn)
		stream.Close()
		close(done)
	}()
	if n := br.Buffered(); n > 0 {
		io.CopyN(targetConn, br, int64(n)) //nolint:errcheck
	}
	io.Copy(targetConn, stream)
	targetConn.Close()
	<-done // Wait for the stream to close.
}

// rollingDeadlineRW wraps a kcp.UDPSession and resets read/write deadlines on
// every I/O call. This ensures:
//   - Reads time out if no data arrives within kcpReadTimeout (detects a stalled
//     session where the client has silently disappeared and stopped querying).
//   - Writes time out within kcpWriteTimeout if the client's KCP receive window
//     is full (i.e. the client has stopped ACKing), which lets smux keepalive
//     failures surface quickly instead of blocking indefinitely.
type rollingDeadlineRW struct {
	conn         *kcp.UDPSession
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (r *rollingDeadlineRW) Read(b []byte) (int, error) {
	r.conn.SetReadDeadline(time.Now().Add(r.readTimeout))
	return r.conn.Read(b)
}

func (r *rollingDeadlineRW) Write(b []byte) (int, error) {
	r.conn.SetWriteDeadline(time.Now().Add(r.writeTimeout))
	return r.conn.Write(b)
}

func (r *rollingDeadlineRW) Close() error {
	return r.conn.Close()
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, privkey []byte) error {
	// Put a Noise channel on top of the KCP conn, wrapped in rolling per-op
	// deadlines so that a silently-disappeared client is detected promptly.
	rw, err := noise.NewServer(&rollingDeadlineRW{
		conn:         conn,
		readTimeout:  kcpReadTimeout,
		writeTimeout: kcpWriteTimeout,
	}, privkey)
	if err != nil {
		return fmt.Errorf("failed to create noise connection: %w", err)
	}

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return fmt.Errorf("failed to accept stream: %w", err)
		}
		slog.Info("begin stream", slog.String("conv", fmt.Sprintf("%08x", conn.GetConv())), slog.Any("stream_id", stream.ID()))
		go func() {
			defer func() {
				slog.Info("end stream", slog.String("conv", fmt.Sprintf("%08x", conn.GetConv())), slog.Any("stream_id", stream.ID()))
				stream.Close()
			}()
			err := handleStream(stream, conn.GetConv())
			if err != nil {
				slog.Error("handleStream failed", slog.String("conv", fmt.Sprintf("%08x", conn.GetConv())), slog.Any("stream_id", stream.ID()), slog.Any("err", err))
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		slog.Info("begin session", slog.String("conv", fmt.Sprintf("%08x", conn.GetConv())))
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Tune KCP for low-latency interactive use over a high-delay DNS tunnel:
		//   nodelay=1  → minimum RTO 30 ms (vs 100 ms default)
		//   interval=10 → flush/retransmit tick every 10 ms
		//   resend=2   → fast-retransmit after 2 duplicate ACKs
		//   nc=1       → disable congestion window
		conn.SetNoDelay(1, 10, 2, 1)
		// Send ACKs immediately rather than batching them with the next tick.
		conn.SetACKNoDelay(true)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		if rc := conn.SetMtu(mtu); !rc {
			panic(rc)
		}
		go func() {
			defer func() {
				slog.Info("end session", slog.String("conv", fmt.Sprintf("%08x", conn.GetConv())))
				conn.Close()
			}()
			err := acceptStreams(conn, privkey)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				slog.Error("acceptStreams failed", slog.String("conv", fmt.Sprintf("%08x", conn.GetConv())), slog.Any("err", err))
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding. It
// returns a nil error only when a packet was read successfully. It returns
// io.EOF only when there were 0 bytes remaining to read from r. It returns
// io.ErrUnexpectedEOF when EOF occurs in the middle of an encoded packet.
//
// The prefixing scheme is as follows. A length prefix L < 0xe0 means a data
// packet of L bytes. A length prefix L >= 0xe0 means padding of L - 0xe0 bytes
// (not counting the length of the length prefix itself).
func nextPacket(r *bytes.Reader) ([]byte, error) {
	// Convert io.EOF to io.ErrUnexpectedEOF.
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(io.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for for carrying downstream data in a TXT record.
func responseFor(query *dns.Message, domain dns.Name) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			slog.Warn("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			slog.Warn("BADVERS: unsupported EDNS version", slog.Any("version", version))
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		slog.Warn("FORMERR: unexpected question count", slog.Any("count", len(query.Question)))
		return resp, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		slog.Warn("NXDOMAIN: not authoritative", slog.Any("name", question.Name))
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		slog.Warn("NOTIMPL: unrecognized OPCODE", slog.Any("opcode", query.Opcode()))
		return resp, nil
	}

	if question.Type != dns.RRTypeTXT {
		// We only support QTYPE == TXT.
		resp.Flags |= dns.RcodeNameError
		// No log message here; it's common for recursive resolvers to
		// send NS or A queries when the client only asked for a TXT. I
		// suspect this is related to QNAME minimization, but I'm not
		// sure. https://tools.ietf.org/html/rfc7816
		// log.Printf("NXDOMAIN: QTYPE %d != TXT", question.Type)
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error, make like the name doesn't exist.
		resp.Flags |= dns.RcodeNameError
		slog.Warn("NXDOMAIN: base32 decoding error", slog.Any("err", err))
		return resp, nil
	}
	payload = payload[:n]

	// We require clients to support EDNS(0) with a minimum payload size;
	// otherwise we would have to set a small KCP MTU (only around 200
	// bytes). https://tools.ietf.org/html/rfc6891#section-7 "If there is a
	// problem with processing the OPT record itself, such as an option
	// value that is badly formatted or that includes out-of-range values, a
	// FORMERR MUST be returned."
	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		slog.Warn("FORMERR: requester payload too small", slog.Any("payload_size", payloadSize), slog.Any("minimum", maxUDPPayload))
		return resp, nil
	}

	return resp, payload
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
// recvLoop sends instances of record to sendLoop via a channel. sendLoop
// receives instances of record and may fill in the message's Answer section
// before sending it.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on ttConn's incoming queue. Whenever
// a query calls for a response, constructs a partial response and passes it to
// sendLoop over ch.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				slog.Warn("ReadFrom temporary error", slog.Any("err", err))
				continue
			}
			return err
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			slog.Warn("cannot parse DNS query", slog.Any("err", err))
			continue
		}

		resp, payload := responseFor(&query, domain)
		// Extract the ClientID from the payload.
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			// Discard padding and pull out the packets contained in
			// the payload.
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacket(r)
				if err != nil {
					break
				}
				// Feed the incoming packet to KCP.
				ttConn.QueueIncoming(p, clientID)
			}
		} else {
			// Payload is not long enough to contain a ClientID.
			if resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
				slog.Warn("NXDOMAIN: payload too short for ClientID", slog.Any("bytes", n))
			}
		}
		// If a response is called for, pass it to sendLoop via the channel.
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID}:
			default:
			}
		}
	}
}

// sendLoop repeatedly receives records from ch. Those that represent an error
// response, it sends on the network immediately. Those that represent a
// response capable of carrying data, it packs full of as many packets as will
// fit while keeping the total size under maxEncodedPayload, then sends it.
func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, maxEncodedPayload int) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				slog.Debug("closing sendLoop")
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			// If it's a non-error response, we can fill the Answer
			// section with downstream packets.

			// Any changes to how responses are built need to happen
			// also in computeMaxEncodedPayload.
			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil, // will be filled in below
				},
			}

			var payload bytes.Buffer
			limit := maxEncodedPayload
			// We loop and bundle as many packets from OutgoingQueue
			// into the response as will fit. Any packet that would
			// overflow the capacity of the DNS response, we stash
			// to be bundled into a future response.
			timer := time.NewTimer(maxResponseDelay)
			for {
				var p []byte
				unstash := ttConn.Unstash(rec.ClientID)
				outgoing := ttConn.OutgoingQueue(rec.ClientID)
				// Prioritize taking a packet first from the
				// stash, then from the outgoing queue, then
				// finally check for the expiration of the timer
				// or for a receive on ch (indicating a new
				// query that we must respond to).
				select {
				case p = <-unstash:
				default:
					select {
					case p = <-unstash:
					case p = <-outgoing:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						case <-timer.C:
						case nextRec = <-ch:
						}
					}
				}
				// We wait for the first packet in a bundle
				// only. The second and later packets must be
				// immediately available or they will be omitted
				// from this bundle.
				timer.Reset(0)

				if len(p) == 0 {
					// timer expired or receive on ch, we
					// are done with this response.
					break
				}

				limit -= 2 + len(p)
				if payload.Len() == 0 {
					// No packet length check for the first
					// packet; if it's too large, we allow
					// it to be truncated and dropped by the
					// receiver.
				} else if limit < 0 {
					// Stash this packet to send in the next
					// response.
					ttConn.Stash(p, rec.ClientID)
					break
				}
				if int(uint16(len(p))) != len(p) {
					panic(len(p))
				}
				binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}
			timer.Stop()

			rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payload.Bytes())
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			slog.Error("resp WireFormat error", slog.Any("err", err))
			continue
		}
		// Truncate if necessary.
		// https://tools.ietf.org/html/rfc1035#section-4.1.1
		if len(buf) > maxUDPPayload {
			slog.Debug("truncating response", slog.Any("size", len(buf)), slog.Any("max", maxUDPPayload))
			buf = buf[:maxUDPPayload]
			buf[2] |= 0x02 // TC = 1
		}

		// Now we actually send the message as a UDP packet.
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				slog.Warn("WriteTo temporary error", slog.Any("err", err))
				continue
			}
			return err
		}
	}
	return nil
}

// computeMaxEncodedPayload computes the maximum amount of downstream TXT RR
// data that keep the overall response size less than maxUDPPayload, in the
// worst case when the response answers a query that has a maximum-length name
// in its Question section. Returns 0 in the case that no amount of data makes
// the overall response size small enough.
//
// This function needs to be kept in sync with sendLoop with regard to how it
// builds candidate responses.
func computeMaxEncodedPayload(limit int) int {
	// 64+64+64+62 octets, needs to be base32-decodable.
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		// Compute the encoded length of maxLengthName and that its
		// length is actually at the maximum of 255 octets.
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1 // For the terminating null label.
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  dns.RRTypeTXT,
				Class: dns.RRTypeTXT,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit, // requester's UDP payload size
				TTL:   0,          // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, dns.Name([][]byte{}))
	// As in sendLoop.
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   responseTTL,
			Data:  nil, // will be filled in below
		},
	}

	// Binary search to find the maximum payload length that does not result
	// in a wire-format message whose length exceeds the limit.
	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

func runIPTablesCmd(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	if output, err := c.CombinedOutput(); err != nil {
		cmd = cmd + " " + strings.Join(args, " ")
		return fmt.Errorf("failed to run %q: %w, output: %s", cmd, err, output)
	}
	return nil
}

// setupIPTables sets up the iptables rules to redirect incoming DNS queries to specified port.
func setupIPTables(port string) error {
	// remove rules in case they already exist
	cleanupIPTables(port)

	// IPv4
	if err := runIPTablesCmd("iptables", "-I", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := runIPTablesCmd("iptables", "-t", "nat", "-I", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port); err != nil {
		return err
	}
	// IPv6
	if err := runIPTablesCmd("ip6tables", "-I", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"); err != nil {
		return err
	}
	return runIPTablesCmd("ip6tables", "-t", "nat", "-I", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port)
}

func cleanupIPTables(port string) error {
	// IPv4
	if err := runIPTablesCmd("iptables", "-D", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := runIPTablesCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port); err != nil {
		return err
	}
	// IPv6
	if err := runIPTablesCmd("ip6tables", "-D", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"); err != nil {
		return err
	}
	return runIPTablesCmd("ip6tables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port)
}

func run(privkey []byte, domain dns.Name, dnsConn net.PacketConn) error {
	defer dnsConn.Close()

	// We have a variable amount of room in which to encode downstream
	// packets in each response, because each response must contain the
	// query's Question section, which is of variable length. But we cannot
	// give dynamic packet size limits to KCP; the best we can do is set a
	// global maximum which no packet will exceed. We choose that maximum to
	// keep the UDP payload size under maxUDPPayload, even in the worst case
	// of a maximum-length name in the query's Question section.
	maxEncodedPayload := computeMaxEncodedPayload(maxUDPPayload)
	// 2 bytes accounts for a packet length prefix.
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}

	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()

	go func() {
		err := acceptSessions(ln, privkey, mtu)
		if err != nil {
			slog.Error("acceptSessions error", slog.Any("err", err))
		}
	}()

	ch := make(chan *record, sendLoopChanSize)
	defer close(ch)

	// We could run multiple copies of sendLoop; that would allow more time
	// for each response to collect downstream data before being evicted by
	// another response that needs to be sent.
	for i := 0; i < numSendLoops; i++ {
		go func() {
			err := sendLoop(dnsConn, ttConn, ch, maxEncodedPayload)
			if err != nil {
				slog.Error("sendLoop error", slog.Any("err", err))
			}
		}()
	}

	return recvLoop(domain, dnsConn, ttConn, ch)
}

func startPprof() {
	go func() {
		if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil {
			slog.Error("pprof server stopped", slog.Any("err", err))
		}
	}()
}

func main() {
	var genKey bool
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string
	var udpAddr string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key -privkey-file PRIVKEYFILE -pubkey-file PUBKEYFILE
  %[1]s -udp ADDR -privkey-file PRIVKEYFILE DOMAIN

Example:
  %[1]s -gen-key -privkey-file server.key -pubkey-file server.pub
  %[1]s -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen on (required)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.TimeValue(a.Value.Time().UTC())
			}
			return a
		},
	})))

	if genKey {
		// -gen-key mode.
		if flag.NArg() != 0 || privkeyString != "" || udpAddr != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ordinary server mode.
		if flag.NArg() != 1 {
			fmt.Fprintf(os.Stderr, "exactly one domain name argument is required\n")
			flag.Usage()
			os.Exit(1)
		}
		domain, err := dns.ParseName(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}

		if udpAddr == "" {
			fmt.Fprintf(os.Stderr, "the -udp option is required\n")
			os.Exit(1)
		}
		dnsConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "opening UDP listener: %v\n", err)
			os.Exit(1)
		}

		_, udpPort, _ := net.SplitHostPort(udpAddr)
		if udpPort != "53" {
			if err := setupIPTables(udpPort); err != nil {
				fmt.Fprintf(os.Stderr, "cannot set up iptables: %v\n", err)
				os.Exit(1)
			}
			defer cleanupIPTables(udpPort)
		}

		if pubkeyFilename != "" {
			fmt.Fprintf(os.Stderr, "-pubkey-file may only be used with -gen-key\n")
			os.Exit(1)
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			fmt.Fprintf(os.Stderr, "only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				fmt.Fprintf(os.Stderr, "privkey format error: %v\n", err)
				os.Exit(1)
			}
		}
		if len(privkey) == 0 {
			slog.Warn("generating a temporary one-time keypair")
			slog.Warn("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		pprofDebug := strings.TrimSpace(os.Getenv("PPROF_DEBUG"))
		if pprofDebug != "" && pprofDebug != "0" && !strings.EqualFold(pprofDebug, "false") {
			startPprof()
		}
		err = run(privkey, domain, dnsConn)
		if err != nil {
			slog.Error("run failed", slog.Any("err", err))
			os.Exit(1)
		}
	}
}

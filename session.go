package dnstt

import (
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/xtaci/kcp-go"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// newSession creates a new smux multiplex session over pconn. pubKey is the server public key and
// is used to create a Noise channel on top of the connection, if it is not nil.
func newSession(pconn net.PacketConn, mtu int, pubKey []byte) (sess *smux.Session, err error) {
	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(turbotunnel.DummyAddr{}, nil, 0, 0, pconn)
	if err != nil {
		return nil, fmt.Errorf("opening KCP conn: %w", err)
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	slog.Debug("begin session", "sessionID", fmt.Sprintf("%08x", conn.GetConv()))
	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if conn.SetMtu(mtu) {
		return nil, fmt.Errorf("setting MTU %d: %w", mtu, err)
	}

	// Put a Noise channel on top of the KCP conn.
	var rw io.ReadWriteCloser = conn
	if pubKey != nil {
		// Put a Noise channel on top of the KCP conn.
		rw, err = noise.NewClient(conn, pubKey)
		if err != nil {
			return nil, fmt.Errorf("opening Noise channel: %w", err)
		}
	}

	// Start a smux session
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	return smux.Client(rw, smuxConfig)
}

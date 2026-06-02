// Author: David Fifield
// david@bamsoftware.com
// https://www.bamsoftware.com/software/dnstt/
//
// package dnstt-client
// ///////////////////////////////////////////////////////////
// /////    This file is unmodified from the original    /////
// ///////////////////////////////////////////////////////////
package dnstt

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const dialTimeout = 30 * time.Second

// TLSPacketConn is a TLS- and TCP-based transport for DNS messages, used for
// DNS over TLS (DoT). Its WriteTo and ReadFrom methods exchange DNS messages
// over a TLS channel, prefixing each message with a two-octet length field as
// in DNS over TCP.
//
// TLSPacketConn deals only with already formatted DNS messages. It does not
// handle encoding information into the messages. That is rather the
// responsibility of DNSPacketConn.
//
// https://tools.ietf.org/html/rfc7858
type TLSPacketConn struct {
	// closed is closed by Close so sendLoop returns and the redial loop stops
	// reconnecting. conn holds the live TLS connection so Close can close it,
	// unblocking recvLoop's blocking read.
	closed    chan struct{}
	closeOnce sync.Once
	connMu    sync.Mutex
	conn      net.Conn

	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewTLSPacketConn creates a new TLSPacketConn configured to use the TLS
// server at addr as a DNS over TLS resolver. It maintains a TLS connection to
// the resolver, reconnecting as necessary. It closes the connection if any
// reconnection attempt fails.
func NewTLSPacketConn(addr string, dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)) (*TLSPacketConn, error) {
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		return dialTLSContext(ctx, "tcp", addr)
	}
	// We maintain one TLS connection at a time, redialing it whenever it
	// becomes disconnected. We do the first dial here, outside the
	// goroutine, so that any immediate and permanent connection errors are
	// reported directly to the caller of NewTLSPacketConn.
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	c := &TLSPacketConn{
		closed:          make(chan struct{}),
		conn:            conn,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	go func() {
		defer c.Close()
		for {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				err := c.recvLoop(conn)
				if err != nil {
					log.Printf("recvLoop: %v", err)
				}
				wg.Done()
			}()
			go func() {
				err := c.sendLoop(conn)
				if err != nil {
					log.Printf("sendLoop: %v", err)
				}
				wg.Done()
			}()
			wg.Wait()
			conn.Close()

			select {
			case <-c.closed:
				return
			default:
			}

			// Whenever the TLS connection dies, redial a new one.
			conn, err = dial()
			if err != nil {
				log.Printf("dial tls: %v", err)
				break
			}
			select {
			case <-c.closed:
				conn.Close()
				return
			default:
			}
			c.connMu.Lock()
			c.conn = conn
			c.connMu.Unlock()
		}
	}()
	return c, nil
}

// Close stops the send loop and redial loop and closes the live TLS connection,
// unblocking recvLoop. Without it the redial loop reconnects forever after the
// session ends.
func (c *TLSPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.connMu.Lock()
		if c.conn != nil {
			c.conn.Close()
		}
		c.connMu.Unlock()
	})
	return c.QueuePacketConn.Close()
}

// recvLoop reads length-prefixed messages from conn and passes them to the
// incoming queue.
func (c *TLSPacketConn) recvLoop(conn net.Conn) error {
	br := bufio.NewReader(conn)
	for {
		var length uint16
		err := binary.Read(br, binary.BigEndian, &length)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return err
		}
		p := make([]byte, int(length))
		_, err = io.ReadFull(br, p)
		if err != nil {
			return err
		}
		c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
	}
}

// sendLoop reads messages from the outgoing queue and writes them,
// length-prefixed, to conn.
func (c *TLSPacketConn) sendLoop(conn net.Conn) error {
	bw := bufio.NewWriter(conn)
	outgoing := c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{})
	for {
		var p []byte
		select {
		case <-c.closed:
			return nil
		case p = <-outgoing:
		}

		length := uint16(len(p))
		if int(length) != len(p) {
			panic(len(p))
		}
		err := binary.Write(bw, binary.BigEndian, &length)
		if err != nil {
			return err
		}
		_, err = bw.Write(p)
		if err != nil {
			return err
		}
		err = bw.Flush()
		if err != nil {
			return err
		}
	}
}

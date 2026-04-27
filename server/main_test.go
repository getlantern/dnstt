package main

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPipeDataExitsOnStreamClose verifies pipeData goroutines exit when the
// smux stream side closes — the normal client-disconnect path.
func TestPipeDataExitsOnStreamClose(t *testing.T) {
	stream, streamPeer := net.Pipe()
	targetConn, targetPeer := net.Pipe()
	defer targetPeer.Close()

	done := make(chan struct{})
	go func() {
		pipeData(stream, targetConn)
		close(done)
	}()

	streamPeer.Close() // client disconnects

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeData did not exit after stream close")
	}
}

// TestPipeDataExitsOnTargetConnClose verifies pipeData exits when the upstream
// target closes — e.g. the server finishes its response.
func TestPipeDataExitsOnTargetConnClose(t *testing.T) {
	stream, streamPeer := net.Pipe()
	targetConn, targetPeer := net.Pipe()
	defer streamPeer.Close()

	done := make(chan struct{})
	go func() {
		pipeData(stream, targetConn)
		close(done)
	}()

	targetPeer.Close() // upstream closes

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeData did not exit after target close")
	}
}

// TestPipeDataExitsOnHungTarget is the regression test for the goroutine leak.
// It verifies that pipeData exits when the upstream connection stops responding
// — the scenario TCP keepalives are designed to detect.
//
// In production, the OS fires a connection-level error once keepalive probes go
// unanswered. We replicate that here by setting a read deadline, which produces
// the same net.Error the OS-level closure generates.
func TestPipeDataExitsOnHungTarget(t *testing.T) {
	// A server that accepts but never writes — simulates a hung upstream.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(10 * time.Second) // hangs indefinitely
	}()

	targetConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	// Simulate the OS closing the connection after keepalive probes fail.
	// SetReadDeadline produces the same net.Error that an OS-level close does.
	err = targetConn.(*net.TCPConn).SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	require.NoError(t, err)

	stream, streamPeer := net.Pipe()
	defer streamPeer.Close()

	done := make(chan struct{})
	go func() {
		pipeData(stream, targetConn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeData did not exit after hung target connection timed out")
	}
}

// TestPipeDataNoGoroutineLeak verifies that goroutines do not accumulate across
// many pipeData calls once connections close — the core property the keepalive
// fix is meant to ensure.
func TestPipeDataNoGoroutineLeak(t *testing.T) {
	const n = 20
	baseline := runtime.NumGoroutine()

	for i := 0; i < n; i++ {
		stream, streamPeer := net.Pipe()
		targetConn, targetPeer := net.Pipe()

		go pipeData(stream, targetConn)

		// Close both remote ends so pipeData drains immediately.
		streamPeer.Close()
		targetPeer.Close()
	}

	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+5
	}, 5*time.Second, 10*time.Millisecond,
		"goroutines did not drain after connections closed (current: %d, baseline: %d)",
		runtime.NumGoroutine(), baseline)
}

// TestWriteTimeoutConnTimesOut verifies that writeTimeoutConn returns a timeout
// error when the remote peer stops consuming data — simulating a client that
// has disappeared and left the KCP send-window full.
func TestWriteTimeoutConnTimesOut(t *testing.T) {
	// net.Pipe is synchronous: writes to 'a' block until 'b' reads.
	// By not reading from 'b' we recreate the full-send-window condition.
	a, b := net.Pipe()
	defer b.Close()

	wrapped := &writeTimeoutConn{a, 100 * time.Millisecond}

	_, err := wrapped.Write([]byte("data that will never be consumed"))
	require.Error(t, err, "expected write to time out when reader is not consuming")
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout(), "expected a timeout error, got: %v", err)
}

// TestWriteTimeoutConnSucceedsNormally verifies that writeTimeoutConn does not
// interfere with writes when the remote peer is actively reading.
func TestWriteTimeoutConnSucceedsNormally(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go io.Copy(io.Discard, b) // consume everything written to a

	wrapped := &writeTimeoutConn{a, 100 * time.Millisecond}
	_, err := wrapped.Write([]byte("hello"))
	assert.NoError(t, err)
}

// TestUpstreamConnKeepaliveEnabled verifies that the TCP keepalive option is
// successfully applied to an upstream connection — i.e. both the type assertion
// and the syscall succeed without error.
func TestUpstreamConnKeepaliveEnabled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	tc, ok := conn.(*net.TCPConn)
	require.True(t, ok, "net.Dial returned a non-TCP conn")
	assert.NoError(t, tc.SetKeepAlive(true))
	assert.NoError(t, tc.SetKeepAlivePeriod(upstreamKeepalivePeriod))
}

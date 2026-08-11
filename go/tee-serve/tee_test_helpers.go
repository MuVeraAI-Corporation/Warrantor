package teeserve

import (
	"net"
	"os"
	"runtime"
	"testing"
)

// requireUnixSocketDial skips the calling test when the host cannot dial a Unix domain socket.
//
// Windows has supported AF_UNIX since 1803 and net.Listen("unix", ...) works here, but
// net.Dial("unix", ...) fails with WSAEINVAL ("An invalid argument was supplied") because the Go
// dialer binds the client socket to an unnamed local address before connecting, which Windows
// AF_UNIX rejects. Verified on go1.26.0 windows/amd64: listen succeeds, dial fails, for both short
// and long paths and for either path separator.
//
// This is a host limitation, not a defect in SocketUpstream, so the test is skipped rather than
// weakened -- Linux CI still exercises the real socket path end to end. Skipping loudly beats a
// permanently red suite that developers learn to ignore.
func requireUnixSocketDial(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	t.Skip("net.Dial(\"unix\") is unsupported on Windows (WSAEINVAL); " +
		"SocketUpstream is exercised on Linux CI")
}

// listenUnix opens a Unix Domain Socket listener at path. Wraps net.Listen so tests don't
// need to import both packages.
func listenUnix(path string) (net.Listener, error) {
	// Remove a stale socket if present.
	_ = os.Remove(path)
	return net.Listen("unix", path)
}

// dialUnix opens a one-shot connection to a Unix Domain Socket.
func dialUnix(path string) (net.Conn, error) {
	return net.Dial("unix", path)
}

// removeFile is os.Remove with a stable name so the test file reads cleanly.
func removeFile(path string) error { return os.Remove(path) }

package teeserve

import (
	"net"
	"os"
)

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

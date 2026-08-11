// Package identity — TLS tests (H6).
//
// Verifies the self-signed cert generator, the on-disk cert-material cache, and that the gateway
// can actually serve over HTTPS.
package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGenerateSelfSignedCertShape verifies the generated PEM blocks are well-formed and parse back
// into an x509 certificate + ECDSA key.
func TestGenerateSelfSignedCertShape(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"localhost", "agent.local"})
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Errorf("certPEM missing CERTIFICATE block: %s", certPEM)
	}
	if !strings.Contains(string(keyPEM), "EC PRIVATE KEY") {
		t.Errorf("keyPEM missing EC PRIVATE KEY block: %s", keyPEM)
	}

	// The cert+key pair must be usable as a tls.Certificate (i.e. they match).
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}
	_ = tlsCert

	// Parse the cert to check its DNS names.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("pem.Decode cert failed")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	if got := parsed.DNSNames; len(got) != 2 || got[0] != "localhost" || got[1] != "agent.local" {
		t.Errorf("DNSNames = %v, want [localhost agent.local]", got)
	}
	// The cert must be valid right now (with the 1-minute backward skew).
	now := time.Now()
	if now.Before(parsed.NotBefore) {
		t.Errorf("cert NotBefore %v is in the future", parsed.NotBefore)
	}
	if now.After(parsed.NotAfter) {
		t.Errorf("cert NotAfter %v is in the past", parsed.NotAfter)
	}
	// Must not be a CA (we only sign leaf certs).
	if parsed.IsCA {
		t.Error("self-signed leaf cert must not be a CA")
	}
}

// TestGenerateSelfSignedCertDefaultsToLocalhost verifies that an empty dnsNames slice falls back to
// "localhost".
func TestGenerateSelfSignedCertDefaultsToLocalhost(t *testing.T) {
	certPEM, _, err := generateSelfSignedCert(nil)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "localhost" {
		t.Errorf("DNSNames = %v, want [localhost]", parsed.DNSNames)
	}
}

// TestEnsureCertMaterialGeneratesWhenMissing verifies that missing files are generated.
func TestEnsureCertMaterialGeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	cp, kp, err := EnsureCertMaterial(certPath, keyPath, []string{"localhost"})
	if err != nil {
		t.Fatalf("EnsureCertMaterial: %v", err)
	}
	if cp != certPath || kp != keyPath {
		t.Errorf("returned paths = (%q,%q), want (%q,%q)", cp, kp, certPath, keyPath)
	}
	if !fileExists(certPath) || !fileExists(keyPath) {
		t.Error("cert/key files were not written")
	}
}

// TestEnsureCertMaterialPreservesExisting verifies that pre-existing files are not overwritten (so
// callers can place their own SVID-derived cert/key without us clobbering them).
func TestEnsureCertMaterialPreservesExisting(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	// Generate once.
	_, _, err := EnsureCertMaterial(certPath, keyPath, []string{"first.local"})
	if err != nil {
		t.Fatalf("first EnsureCertMaterial: %v", err)
	}
	firstCert, _ := readFile(t, certPath)

	// Second call with a different DNS name must NOT regenerate (files already exist).
	_, _, err = EnsureCertMaterial(certPath, keyPath, []string{"second.local"})
	if err != nil {
		t.Fatalf("second EnsureCertMaterial: %v", err)
	}
	secondCert, _ := readFile(t, certPath)
	if !bytesEqual(firstCert, secondCert) {
		t.Error("existing cert was regenerated; EnsureCertMaterial must preserve existing files")
	}
}

// TestEnsureCertMaterialRejectsEmptyPaths verifies the guard on empty paths.
func TestEnsureCertMaterialRejectsEmptyPaths(t *testing.T) {
	if _, _, err := EnsureCertMaterial("", "k.pem", nil); err == nil {
		t.Error("expected error for empty cert path")
	}
	if _, _, err := EnsureCertMaterial("c.pem", "", nil); err == nil {
		t.Error("expected error for empty key path")
	}
}

// TestServeTLSRealHandshake spins up the gateway over HTTPS using generated self-signed material
// and performs a real TLS handshake + HTTP request. This is the end-to-end check that the H6 TLS
// path works against the actual http.Server.
func TestServeTLSRealHandshake(t *testing.T) {
	svc, err := NewService("muveraai.com")
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	gw := NewHTTPGateway(svc)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	if _, _, err := EnsureCertMaterial(certPath, keyPath, []string{"localhost"}); err != nil {
		t.Fatalf("EnsureCertMaterial: %v", err)
	}

	// Bind to :0 so the OS picks a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // the http.Server will re-listen on this addr

	server := &http.Server{
		Addr:              addr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = server.ListenAndServeTLS(certPath, keyPath)
	}()
	defer server.Close()

	// Wait for the listener to come up.
	deadline := time.Now().Add(3 * time.Second)
	var connected bool
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			connected = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !connected {
		t.Fatalf("server did not come up on %s", addr)
	}

	// Build a client that trusts the self-signed cert (we have the PEM on disk).
	certPEM, _ := readFile(t, certPath)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append cert to pool")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
				ServerName: "localhost",
			},
		},
	}

	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz over TLS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("body = %s, want status:ok", body)
	}
}

// TestServeTLSRejectsUntrustedClient verifies that a client that does NOT trust the self-signed
// cert fails the handshake. This guards the inverse: TLS is actually being enforced.
func TestServeTLSRejectsUntrustedClient(t *testing.T) {
	svc, _ := NewService("muveraai.com")
	gw := NewHTTPGateway(svc)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	if _, _, err := EnsureCertMaterial(certPath, keyPath, []string{"localhost"}); err != nil {
		t.Fatalf("EnsureCertMaterial: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	server := &http.Server{
		Addr:              addr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = server.ListenAndServeTLS(certPath, keyPath)
	}()
	defer server.Close()

	// Wait for listener.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Client that trusts ONLY the system roots (which do not include our self-signed cert).
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Empty pool + InsecureSkipVerify=false => the self-signed cert is untrusted.
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	_, err = client.Get("https://" + addr + "/healthz")
	if err == nil {
		t.Fatal("expected TLS handshake to fail with an untrusted cert, got success")
	}
}

// readFile is a small helper that reads a file and fails the test on error.
func readFile(t *testing.T, path string) ([]byte, []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b, nil
}

// bytesEqual reports whether two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

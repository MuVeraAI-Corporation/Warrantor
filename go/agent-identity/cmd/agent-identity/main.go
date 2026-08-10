// Command agent-identity is the I1 agent-identity service.
//
// Wave-2 v1.0: serves the HTTP/JSON gateway on the configured address. Real SPIRE integration
// (task 03) will add the SPIFFE WorkloadAPI as an alternative SVID source.
//
// H6: optional TLS termination at the gateway. When `--tls` is set the gateway serves HTTPS using
// the cert/key at `--cert`/`--key` (default paths under the OS temp dir). When neither file exists,
// an ephemeral self-signed ECDSA certificate is generated at startup. The default (no `--tls`) is
// plaintext HTTP, preserving backward compatibility.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"warrantor.dev/agent-identity"
)

// Default cert/key paths used when --tls is set without explicit paths. They live under the OS temp
// dir so a fresh checkout works without write access to /etc.
const (
	defaultCertFile = "agent-identity-cert.pem"
	defaultKeyFile  = "agent-identity-key.pem"
)

func main() {
	addr := flag.String("addr", ":8441", "listen address for the HTTP/JSON gateway")
	trustDomain := flag.String("trust-domain", "warrantor.dev", "SPIFFE trust domain")
	// H6: TLS flags.
	tlsEnabled := flag.Bool("tls", false, "enable TLS (HTTPS) on the gateway (default: false, plaintext HTTP for backward compat)")
	certFile := flag.String("cert", "", "path to TLS certificate PEM (when --tls; generated if empty)")
	keyFile := flag.String("key", "", "path to TLS private key PEM (when --tls; generated if empty)")
	tlsDNSName := flag.String("tls-dns-name", "localhost", "DNS name baked into a generated self-signed cert (when --tls without --cert/--key)")
	flag.Parse()

	svc, err := identity.NewService(*trustDomain)
	if err != nil {
		log.Fatalf("agent-identity: construct service: %v", err)
	}
	gw := identity.NewHTTPGateway(svc)
	h := gw.Handler()

	server := &http.Server{
		Addr:              *addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("agent-identity: shutting down...")
		_ = server.Close()
	}()

	// Resolve TLS material if --tls is set.
	certPath, keyPath := "", ""
	if *tlsEnabled {
		cp := *certFile
		kp := *keyFile
		if cp == "" || kp == "" {
			// Default under the OS temp dir so the binary is self-contained.
			tmp := os.TempDir()
			if cp == "" {
				cp = filepath.Join(tmp, defaultCertFile)
			}
			if kp == "" {
				kp = filepath.Join(tmp, defaultKeyFile)
			}
		}
		resolvedCert, resolvedKey, err := identity.EnsureCertMaterial(cp, kp, []string{*tlsDNSName})
		if err != nil {
			log.Fatalf("agent-identity: TLS material: %v", err)
		}
		certPath = resolvedCert
		keyPath = resolvedKey
	}

	scheme := "http"
	if *tlsEnabled {
		scheme = "https"
	}
	fmt.Fprintf(os.Stderr, "agent-identity: listening on %s (%s, trust-domain=%s, verifying-key=%s)\n",
		*addr, scheme, *trustDomain, svc.VerifyingKeyHex())
	if *tlsEnabled {
		fmt.Fprintf(os.Stderr, "agent-identity: TLS cert=%s key=%s\n", certPath, keyPath)
		if err := server.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("agent-identity: serve TLS: %v", err)
		}
		return
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("agent-identity: serve: %v", err)
	}
}

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
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"muveraai.com/go/agent-identity"
)

// Default cert/key paths used when --tls is set without explicit paths. They live under the OS temp
// dir so a fresh checkout works without write access to /etc.
const (
	defaultCertFile = "agent-identity-cert.pem"
	defaultKeyFile  = "agent-identity-key.pem"
)

// Environment variables. Containers set environment, not flags: the Dockerfile's CMD is empty, so
// anything that is flag-only can never be configured in a deployed container. Each of these is the
// *default* for the matching flag, so an explicit flag still wins.
const (
	envTrustDomain = "AUMOS_TRUST_DOMAIN"
	envAddr        = "AUMOS_IDENTITY_ADDR"
	// envSigningKey carries a hex-encoded 32-byte Ed25519 seed. Every replica must be given the
	// same value or they will reject each other's tokens.
	envSigningKey = "AUMOS_IDENTITY_SIGNING_KEY"
	// envSigningKeyFile points at a file containing that hex seed — the form to use with a
	// mounted Kubernetes secret or a Vault agent sidecar, so the key never appears in `ps` output
	// or in the pod's environment.
	envSigningKeyFile = "AUMOS_IDENTITY_SIGNING_KEY_FILE"
	// envAllowEphemeralKey must be set to "true" to start without shared key material. It exists
	// so a single-replica dev run stays one command, while a replicated deployment that forgot to
	// mount its key fails loudly at startup instead of silently failing ~2/3 of verifies.
	envAllowEphemeralKey = "AUMOS_IDENTITY_ALLOW_EPHEMERAL_KEY"
)

// envOr returns the environment value for `key`, or `fallback` when it is unset or empty.
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// loadSigningSeed resolves the Ed25519 seed from the key file or the inline env var, in that
// order. It returns (nil, nil) when neither is configured, meaning "generate an ephemeral key".
func loadSigningSeed() ([]byte, error) {
	if path := strings.TrimSpace(os.Getenv(envSigningKeyFile)); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s=%s: %w", envSigningKeyFile, path, err)
		}
		return decodeSeed(strings.TrimSpace(string(raw)), envSigningKeyFile)
	}
	if inline := strings.TrimSpace(os.Getenv(envSigningKey)); inline != "" {
		return decodeSeed(inline, envSigningKey)
	}
	return nil, nil
}

func decodeSeed(value, source string) ([]byte, error) {
	seed, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex-encoded: %w", source, err)
	}
	if len(seed) != identity.SigningKeySeedLen {
		return nil, fmt.Errorf("%s must decode to %d bytes, got %d",
			source, identity.SigningKeySeedLen, len(seed))
	}
	return seed, nil
}

// newServiceFromEnv builds the service, choosing shared or ephemeral key material and refusing to
// start ephemerally unless that was asked for explicitly.
func newServiceFromEnv(trustDomain string) (*identity.Service, error) {
	seed, err := loadSigningSeed()
	if err != nil {
		return nil, err
	}
	if seed != nil {
		return identity.NewServiceWithSeed(trustDomain, seed)
	}

	allow, _ := strconv.ParseBool(os.Getenv(envAllowEphemeralKey))
	if !allow {
		return nil, fmt.Errorf(
			"no signing key configured: set %s (path to a hex Ed25519 seed) or %s.\n"+
				"Every replica must share this key -- without it each process signs with its own "+
				"key and rejects tokens issued by its siblings.\n"+
				"For a single-replica development run, set %s=true to accept a generated key.\n"+
				"Generate one with: openssl rand -hex %d",
			envSigningKeyFile, envSigningKey, envAllowEphemeralKey, identity.SigningKeySeedLen)
	}
	return identity.NewService(trustDomain)
}

func main() {
	addr := flag.String("addr", envOr(envAddr, ":8441"), "listen address for the HTTP/JSON gateway (env "+envAddr+")")
	trustDomain := flag.String("trust-domain", envOr(envTrustDomain, "muveraai.com"), "SPIFFE trust domain (env "+envTrustDomain+")")
	// H6: TLS flags.
	tlsEnabled := flag.Bool("tls", false, "enable TLS (HTTPS) on the gateway (default: false, plaintext HTTP for backward compat)")
	certFile := flag.String("cert", "", "path to TLS certificate PEM (when --tls; generated if empty)")
	keyFile := flag.String("key", "", "path to TLS private key PEM (when --tls; generated if empty)")
	tlsDNSName := flag.String("tls-dns-name", "localhost", "DNS name baked into a generated self-signed cert (when --tls without --cert/--key)")
	flag.Parse()

	svc, err := newServiceFromEnv(*trustDomain)
	if err != nil {
		log.Fatalf("agent-identity: %v", err)
	}
	if svc.HasEphemeralKey() {
		log.Printf("agent-identity: WARNING: using a generated signing key. This process cannot be "+
			"replicated -- tokens it issues will be rejected by any sibling. Set %s for a real deployment.",
			envSigningKeyFile)
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

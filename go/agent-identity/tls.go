// Package identity — TLS support (H6).
//
// H6 fix: the agent-identity gateway previously only listened over plain HTTP. This adds optional
// TLS so deployments can terminate HTTPS at the gateway itself (useful for local single-binary
// deployments and for environments where a sidecar TLS terminator is not desired). TLS is opt-in
// via the `--tls` flag; the default (no flag) preserves the plaintext listener for backward
// compatibility.
//
// When `--tls` is set without explicit `--cert`/`--key` paths, the gateway generates an ephemeral
// self-signed certificate at startup (ECDSA P-256). The generated material is written to disk so
// the process can be restarted without rotating the cert (unless the caller wants a fresh cert each
// boot, in which case they point `--cert`/`--key` at /dev/null-equivalents or delete the files
// between runs). For production, callers should supply their own cert/key (e.g. from cert-manager
// or SPIRE's X.509 SVID).
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// DefaultSelfSignedCertOrg is the organization baked into the ephemeral self-signed certificate.
const DefaultSelfSignedCertOrg = "Warrantor"

// MinRSACertValidity is the minimum validity period for a self-signed cert. We default to one year
// (365 days) to avoid the cert expiring between releases.
const DefaultCertValidity = 365 * 24 * time.Hour

// Sentinel errors for TLS support.
var (
	// ErrTLSMaterialMissing is returned when TLS is requested but neither a cert/key pair nor a
	// writable location for generated material is available.
	ErrTLSMaterialMissing = errors.New("identity: TLS requested but no cert/key material available")
)

// generateSelfSignedCert generates an ephemeral self-signed certificate using ECDSA P-256. It
// returns the certificate and private key as PEM-encoded bytes, ready to be written to disk and
// passed to [http.Server.ListenAndServeTLS].
//
// The certificate is scoped to the supplied DNS names (typically the gateway's hostname and
// localhost). If no names are supplied, the certificate is valid for "localhost" only (sufficient
// for local single-binary deployments; production should supply a real hostname).
//
// The private key never leaves the process except via the returned PEM bytes (which the caller may
// write to disk). It is not retained in memory after the function returns.
func generateSelfSignedCert(dnsNames []string) (certPEM, keyPEM []byte, err error) {
	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: generate ECDSA key: %w", err)
	}

	// Serial number — random 128-bit positive integer (per RFC 5280 §4.1.2.2).
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("identity: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{DefaultSelfSignedCertOrg},
			CommonName:   dnsNames[0],
		},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-1 * time.Minute), // small skew for clock drift
		NotAfter:              now.Add(DefaultCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: create self-signed cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: marshal ECDSA private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// writeCertMaterial writes the PEM-encoded cert and key to the supplied paths. Files are created
// with 0600 permissions where the platform supports it (on Windows os.WriteFile honors the umask
// but does not support the POSIX mode bits beyond read/write). Returns an error if either write
// fails; on failure the caller is responsible for cleaning up any partial files.
func writeCertMaterial(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("identity: write cert %q: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		// Best-effort cleanup of the cert we just wrote so a half-written pair is not left behind.
		_ = os.Remove(certPath)
		return fmt.Errorf("identity: write key %q: %w", keyPath, err)
	}
	return nil
}

// EnsureCertMaterial ensures that cert and key files exist at the supplied paths. If either file is
// missing, fresh self-signed material is generated and written to both paths. If both files exist,
// they are left untouched (so callers can pre-place their own cert/key, e.g. an X.509 SVID from
// SPIRE). Returns (certPath, keyPath, error).
//
// When dnsNames is empty the generated certificate is scoped to "localhost".
func EnsureCertMaterial(certPath, keyPath string, dnsNames []string) (string, string, error) {
	if certPath == "" || keyPath == "" {
		return "", "", fmt.Errorf("%w: empty cert or key path", ErrTLSMaterialMissing)
	}
	// If both files already exist, leave them alone (caller may have pre-placed an SVID).
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}
	certPEM, keyPEM, err := generateSelfSignedCert(dnsNames)
	if err != nil {
		return "", "", err
	}
	if err := writeCertMaterial(certPath, keyPath, certPEM, keyPEM); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// fileExists reports whether path names an existing regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

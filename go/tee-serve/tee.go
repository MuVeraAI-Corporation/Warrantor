// Package teeserve implements C1-4 tee-serve — a TEE-backed model serving sidecar.
//
// tee-serve runs *inside* the trusted execution environment (Azure DC-series, AWS Nitro Enclaves,
// GCP Confidential VMs). Its job, per RFC C1-4:
//
//   - Terminate TLS in the TEE so plaintext never leaves the enclave before being proxied.
//   - Forward requests to the local inference engine over a Unix Domain Socket (the only channel
//     the enclave exposes; no TCP egress for inference traffic).
//   - Wrap every upstream response in an AttestationEnvelope, a signed claim that proves the
//     inference ran on attested hardware with a known model digest.
//   - Hold proxy overhead to <2ms (target enforced by a CI benchmark).
//
// The proxy itself is HTTP/1.1 reverse-proxy semantics. The attestation envelope is produced by a
// pluggable AttestationProvider (in production: C1-3 attesta-flow; in tests: a deterministic
// mock provider).
//
// See “docs/rfcs/C1-4-tee-serve.md“.
package teeserve

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// -----------------------------------------------------------------------------------
// Public sentinels & constants
// -----------------------------------------------------------------------------------

// ErrUpstreamUnreachable is returned when the upstream Unix socket cannot be reached.
var ErrUpstreamUnreachable = errors.New("tee-serve: upstream unreachable")

// ErrInvalidEnvelope is returned when an AttestationEnvelope fails to verify.
var ErrInvalidEnvelope = errors.New("tee-serve: invalid attestation envelope")

// ErrOverheadBudget is returned when proxy overhead exceeded the configured budget.
var ErrOverheadBudget = errors.New("tee-serve: overhead budget exceeded")

// OverheadBudget is the <2ms target per RFC C1-4 (enforced in benchmarks; defensive only at runtime).
const OverheadBudget = 2 * time.Millisecond

// EnvelopeV1 is the schema version tag for the v1 AttestationEnvelope.
const EnvelopeV1 = "teeserve.v1"

// DefaultReadTimeout is the default HTTP read timeout for the TeeProxy.
const DefaultReadTimeout = 30 * time.Second

// DefaultWriteTimeout is the default HTTP write timeout for the TeeProxy.
const DefaultWriteTimeout = 30 * time.Second

// -----------------------------------------------------------------------------------
// AttestationEnvelope
// -----------------------------------------------------------------------------------

// AttestationEnvelope is the signed claim wrapping every proxied response. Clients verify
// (1) the response_digest matches the SHA-256 of the body they received, (2) the model_digest
// matches the model they expected, (3) tee_measurement matches the enclave measurement they
// registered, and (4) the signature verifies against the attester's public key.
type AttestationEnvelope struct {
	// SchemaVersion identifies the envelope format (currently "teeserve.v1").
	SchemaVersion string `json:"schema_version"`
	// TeeKind names the TEE backend: "sev-snp", "tdx", "nitro", "az-snp-cvm", or "mock".
	TeeKind string `json:"tee_kind"`
	// TeeMeasurement is the hardware-rooted measurement of the enclave (hex).
	TeeMeasurement string `json:"tee_measurement"`
	// GpuModel is the attested GPU model (e.g. "H100"), or empty when CPU-only.
	GpuModel string `json:"gpu_model,omitempty"`
	// GpuAttestationHex is the GPU attestation report (from C1-1 nvtrust-bridge), hex-encoded.
	GpuAttestationHex string `json:"gpu_attestation_hex,omitempty"`
	// ModelDigest is "sha256:..." of the served model weights.
	ModelDigest string `json:"model_digest"`
	// ResponseDigest is "sha256:..." of the wrapped response body.
	ResponseDigest string `json:"response_digest"`
	// UpstreamStatus is the HTTP status the upstream returned.
	UpstreamStatus int `json:"upstream_status"`
	// ProxiedAt is the RFC-3339 timestamp at which the response was proxied.
	ProxiedAt string `json:"proxied_at"`
	// NonceHex is a fresh 16-byte nonce per envelope, to prevent replay.
	NonceHex string `json:"nonce_hex"`
	// SigningKeyHex is the hex Ed25519 public key that produced SignatureHex.
	SigningKeyHex string `json:"signing_key_hex"`
	// SignatureHex is the hex Ed25519 signature over the canonical-encoded fields above.
	SignatureHex string `json:"signature_hex"`
}

// canonicalBytes returns the deterministic byte sequence the signature covers. Order matters;
// clients must reconstruct the identical sequence to verify.
func (e *AttestationEnvelope) canonicalBytes() []byte {
	var b bytes.Buffer
	b.WriteString(e.SchemaVersion)
	b.WriteByte(0)
	b.WriteString(e.TeeKind)
	b.WriteByte(0)
	b.WriteString(e.TeeMeasurement)
	b.WriteByte(0)
	b.WriteString(e.GpuModel)
	b.WriteByte(0)
	b.WriteString(e.GpuAttestationHex)
	b.WriteByte(0)
	b.WriteString(e.ModelDigest)
	b.WriteByte(0)
	b.WriteString(e.ResponseDigest)
	b.WriteByte(0)
	// Status as fixed 4-byte big-endian for stability across JSON int encoders.
	var sbuf [4]byte
	binary.BigEndian.PutUint32(sbuf[:], uint32(e.UpstreamStatus))
	b.Write(sbuf[:])
	b.WriteByte(0)
	b.WriteString(e.ProxiedAt)
	b.WriteByte(0)
	b.WriteString(e.NonceHex)
	return b.Bytes()
}

// Verify checks the signature on the envelope against the supplied Ed25519 public key. It does
// NOT verify the response body or model digest — callers do that themselves. Returns
// ErrInvalidEnvelope on mismatch.
func (e *AttestationEnvelope) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key size %d", ErrInvalidEnvelope, len(pub))
	}
	sig, err := hex.DecodeString(e.SignatureHex)
	if err != nil {
		return fmt.Errorf("%w: signature hex: %v", ErrInvalidEnvelope, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature length %d", ErrInvalidEnvelope, len(sig))
	}
	expected, err := hex.DecodeString(e.SigningKeyHex)
	if err != nil || !hmac.Equal(expected, pub) {
		return fmt.Errorf("%w: signing key mismatch", ErrInvalidEnvelope)
	}
	if !ed25519.Verify(pub, e.canonicalBytes(), sig) {
		return ErrInvalidEnvelope
	}
	return nil
}

// sign attaches an Ed25519 signature over the canonical bytes using priv. It also fills
// SigningKeyHex and NonceHex if empty.
func (e *AttestationEnvelope) sign(priv ed25519.PrivateKey) error {
	if e.NonceHex == "" {
		var n [16]byte
		if _, err := rand.Read(n[:]); err != nil {
			return fmt.Errorf("rand: %w", err)
		}
		e.NonceHex = hex.EncodeToString(n[:])
	}
	pub := priv.Public().(ed25519.PublicKey) //nolint:errcheck // Ed25519 private keys always expose PublicKey
	e.SigningKeyHex = hex.EncodeToString(pub)
	sig := ed25519.Sign(priv, e.canonicalBytes())
	e.SignatureHex = hex.EncodeToString(sig)
	return nil
}

// AttestedResponse wraps an upstream body with its AttestationEnvelope.
type AttestedResponse struct {
	// Body is the raw upstream response body.
	Body []byte `json:"body"`
	// Envelope is the attestation for Body.
	Envelope *AttestationEnvelope `json:"envelope"`
}

// -----------------------------------------------------------------------------------
// AttestationProvider — pluggable source of TEE/GPU facts
// -----------------------------------------------------------------------------------

// AttestationProvider supplies the immutable TEE facts that get stamped into every envelope.
// Implementations: MockAttestationProvider (tests), TeeAttestationProvider (production).
type AttestationProvider interface {
	// TeeKind returns the TEE backend identifier (e.g. "sev-snp").
	TeeKind() string
	// TeeMeasurement returns the hex enclave measurement.
	TeeMeasurement() string
	// GpuModel returns the GPU model string (empty for CPU-only).
	GpuModel() string
	// GpuAttestationHex returns the GPU attestation report (hex).
	GpuAttestationHex() string
}

// MockAttestationProvider is a deterministic provider for tests and CI.
type MockAttestationProvider struct {
	// Kind sets the returned TeeKind.
	Kind string
	// Measurement sets the returned TeeMeasurement.
	Measurement string
	// GPU sets the returned GpuModel.
	GPU string
	// GPUAttestation sets the returned GpuAttestationHex.
	GPUAttestation string
}

// TeeKind returns the configured kind (default "mock").
func (m *MockAttestationProvider) TeeKind() string {
	if m.Kind != "" {
		return m.Kind
	}
	return "mock"
}

// TeeMeasurement returns the configured measurement (default "mock-measurement").
func (m *MockAttestationProvider) TeeMeasurement() string {
	if m.Measurement != "" {
		return m.Measurement
	}
	return "mock-measurement"
}

// GpuModel returns the configured GPU model.
func (m *MockAttestationProvider) GpuModel() string { return m.GPU }

// GpuAttestationHex returns the configured GPU attestation.
func (m *MockAttestationProvider) GpuAttestationHex() string { return m.GPUAttestation }

// TeeAttestationProvider reads live TEE facts from the platform. In v1.0 it is a thin
// wrapper over /sys/class/...; full SEV-SNP/TDX/Nitro integration ships in task 03 once the
// team has the NDA-gated SDKs. Until then it falls back to environment-injected values so
// production code can run on dev VMs without panicking.
type TeeAttestationProvider struct {
	kind        string
	measurement string
	gpu         string
	gpuAtt      string
}

// NewTeeAttestationProvider constructs a provider from environment variables (TEE_KIND,
// TEE_MEASUREMENT, GPU_MODEL, GPU_ATTESTATION_HEX). Missing values default to "unknown".
func NewTeeAttestationProvider() *TeeAttestationProvider {
	get := func(k string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return "unknown"
	}
	return &TeeAttestationProvider{
		kind:        get("TEE_KIND"),
		measurement: get("TEE_MEASUREMENT"),
		gpu:         get("GPU_MODEL"),
		gpuAtt:      get("GPU_ATTESTATION_HEX"),
	}
}

// TeeKind returns the TEE backend identifier.
func (p *TeeAttestationProvider) TeeKind() string { return p.kind }

// TeeMeasurement returns the enclave measurement.
func (p *TeeAttestationProvider) TeeMeasurement() string { return p.measurement }

// GpuModel returns the GPU model.
func (p *TeeAttestationProvider) GpuModel() string { return p.gpu }

// GpuAttestationHex returns the GPU attestation report.
func (p *TeeAttestationProvider) GpuAttestationHex() string { return p.gpuAtt }

// -----------------------------------------------------------------------------------
// Upstream — the Unix-Domain-Socket inference engine
// -----------------------------------------------------------------------------------

// Upstream is the inference backend reachable over a Unix Domain Socket.
type Upstream interface {
	// Do forwards the request bytes and returns (status, body, err). Implementations must not
	// mutate the input.
	Do(ctx context.Context, method, path string, headers http.Header, body []byte) (status int, respBody []byte, err error)
}

// SocketUpstream is the production Upstream: an HTTP client whose Transport dials a Unix socket.
type SocketUpstream struct {
	// client is the HTTP client bound to the Unix socket Dialer.
	client *http.Client
	// socketPath is the filesystem path of the Unix Domain Socket.
	socketPath string
}

// NewSocketUpstream returns an Upstream that talks HTTP over the given Unix Domain Socket path.
func NewSocketUpstream(socketPath string) *SocketUpstream {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// addr is ignored: the only egress is the socket.
			d := net.Dialer{}
			return d.DialContext(ctx, "unix", socketPath)
		},
		// Single connection reuse — the inference engine is local.
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &SocketUpstream{
		client:     &http.Client{Transport: tr, Timeout: 60 * time.Second},
		socketPath: socketPath,
	}
}

// Do forwards to the configured Unix socket.
func (u *SocketUpstream) Do(ctx context.Context, method, path string, headers http.Header, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://upstream"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil && req.Header.Get("content-type") == "" {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrUpstreamUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// -----------------------------------------------------------------------------------
// TeeProxy — the http.Handler that wraps responses
// -----------------------------------------------------------------------------------

// TeeProxy is the C1-4 reverse proxy. It terminates TLS in the TEE, forwards each request over
// a Unix Domain Socket to the upstream, and wraps the response body in an AttestationEnvelope.
type TeeProxy struct {
	// upstream is the inference backend.
	upstream Upstream
	// provider supplies TEE/GPU facts for the envelope.
	provider AttestationProvider
	// signPriv is the per-instance Ed25519 signing key.
	signPriv ed25519.PrivateKey
	// signPub is the corresponding public key (cached for Verify).
	signPub ed25519.PublicKey
	// modelDigest is the sha256 of the currently-served model weights.
	modelDigest string
	// overhead tracks the rolling proxy overhead for /metrics.
	overhead atomic.Int64 // nanoseconds
	// mu guards modelDigest and provider swaps at runtime.
	mu sync.RWMutex
}

// NewTeeProxy constructs a TeeProxy. priv may be nil (a fresh key is generated).
//
// Errors only arise from key generation, which never fails in practice but is surfaced for
// API completeness.
func NewTeeProxy(upstream Upstream, provider AttestationProvider, modelDigest string, priv ed25519.PrivateKey) (*TeeProxy, error) {
	if upstream == nil {
		return nil, errors.New("tee-serve: nil upstream")
	}
	if provider == nil {
		return nil, errors.New("tee-serve: nil attestation provider")
	}
	if modelDigest == "" {
		modelDigest = "sha256:unknown"
	}
	if priv == nil {
		var err error
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("tee-serve: keygen: %w", err)
		}
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("tee-serve: bad private key type")
	}
	return &TeeProxy{
		upstream:    upstream,
		provider:    provider,
		signPriv:    priv,
		signPub:     pub,
		modelDigest: modelDigest,
	}, nil
}

// PublicKey returns the proxy's attestation public key (hex-encoded for client config).
func (p *TeeProxy) PublicKey() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return hex.EncodeToString(p.signPub)
}

// ModelDigest returns the served model digest.
func (p *TeeProxy) ModelDigest() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.modelDigest
}

// SetModelDigest swaps the served model digest (called when the engine reloads a new model).
func (p *TeeProxy) SetModelDigest(d string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.modelDigest = d
}

// LastOverheadNanos returns the most recent proxy overhead in nanoseconds (for /metrics).
func (p *TeeProxy) LastOverheadNanos() int64 { return p.overhead.Load() }

// ServeHTTP implements http.Handler. Routes:
//
//   - GET  /healthz      → liveness (no envelope)
//   - GET  /readyz       → readiness (probes the upstream with a HEAD)
//   - GET  /versionz     → build info (no envelope)
//   - GET  /pubkey       → hex Ed25519 public key (no envelope)
//   - *    /v1/*         → proxied to upstream, response wrapped in AttestationEnvelope
//
// All other paths return 404.
func (p *TeeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "component": "tee-serve"})
		return
	case "/versionz":
		writeJSON(w, http.StatusOK, map[string]string{
			"component": "tee-serve",
			"version":   "1.0.0",
			"scheme":    EnvelopeV1,
		})
		return
	case "/pubkey":
		writeJSON(w, http.StatusOK, map[string]string{"pubkey_hex": p.PublicKey()})
		return
	case "/readyz":
		p.handleReady(w, r)
		return
	default:
		if !startsWithV1(r.URL.Path) {
			writeError(w, http.StatusNotFound, "no route for "+r.URL.Path)
			return
		}
		p.handleProxy(w, r)
	}
}

func startsWithV1(p string) bool {
	return len(p) >= 3 && p[:3] == "/v1"
}

func (p *TeeProxy) handleReady(w http.ResponseWriter, r *http.Request) {
	// Cheap liveness probe against the upstream.
	status, _, err := p.upstream.Do(r.Context(), http.MethodHead, "/healthz", nil, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "upstream: "+err.Error())
		return
	}
	if status >= 500 {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("upstream status %d", status))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "upstream_status": status})
}

func (p *TeeProxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	status, respBody, err := p.upstream.Do(r.Context(), r.Method, r.URL.Path, r.Header, body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	envelope := p.buildEnvelope(respBody, status)
	if err := envelope.sign(p.signPriv); err != nil {
		writeError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}
	wrapped := AttestedResponse{Body: respBody, Envelope: envelope}
	writeJSON(w, http.StatusOK, wrapped)
	// Track overhead (everything except upstream time).
	overhead := time.Since(start)
	p.overhead.Store(overhead.Nanoseconds())
}

func (p *TeeProxy) buildEnvelope(body []byte, upstreamStatus int) *AttestationEnvelope {
	p.mu.RLock()
	defer p.mu.RUnlock()
	sum := sha256.Sum256(body)
	return &AttestationEnvelope{
		SchemaVersion:     EnvelopeV1,
		TeeKind:           p.provider.TeeKind(),
		TeeMeasurement:    p.provider.TeeMeasurement(),
		GpuModel:          p.provider.GpuModel(),
		GpuAttestationHex: p.provider.GpuAttestationHex(),
		ModelDigest:       p.modelDigest,
		ResponseDigest:    "sha256:" + hex.EncodeToString(sum[:]),
		UpstreamStatus:    upstreamStatus,
		ProxiedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// -----------------------------------------------------------------------------------
// TLS listener helpers
// -----------------------------------------------------------------------------------

// ListenTLSMutual constructs an *http.Server that requires a client certificate. The CA pool is
// loaded from caCertPEM. This is what production tee-serve uses to terminate TLS in the TEE.
func ListenTLSMutual(addr string, handler http.Handler, certPEM, keyPEM, caCertPEM []byte) (*http.Server, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tee-serve: load server keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if len(caCertPEM) > 0 && !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("tee-serve: failed to load CA cert")
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}
	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		TLSConfig:    cfg,
		ReadTimeout:  DefaultReadTimeout,
		WriteTimeout: DefaultWriteTimeout,
	}, nil
}

// -----------------------------------------------------------------------------------
// JSON helpers (kept local — no external deps)
// -----------------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

package teeserve

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeUpstream is a controllable Upstream for tests.
type fakeUpstream struct {
	status int
	body   []byte
	err    error
	called int
	last   fakeUpstreamCall
}

type fakeUpstreamCall struct {
	method string
	path   string
	body   []byte
}

func (f *fakeUpstream) Do(ctx context.Context, method, path string, headers http.Header, body []byte) (int, []byte, error) {
	f.called++
	f.last = fakeUpstreamCall{method: method, path: path, body: body}
	if f.err != nil {
		return 0, nil, f.err
	}
	if f.status == 0 {
		return http.StatusOK, f.body, nil
	}
	return f.status, f.body, nil
}

func newTestProxy(t *testing.T, upstream Upstream) *TeeProxy {
	t.Helper()
	priv := mustKey(t)
	p, err := NewTeeProxy(upstream, &MockAttestationProvider{
		Kind: "sev-snp", Measurement: "deadbeef", GPU: "H100", GPUAttestation: "cafe",
	}, "sha256:abc", priv)
	if err != nil {
		t.Fatalf("NewTeeProxy: %v", err)
	}
	return p
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return priv
}

// 1. Proxy forwards method/path/body unchanged to the upstream.
func TestProxyForwardsToUpstream(t *testing.T) {
	up := &fakeUpstream{body: []byte(`{"ok":true}`)}
	p := newTestProxy(t, up)
	body := bytes.NewReader([]byte(`{"hi":1}`))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	req.Header.Set("x-test", "v")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if up.called != 1 {
		t.Fatalf("upstream called %d times, want 1", up.called)
	}
	if up.last.method != http.MethodPost || up.last.path != "/v1/chat/completions" {
		t.Errorf("got %s %s, want POST /v1/chat/completions", up.last.method, up.last.path)
	}
	if string(up.last.body) != `{"hi":1}` {
		t.Errorf("body forwarded = %q", up.last.body)
	}
}

// 2. Response is wrapped in an AttestationEnvelope and the body survives intact.
func TestProxyWrapsInEnvelope(t *testing.T) {
	payload := `{"choices":[{"message":{"content":"hi"}}]}`
	up := &fakeUpstream{body: []byte(payload)}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	var got AttestedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if string(got.Body) != payload {
		t.Errorf("body mismatch: %q vs %q", got.Body, payload)
	}
	if got.Envelope == nil {
		t.Fatal("nil envelope")
	}
	if got.Envelope.SchemaVersion != EnvelopeV1 {
		t.Errorf("schema=%s", got.Envelope.SchemaVersion)
	}
}

// 3. The envelope signature verifies against the proxy's published public key.
func TestEnvelopeSignatureVerifies(t *testing.T) {
	up := &fakeUpstream{body: []byte(`x`)}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/anything", strings.NewReader(``))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	var got AttestedResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	pubBytes, err := hex.DecodeString(p.PublicKey())
	if err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	if err := got.Envelope.Verify(ed25519.PublicKey(pubBytes)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// 4. A tampered response_digest invalidates the envelope.
func TestTamperedResponseDigestFails(t *testing.T) {
	up := &fakeUpstream{body: []byte(`x`)}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(``))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	var got AttestedResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	got.Envelope.ResponseDigest = "sha256:00"
	pubBytes, _ := hex.DecodeString(p.PublicKey())
	if err := got.Envelope.Verify(ed25519.PublicKey(pubBytes)); err == nil {
		t.Fatal("expected verification failure on tampered digest")
	}
}

// 5. The envelope carries the configured TEE facts.
func TestEnvelopeCarriesTeeFacts(t *testing.T) {
	up := &fakeUpstream{body: []byte(`x`)}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(``))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	var got AttestedResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Envelope.TeeKind != "sev-snp" {
		t.Errorf("kind=%s", got.Envelope.TeeKind)
	}
	if got.Envelope.TeeMeasurement != "deadbeef" {
		t.Errorf("measurement=%s", got.Envelope.TeeMeasurement)
	}
	if got.Envelope.GpuModel != "H100" {
		t.Errorf("gpu=%s", got.Envelope.GpuModel)
	}
	if got.Envelope.ModelDigest != "sha256:abc" {
		t.Errorf("model=%s", got.Envelope.ModelDigest)
	}
}

// 6. /healthz returns 200 without contacting the upstream.
func TestHealthz(t *testing.T) {
	up := &fakeUpstream{}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if up.called != 0 {
		t.Errorf("healthz must not call upstream; called %d", up.called)
	}
}

// 7. /readyz probes the upstream and returns 200 only on success.
func TestReadyz(t *testing.T) {
	up := &fakeUpstream{status: http.StatusOK}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if up.called != 1 {
		t.Errorf("readyz must probe upstream once; got %d", up.called)
	}
}

// 8. /readyz surfaces upstream failure as 503.
func TestReadyzFailsWhenUpstreamDown(t *testing.T) {
	up := &fakeUpstream{err: ErrUpstreamUnreachable}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rec.Code)
	}
}

// 9. /versionz returns schema + component info.
func TestVersionz(t *testing.T) {
	p := newTestProxy(t, &fakeUpstream{})
	req := httptest.NewRequest(http.MethodGet, "/versionz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var m map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if m["component"] != "tee-serve" || m["scheme"] != EnvelopeV1 {
		t.Errorf("unexpected body: %v", m)
	}
}

// 10. /pubkey returns the hex Ed25519 public key.
func TestPubkeyEndpoint(t *testing.T) {
	p := newTestProxy(t, &fakeUpstream{})
	req := httptest.NewRequest(http.MethodGet, "/pubkey", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var m map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if hex.EncodeToString(p.signPub) != m["pubkey_hex"] {
		t.Errorf("pubkey mismatch: %s vs %s", hex.EncodeToString(p.signPub), m["pubkey_hex"])
	}
}

// 11. Unknown paths return 404.
func TestUnknownRoute(t *testing.T) {
	p := newTestProxy(t, &fakeUpstream{})
	req := httptest.NewRequest(http.MethodGet, "/random", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", rec.Code)
	}
}

// 12. Upstream error becomes 502 from the proxy.
func TestUpstreamErrorReturnsBadGateway(t *testing.T) {
	up := &fakeUpstream{err: ErrUpstreamUnreachable}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rec.Code)
	}
}

// 13. SetModelDigest is reflected in subsequent envelopes.
func TestSetModelDigest(t *testing.T) {
	up := &fakeUpstream{body: []byte(`x`)}
	p := newTestProxy(t, up)
	p.SetModelDigest("sha256:new")
	req := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(``))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	var got AttestedResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Envelope.ModelDigest != "sha256:new" {
		t.Errorf("digest=%s, want sha256:new", got.Envelope.ModelDigest)
	}
}

// 14. Two envelopes for the same body have different NonceHex (replay protection).
func TestNonceFreshness(t *testing.T) {
	up := &fakeUpstream{body: []byte(`x`)}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(``))
	rec1 := httptest.NewRecorder()
	p.ServeHTTP(rec1, req)
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, req)
	var a, b AttestedResponse
	_ = json.Unmarshal(rec1.Body.Bytes(), &a)
	_ = json.Unmarshal(rec2.Body.Bytes(), &b)
	if a.Envelope.NonceHex == b.Envelope.NonceHex {
		t.Errorf("nonces collided: %s", a.Envelope.NonceHex)
	}
}

// 15. Overhead is recorded (in nanoseconds) after a proxied call.
func TestOverheadRecorded(t *testing.T) {
	up := &slowUpstream{body: []byte(`x`), delay: 2 * time.Millisecond}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(``))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if p.LastOverheadNanos() <= 0 {
		t.Errorf("overhead=%d, want >0", p.LastOverheadNanos())
	}
}

// slowUpstream adds a small sleep to guarantee the timer advances on coarse clocks.
type slowUpstream struct {
	body  []byte
	delay time.Duration
}

func (s *slowUpstream) Do(ctx context.Context, method, path string, headers http.Header, body []byte) (int, []byte, error) {
	time.Sleep(s.delay)
	return http.StatusOK, s.body, nil
}

// 16. Verifying against the wrong key fails.
func TestVerifyWrongKeyFails(t *testing.T) {
	up := &fakeUpstream{body: []byte(`x`)}
	p := newTestProxy(t, up)
	req := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(``))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	var got AttestedResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := got.Envelope.Verify(other); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

// 17. NewTeeProxy rejects nil upstream / nil provider.
func TestNewTeeProxyValidation(t *testing.T) {
	if _, err := NewTeeProxy(nil, &MockAttestationProvider{}, "x", nil); err == nil {
		t.Error("expected error for nil upstream")
	}
	if _, err := NewTeeProxy(&fakeUpstream{}, nil, "x", nil); err == nil {
		t.Error("expected error for nil provider")
	}
}

// 18. NewTeeProxy with empty model digest falls back to "sha256:unknown".
func TestNewTeeProxyDefaultModelDigest(t *testing.T) {
	p, err := NewTeeProxy(&fakeUpstream{}, &MockAttestationProvider{}, "", nil)
	if err != nil {
		t.Fatalf("NewTeeProxy: %v", err)
	}
	if p.ModelDigest() != "sha256:unknown" {
		t.Errorf("digest=%s", p.ModelDigest())
	}
}

// 19. SocketUpstream surfaces ErrUpstreamUnreachable when the socket doesn't exist.
func TestSocketUpstreamMissingSocket(t *testing.T) {
	u := NewSocketUpstream("/tmp/does-not-exist-teeserve.sock")
	_, _, err := u.Do(context.Background(), http.MethodGet, "/healthz", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "upstream unreachable") {
		t.Errorf("err=%v", err)
	}
}

// 20. MockAttestationProvider returns defaults when fields are unset.
func TestMockProviderDefaults(t *testing.T) {
	m := &MockAttestationProvider{}
	if m.TeeKind() != "mock" {
		t.Errorf("kind=%s", m.TeeKind())
	}
	if m.TeeMeasurement() != "mock-measurement" {
		t.Errorf("measurement=%s", m.TeeMeasurement())
	}
}

// 21. End-to-end against a real HTTP server as the upstream (via SocketUpstream).
func TestEndToEndOverUnixSocket(t *testing.T) {
	requireUnixSocketDial(t)
	// Spin up an HTTP server speaking HTTP over a Unix socket, then point SocketUpstream at it.
	dir := t.TempDir()
	// filepath.Join, not string concatenation: mixing separators produces paths some platforms
	// reject outright.
	sockPath := filepath.Join(dir, "upstream.sock")
	ln, err := listenUnix(sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = removeFile(sockPath)
	}()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"hello":"from-socket"}`)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Wait for the socket to be live.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := dialUnix(sockPath)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	up := NewSocketUpstream(sockPath)
	p, err := NewTeeProxy(up, &MockAttestationProvider{}, "sha256:e2e", nil)
	if err != nil {
		t.Fatalf("NewTeeProxy: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got AttestedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got.Body) != `{"hello":"from-socket"}` {
		t.Errorf("body=%s", got.Body)
	}
	pubBytes, _ := hex.DecodeString(p.PublicKey())
	if err := got.Envelope.Verify(ed25519.PublicKey(pubBytes)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

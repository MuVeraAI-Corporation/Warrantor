package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMockBackendCompletes(t *testing.T) {
	b := &MockBackend{}
	resp, err := b.Complete(context.Background(), &ChatRequest{
		Model:    "m",
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Model != "m" {
		t.Errorf("model = %q", resp.Model)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Content != "echo: hi" {
		t.Errorf("unexpected choices: %+v", resp.Choices)
	}
}

func TestRouterPicksPerModel(t *testing.T) {
	mock := &MockBackend{}
	r := NewRouter(mock)
	// Register a second mock for a specific model to confirm routing.
	other := &MockBackend{}
	r.Route("special-model", other)
	if r.Pick("special-model") != other {
		t.Error("router should pick the per-model backend")
	}
	if r.Pick("anything-else") != mock {
		t.Error("router should fall back to default")
	}
}

func TestProxyServesChatCompletions(t *testing.T) {
	p := NewProxy(NewRouter(&MockBackend{}), false)
	body := bytes.NewReader([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp ChatResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Choices) != 1 {
		t.Errorf("choices = %d", len(resp.Choices))
	}
}

func TestProxyRejectsMissingModel(t *testing.T) {
	p := NewProxy(NewRouter(&MockBackend{}), false)
	body := bytes.NewReader([]byte(`{"messages":[]}`))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing model, got %d", rec.Code)
	}
}

func TestProxyHealthAndVersion(t *testing.T) {
	p := NewProxy(NewRouter(&MockBackend{}), false)
	for path, wantKey := range map[string]string{
		"/healthz":  "status",
		"/versionz": "component",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, rec.Code)
		}
		var m map[string]string
		_ = json.NewDecoder(rec.Body).Decode(&m)
		if _, ok := m[wantKey]; !ok {
			t.Errorf("%s: missing key %q in %v", path, wantKey, m)
		}
	}
}

func TestProxyWrapsAttestationWhenEnabled(t *testing.T) {
	p := NewProxy(NewRouter(&MockBackend{}), true)
	body := bytes.NewReader([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var ar AttestedResponse
	if err := json.NewDecoder(rec.Body).Decode(&ar); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ar.Attestation == nil {
		t.Error("expected attestation envelope when wrap is enabled")
	}
	if ar.Attestation.Attested {
		t.Error("v1.0 attestation should be Attested=false (filled by attesta-flow in production)")
	}
}

func TestHTTPBackendType(t *testing.T) {
	b := NewHTTPBackend(BackendVLLM, "http://localhost:8080")
	if b.Type() != BackendVLLM {
		t.Errorf("type = %s", b.Type())
	}
}

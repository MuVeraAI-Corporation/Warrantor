// Package proxy implements N1 open-serve-kit — an OpenAI-compatible proxy that routes
// /v1/chat/completions and /v1/completions to pluggable backends (vLLM, Triton, TensorRT-LLM,
// Ollama). Optionally wraps each response in an attestation envelope (attesta-flow C1-3).
//
// Per RFC N1: backend-agnostic. The Backend interface abstracts the inference engine; concrete
// implementations (vLLM, Triton, etc.) are registered at startup.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// BackendType identifies a supported backend.
type BackendType string

const (
	BackendVLLM       BackendType = "vllm"
	BackendTriton     BackendType = "triton"
	BackendTensorRT   BackendType = "tensorrt-llm"
	BackendOllama     BackendType = "ollama"
	BackendMock       BackendType = "mock" // for CI / development
)

// ChatRequest mirrors the OpenAI /v1/chat/completions request shape (subset).
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	// Pass-through fields the proxy doesn't interpret:
	Extra map[string]any `json:"-"`
}

// ChatMessage is one message in the chat conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatChoice is one choice in the completion response.
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ChatResponse mirrors the OpenAI /v1/chat/completions response shape (subset).
type ChatResponse struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []ChatChoice  `json:"choices"`
	Usage   map[int]int   `json:"usage,omitempty"`
}

// AttestationEnvelope wraps a response with an attestation claim (per RFC N1).
type AttestationEnvelope struct {
	GPUModel        string `json:"gpu_model,omitempty"`
	Attested        bool   `json:"attested"`
	AttestationHex  string `json:"attestation_hex,omitempty"`
	VerifierKeyHex  string `json:"verifier_key_hex,omitempty"`
}

// AttestedResponse wraps a ChatResponse with an optional attestation.
type AttestedResponse struct {
	ChatResponse
	Attestation *AttestationEnvelope `json:"attestation,omitempty"`
}

// Backend is the interface every inference backend implements.
type Backend interface {
	Type() BackendType
	// Complete sends req to the backend and returns the response. Implementations may mutate
	// req.Model to map from the public model id to the backend's internal id.
	Complete(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
}

// MockBackend is a deterministic backend for CI / development.
type MockBackend struct {
	mu  sync.Mutex
	cnt int
}

// Type returns BackendMock.
func (m *MockBackend) Type() BackendType { return BackendMock }

// Complete returns a deterministic response echoing the last user message.
func (m *MockBackend) Complete(_ context.Context, req *ChatRequest) (*ChatResponse, error) {
	m.mu.Lock()
	m.cnt++
	id := m.cnt
	m.mu.Unlock()
	lastUser := ""
	for _, msg := range req.Messages {
		if msg.Role == "user" {
			lastUser = msg.Content
		}
	}
	return &ChatResponse{
		ID:      fmt.Sprintf("chatcmpl-mock-%d", id),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []ChatChoice{
			{
				Index:        0,
				Message:      ChatMessage{Role: "assistant", Content: "echo: " + lastUser},
				FinishReason: "stop",
			},
		},
	}, nil
}

// HTTPBackend calls a real backend over HTTP. The backend must expose an OpenAI-compatible
// /v1/chat/completions endpoint.
type HTTPBackend struct {
	backendType BackendType
	baseURL     string
	client      *http.Client
}

// NewHTTPBackend constructs an HTTPBackend pointing at baseURL.
func NewHTTPBackend(t BackendType, baseURL string) *HTTPBackend {
	return &HTTPBackend{
		backendType: t,
		baseURL:     strings.TrimRight(baseURL, "/"),
		client:      &http.Client{Timeout: 60 * time.Second},
	}
}

// Type returns the backend type.
func (b *HTTPBackend) Type() BackendType { return b.backendType }

// Complete forwards the request to the backend's /v1/chat/completions endpoint.
func (b *HTTPBackend) Complete(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("open-serve-kit: marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/v1/chat/completions", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("open-serve-kit: new request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("open-serve-kit: call %s: %w", b.backendType, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("open-serve-kit: %s returned %d: %s", b.backendType, resp.StatusCode, string(raw))
	}
	var out ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("open-serve-kit: decode: %w", err)
	}
	return &out, nil
}

// Router selects a backend for a given model. The default routes everything to one backend;
// production deployments register per-model routes.
type Router struct {
	default_ Backend
	byModel  map[string]Backend
}

// NewRouter constructs a Router with a default backend.
func NewRouter(defaultBackend Backend) *Router {
	return &Router{default_: defaultBackend, byModel: map[string]Backend{}}
}

// Route registers a backend for a specific model id.
func (r *Router) Route(model string, b Backend) {
	r.byModel[model] = b
}

// Pick returns the backend for a model, falling back to the default.
func (r *Router) Pick(model string) Backend {
	if b, ok := r.byModel[model]; ok {
		return b
	}
	return r.default_
}

// Proxy is the OpenAI-compatible proxy.
type Proxy struct {
	router           *Router
	wrapAttestation  bool
}

// NewProxy constructs a Proxy. If wrapAttestation is true, responses are wrapped in an
// AttestationEnvelope (the attestation itself is supplied by attesta-flow C1-3 in production;
// v1.0 leaves Attested=false).
func NewProxy(router *Router, wrapAttestation bool) *Proxy {
	return &Proxy{router: router, wrapAttestation: wrapAttestation}
}

// ServeHTTP implements http.Handler, exposing /v1/chat/completions and /healthz.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	case "/versionz":
		writeJSON(w, http.StatusOK, map[string]string{"component": "open-serve-kit", "version": "1.0.0"})
		return
	case "/v1/chat/completions":
		p.handleChat(w, r)
		return
	case "/v1/completions":
		// Legacy completions endpoint — same handler (OpenAI-compatible).
		p.handleChat(w, r)
		return
	default:
		writeError(w, http.StatusNotFound, "no route for "+r.URL.Path)
	}
}

func (p *Proxy) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		writeError(w, http.StatusBadRequest, "missing 'model'")
		return
	}
	backend := p.router.Pick(req.Model)
	resp, err := backend.Complete(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if p.wrapAttestation {
		writeJSON(w, http.StatusOK, AttestedResponse{
			ChatResponse: *resp,
			Attestation:  &AttestationEnvelope{Attested: false}, // filled by attesta-flow in production
		})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

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

// ErrUnknownBackend is returned by helpers that look up a backend by type.
var ErrUnknownBackend = errors.New("open-serve-kit: unknown backend type")

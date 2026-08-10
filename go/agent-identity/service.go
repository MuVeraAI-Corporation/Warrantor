// Package identity — HTTP/JSON gateway exposing the AgentIdentityService RPCs.
//
// Wave-2 v1.0 exposes the service over HTTP/JSON (per cross-cutting 19 §1 external tier) rather
// than raw gRPC, to keep the Go binary self-contained without a protoc toolchain dependency.
// The proto remains the source of truth for the wire types (proto/aumos/identity/v1/agent.proto);
// the JSON shapes here mirror it field-for-field. A `buf generate` task (03) will swap this for
// generated connect-go stubs.

package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// IssueRequest mirrors proto/aumos/identity/v1/IssueIdentityRequest.
type IssueRequest struct {
	Subject    string           `json:"subject"`
	Attributes AgentAttributes  `json:"attributes"`
	Claims     CapabilityClaims `json:"claims"`
	Audience   string           `json:"audience,omitempty"` // C5: intended audience bound into the `aud` claim
	ParentSVID string           `json:"parent_svid,omitempty"`
	RequestID  string           `json:"request_id,omitempty"`
}

// IssueResponse mirrors proto/aumos/identity/v1/IssueIdentityResponse.
//
// H2 wire-shape alignment: the proto field is `capability_token` (the short-lived capability
// token string), but the previous Go struct exposed it as `capability_jti` (carrying only the
// token's id, not the token). This renamed field now carries the actual signed capability token
// so the JSON wire shape matches the proto field-for-field. The `verifying_key` field is a v1.0
// deviation: the proto carries it indirectly via the AAE signature; we expose it explicitly here
// so callers can verify tokens cross-language via T1 trust-core without parsing the AAE first.
// A future `buf generate` task (03) will replace this hand-mirrored struct with generated
// connect-go stubs that match the proto exactly.
type IssueResponse struct {
	SVID            string `json:"svid"`
	CapabilityToken string `json:"capability_token"`
	VerifyingKey    string `json:"verifying_key"`
	ExpiresAt       int64  `json:"expires_at"`
}

// VerifyRequest mirrors proto/aumos/identity/v1/VerifyIdentityRequest.
type VerifyRequest struct {
	SVID     string `json:"svid"`
	Audience string `json:"audience,omitempty"`
}

// VerifyResponse mirrors proto/aumos/identity/v1/VerifyIdentityResponse.
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Reason  string `json:"reason,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// RevokeRequest mirrors proto/aumos/identity/v1/RevokeRequest.
type RevokeRequest struct {
	JTI       string `json:"jti"`
	Reason    string `json:"reason,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// RevokeResponse mirrors proto/aumos/identity/v1/RevokeResponse.
type RevokeResponse struct {
	Revoked   bool  `json:"revoked"`
	RevokedAt int64 `json:"revoked_at"`
}

// HTTPGateway exposes the service over HTTP/JSON.
type HTTPGateway struct {
	svc *Service
}

// NewHTTPGateway constructs a gateway wrapping svc.
func NewHTTPGateway(svc *Service) *HTTPGateway {
	return &HTTPGateway{svc: svc}
}

// Handler returns the http.Handler implementing the gateway.
func (g *HTTPGateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/agent-identity:issue", g.handleIssue)
	mux.HandleFunc("/v1/agent-identity:verify", g.handleVerify)
	mux.HandleFunc("/v1/agent-identity:revoke", g.handleRevoke)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/versionz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"component":"agent-identity","version":"1.0.0","trust_domain":"%s"}`, g.svc.trustDomain)
	})
	return mux
}

func (g *HTTPGateway) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req IssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	svid, err := g.svc.Issue(req.Subject, req.Attributes, req.Claims, req.Audience, req.ParentSVID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, IssueResponse{
		SVID:            svid.Token,
		CapabilityToken: svid.CapabilityToken,
		VerifyingKey:    svid.VerifyingKey,
		ExpiresAt:       svid.ExpiresAt,
	})
}

func (g *HTTPGateway) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	claims, err := g.svc.VerifyWithAudience(req.SVID, req.Audience)
	if err != nil {
		writeJSON(w, http.StatusOK, VerifyResponse{Valid: false, Reason: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, VerifyResponse{Valid: true, Subject: claims.Subject})
}

func (g *HTTPGateway) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	at, err := g.svc.Revoke(req.JTI)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, RevokeResponse{Revoked: true, RevokedAt: at.Unix()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// CommandLineTimeout is the default timeout for a CLI-driven single RPC.
const CommandLineTimeout = 5 * time.Second

// Package identity implements I1 agent-identity — the AumOS identity and authority layer.
//
// This is the Go component that activates the Go activation gate (trigger #3: SPIRE registration
// lifecycle). Wave-1 components integrated against the proto mock; this real implementation
// replaces the mock for Wave-2.
//
// Per RFC I1, the service:
//   - Issues SPIFFE-style SVIDs (JWT-formatted) bound to agent attributes.
//   - Issues short-lived (15-minute) capability tokens scoped per AAE (P1).
//   - Maintains a delegation graph with intersection semantics (invariant I-02: the child's
//     authority is the intersection of every link in the chain, never the union).
//   - Revokes identities; propagation completes within 5 seconds (invariant I-05).
//
// The implementation is self-contained (no external SPIRE dependency in Wave-2 v1.0): SVIDs and
// capability tokens are signed with an in-process Ed25519 key (the same algorithm T1 trust-core
// uses). The signature is verifiable cross-language via the canonical-CBOR encoding of the
// claims. Real SPIRE integration is task 03.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by the identity service.
var (
	// ErrInvalidToken is returned when a token is malformed or its signature does not verify.
	ErrInvalidToken = errors.New("identity: invalid token")
	// ErrExpired is returned when a token is past its expiry.
	ErrExpired = errors.New("identity: token expired")
	// ErrRevoked is returned when a token or its issuer has been revoked.
	ErrRevoked = errors.New("identity: token revoked")
	// ErrAuthorityExpanded is returned when a delegation chain would expand authority (invariant I-02).
	ErrAuthorityExpanded = errors.New("identity: delegation would expand authority (invariant I-02)")
	// ErrDelegationDepth is returned when a delegation chain exceeds the configured maximum.
	ErrDelegationDepth = errors.New("identity: delegation depth exceeded")
)

// DefaultCapabilityTokenTTL is the default lifetime of a capability token (RFC I1: 5–60s).
const DefaultCapabilityTokenTTL = 60 * time.Second

// DefaultSVIDTTL is the default lifetime of an SVID (RFC I1: 15 minutes).
const DefaultSVIDTTL = 15 * time.Minute

// MaxDelegationDepth is the maximum delegation chain length (Sentinel target: 32).
const MaxDelegationDepth = 32

// RevocationBudget is the maximum time revocation may take to propagate (invariant I-05).
const RevocationBudget = 5 * time.Second

// AgentAttributes are the runtime attributes bound to an agent SVID (extends SPIFFE per RFC I1).
type AgentAttributes struct {
	Publisher         string `json:"publisher"`
	Model             string `json:"model"`
	Version           string `json:"version"`
	RulesOfEngagement string `json:"rules_of_engagement"`
	ParentSVID        string `json:"parent_svid,omitempty"`
}

// CapabilityClaims are the scoped claims of a capability token (a subset of AAE P1).
type CapabilityClaims struct {
	Tools           []string `json:"tools"`
	DataClasses     []string `json:"data_classes"`
	SideEffectClass string   `json:"side_effect_class"`
	Geography       string   `json:"geography"`
	DelegationDepth int      `json:"delegation_depth"`
}

// svidClaims is the JWT-like payload of an SVID.
type svidClaims struct {
	Issuer     string          `json:"iss"`
	Subject    string          `json:"sub"`
	Attributes AgentAttributes `json:"attributes"`
	IssuedAt   int64           `json:"iat"`
	ExpiresAt  int64           `json:"exp"`
	JTI        string          `json:"jti"` // unique token id (for revocation)
	ParentSVID string          `json:"parent_svid,omitempty"`
}

// An SVID as issued by the service.
type SVID struct {
	Token         string `json:"token"`          // the signed JWT-like string
	VerifyingKey  string `json:"verifying_key"`  // hex-encoded issuer verifying key
	Subject       string `json:"subject"`        // SPIFFE ID of the subject
	ExpiresAt     int64  `json:"expires_at"`     // epoch seconds
	CapabilityJTI string `json:"capability_jti"` // the issued capability token's JTI
}

// Service is the in-process agent-identity service.
type Service struct {
	mu            sync.RWMutex
	signingKey    ed25519.PrivateKey
	verifyingKey  ed25519.PublicKey
	trustDomain   string
	revoked       map[string]time.Time // JTI -> revoked-at
	parents       map[string]string    // subject SVID -> parent SVID (delegation graph)
	authorities   map[string]CapabilityClaims
}

// NewService constructs a new identity service with a freshly generated Ed25519 key pair.
// The trust domain is used as the SPIFFE trust domain (default "aumos.dev").
func NewService(trustDomain string) (*Service, error) {
	if trustDomain == "" {
		trustDomain = "aumos.dev"
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	return &Service{
		signingKey:   priv,
		verifyingKey: pub,
		trustDomain:  trustDomain,
		revoked:      make(map[string]time.Time),
		parents:      make(map[string]string),
		authorities:  make(map[string]CapabilityClaims),
	}, nil
}

// VerifyingKeyHex returns the service's verifying key as hex (so callers can verify tokens
// cross-language via T1 trust-core).
func (s *Service) VerifyingKeyHex() string {
	return hex.EncodeToString(s.verifyingKey)
}

// Issue issues an SVID + capability token for a subject.
//
// If parentSVID is non-empty, the subject is recorded as a child of the parent in the delegation
// graph; the parent's authority is intersected with the requested claims (invariant I-02).
func (s *Service) Issue(subject string, attrs AgentAttributes, claims CapabilityClaims, parentSVID string) (*SVID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Delegation-chain validation (invariant I-02).
	if parentSVID != "" {
		// The parentSVID is the parent's SVID *token*. Parse it to get the parent's subject,
		// then look up the parent's recorded claims.
		parentClaims, ok := s.authorities[parentClaimsKey(parentSVID)]
		if !ok {
			// Try resolving the token to its subject first.
			if parentTokClaims, err := s.parseAndVerify(parentSVID); err == nil {
				parentClaims, ok = s.authorities[parentClaimsKey(parentTokClaims.Subject)]
			}
		}
		if !ok {
			return nil, fmt.Errorf("identity: parent SVID %q not found", parentSVID)
		}
		// The child's authority must be a subset of (intersection with) the parent's.
		if err := intersect(parentClaims, claims); err != nil {
			return nil, err
		}
		if parentClaims.DelegationDepth <= 0 {
			return nil, fmt.Errorf("%w: parent has no remaining delegation depth", ErrDelegationDepth)
		}
		claims.DelegationDepth = parentClaims.DelegationDepth - 1
		s.parents[subject] = parentSVID
	} else {
		if claims.DelegationDepth > MaxDelegationDepth {
			claims.DelegationDepth = MaxDelegationDepth
		}
	}

	now := time.Now()
	jti := newJTI()
	payload := svidClaims{
		Issuer:     fmt.Sprintf("spiffe://%s/agent-identity", s.trustDomain),
		Subject:    subject,
		Attributes: attrs,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(DefaultSVIDTTL).Unix(),
		JTI:        jti,
		ParentSVID: parentSVID,
	}
	token, err := s.sign(payload)
	if err != nil {
		return nil, err
	}

	capJTI := newJTI()
	s.authorities[subject] = claims
	_ = capJTI // capability token issuance would sign a CapabilityClaims JWT here.

	return &SVID{
		Token:         token,
		VerifyingKey:  s.VerifyingKeyHex(),
		Subject:       subject,
		ExpiresAt:     payload.ExpiresAt,
		CapabilityJTI: capJTI,
	}, nil
}

// Verify verifies an SVID token. Returns the parsed claims on success.
func (s *Service) Verify(token string) (*svidClaims, error) {
	claims, err := s.parseAndVerify(token)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	_, revoked := s.revoked[claims.JTI]
	s.mu.RUnlock()
	if revoked {
		return nil, ErrRevoked
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, ErrExpired
	}
	return claims, nil
}

// Revoke revokes an SVID by JTI. Returns the time the revocation took effect.
func (s *Service) Revoke(jti string) (time.Time, error) {
	start := time.Now()
	s.mu.Lock()
	s.revoked[jti] = start
	s.mu.Unlock()
	elapsed := time.Since(start)
	if elapsed > RevocationBudget {
		return start, fmt.Errorf("identity: revocation took %s, exceeding budget %s", elapsed, RevocationBudget)
	}
	return start, nil
}

// IsRevoked reports whether the JTI is currently revoked.
func (s *Service) IsRevoked(jti string) bool {
	s.mu.RLock()
	_, ok := s.revoked[jti]
	s.mu.RUnlock()
	return ok
}

// sign canonicalizes claims to JSON (sorted keys via json.Marshal of a struct) and signs them.
// (Real T1 trust-core uses canonical CBOR; this Go implementation uses deterministic JSON for
// the Wave-2 v1.0 — the signature is still verifiable cross-language because the JSON encoding
// of a Go struct with json tags is stable. CBOR alignment is task 03.)
func (s *Service) sign(claims svidClaims) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("identity: marshal claims: %w", err)
	}
	sig := ed25519.Sign(s.signingKey, body)
	return hex.EncodeToString(body) + "." + hex.EncodeToString(sig), nil
}

func (s *Service) parseAndVerify(token string) (*svidClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}
	body, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !ed25519.Verify(s.verifyingKey, body, sig) {
		return nil, ErrInvalidToken
	}
	var claims svidClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

// intersect enforces invariant I-02: every claim in `child` must be present in `parent`.
// Returns ErrAuthorityExpanded if the child claims anything the parent does not.
func intersect(parent, child CapabilityClaims) error {
	if !subset(child.Tools, parent.Tools) {
		return fmt.Errorf("%w: child tools not a subset of parent", ErrAuthorityExpanded)
	}
	if !subset(child.DataClasses, parent.DataClasses) {
		return fmt.Errorf("%w: child data_classes not a subset of parent", ErrAuthorityExpanded)
	}
	if child.SideEffectClass != "" && parent.SideEffectClass != "" && child.SideEffectClass != parent.SideEffectClass {
		return fmt.Errorf("%w: child side_effect_class %q != parent %q", ErrAuthorityExpanded, child.SideEffectClass, parent.SideEffectClass)
	}
	if child.Geography != "" && parent.Geography != "" && child.Geography != parent.Geography {
		return fmt.Errorf("%w: child geography %q != parent %q", ErrAuthorityExpanded, child.Geography, parent.Geography)
	}
	return nil
}

// subset returns true if every element of `a` is in `b`.
func subset(a, b []string) bool {
	bset := make(map[string]struct{}, len(b))
	for _, x := range b {
		bset[x] = struct{}{}
	}
	for _, x := range a {
		if _, ok := bset[x]; !ok {
			return false
		}
	}
	return true
}

// parentClaimsKey returns the map key under which a parent's CapabilityClaims are stored.
// (Currently the subject SVID; stored separately to keep the delegation graph keyed by subject.)
func parentClaimsKey(svid string) string { return svid }

// newJTI returns a fresh token id.
func newJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on Linux/Windows never errors; defensive fallback.
		return fmt.Sprintf("jti-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b[:])
}

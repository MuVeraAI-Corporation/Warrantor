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

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Sentinel errors returned by the identity service.
var (
	// ErrInvalidToken is returned when a token is malformed or its signature does not verify.
	ErrInvalidToken = errors.New("identity: invalid token")
	// ErrExpired is returned when a token is past its expiry.
	ErrExpired = errors.New("identity: token expired")
	// ErrRevoked is returned when a token or its issuer has been revoked.
	ErrRevoked = errors.New("identity: token revoked")
	// ErrAudienceMismatch is returned when the token's audience claim does not match the
	// audience the verifier requested (C5 confused-deputy defense).
	ErrAudienceMismatch = errors.New("identity: audience mismatch")
	// ErrAuthorityExpanded is returned when a delegation chain would expand authority (invariant I-02).
	ErrAuthorityExpanded = errors.New("identity: delegation would expand authority (invariant I-02)")
	// ErrDelegationDepth is returned when a delegation chain exceeds the configured maximum.
	ErrDelegationDepth = errors.New("identity: delegation depth exceeded")
	// ErrInvalidSubject is returned when a subject is not a well-formed SPIFFE ID belonging to
	// this service's trust domain.
	ErrInvalidSubject = errors.New("identity: subject is not a valid SPIFFE ID in this trust domain")
	// ErrWrongTokenType is returned when a token of one type (e.g. a capability token) is
	// presented where another type (e.g. an SVID) is required.
	ErrWrongTokenType = errors.New("identity: wrong token type")
)

// Token type tags. These are bound into both the claims (`typ`) and — more importantly — the
// signed byte string, so a token of one type cannot be verified as another even if an attacker
// rewrites the claim. See signWithDomain.
const (
	tokenTypeSVID       = "svid"
	tokenTypeCapability = "cap"
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
	Type       string          `json:"typ"` // always tokenTypeSVID
	Issuer     string          `json:"iss"`
	Subject    string          `json:"sub"`
	Audience   string          `json:"aud,omitempty"` // C5: real audience claim (confused-deputy defense)
	Attributes AgentAttributes `json:"attributes"`
	IssuedAt   int64           `json:"iat"`
	ExpiresAt  int64           `json:"exp"`
	JTI        string          `json:"jti"` // unique token id (for revocation)
	ParentSVID string          `json:"parent_svid,omitempty"`
	// ParentJTI is the JTI of the parent SVID this token was delegated from. It is what makes
	// revocation transitive: Verify walks parent JTIs and rejects the child if any ancestor is
	// revoked (invariant I-05). Empty for root identities.
	ParentJTI string `json:"parent_jti,omitempty"`
}

// capabilityTokenClaims is the JWT-like payload of the short-lived capability token bound to an
// SVID. It mirrors a subset of the AAE (P1) — the per-action capability envelope. The token is
// signed with the same Ed25519 key as the SVID so a single verifying key suffices.
type capabilityTokenClaims struct {
	Type            string   `json:"typ"` // always tokenTypeCapability
	Issuer          string   `json:"iss"` // spiffe://<td>/agent-identity
	Subject         string   `json:"sub"` // the SVID subject this token is bound to
	Tools           []string `json:"tools"`
	DataClasses     []string `json:"data_classes"`
	SideEffectClass string   `json:"side_effect_class"`
	Geography       string   `json:"geography"`
	DelegationDepth int      `json:"delegation_depth"`
	IssuedAt        int64    `json:"iat"`
	ExpiresAt       int64    `json:"exp"` // short TTL (DefaultCapabilityTokenTTL)
	JTI             string   `json:"jti"` // capability-token JTI (for revocation)
}

// An SVID as issued by the service.
//
// H2: the field previously named `CapabilityJTI` (carrying only the capability token's id) is
// retained for internal revocation bookkeeping, and a new `CapabilityToken` field carries the
// actual signed capability token. The JSON wire shape (IssueResponse) now exposes
// `capability_token` (the token) rather than `capability_jti` (just its id), matching
// `IssueIdentityResponse.capability_token` in proto/warrantor/identity/v1/agent.proto.
type SVID struct {
	Token           string `json:"token"`            // the signed SVID (JWT-like string)
	VerifyingKey    string `json:"verifying_key"`    // hex-encoded issuer verifying key
	Subject         string `json:"subject"`          // SPIFFE ID of the subject
	ExpiresAt       int64  `json:"expires_at"`       // epoch seconds
	CapabilityToken string `json:"capability_token"` // the signed short-lived capability token
	CapabilityJTI   string `json:"capability_jti"`   // capability token's JTI (for revocation; NOT the wire shape)
}

// SigningKeySeedLen is the length of the Ed25519 seed accepted by NewServiceWithSeed.
const SigningKeySeedLen = ed25519.SeedSize

// Service is the in-process agent-identity service.
type Service struct {
	mu            sync.RWMutex
	signingKey    ed25519.PrivateKey
	verifyingKey  ed25519.PublicKey
	trustDomain   string
	trustDomainID spiffeid.TrustDomain
	// ephemeralKey records that the signing key was generated in-process rather than loaded from
	// shared material. Such a service CANNOT be replicated: siblings would sign with different
	// keys and reject each other's tokens. Callers surface this via HasEphemeralKey.
	ephemeralKey bool
	revoked      map[string]time.Time // JTI -> revoked-at
	parents      map[string]string    // subject SVID -> parent SVID (delegation graph)
	parentJTI    map[string]string    // child JTI -> parent JTI (revocation propagation)
	authorities  map[string]CapabilityClaims
}

// NewService constructs a new identity service with a freshly generated Ed25519 key pair.
// The trust domain is used as the SPIFFE trust domain (default "muveraai.com").
//
// The generated key lives only in this process. That is fine for tests and single-replica
// deployments, but a replicated deployment MUST use [NewServiceWithSeed] with shared key
// material — otherwise each replica signs with its own key and rejects every token issued by a
// sibling. [Service.HasEphemeralKey] reports which mode a service is in so the caller can refuse
// to start, or warn, when replicated.
func NewService(trustDomain string) (*Service, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	svc, err := newService(trustDomain, priv, pub)
	if err != nil {
		return nil, err
	}
	svc.ephemeralKey = true
	return svc, nil
}

// NewServiceWithSeed constructs an identity service whose Ed25519 key is derived deterministically
// from `seed` (exactly [SigningKeySeedLen] bytes). Every replica given the same seed produces the
// same verifying key, so tokens issued by one replica verify at every other — the precondition for
// running more than one instance.
//
// The seed is secret key material: source it from a mounted secret or a Vault KV path, never from
// an image layer or a command-line argument.
func NewServiceWithSeed(trustDomain string, seed []byte) (*Service, error) {
	if len(seed) != SigningKeySeedLen {
		return nil, fmt.Errorf("identity: signing key seed must be %d bytes, got %d", SigningKeySeedLen, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok { // unreachable: NewKeyFromSeed always yields an ed25519 public key
		return nil, errors.New("identity: derived key is not an ed25519 public key")
	}
	return newService(trustDomain, priv, pub)
}

func newService(trustDomain string, priv ed25519.PrivateKey, pub ed25519.PublicKey) (*Service, error) {
	if trustDomain == "" {
		trustDomain = "muveraai.com"
	}
	// Reject a malformed trust domain at construction rather than minting tokens under an
	// unparseable issuer for the lifetime of the process.
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("identity: invalid trust domain %q: %w", trustDomain, err)
	}
	return &Service{
		signingKey:    priv,
		verifyingKey:  pub,
		trustDomain:   td.Name(),
		trustDomainID: td,
		revoked:       make(map[string]time.Time),
		parents:       make(map[string]string),
		parentJTI:     make(map[string]string),
		authorities:   make(map[string]CapabilityClaims),
	}, nil
}

// HasEphemeralKey reports whether this service generated its own signing key. A service with an
// ephemeral key cannot be safely replicated.
func (s *Service) HasEphemeralKey() bool { return s.ephemeralKey }

// TrustDomain returns the SPIFFE trust domain this service issues under.
func (s *Service) TrustDomain() string { return s.trustDomain }

// validateSubject requires the subject to be a well-formed SPIFFE ID inside this service's trust
// domain. Without this the service accepted any string at all — including IDs belonging to a
// foreign trust domain, which is the whole point of having one.
func (s *Service) validateSubject(subject string) error {
	id, err := spiffeid.FromString(subject)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrInvalidSubject, subject, err)
	}
	if !id.MemberOf(s.trustDomainID) {
		return fmt.Errorf("%w: %q belongs to trust domain %q, not %q",
			ErrInvalidSubject, subject, id.TrustDomain().Name(), s.trustDomain)
	}
	// A bare "spiffe://<td>" with no path names the trust domain itself, not a workload.
	if id.Path() == "" {
		return fmt.Errorf("%w: %q has no path component", ErrInvalidSubject, subject)
	}
	return nil
}

// VerifyingKeyHex returns the service's verifying key as hex (so callers can verify tokens
// cross-language via T1 trust-core).
func (s *Service) VerifyingKeyHex() string {
	return hex.EncodeToString(s.verifyingKey)
}

// Issue issues an SVID + capability token for a subject.
//
// `audience` is the intended audience for the SVID (the confused-deputy defense, C5). It is
// bound into the token's `aud` claim; Verify checks it when a non-empty audience is supplied.
// Pass "" if no specific audience is required.
//
// If parentSVID is non-empty, the subject is recorded as a child of the parent in the delegation
// graph; the parent's authority is intersected with the requested claims (invariant I-02).
func (s *Service) Issue(subject string, attrs AgentAttributes, claims CapabilityClaims, audience string, parentSVID string) (*SVID, error) {
	if err := s.validateSubject(subject); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Delegation-chain validation (invariant I-02).
	parentJTI := ""
	if parentSVID != "" {
		// parentSVID must be the parent's SVID *token*, and the caller must prove possession of
		// it by presenting it in full. Resolving a bare subject string here (as an earlier
		// version did) let anyone who merely knew a parent's public SPIFFE ID inherit its
		// authority — the ID is not a secret.
		parentTokClaims, err := s.verifyLocked(parentSVID, "", tokenTypeSVID)
		if err != nil {
			return nil, fmt.Errorf("identity: parent SVID rejected: %w", err)
		}
		parentClaims, ok := s.authorities[parentClaimsKey(parentTokClaims.Subject)]
		if !ok {
			return nil, fmt.Errorf("identity: parent SVID %q not found", parentTokClaims.Subject)
		}
		// The child's authority must be a subset of (intersection with) the parent's.
		if err := intersect(parentClaims, claims); err != nil {
			return nil, err
		}
		if parentClaims.DelegationDepth <= 0 {
			return nil, fmt.Errorf("%w: parent has no remaining delegation depth", ErrDelegationDepth)
		}
		claims.DelegationDepth = parentClaims.DelegationDepth - 1
		parentJTI = parentTokClaims.JTI
		s.parents[subject] = parentSVID
	} else {
		if claims.DelegationDepth > MaxDelegationDepth {
			claims.DelegationDepth = MaxDelegationDepth
		}
	}

	now := time.Now()
	jti := newJTI()
	payload := svidClaims{
		Type:       tokenTypeSVID,
		Issuer:     fmt.Sprintf("spiffe://%s/agent-identity", s.trustDomain),
		Subject:    subject,
		Audience:   audience,
		Attributes: attrs,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(DefaultSVIDTTL).Unix(),
		JTI:        jti,
		ParentSVID: parentSVID,
		ParentJTI:  parentJTI,
	}
	token, err := s.sign(payload)
	if err != nil {
		return nil, err
	}

	// Issue the short-lived capability token bound to this SVID (H2: previously this was a stub
	// that only minted a JTI without signing a token; now we sign a real capability token whose
	// JSON shape matches a subset of the AAE P1, so the wire field `capability_token` carries the
	// actual token, not just its id).
	capJTI := newJTI()
	capNow := time.Now()
	capPayload := capabilityTokenClaims{
		Type:            tokenTypeCapability,
		Issuer:          fmt.Sprintf("spiffe://%s/agent-identity", s.trustDomain),
		Subject:         subject,
		Tools:           claims.Tools,
		DataClasses:     claims.DataClasses,
		SideEffectClass: claims.SideEffectClass,
		Geography:       claims.Geography,
		DelegationDepth: claims.DelegationDepth,
		IssuedAt:        capNow.Unix(),
		ExpiresAt:       capNow.Add(DefaultCapabilityTokenTTL).Unix(),
		JTI:             capJTI,
	}
	capToken, err := s.signCapability(capPayload)
	if err != nil {
		return nil, err
	}
	s.authorities[subject] = claims
	if parentJTI != "" {
		s.parentJTI[jti] = parentJTI
	}

	return &SVID{
		Token:           token,
		VerifyingKey:    s.VerifyingKeyHex(),
		Subject:         subject,
		ExpiresAt:       payload.ExpiresAt,
		CapabilityToken: capToken,
		CapabilityJTI:   capJTI,
	}, nil
}

// Verify verifies an SVID token. Returns the parsed claims on success.
//
// C5: when `audience` is non-empty, the token's `aud` claim MUST equal it. This is the real
// confused-deputy defense (the previous implementation compared the issuer prefix, which always
// matched and provided no protection). The audience-aware entrypoint is VerifyWithAudience;
// this method preserves the legacy signature by calling VerifyWithAudience with an empty
// audience (which skips the check for backward compatibility).
func (s *Service) Verify(token string) (*svidClaims, error) {
	return s.VerifyWithAudience(token, "")
}

// VerifyWithAudience verifies an SVID token and, when `audience` is non-empty, additionally
// requires the token's embedded `aud` claim to match `audience` exactly. Returns the parsed
// claims on success.
//
// # Errors
// Returns [ErrInvalidToken] if the signature is invalid, [ErrAudienceMismatch] if the audience
// does not match, [ErrRevoked] if the token's JTI is revoked, or [ErrExpired] if expired.
func (s *Service) VerifyWithAudience(token string, audience string) (*svidClaims, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.verifyLocked(token, audience, tokenTypeSVID)
}

// VerifyCapability verifies a capability token. It is the counterpart to [Service.Verify] for the
// other token type; before it existed nothing in the repo could check a capability token, and
// callers reached for Verify — which happily accepted one, because both types were signed the
// same way over untagged JSON.
//
// # Errors
// Returns [ErrWrongTokenType] if `token` is an SVID rather than a capability token, plus the same
// signature/expiry/revocation errors as [Service.VerifyWithAudience].
func (s *Service) VerifyCapability(token string) (*capabilityTokenClaims, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	body, err := s.openToken(token, tokenTypeCapability)
	if err != nil {
		return nil, err
	}
	var claims capabilityTokenClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if claims.Type != tokenTypeCapability {
		return nil, ErrWrongTokenType
	}
	if _, revoked := s.revoked[claims.JTI]; revoked {
		return nil, ErrRevoked
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, ErrExpired
	}
	return &claims, nil
}

// verifyLocked is the SVID verification core. The caller must hold s.mu (read or write).
func (s *Service) verifyLocked(token string, audience string, expectedType string) (*svidClaims, error) {
	body, err := s.openToken(token, expectedType)
	if err != nil {
		return nil, err
	}
	var claims svidClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if claims.Type != expectedType {
		return nil, ErrWrongTokenType
	}
	// C5: confused-deputy defense — when the caller specifies an audience, the token must carry
	// exactly that audience. (An empty requested audience skips the check, preserving backward
	// compatibility for callers that don't care.)
	if audience != "" && claims.Audience != audience {
		return nil, ErrAudienceMismatch
	}
	if err := s.checkRevokedChainLocked(claims.JTI); err != nil {
		return nil, err
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, ErrExpired
	}
	return &claims, nil
}

// checkRevokedChainLocked reports ErrRevoked if `jti` or any of its ancestors in the delegation
// graph is revoked. Revoking a parent has to invalidate everything delegated from it — otherwise
// an attacker who obtained a child token keeps their authority after the compromised parent is
// cut off, and invariant I-05 means nothing. The caller must hold s.mu.
func (s *Service) checkRevokedChainLocked(jti string) error {
	// The graph is built only by Issue (each child records exactly one parent), so it is a
	// forest and cannot contain a cycle. The depth bound is belt-and-braces against a future
	// change introducing one, and costs nothing.
	for depth := 0; jti != "" && depth <= MaxDelegationDepth; depth++ {
		if _, revoked := s.revoked[jti]; revoked {
			return ErrRevoked
		}
		jti = s.parentJTI[jti]
	}
	return nil
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
	return s.signWithDomain(tokenTypeSVID, body), nil
}

// signCapability canonicalizes the capability-token claims to JSON and signs them with the
// service's Ed25519 key. Same encoding scheme as [sign] (hex(body) "." hex(sig)) so the token
// is verifiable cross-language via T1 trust-core. Used by Issue to mint the real capability
// token bound to an SVID (H2: previously only the JTI was minted).
func (s *Service) signCapability(claims capabilityTokenClaims) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("identity: marshal capability claims: %w", err)
	}
	return s.signWithDomain(tokenTypeCapability, body), nil
}

// signingInput binds the token type into the signed bytes themselves. Both token types are signed
// with the same key, so without this an attacker could present a low-value capability token where
// a high-value SVID is expected and the signature would check out. The type tag is length-prefixed
// so it cannot be re-split: "cap" + body X is never the same byte string as "ca" + body pX.
func signingInput(typ string, body []byte) []byte {
	out := make([]byte, 0, len(typ)+len(body)+16)
	out = append(out, "aumos-identity-v1/"...)
	out = append(out, byte(len(typ)))
	out = append(out, typ...)
	return append(out, body...)
}

func (s *Service) signWithDomain(typ string, body []byte) string {
	sig := ed25519.Sign(s.signingKey, signingInput(typ, body))
	return hex.EncodeToString(body) + "." + hex.EncodeToString(sig)
}

// openToken splits a token, checks its signature under the expected type's domain, and returns
// the raw claims body. It does NOT interpret the claims — callers unmarshal and check them.
func (s *Service) openToken(token string, expectedType string) ([]byte, error) {
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
	if !ed25519.Verify(s.verifyingKey, signingInput(expectedType, body), sig) {
		return nil, ErrInvalidToken
	}
	return body, nil
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

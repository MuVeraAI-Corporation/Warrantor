package identity

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// hexDecode is a thin wrapper used by the H2 wire-shape tests.
func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

func TestIssueAndVerifyRoundTrip(t *testing.T) {
	svc, err := NewService("aumos.dev")
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svid, err := svc.Issue(
		"spiffe://aumos.dev/agent/coding-1",
		AgentAttributes{Publisher: "aumos.dev/coding-agent", Model: "claude-opus-4.5"},
		CapabilityClaims{Tools: []string{"github"}, SideEffectClass: "write", DelegationDepth: 2},
		"", // audience
		"",
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if svid.Token == "" {
		t.Fatal("empty token")
	}
	claims, err := svc.Verify(svid.Token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "spiffe://aumos.dev/agent/coding-1" {
		t.Errorf("subject = %q, want coding-1", claims.Subject)
	}
}

func TestTamperedTokenFails(t *testing.T) {
	svc, _ := NewService("aumos.dev")
	svid, _ := svc.Issue("spiffe://aumos.dev/agent/x", AgentAttributes{}, CapabilityClaims{}, "", "")
	// Flip one byte in the signature half.
	parts := strings.SplitN(svid.Token, ".", 2)
	tampered := parts[0] + "." + flipHex(parts[1])
	if _, err := svc.Verify(tampered); err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestAudienceMismatchRejectedC5(t *testing.T) {
	// C5: the confused-deputy defense must check the real `aud` claim. A token issued for
	// audience "service-a" must NOT verify when the caller requests audience "service-b".
	svc, _ := NewService("aumos.dev")
	svid, err := svc.Issue(
		"spiffe://aumos.dev/agent/x",
		AgentAttributes{},
		CapabilityClaims{},
		"service-a", // intended audience
		"",
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Matching audience verifies.
	if _, err := svc.VerifyWithAudience(svid.Token, "service-a"); err != nil {
		t.Errorf("matching audience should verify, got: %v", err)
	}
	// Mismatched audience must be rejected with ErrAudienceMismatch (not the old always-pass issuer-prefix check).
	if _, err := svc.VerifyWithAudience(svid.Token, "service-b"); err != ErrAudienceMismatch {
		t.Errorf("expected ErrAudienceMismatch for wrong audience, got %v", err)
	}
	// A token issued with no audience must NOT satisfy a non-empty audience request.
	noAud, _ := svc.Issue("spiffe://aumos.dev/agent/y", AgentAttributes{}, CapabilityClaims{}, "", "")
	if _, err := svc.VerifyWithAudience(noAud.Token, "service-a"); err != ErrAudienceMismatch {
		t.Errorf("expected ErrAudienceMismatch when token has no aud but a non-empty audience is requested, got %v", err)
	}
	// Empty requested audience skips the check (backward compat).
	if _, err := svc.VerifyWithAudience(svid.Token, ""); err != nil {
		t.Errorf("empty requested audience should skip the check, got: %v", err)
	}
}

func TestRevokedTokenRejected(t *testing.T) {
	svc, _ := NewService("aumos.dev")
	svid, _ := svc.Issue("spiffe://aumos.dev/agent/x", AgentAttributes{}, CapabilityClaims{}, "", "")
	claims, _ := svc.Verify(svid.Token)
	if _, err := svc.Revoke(claims.JTI); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Verify(svid.Token); err != ErrRevoked {
		t.Errorf("expected ErrRevoked, got %v", err)
	}
}

func TestRevocationBudgetMet(t *testing.T) {
	// Revocation is in-memory so completes well under the 5s budget.
	svc, _ := NewService("aumos.dev")
	start := time.Now()
	_, err := svc.Revoke("any-jti")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if elapsed := time.Since(start); elapsed > RevocationBudget {
		t.Errorf("revocation took %s, budget %s", elapsed, RevocationBudget)
	}
}

func TestDelegationIntersection_I02(t *testing.T) {
	// Invariant I-02: child authority must be a subset of (intersection with) parent.
	svc, _ := NewService("aumos.dev")
	parent, err := svc.Issue(
		"spiffe://aumos.dev/agent/parent",
		AgentAttributes{},
		CapabilityClaims{Tools: []string{"github", "slack"}, DataClasses: []string{"L0", "L1"}, SideEffectClass: "write", DelegationDepth: 2},
		"",
		"",
	)
	if err != nil {
		t.Fatalf("parent Issue: %v", err)
	}

	// Child A: subset of parent — must succeed.
	_, err = svc.Issue(
		"spiffe://aumos.dev/agent/childA",
		AgentAttributes{},
		CapabilityClaims{Tools: []string{"github"}, DataClasses: []string{"L0"}, SideEffectClass: "write", DelegationDepth: 1},
		"",
		parent.Token,
	)
	if err != nil {
		t.Errorf("childA (subset) should succeed, got: %v", err)
	}

	// Child B: claims a tool the parent does not have — must fail with ErrAuthorityExpanded.
	_, err = svc.Issue(
		"spiffe://aumos.dev/agent/childB",
		AgentAttributes{},
		CapabilityClaims{Tools: []string{"aws"}, SideEffectClass: "write", DelegationDepth: 1},
		"",
		parent.Token,
	)
	if err == nil || !strings.Contains(err.Error(), "expand authority") {
		t.Errorf("childB (tool expansion) should fail with ErrAuthorityExpanded, got: %v", err)
	}

	// Child C: claims a higher side-effect class — must fail.
	_, err = svc.Issue(
		"spiffe://aumos.dev/agent/childC",
		AgentAttributes{},
		CapabilityClaims{Tools: []string{"github"}, SideEffectClass: "financial", DelegationDepth: 1},
		"",
		parent.Token,
	)
	if err == nil || !strings.Contains(err.Error(), "expand authority") {
		t.Errorf("childC (side-effect escalation) should fail, got: %v", err)
	}
}

func TestDelegationDepthExhausted(t *testing.T) {
	svc, _ := NewService("aumos.dev")
	leaf, err := svc.Issue(
		"spiffe://aumos.dev/agent/leaf",
		AgentAttributes{},
		CapabilityClaims{Tools: []string{"github"}, DelegationDepth: 0}, // no further delegation
		"",
		"",
	)
	if err != nil {
		t.Fatalf("leaf Issue: %v", err)
	}
	_, err = svc.Issue(
		"spiffe://aumos.dev/agent/grandchild",
		AgentAttributes{},
		CapabilityClaims{Tools: []string{"github"}, DelegationDepth: 1},
		"",
		leaf.Token,
	)
	if err == nil {
		t.Error("grandchild of a depth-0 leaf should fail")
	}
}

func TestSubset(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"empty subset of anything", nil, []string{"x"}, true},
		{"equal sets", []string{"x", "y"}, []string{"y", "x"}, true},
		{"proper subset", []string{"x"}, []string{"x", "y"}, true},
		{"not subset", []string{"z"}, []string{"x", "y"}, false},
	}
	for _, c := range cases {
		if got := subset(c.a, c.b); got != c.want {
			t.Errorf("%s: subset(%v, %v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}

func TestVerifyingKeyHexIsStable(t *testing.T) {
	svc, _ := NewService("aumos.dev")
	k1 := svc.VerifyingKeyHex()
	k2 := svc.VerifyingKeyHex()
	if k1 != k2 {
		t.Error("VerifyingKeyHex must be stable across calls")
	}
	if len(k1) != 64 { // 32 bytes hex
		t.Errorf("verifying key hex length = %d, want 64", len(k1))
	}
}

// TestCapabilityTokenIssued_H2 covers the H2 wire-shape fix: Issue must populate a signed
// capability token (not just the JTI), and the wire shape must expose `capability_token` so it
// matches proto/aumos/identity/v1/IssueIdentityResponse.capability_token.
func TestCapabilityTokenIssued_H2(t *testing.T) {
	svc, _ := NewService("aumos.dev")
	svid, err := svc.Issue(
		"spiffe://aumos.dev/agent/cap",
		AgentAttributes{Publisher: "aumos.dev/coding-agent"},
		CapabilityClaims{
			Tools:           []string{"github", "slack"},
			DataClasses:     []string{"L0"},
			SideEffectClass: "write",
			Geography:       "US",
			DelegationDepth: 2,
		},
		"",
		"",
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// The capability token must be a real signed token (not empty, not just the JTI).
	if svid.CapabilityToken == "" {
		t.Fatal("CapabilityToken must be populated (H2: previously only the JTI was minted)")
	}
	if svid.CapabilityToken == svid.CapabilityJTI {
		t.Fatal("CapabilityToken must be the signed token, not equal to the JTI")
	}
	// The token must be of the form hex(body) "." hex(sig).
	parts := strings.SplitN(svid.CapabilityToken, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("capability token must be hex.hex, got %q", svid.CapabilityToken)
	}
	body, err := hexDecode(parts[0])
	if err != nil {
		t.Fatalf("capability token body hex decode: %v", err)
	}
	// The capability token body must be a capabilityTokenClaims JSON (contains a "jti" field).
	if !strings.Contains(string(body), `"jti"`) {
		t.Errorf("capability token body must contain a jti claim, got: %s", body)
	}
}

// TestIssueResponseWireShape_H2 verifies the JSON wire shape emitted by the gateway carries the
// proto field name `capability_token` (not the old `capability_jti`).
func TestIssueResponseWireShape_H2(t *testing.T) {
	svc, _ := NewService("aumos.dev")
	svid, _ := svc.Issue(
		"spiffe://aumos.dev/agent/wire",
		AgentAttributes{},
		CapabilityClaims{Tools: []string{"github"}},
		"",
		"",
	)
	resp := IssueResponse{
		SVID:            svid.Token,
		CapabilityToken: svid.CapabilityToken,
		VerifyingKey:    svid.VerifyingKey,
		ExpiresAt:       svid.ExpiresAt,
	}
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jsonStr := string(out)
	if !strings.Contains(jsonStr, `"capability_token"`) {
		t.Errorf("wire shape must carry capability_token, got: %s", jsonStr)
	}
	if strings.Contains(jsonStr, `"capability_jti"`) {
		t.Errorf("wire shape must NOT carry capability_jti (renamed in H2), got: %s", jsonStr)
	}
	// Round-trip: the JSON must deserialize back into IssueResponse with the token populated.
	var back IssueResponse
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.CapabilityToken != svid.CapabilityToken {
		t.Errorf("round-trip capability_token mismatch")
	}
}

// flipHex flips the first hex char of a hex string (for tamper tests).
func flipHex(h string) string {
	if len(h) == 0 {
		return h
	}
	b := []byte(h)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

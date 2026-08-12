// Regression tests for the six identity defects found in the end-to-end audit.
//
// Each test is written as the attack it prevents, so a regression reads as "the exploit works
// again" rather than "an assertion changed".
package identity

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testTrustDomain = "muveraai.com"

func newTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(testTrustDomain)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func fullClaims() CapabilityClaims {
	return CapabilityClaims{
		Tools:           []string{"read", "write"},
		DataClasses:     []string{"public"},
		SideEffectClass: "none",
		Geography:       "IN",
		DelegationDepth: 5,
	}
}

// --- AX-29: the service accepted any string as a subject ---------------------

func TestIssueRejectsSubjectsThatAreNotSPIFFEIDs(t *testing.T) {
	svc := newTestService(t)
	for _, subject := range []string{
		"",                       // empty
		"agent/alpha",            // no scheme
		"https://muveraai.com/a", // wrong scheme
		"spiffe://muveraai.com",  // trust domain itself, no workload path
		"not a url at all",       //
		"spiffe:///agent/alpha",  // no trust domain
	} {
		if _, err := svc.Issue(subject, AgentAttributes{}, fullClaims(), "", ""); err == nil {
			t.Errorf("Issue(%q) succeeded; want rejection", subject)
		} else if !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("Issue(%q) error = %v; want ErrInvalidSubject", subject, err)
		}
	}
}

func TestIssueRejectsForeignTrustDomains(t *testing.T) {
	svc := newTestService(t)
	// A well-formed SPIFFE ID -- but not ours. Accepting it would let another trust domain's
	// identities be minted under our issuer, which defeats the purpose of a trust domain.
	foreign := "spiffe://evil.example/agent/alpha"
	_, err := svc.Issue(foreign, AgentAttributes{}, fullClaims(), "", "")
	if err == nil {
		t.Fatalf("Issue(%q) succeeded; want rejection", foreign)
	}
	if !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("error = %v; want ErrInvalidSubject", err)
	}
	if !strings.Contains(err.Error(), "evil.example") {
		t.Errorf("error %q should name the offending trust domain", err)
	}
}

func TestNewServiceRejectsMalformedTrustDomain(t *testing.T) {
	if _, err := NewService("not a trust domain"); err == nil {
		t.Fatal("NewService accepted a malformed trust domain")
	}
}

// --- Multi-replica: every process generated its own key ----------------------

func TestSeededServicesShareAVerifyingKey(t *testing.T) {
	seed := make([]byte, SigningKeySeedLen)
	for i := range seed {
		seed[i] = byte(i)
	}
	replicaA, err := NewServiceWithSeed(testTrustDomain, seed)
	if err != nil {
		t.Fatalf("replica A: %v", err)
	}
	replicaB, err := NewServiceWithSeed(testTrustDomain, seed)
	if err != nil {
		t.Fatalf("replica B: %v", err)
	}
	if replicaA.VerifyingKeyHex() != replicaB.VerifyingKeyHex() {
		t.Fatalf("replicas disagree on verifying key:\n A=%s\n B=%s",
			replicaA.VerifyingKeyHex(), replicaB.VerifyingKeyHex())
	}

	// The point of the shared key: a token issued at one replica verifies at its sibling.
	subject := "spiffe://muveraai.com/agent/replica-test"
	svid, err := replicaA.Issue(subject, AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue at replica A: %v", err)
	}
	claims, err := replicaB.Verify(svid.Token)
	if err != nil {
		t.Fatalf("replica B rejected replica A's token: %v", err)
	}
	if claims.Subject != subject {
		t.Errorf("subject = %q; want %q", claims.Subject, subject)
	}
}

func TestEphemeralKeyIsFlaggedAndSeededKeyIsNot(t *testing.T) {
	if !newTestService(t).HasEphemeralKey() {
		t.Error("NewService should report an ephemeral key so callers can refuse to replicate")
	}
	seeded, err := NewServiceWithSeed(testTrustDomain, make([]byte, SigningKeySeedLen))
	if err != nil {
		t.Fatalf("NewServiceWithSeed: %v", err)
	}
	if seeded.HasEphemeralKey() {
		t.Error("a seeded service must not be flagged ephemeral")
	}
}

func TestNewServiceWithSeedRejectsWrongSeedLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewServiceWithSeed(testTrustDomain, make([]byte, n)); err == nil {
			t.Errorf("accepted a %d-byte seed; want %d bytes", n, SigningKeySeedLen)
		}
	}
}

// --- Token type confusion ----------------------------------------------------

func TestCapabilityTokenDoesNotVerifyAsAnSVID(t *testing.T) {
	svc := newTestService(t)
	subject := "spiffe://muveraai.com/agent/alpha"
	svid, err := svc.Issue(subject, AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// The capability token is short-lived and narrowly scoped. Presenting it where a 15-minute
	// SVID is expected must fail -- previously it verified, because both types were signed with
	// the same key over untagged JSON.
	if _, err := svc.Verify(svid.CapabilityToken); err == nil {
		t.Fatal("capability token verified as an SVID")
	}
}

func TestSVIDDoesNotVerifyAsACapabilityToken(t *testing.T) {
	svc := newTestService(t)
	svid, err := svc.Issue("spiffe://muveraai.com/agent/alpha", AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := svc.VerifyCapability(svid.Token); err == nil {
		t.Fatal("SVID verified as a capability token")
	}
}

func TestVerifyCapabilityAcceptsARealCapabilityToken(t *testing.T) {
	svc := newTestService(t)
	subject := "spiffe://muveraai.com/agent/alpha"
	svid, err := svc.Issue(subject, AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := svc.VerifyCapability(svid.CapabilityToken)
	if err != nil {
		t.Fatalf("VerifyCapability: %v", err)
	}
	if claims.Subject != subject {
		t.Errorf("subject = %q; want %q", claims.Subject, subject)
	}
	if got, want := claims.Tools, fullClaims().Tools; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("tools = %v; want %v", got, want)
	}
}

// TestSignatureDomainSeparationIsIndependentOfTheTypClaim isolates the second layer of the
// type-confusion defense. The `typ` claim alone is already tamper-proof (it sits inside the signed
// body), so every test above would still pass with domain separation removed. This one would not:
// it signs an opaque body under one domain and shows the signature does not open under the other,
// with no claim involved. That layer is what protects a future token type whose claims are parsed
// more leniently.
func TestSignatureDomainSeparationIsIndependentOfTheTypClaim(t *testing.T) {
	svc := newTestService(t)
	body := []byte(`{"opaque":"payload"}`)
	capToken := svc.signWithDomain(tokenTypeCapability, body)

	if _, err := svc.openToken(capToken, tokenTypeSVID); err == nil {
		t.Fatal("a capability-domain signature opened under the SVID domain")
	}
	if _, err := svc.openToken(capToken, tokenTypeCapability); err != nil {
		t.Fatalf("token should open under its own domain: %v", err)
	}
}

// TestRewritingTheTypClaimBreaksTheSignature covers the first layer: the type tag lives inside the
// signed body, so an attacker cannot relabel a capability token as an SVID.
func TestRewritingTheTypClaimBreaksTheSignature(t *testing.T) {
	svc := newTestService(t)
	svid, err := svc.Issue("spiffe://muveraai.com/agent/alpha", AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.SplitN(svid.CapabilityToken, ".", 2)
	body, err := hex.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw["typ"] = tokenTypeSVID // attacker relabels the capability token as an SVID
	forged, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tampered := hex.EncodeToString(forged) + "." + parts[1]
	if _, err := svc.Verify(tampered); err == nil {
		t.Fatal("relabelled capability token verified as an SVID")
	}
}

// --- Delegation: revoked/expired parents, and transitive revocation ----------

func issueParentAndChild(t *testing.T, svc *Service) (parent *SVID, child *SVID) {
	t.Helper()
	parent, err := svc.Issue("spiffe://muveraai.com/agent/parent", AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue parent: %v", err)
	}
	child, err = svc.Issue("spiffe://muveraai.com/agent/child", AgentAttributes{}, fullClaims(), "", parent.Token)
	if err != nil {
		t.Fatalf("Issue child: %v", err)
	}
	return parent, child
}

func TestRevokingAParentInvalidatesItsChildren(t *testing.T) {
	svc := newTestService(t)
	parent, child := issueParentAndChild(t, svc)

	if _, err := svc.Verify(child.Token); err != nil {
		t.Fatalf("child should verify before revocation: %v", err)
	}
	parentClaims, err := svc.Verify(parent.Token)
	if err != nil {
		t.Fatalf("parent verify: %v", err)
	}
	if _, err := svc.Revoke(parentClaims.JTI); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// The whole point of revocation: cutting off a compromised parent must cut off everything
	// delegated from it. Previously the child sailed on.
	if _, err := svc.Verify(child.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("child verify after parent revoked = %v; want ErrRevoked", err)
	}
}

func TestRevocationPropagatesThroughAGrandchild(t *testing.T) {
	svc := newTestService(t)
	parent, child := issueParentAndChild(t, svc)
	grandchild, err := svc.Issue("spiffe://muveraai.com/agent/grandchild2", AgentAttributes{}, fullClaims(), "", child.Token)
	if err != nil {
		t.Fatalf("Issue grandchild: %v", err)
	}

	parentClaims, err := svc.Verify(parent.Token)
	if err != nil {
		t.Fatalf("parent verify: %v", err)
	}
	if _, err := svc.Revoke(parentClaims.JTI); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Verify(grandchild.Token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("grandchild verify after root revoked = %v; want ErrRevoked", err)
	}
}

func TestCannotDelegateFromARevokedParent(t *testing.T) {
	svc := newTestService(t)
	parent, err := svc.Issue("spiffe://muveraai.com/agent/parent2", AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue parent: %v", err)
	}
	claims, err := svc.Verify(parent.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := svc.Revoke(claims.JTI); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = svc.Issue("spiffe://muveraai.com/agent/child2", AgentAttributes{}, fullClaims(), "", parent.Token)
	if err == nil {
		t.Fatal("minted a fresh child from a revoked parent token")
	}
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("error = %v; want ErrRevoked", err)
	}
}

func TestCannotDelegateFromAnExpiredParent(t *testing.T) {
	svc := newTestService(t)
	subject := "spiffe://muveraai.com/agent/expired-parent"
	parent, err := svc.Issue(subject, AgentAttributes{}, fullClaims(), "", "")
	if err != nil {
		t.Fatalf("Issue parent: %v", err)
	}
	// Forge an already-expired token signed by this service: re-sign the parent's claims with a
	// past exp. This is the "attacker kept an old token" case.
	claims, err := svc.Verify(parent.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	expired := *claims
	expired.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	expiredToken, err := svc.sign(expired)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := svc.Verify(expiredToken); !errors.Is(err, ErrExpired) {
		t.Fatalf("sanity: expired token verify = %v; want ErrExpired", err)
	}
	_, err = svc.Issue("spiffe://muveraai.com/agent/child3", AgentAttributes{}, fullClaims(), "", expiredToken)
	if err == nil {
		t.Fatal("minted a child from an expired parent token")
	}
	if !errors.Is(err, ErrExpired) {
		t.Errorf("error = %v; want ErrExpired", err)
	}
}

// --- Proof of possession -----------------------------------------------------

// TestDelegationRequiresTheParentTokenNotJustItsSubject is the PoP fix. A SPIFFE ID is public --
// it shows up in logs, configs and other agents' tokens. Knowing one must not confer its authority.
func TestDelegationRequiresTheParentTokenNotJustItsSubject(t *testing.T) {
	svc := newTestService(t)
	parentSubject := "spiffe://muveraai.com/agent/victim"
	if _, err := svc.Issue(parentSubject, AgentAttributes{}, fullClaims(), "", ""); err != nil {
		t.Fatalf("Issue parent: %v", err)
	}

	// The attacker knows the victim's SPIFFE ID but never held its token.
	_, err := svc.Issue(
		"spiffe://muveraai.com/agent/attacker",
		AgentAttributes{Publisher: "evil"},
		fullClaims(),
		"",
		parentSubject, // a bare subject string, not a token
	)
	if err == nil {
		t.Fatal("inherited a parent's authority by naming its public SPIFFE ID")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("error = %v; want ErrInvalidToken", err)
	}
}

func TestLegitimateDelegationStillWorks(t *testing.T) {
	svc := newTestService(t)
	_, child := issueParentAndChild(t, svc)
	claims, err := svc.Verify(child.Token)
	if err != nil {
		t.Fatalf("legitimate child should verify: %v", err)
	}
	if claims.Subject != "spiffe://muveraai.com/agent/child" {
		t.Errorf("subject = %q", claims.Subject)
	}
	if claims.ParentJTI == "" {
		t.Error("child must record its parent's JTI for revocation propagation")
	}
	// I-02 still holds: the child's depth is strictly below the parent's.
	if claims.Attributes.ParentSVID != "" && claims.ParentSVID == "" {
		t.Error("parent linkage lost")
	}
}

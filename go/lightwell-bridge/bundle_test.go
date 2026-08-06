package lightwellbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// ----- helpers -------------------------------------------------------------------------

func mustSHA(t *testing.T, bytes []byte) string {
	t.Helper()
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

func validBundle(t *testing.T) PatchBundle {
	t.Helper()
	artifact := PatchArtifact{
		Kind:      KindGuardrail,
		Name:      "guardrail-v2",
		URI:       "oci://registry/guardrail-v2",
		SHA256:    mustSHA(t, []byte("guardrail-bytes")),
		SizeBytes: 1024,
	}
	return PatchBundle{
		ID:               "bundle-1",
		SpecVersion:      Version,
		CreatedAt:        time.Now().UTC(),
		Artifacts:        []PatchArtifact{artifact},
		Rollout:          DefaultPolicy(StrategyCanary),
		AffectedVersions: []string{"v1.0.0", "v1.0.1"},
		Severity:         "high",
	}
}

// ----- PatchArtifact / PatchBundle ----------------------------------------------------

func TestPatchArtifactVerifyMatches(t *testing.T) {
	a := PatchArtifact{Name: "x", SHA256: mustSHA(t, []byte("payload"))}
	if err := a.Verify([]byte("payload")); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestPatchArtifactVerifyRejectsTamperedBytes(t *testing.T) {
	a := PatchArtifact{Name: "x", SHA256: mustSHA(t, []byte("payload"))}
	err := a.Verify([]byte("tampered"))
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestBundleHasKindAndKinds(t *testing.T) {
	b := validBundle(t)
	if !b.HasKind(KindGuardrail) {
		t.Fatal("expected guardrail kind present")
	}
	if b.HasKind(KindModelWeight) {
		t.Fatal("model weight kind should be absent")
	}
	kinds := b.Kinds()
	if len(kinds) != 1 || kinds[0] != KindGuardrail {
		t.Fatalf("unexpected kinds: %v", kinds)
	}
}

func TestBundleTotalSizeSumsArtifacts(t *testing.T) {
	b := validBundle(t)
	b.Artifacts = append(b.Artifacts, PatchArtifact{Name: "second", SizeBytes: 2048})
	if got := b.TotalSize(); got != 1024+2048 {
		t.Fatalf("total size: %d", got)
	}
}

func TestBundleValidateAcceptsValidBundle(t *testing.T) {
	if err := validBundle(t).Validate(); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
}

func TestBundleValidateRejectsMissingID(t *testing.T) {
	b := validBundle(t)
	b.ID = ""
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestBundleValidateRejectsEmptyArtifacts(t *testing.T) {
	b := validBundle(t)
	b.Artifacts = nil
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for empty artifacts")
	}
}

func TestBundleValidateRejectsMissingSHA(t *testing.T) {
	b := validBundle(t)
	b.Artifacts[0].SHA256 = ""
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for missing sha256")
	}
}

// ----- RolloutPolicy ------------------------------------------------------------------

func TestDefaultPolicyCanaryEndsAt100(t *testing.T) {
	p := DefaultPolicy(StrategyCanary)
	if err := p.Validate(); err != nil {
		t.Fatalf("default canary invalid: %v", err)
	}
	if p.Waves[len(p.Waves)-1] != 100 {
		t.Fatalf("canary must end at 100, got %v", p.Waves)
	}
}

func TestRolloutValidateRejectsUnknownStrategy(t *testing.T) {
	p := RolloutPolicy{Strategy: "weird"}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for unknown strategy")
	}
}

func TestRolloutValidateRejectsWavesNotEndingAt100(t *testing.T) {
	p := RolloutPolicy{Strategy: StrategyCanary, Waves: []int{1, 10, 50}, SoakSeconds: 1, MaxFailures: 1}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error: waves do not end at 100")
	}
}

func TestRolloutValidateRejectsNonIncreasingWaves(t *testing.T) {
	p := RolloutPolicy{Strategy: StrategyStaged, Waves: []int{50, 25, 100}, SoakSeconds: 1, MaxFailures: 1}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error: waves not increasing")
	}
}

func TestRolloutSoakDuration(t *testing.T) {
	p := RolloutPolicy{SoakSeconds: 90}
	if p.Soak().Seconds() != 90 {
		t.Fatalf("soak: %v", p.Soak())
	}
}

// ----- AffectedVersionGraph -----------------------------------------------------------

func TestGraphPatchesForReturnsSortedBundles(t *testing.T) {
	g := NewAffectedVersionGraph()
	g.Add("bundle-b", []string{"v1"})
	g.Add("bundle-a", []string{"v1"})
	got := g.PatchesFor("v1")
	if len(got) != 2 || got[0] != "bundle-a" || got[1] != "bundle-b" {
		t.Fatalf("unexpected ordering: %v", got)
	}
}

func TestGraphAffectedVersionsInverse(t *testing.T) {
	g := NewAffectedVersionGraph()
	g.Add("bundle-1", []string{"v1.0.0", "v1.0.1"})
	got := g.AffectedVersions("bundle-1")
	if len(got) != 2 || got[0] != "v1.0.0" || got[1] != "v1.0.1" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestGraphIdempotentAdd(t *testing.T) {
	g := NewAffectedVersionGraph()
	g.Add("b1", []string{"v1"})
	g.Add("b1", []string{"v1"}) // dup
	if got := g.PatchesFor("v1"); len(got) != 1 {
		t.Fatalf("expected dedup, got %v", got)
	}
}

func TestGraphAllVersionsSorted(t *testing.T) {
	g := NewAffectedVersionGraph()
	g.Add("b", []string{"v3", "v1", "v2"})
	got := g.AllVersions()
	if len(got) != 3 || got[0] != "v1" || got[1] != "v2" || got[2] != "v3" {
		t.Fatalf("expected sorted, got %v", got)
	}
}

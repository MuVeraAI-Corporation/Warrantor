package sovereign

import (
	"errors"
	"strings"
	"testing"
)

func TestRequiredComponentsPerMode(t *testing.T) {
	cases := []struct {
		mode     DeploymentMode
		expected []string
	}{
		{ModeSafeLocal, []string{"agent-identity", "eval-guard", "trust-core"}},
		{ModeSafeTeam, []string{"agent-identity", "credential-vault", "eval-guard", "flight-recorder", "trust-core"}},
		{
			ModeSafeProduction,
			[]string{"agent-identity", "credential-vault", "eval-guard", "flight-recorder", "inference-proxy", "kill-switch", "tenant-guard", "trust-core"},
		},
	}
	for _, tc := range cases {
		got, err := RequiredComponents(tc.mode)
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if !equalStrings(got, tc.expected) {
			t.Errorf("%s: got %v, want %v", tc.mode, got, tc.expected)
		}
	}
}

func TestRequiredComponentsAreAdditive(t *testing.T) {
	local, _ := RequiredComponents(ModeSafeLocal)
	team, _ := RequiredComponents(ModeSafeTeam)
	prod, _ := RequiredComponents(ModeSafeProduction)
	if !subset(local, team) {
		t.Error("safe_team must be a superset of safe_local")
	}
	if !subset(team, prod) {
		t.Error("safe_production must be a superset of safe_team")
	}
}

func TestRequiredComponentsInvalidMode(t *testing.T) {
	_, err := RequiredComponents(DeploymentMode("bogus"))
	if !errors.Is(err, ErrInvalidMode) {
		t.Errorf("expected ErrInvalidMode, got %v", err)
	}
}

func TestExportBundleProducesValidBundle(t *testing.T) {
	b, err := ExportBundle(SovereignConfig{
		Mode:      ModeSafeLocal,
		GPUModel:  "H100",
		TrustRoot: "spiffe://aumos.dev",
		Version:   "1.2.3",
	})
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}
	if b.Version != "1.2.3" {
		t.Errorf("version = %q", b.Version)
	}
	if b.Mode != ModeSafeLocal {
		t.Errorf("mode = %q", b.Mode)
	}
	if b.Checksum == "" {
		t.Error("checksum must be set")
	}
	if !strings.HasPrefix(b.Checksum, "sha256:") {
		t.Errorf("checksum should be sha256-prefixed, got %q", b.Checksum)
	}
	required, _ := RequiredComponents(ModeSafeLocal)
	if !equalStrings(b.Components, required) {
		t.Errorf("components = %v, want exactly the mode's required set %v", b.Components, required)
	}
}

func TestExportBundleInvalidMode(t *testing.T) {
	_, err := ExportBundle(SovereignConfig{Mode: DeploymentMode("nope")})
	if !errors.Is(err, ErrInvalidMode) {
		t.Errorf("expected ErrInvalidMode, got %v", err)
	}
}

func TestExportBundleIncludesExtraComponents(t *testing.T) {
	b, err := ExportBundle(SovereignConfig{
		Mode:            ModeSafeLocal,
		ExtraComponents: []string{"my-custom-tool", "eval-guard"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// eval-guard must not be duplicated; my-custom-tool must be appended (sorted).
	if !equalStrings(b.Components, []string{"agent-identity", "eval-guard", "my-custom-tool", "trust-core"}) {
		t.Errorf("extra components not merged/deduped correctly: %v", b.Components)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	for _, mode := range AllModes() {
		b, err := ExportBundle(SovereignConfig{Mode: mode, GPUModel: "H100", TrustRoot: "tr"})
		if err != nil {
			t.Fatalf("%s export: %v", mode, err)
		}
		v, err := ImportBundle(b)
		if err != nil {
			t.Fatalf("%s import: %v", mode, err)
		}
		if !v.Valid {
			t.Errorf("%s: validation not valid: %+v", mode, v)
		}
		if !v.ChecksumOK {
			t.Errorf("%s: checksum not ok", mode)
		}
		if len(v.Missing) != 0 {
			t.Errorf("%s: missing components %v", mode, v.Missing)
		}
	}
}

func TestImportBundleDetectsChecksumTamper(t *testing.T) {
	b, err := ExportBundle(SovereignConfig{Mode: ModeSafeLocal})
	if err != nil {
		t.Fatal(err)
	}
	b.Checksum = "sha256:deadbeef"
	_, err = ImportBundle(b)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestImportBundleDetectsComponentTamper(t *testing.T) {
	b, err := ExportBundle(SovereignConfig{Mode: ModeSafeLocal})
	if err != nil {
		t.Fatal(err)
	}
	// Drop a required component but keep the (now-stale) checksum.
	b.Components = []string{"trust-core", "agent-identity"}
	_, err = ImportBundle(b)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("tampered components should fail checksum first; got %v", err)
	}
}

func TestImportBundleDetectsMissingComponent(t *testing.T) {
	b, err := ExportBundle(SovereignConfig{Mode: ModeSafeLocal})
	if err != nil {
		t.Fatal(err)
	}
	// Remove one required component and recompute checksum so we exercise the
	// missing-component path rather than the checksum path.
	b.Components = []string{"trust-core", "agent-identity"} // dropped eval-guard
	b.Checksum = computeChecksum(b.Components)
	v, err := ImportBundle(b)
	if !errors.Is(err, ErrMissingComponent) {
		t.Errorf("expected ErrMissingComponent, got %v", err)
	}
	if v == nil || len(v.Missing) == 0 || v.Missing[0] != "eval-guard" {
		t.Errorf("expected missing=[eval-guard], got %+v", v)
	}
}

func TestValidateBundleAgainstDeclaredMode(t *testing.T) {
	b, err := ExportBundle(SovereignConfig{Mode: ModeSafeProduction})
	if err != nil {
		t.Fatal(err)
	}
	// Validating against the same mode it was built for must pass.
	if err := ValidateBundle(b, SovereignConfig{Mode: ModeSafeProduction}); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidateBundleRejectsPromotionToHigherMode(t *testing.T) {
	// A safe_local bundle is missing production-only components.
	b, err := ExportBundle(SovereignConfig{Mode: ModeSafeLocal})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateBundle(b, SovereignConfig{Mode: ModeSafeProduction})
	if !errors.Is(err, ErrMissingComponent) {
		t.Errorf("expected ErrMissingComponent, got %v", err)
	}
	if !strings.Contains(err.Error(), "inference-proxy") {
		t.Errorf("error should name a production-only component: %v", err)
	}
}

func TestValidateBundleAcceptsLoweringMode(t *testing.T) {
	// A production bundle satisfies the local requirements (production ⊇ local).
	b, err := ExportBundle(SovereignConfig{Mode: ModeSafeProduction})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundle(b, SovereignConfig{Mode: ModeSafeLocal}); err != nil {
		t.Errorf("lowering mode should succeed, got %v", err)
	}
}

func TestValidateBundleDetectsChecksumMismatch(t *testing.T) {
	b, err := ExportBundle(SovereignConfig{Mode: ModeSafeLocal})
	if err != nil {
		t.Fatal(err)
	}
	b.Checksum = "sha256:wrong"
	if err := ValidateBundle(b, SovereignConfig{Mode: ModeSafeLocal}); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestIsKnownMode(t *testing.T) {
	for _, m := range AllModes() {
		if !IsKnownMode(m) {
			t.Errorf("%s should be known", m)
		}
	}
	if IsKnownMode(DeploymentMode("garbage")) {
		t.Error("garbage should not be a known mode")
	}
}

func TestChecksumOrderInvariant(t *testing.T) {
	// Two bundles with the same components in different orders must share a checksum.
	a, _ := ExportBundle(SovereignConfig{Mode: ModeSafeLocal})
	b := &SovereignBundle{
		Version:    a.Version,
		Mode:       a.Mode,
		Components: reverse(append([]string(nil), a.Components...)),
	}
	b.Checksum = computeChecksum(b.Components)
	if a.Checksum != b.Checksum {
		t.Errorf("checksum should be order-invariant: %s vs %s", a.Checksum, b.Checksum)
	}
}

// --- helpers ---

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func subset(sub, sup []string) bool {
	set := make(map[string]struct{}, len(sup))
	for _, s := range sup {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func reverse(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

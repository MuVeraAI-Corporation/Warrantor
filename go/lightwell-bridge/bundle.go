package lightwellbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Version is the package version (mirrored from cmd/main.go).
const Version = "1.0.0"

// PatchKind enumerates the four kinds of artifacts a PatchBundle may carry.
type PatchKind string

const (
	// KindModelWeight is a model-weight update (e.g. LoRA delta or full checkpoint).
	KindModelWeight PatchKind = "model_weight"
	// KindGuardrail is a guardrail policy update (e.g. new regex blocklist).
	KindGuardrail PatchKind = "guardrail"
	// KindConfigChange is a runtime configuration change (e.g. sampling params).
	KindConfigChange PatchKind = "config_change"
	// KindRuntimeUpdate is a runtime binary update (e.g. inference server patch).
	KindRuntimeUpdate PatchKind = "runtime_update"
)

// AllPatchKinds returns every PatchKind in canonical order.
func AllPatchKinds() []PatchKind {
	return []PatchKind{KindModelWeight, KindGuardrail, KindConfigChange, KindRuntimeUpdate}
}

// PatchArtifact is one concrete artifact inside a bundle.
type PatchArtifact struct {
	// Kind is the artifact kind.
	Kind PatchKind
	// Name is the human-readable name of the artifact.
	Name string
	// URI is where the artifact bytes live (object store, OCI registry, ...).
	URI string
	// SHA256 is the hex-encoded digest of the artifact bytes.
	SHA256 string
	// SizeBytes is the artifact size in bytes.
	SizeBytes int64
}

// Verify returns nil iff the supplied bytes match the artifact's SHA256.
func (a *PatchArtifact) Verify(bytes []byte) error {
	sum := sha256.Sum256(bytes)
	got := hex.EncodeToString(sum[:])
	if got != a.SHA256 {
		return fmt.Errorf("artifact %q digest mismatch: want %s got %s", a.Name, a.SHA256, got)
	}
	return nil
}

// PatchBundle is the unit of distribution.
type PatchBundle struct {
	// ID is the unique bundle identifier.
	ID string
	// SpecVersion is the bundle schema version.
	SpecVersion string
	// CreatedAt is the bundle creation time (UTC).
	CreatedAt time.Time
	// Artifacts is the set of artifacts the bundle carries.
	Artifacts []PatchArtifact
	// Rollout is the rollout policy for this bundle.
	Rollout RolloutPolicy
	// AffectedVersions lists the deployment versions this patch applies to.
	AffectedVersions []string
	// Severity is the bundle severity ("info" | "low" | "medium" | "high" | "critical").
	Severity string
}

// HasKind reports whether the bundle contains at least one artifact of kind k.
func (b *PatchBundle) HasKind(k PatchKind) bool {
	for _, a := range b.Artifacts {
		if a.Kind == k {
			return true
		}
	}
	return false
}

// Kinds returns the set of kinds present in the bundle.
func (b *PatchBundle) Kinds() []PatchKind {
	seen := map[PatchKind]bool{}
	out := []PatchKind{}
	for _, a := range b.Artifacts {
		if !seen[a.Kind] {
			seen[a.Kind] = true
			out = append(out, a.Kind)
		}
	}
	return out
}

// TotalSize returns the total size of every artifact in the bundle.
func (b *PatchBundle) TotalSize() int64 {
	var n int64
	for _, a := range b.Artifacts {
		n += a.SizeBytes
	}
	return n
}

// Validate returns nil iff the bundle is well-formed: it has an ID, at
// least one artifact, a valid rollout strategy, and every artifact has a
// non-empty SHA256.
func (b PatchBundle) Validate() error {
	if b.ID == "" {
		return errors.New("bundle id is required")
	}
	if len(b.Artifacts) == 0 {
		return errors.New("bundle must contain at least one artifact")
	}
	if b.CreatedAt.IsZero() {
		return errors.New("bundle createdAt is required")
	}
	if err := b.Rollout.Validate(); err != nil {
		return fmt.Errorf("rollout policy: %w", err)
	}
	for i, a := range b.Artifacts {
		if a.Name == "" {
			return fmt.Errorf("artifact[%d]: name is required", i)
		}
		if a.SHA256 == "" {
			return fmt.Errorf("artifact %q: sha256 is required", a.Name)
		}
		if a.URI == "" {
			return fmt.Errorf("artifact %q: uri is required", a.Name)
		}
	}
	return nil
}

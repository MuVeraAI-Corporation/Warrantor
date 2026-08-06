// Package sovereign implements X10 sovereign-stack — the air-gapped sovereign deployment
// bundle manager.
//
// AumOS can be deployed fully air-gapped (no cloud dependencies) for sovereignty-sensitive
// environments. This package produces and validates a SovereignBundle: a self-contained
// manifest that names every component required for a given deployment mode, plus a checksum
// over the component set so the bundle's integrity can be verified at import time without
// any external trust root.
//
// Component requirements accumulate per deployment mode:
//
//	safe_local       = {trust-core, agent-identity, eval-guard}
//	safe_team        = safe_local ∪ {flight-recorder, credential-vault}
//	safe_production  = safe_team ∪ {tenant-guard, kill-switch, inference-proxy}
//
// Per RFC X10: the exporter packs signed container images / helm charts alongside this
// manifest. This package implements the manifest logic itself, which is testable without
// packing real artifacts.
package sovereign

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// DeploymentMode is the sovereignty deployment profile.
type DeploymentMode string

const (
	// ModeSafeLocal runs on a single workstation for one operator.
	ModeSafeLocal DeploymentMode = "safe_local"
	// ModeSafeTeam adds multi-operator components (audit log, credential vault).
	ModeSafeTeam DeploymentMode = "safe_team"
	// ModeSafeProduction adds fleet/scaling components (tenant isolation, kill switch, proxy).
	ModeSafeProduction DeploymentMode = "safe_production"
)

// AllModes lists every supported deployment mode.
func AllModes() []DeploymentMode {
	return []DeploymentMode{ModeSafeLocal, ModeSafeTeam, ModeSafeProduction}
}

// Errors returned by this package.
var (
	// ErrInvalidMode is returned when a deployment mode is not recognized.
	ErrInvalidMode = errors.New("sovereign: invalid deployment mode")
	// ErrChecksumMismatch is returned when an imported bundle's checksum does not match its components.
	ErrChecksumMismatch = errors.New("sovereign: checksum mismatch")
	// ErrMissingComponent is returned when a bundle is missing a component required for its mode.
	ErrMissingComponent = errors.New("sovereign: missing required component")
)

// modeRequirements is the additive component set per mode. Production ⊇ Team ⊇ Local.
var modeRequirements = map[DeploymentMode][]string{
	ModeSafeLocal:      {"trust-core", "agent-identity", "eval-guard"},
	ModeSafeTeam:       {"trust-core", "agent-identity", "eval-guard", "flight-recorder", "credential-vault"},
	ModeSafeProduction: {"trust-core", "agent-identity", "eval-guard", "flight-recorder", "credential-vault", "tenant-guard", "kill-switch", "inference-proxy"},
}

// RequiredComponents returns the components required for a mode, sorted and de-duplicated.
// Returns ErrInvalidMode if the mode is not recognized.
func RequiredComponents(mode DeploymentMode) ([]string, error) {
	comps, ok := modeRequirements[mode]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidMode, mode)
	}
	out := append([]string(nil), comps...)
	sort.Strings(out)
	return out, nil
}

// SovereignConfig describes how to build a bundle.
type SovereignConfig struct {
	// Deployment mode (safe_local / safe_team / safe_production).
	Mode DeploymentMode `json:"mode"`
	// Target GPU model (e.g. "H100", "A100", "L40S"). Informational; recorded in the bundle.
	GPUModel string `json:"gpu_model"`
	// Trust root: a SPIFFE trust domain (e.g. "spiffe://aumos.dev") or a public-key fingerprint.
	TrustRoot string `json:"trust_root"`
	// Optional extra components to include beyond the mode's required set.
	ExtraComponents []string `json:"extra_components,omitempty"`
	// Semantic bundle version (e.g. "1.0.0").
	Version string `json:"version"`
}

// SovereignBundle is the air-gapped deployment manifest.
type SovereignBundle struct {
	// Semantic version of the bundle (mirrors config.Version on export).
	Version string `json:"version"`
	// Deployment mode the bundle was built for.
	Mode DeploymentMode `json:"mode"`
	// GPU model the bundle targets.
	GPUModel string `json:"gpu_model"`
	// Trust root the bundle's components are pinned to.
	TrustRoot string `json:"trust_root"`
	// Components included in the bundle (sorted, de-duplicated).
	Components []string `json:"components"`
	// SHA-256 hex digest over the canonical component set. Verified at import.
	Checksum string `json:"checksum"`
}

// Validation is the result of importing / validating a bundle.
type Validation struct {
	// True when the bundle's checksum matches its components AND all required components are present.
	Valid bool `json:"valid"`
	// The mode the bundle declares.
	Mode DeploymentMode `json:"mode"`
	// Checksum verified OK.
	ChecksumOK bool `json:"checksum_ok"`
	// Required components for the declared mode.
	Required []string `json:"required"`
	// Components present in the bundle but not required for the mode (informational).
	Extras []string `json:"extras"`
	// Components required for the mode but missing from the bundle.
	Missing []string `json:"missing"`
}

// computeChecksum returns the SHA-256 hex digest over the canonical (sorted, de-duplicated,
// newline-joined) component set. The checksum is independent of ordering and duplication in
// the input, so it is stable across equivalent bundles.
func computeChecksum(components []string) string {
	set := dedupeSorted(components)
	h := sha256.Sum256([]byte(strings.Join(set, "\n")))
	return "sha256:" + hex.EncodeToString(h[:])
}

// dedupeSorted returns a sorted, de-duplicated copy of the input.
func dedupeSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		seen[c] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// ExportBundle generates an air-gapped bundle manifest from a config. The bundle's component
// list is the union of the mode's required components and any ExtraComponents, sorted and
// de-duplicated. The checksum is computed over that canonical set.
func ExportBundle(config SovereignConfig) (*SovereignBundle, error) {
	required, err := RequiredComponents(config.Mode)
	if err != nil {
		return nil, err
	}
	combined := append(append([]string(nil), required...), config.ExtraComponents...)
	components := dedupeSorted(combined)

	version := config.Version
	if version == "" {
		version = "1.0.0"
	}

	return &SovereignBundle{
		Version:    version,
		Mode:       config.Mode,
		GPUModel:   config.GPUModel,
		TrustRoot:  config.TrustRoot,
		Components: components,
		Checksum:   computeChecksum(components),
	}, nil
}

// ImportBundle verifies an imported bundle: its checksum must match its components, and its
// declared mode's required components must all be present. The returned Validation captures
// the detailed outcome regardless of pass/fail.
func ImportBundle(bundle *SovereignBundle) (*Validation, error) {
	v := &Validation{Mode: bundle.Mode}

	required, err := RequiredComponents(bundle.Mode)
	if err != nil {
		return v, err
	}
	v.Required = required

	expected := computeChecksum(bundle.Components)
	v.ChecksumOK = expected == bundle.Checksum

	have := make(map[string]struct{}, len(bundle.Components))
	for _, c := range bundle.Components {
		have[c] = struct{}{}
	}
	reqSet := make(map[string]struct{}, len(required))
	for _, c := range required {
		reqSet[c] = struct{}{}
		if _, ok := have[c]; !ok {
			v.Missing = append(v.Missing, c)
		}
	}
	sort.Strings(v.Missing)

	for _, c := range bundle.Components {
		if _, ok := reqSet[c]; !ok {
			v.Extras = append(v.Extras, c)
		}
	}
	sort.Strings(v.Extras)

	v.Valid = v.ChecksumOK && len(v.Missing) == 0

	if !v.ChecksumOK {
		return v, fmt.Errorf("%w: expected %s, bundle has %s", ErrChecksumMismatch, expected, bundle.Checksum)
	}
	if len(v.Missing) > 0 {
		return v, fmt.Errorf("%w: bundle for mode %q is missing %v", ErrMissingComponent, bundle.Mode, v.Missing)
	}
	return v, nil
}

// ValidateBundle checks that a bundle is internally consistent and that it contains every
// component required for the given config's mode. Returns nil if valid; otherwise an error
// wrapping ErrChecksumMismatch or ErrMissingComponent.
//
// This is the same check ImportBundle performs, but parameterized on a config (so a caller
// can validate a bundle against a *different* mode than it declares, e.g. promoting a
// safe_team bundle into a safe_production cluster requires the production component set).
func ValidateBundle(bundle *SovereignBundle, config SovereignConfig) error {
	// Checksum must always match the bundle's own components.
	if got := computeChecksum(bundle.Components); got != bundle.Checksum {
		return fmt.Errorf("%w: expected %s, bundle has %s", ErrChecksumMismatch, got, bundle.Checksum)
	}

	required, err := RequiredComponents(config.Mode)
	if err != nil {
		return err
	}
	have := make(map[string]struct{}, len(bundle.Components))
	for _, c := range bundle.Components {
		have[c] = struct{}{}
	}
	var missing []string
	for _, c := range required {
		if _, ok := have[c]; !ok {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%w: mode %q requires %v", ErrMissingComponent, config.Mode, missing)
	}
	return nil
}

// IsKnownMode reports whether a mode string is one of the supported deployment modes.
func IsKnownMode(mode DeploymentMode) bool {
	_, ok := modeRequirements[mode]
	return ok
}

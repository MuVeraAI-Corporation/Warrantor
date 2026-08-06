// Package fleetmarshal implements F4 fleet-marshal — the Kubernetes operator that rolls
// model updates out across the inference fleet safely.
//
// The operator manages a ModelFleet CRD: the desired state of a model fleet (image, replicas,
// rollout strategy, failure threshold). The controller reconciles toward that state using one
// of three rollout strategies, and auto-rolls back when the failure rate crosses the
// configured threshold.
//
// This package implements the rollout decision logic in pure Go — the K8s API binding
// (controller-runtime, informers, pod patching) lives in cmd/fleet-marshal and is intentionally
// thin. Every K8s interaction is an interface (RolloutExecutor) so the maths can be tested
// exhaustively in-memory.
//
// See ``docs/rfcs/F4-fleet-marshal.md``.
package fleetmarshal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------------
// Public sentinels & constants
// -----------------------------------------------------------------------------------

// ErrRolloutAlreadyRunning is returned when a rollout is started while another is in flight.
var ErrRolloutAlreadyRunning = errors.New("fleet-marshal: rollout already running")

// ErrRolloutAborted is returned when a rollout is rolled back via auto-rollback.
var ErrRolloutAborted = errors.New("fleet-marshal: rollout aborted (failure threshold hit)")

// ErrUnknownStrategy is returned for an unsupported rollout strategy.
var ErrUnknownStrategy = errors.New("fleet-marshal: unknown rollout strategy")

// Version is the operator version (mirrored in cmd/main.go).
const Version = "1.0.0"

// DefaultFailureThreshold is the default fraction of pods that may fail before rollback fires.
const DefaultFailureThreshold = 0.1

// DefaultCanaryStepPct is the default step size for canary rollouts (10% per step).
const DefaultCanaryStepPct = 0.1

// DefaultCanaryStepInterval is the default dwell time per canary step.
const DefaultCanaryStepInterval = 60 * time.Second

// DefaultBlueGreenDwell is the default dwell time on the new (green) fleet before cutover.
const DefaultBlueGreenDwell = 5 * time.Minute

// -----------------------------------------------------------------------------------
// RolloutStrategy
// -----------------------------------------------------------------------------------

// RolloutStrategy names a deployment strategy. Mirrors the k8s DeploymentStrategy enum but
// adds canary and blue-green which the upstream type lacks.
type RolloutStrategy string

const (
	// StrategyAllAtOnce swaps every pod in one pass. Fastest; riskiest.
	StrategyAllAtOnce RolloutStrategy = "all_at_once"
	// StrategyCanary ramps traffic pod-by-pod, observing health at each step.
	StrategyCanary RolloutStrategy = "canary"
	// StrategyBlueGreen brings up a parallel "green" fleet, dwell-observes, then cuts over.
	StrategyBlueGreen RolloutStrategy = "blue_green"
)

// AllStrategies returns the supported strategies, sorted alphabetically (for stable CLI help).
func AllStrategies() []RolloutStrategy {
	out := []RolloutStrategy{StrategyAllAtOnce, StrategyCanary, StrategyBlueGreen}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

// -----------------------------------------------------------------------------------
// ModelFleet — the CRD shape
// -----------------------------------------------------------------------------------

// ModelFleetSpec is the desired state (the CRD `.spec`).
type ModelFleetSpec struct {
	// ModelImage is the inference server image (e.g. "registry/falcon-7b:v2").
	ModelImage string
	// Replicas is the desired pod count.
	Replicas int32
	// Strategy selects how the rollout proceeds.
	Strategy RolloutStrategy
	// FailureThreshold is the fraction of pods that may fail before auto-rollback fires
	// (0.0–1.0; 0 means any failure rolls back; 1 means never roll back).
	FailureThreshold float64
	// CanaryStepPct is the per-step fraction for canary rollouts.
	CanaryStepPct float64
	// CanaryStepInterval is the dwell time per canary step.
	CanaryStepInterval time.Duration
	// BlueGreenDwell is the dwell time on the green fleet before cutover.
	BlueGreenDwell time.Duration
	// MinReplicasForCanary is the minimum fleet size that may use canary (smaller fleets
	// can't meaningfully do 10% steps).
	MinReplicasForCanary int32
}

// DefaultSpec returns a sensible default spec with the given image and replica count.
func DefaultSpec(image string, replicas int32) ModelFleetSpec {
	return ModelFleetSpec{
		ModelImage:             image,
		Replicas:               replicas,
		Strategy:               StrategyCanary,
		FailureThreshold:       DefaultFailureThreshold,
		CanaryStepPct:          DefaultCanaryStepPct,
		CanaryStepInterval:     DefaultCanaryStepInterval,
		BlueGreenDwell:         DefaultBlueGreenDwell,
		MinReplicasForCanary:   10,
	}
}

// ModelFleetStatus is the observed state (the CRD `.status`).
type ModelFleetStatus struct {
	// CurrentImage is the image currently serving traffic.
	CurrentImage string
	// CurrentReplicas is the number of pods currently running.
	CurrentReplicas int32
	// ReadyReplicas is the number of pods passing health checks.
	ReadyReplicas int32
	// FailedReplicas is the number of pods that have failed since the rollout started.
	FailedReplicas int32
	// Phase is the rollout lifecycle phase.
	Phase RolloutPhase
	// LastTransitionAt is the last time Phase changed.
	LastTransitionAt time.Time
	// Message is a human-readable status message.
	Message string
}

// ModelFleet is the full CRD object (spec + status + identity).
type ModelFleet struct {
	// Name is the CRD object name.
	Name string
	// Namespace is the CRD object namespace.
	Namespace string
	// Spec is the desired state.
	Spec ModelFleetSpec
	// Status is the observed state.
	Status ModelFleetStatus
}

// Digest returns "sha256:..." of the spec (used for change detection in reconcile).
func (m *ModelFleet) Digest() string {
	h := sha256.New()
	h.Write([]byte(m.Spec.ModelImage))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", m.Spec.Replicas)))
	h.Write([]byte{0})
	h.Write([]byte(m.Spec.Strategy))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%v", m.Spec.FailureThreshold)))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// -----------------------------------------------------------------------------------
// RolloutPhase
// -----------------------------------------------------------------------------------

// RolloutPhase names where in its lifecycle a rollout is.
type RolloutPhase string

const (
	// PhaseIdle: no rollout in flight; the fleet is stable on CurrentImage.
	PhaseIdle RolloutPhase = "idle"
	// PhasePending: rollout scheduled but not yet started.
	PhasePending RolloutPhase = "pending"
	// PhaseProgressing: rollout in flight.
	PhaseProgressing RolloutPhase = "progressing"
	// PhaseDwell: canary/blue-green dwell — observing health before next step.
	PhaseDwell RolloutPhase = "dwell"
	// PhaseComplete: rollout finished cleanly.
	PhaseComplete RolloutPhase = "complete"
	// PhaseRolledBack: auto-rollback fired; the fleet is back on the previous image.
	PhaseRolledBack RolloutPhase = "rolled_back"
)

// IsTerminal reports whether the phase indicates the rollout has ended.
func (p RolloutPhase) IsTerminal() bool {
	return p == PhaseComplete || p == PhaseRolledBack
}

// -----------------------------------------------------------------------------------
// RolloutExecutor — the K8s interaction surface (mocked in tests)
// -----------------------------------------------------------------------------------

// PodObservation is the health snapshot of one pod in the rollout.
type PodObservation struct {
	// PodID names the pod.
	PodID string
	// Image is the image the pod is running.
	Image string
	// Ready is true if the pod is passing health checks.
	Ready bool
	// Failed is true if the pod has crashed / entered CrashLoopBackOff.
	Failed bool
}

// RolloutExecutor is the surface the orchestrator uses to drive K8s. Each method maps to one
// K8s API call in the production wiring; here they are synchronous and side-effecting so the
// tests can observe the full sequence.
type RolloutExecutor interface {
	// SetReplicas scales the fleet to the given image at the given replica count. Returns
	// the pods that exist after the scale.
	SetReplicas(ctx context.Context, fleet *ModelFleet, image string, replicas int32) ([]string, error)
	// Observe returns the current health of the given pods.
	Observe(ctx context.Context, fleet *ModelFleet, podIDs []string) ([]PodObservation, error)
	// SteerTraffic routes the given fraction of traffic to the pods running image.
	SteerTraffic(ctx context.Context, fleet *ModelFleet, image string, fraction float64) error
	// TearDown removes the pods running the given image (used in blue-green to retire blue).
	TearDown(ctx context.Context, fleet *ModelFleet, image string) error
	// Now returns the executor's notion of "now" (overridable in tests).
	Now() time.Time
	// Sleep blocks for d (overridable in tests).
	Sleep(ctx context.Context, d time.Duration) error
}

// -----------------------------------------------------------------------------------
// Rollout orchestrator
// -----------------------------------------------------------------------------------

// Rollout orchestrates one model update. It is single-shot: construct per desired-state
// change, run once, observe the result.
type Rollout struct {
	// Fleet is the target ModelFleet.
	Fleet *ModelFleet
	// FromImage is the image being replaced (recorded for rollback).
	FromImage string
	// ToImage is the new image being rolled out.
	ToImage string
	// Exec drives K8s.
	Exec RolloutExecutor
	// OnPhase is an optional callback invoked on every phase transition (for metrics).
	OnPhase func(fleet *ModelFleet, phase RolloutPhase, msg string)

	// Mutable state.
	mu     sync.Mutex
	phase  RolloutPhase
	events []RolloutEvent
}

// RolloutEvent is one observable event during a rollout.
type RolloutEvent struct {
	// At is when the event happened.
	At time.Time
	// Phase is the phase at the moment of the event.
	Phase RolloutPhase
	// Message is a human-readable description.
	Message string
}

// NewRollout constructs a Rollout. fromImage may be empty on first deploy.
func NewRollout(fleet *ModelFleet, fromImage, toImage string, exec RolloutExecutor) *Rollout {
	return &Rollout{
		Fleet:     fleet,
		FromImage: fromImage,
		ToImage:   toImage,
		Exec:      exec,
		phase:     PhaseIdle,
	}
}

// Phase returns the current phase.
func (r *Rollout) Phase() RolloutPhase {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.phase
}

// Events returns a copy of the recorded events.
func (r *Rollout) Events() []RolloutEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RolloutEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *Rollout) setPhase(phase RolloutPhase, msg string) {
	r.mu.Lock()
	r.phase = phase
	r.events = append(r.events, RolloutEvent{
		At:      r.Exec.Now(),
		Phase:   phase,
		Message: msg,
	})
	r.Fleet.Status.Phase = phase
	r.Fleet.Status.LastTransitionAt = r.Exec.Now()
	r.Fleet.Status.Message = msg
	fleet := r.Fleet
	cb := r.OnPhase
	r.mu.Unlock()
	if cb != nil {
		cb(fleet, phase, msg)
	}
}

// Run executes the rollout to completion (or rollback). Returns nil on success,
// ErrRolloutAborted on auto-rollback.
//
// Errors from the executor are returned bare (the orchestrator does not retry — that's the
// controller-runtime manager's job in production).
func (r *Rollout) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.phase == PhaseProgressing || r.phase == PhaseDwell || r.phase == PhasePending {
		r.mu.Unlock()
		return ErrRolloutAlreadyRunning
	}
	r.phase = PhaseProgressing
	r.mu.Unlock()

	switch r.Fleet.Spec.Strategy {
	case StrategyAllAtOnce:
		return r.runAllAtOnce(ctx)
	case StrategyCanary:
		return r.runCanary(ctx)
	case StrategyBlueGreen:
		return r.runBlueGreen(ctx)
	default:
		r.setPhase(PhaseRolledBack, fmt.Sprintf("unknown strategy %q", r.Fleet.Spec.Strategy))
		return fmt.Errorf("%w: %q", ErrUnknownStrategy, r.Fleet.Spec.Strategy)
	}
}

// assessHealth observes the given pods and returns (failedFraction, error). If failedFraction
// exceeds the spec threshold, returns a non-nil thresholdHit error alongside.
func (r *Rollout) assessHealth(ctx context.Context, podIDs []string) (failedFraction float64, err error) {
	if len(podIDs) == 0 {
		return 0, nil
	}
	obs, err := r.Exec.Observe(ctx, r.Fleet, podIDs)
	if err != nil {
		return 0, fmt.Errorf("observe: %w", err)
	}
	var failed, ready int32
	for _, p := range obs {
		if p.Failed {
			failed++
		}
		if p.Ready {
			ready++
		}
	}
	r.Fleet.Status.ReadyReplicas = ready
	r.Fleet.Status.FailedReplicas = failed
	frac := float64(failed) / float64(len(podIDs))
	return frac, nil
}

func (r *Rollout) checkThreshold(ctx context.Context, podIDs []string) error {
	frac, err := r.assessHealth(ctx, podIDs)
	if err != nil {
		return err
	}
	if frac > r.Fleet.Spec.FailureThreshold {
		return r.rollback(ctx, fmt.Sprintf(
			"failure fraction %.3f > threshold %.3f", frac, r.Fleet.Spec.FailureThreshold,
		))
	}
	return nil
}

// rollback returns the fleet to FromImage. If FromImage is empty (first deploy), we cannot
// roll back; instead we tear down the new pods and leave the fleet empty.
func (r *Rollout) rollback(ctx context.Context, reason string) error {
	r.setPhase(PhaseRolledBack, "rollback: "+reason)
	if r.FromImage == "" {
		_ = r.Exec.TearDown(ctx, r.Fleet, r.ToImage)
		r.Fleet.Status.CurrentImage = ""
		r.Fleet.Status.CurrentReplicas = 0
		return fmt.Errorf("%w: %s", ErrRolloutAborted, reason)
	}
	pods, err := r.Exec.SetReplicas(ctx, r.Fleet, r.FromImage, r.Fleet.Spec.Replicas)
	if err != nil {
		return fmt.Errorf("rollback SetReplicas: %w", err)
	}
	r.Fleet.Status.CurrentImage = r.FromImage
	r.Fleet.Status.CurrentReplicas = r.Fleet.Spec.Replicas
	_ = pods
	return fmt.Errorf("%w: %s", ErrRolloutAborted, reason)
}

// -----------------------------------------------------------------------------------
// Strategy: all-at-once
// -----------------------------------------------------------------------------------

func (r *Rollout) runAllAtOnce(ctx context.Context) error {
	r.setPhase(PhaseProgressing, "all-at-once: scaling to "+r.ToImage)
	pods, err := r.Exec.SetReplicas(ctx, r.Fleet, r.ToImage, r.Fleet.Spec.Replicas)
	if err != nil {
		return fmt.Errorf("SetReplicas: %w", err)
	}
	r.Fleet.Status.CurrentImage = r.ToImage
	r.Fleet.Status.CurrentReplicas = r.Fleet.Spec.Replicas
	if err := r.checkThreshold(ctx, pods); err != nil {
		return err
	}
	r.setPhase(PhaseComplete, "all-at-once complete")
	return nil
}

// -----------------------------------------------------------------------------------
// Strategy: canary
// -----------------------------------------------------------------------------------

func (r *Rollout) runCanary(ctx context.Context) error {
	// Small-fleet guard: fall back to all-at-once if the fleet can't meaningfully canary.
	if r.Fleet.Spec.Replicas < r.Fleet.Spec.MinReplicasForCanary {
		r.setPhase(PhaseProgressing, "canary: fleet too small, falling back to all-at-once")
		return r.runAllAtOnce(ctx)
	}
	// First, ensure we have the full FromImage fleet up (the canary runs alongside).
	if r.FromImage != "" {
		_, err := r.Exec.SetReplicas(ctx, r.Fleet, r.FromImage, r.Fleet.Spec.Replicas)
		if err != nil {
			return fmt.Errorf("SetReplicas(from): %w", err)
		}
	}
	stepPct := r.Fleet.Spec.CanaryStepPct
	if stepPct <= 0 || stepPct > 1 {
		stepPct = DefaultCanaryStepPct
	}
	for frac := stepPct; frac <= 1.0+1e-9; frac += stepPct {
		if frac > 1.0 {
			frac = 1.0
		}
		canaryReplicas := int32(float64(r.Fleet.Spec.Replicas) * frac)
		if canaryReplicas < 1 {
			canaryReplicas = 1
		}
		r.setPhase(PhaseProgressing, fmt.Sprintf(
			"canary: %.0f%% → %d/%d pods", frac*100, canaryReplicas, r.Fleet.Spec.Replicas,
		))
		canaryPods, err := r.Exec.SetReplicas(ctx, r.Fleet, r.ToImage, canaryReplicas)
		if err != nil {
			return fmt.Errorf("canary SetReplicas: %w", err)
		}
		if err := r.Exec.SteerTraffic(ctx, r.Fleet, r.ToImage, frac); err != nil {
			return fmt.Errorf("SteerTraffic: %w", err)
		}
		// Dwell.
		r.setPhase(PhaseDwell, fmt.Sprintf("canary dwell at %.0f%%", frac*100))
		if err := r.Exec.Sleep(ctx, r.Fleet.Spec.CanaryStepInterval); err != nil {
			return fmt.Errorf("dwell: %w", err)
		}
		if err := r.checkThreshold(ctx, canaryPods); err != nil {
			return err
		}
		if frac >= 1.0 {
			break
		}
	}
	// Cutover: full fleet on ToImage.
	pods, err := r.Exec.SetReplicas(ctx, r.Fleet, r.ToImage, r.Fleet.Spec.Replicas)
	if err != nil {
		return fmt.Errorf("cutover SetReplicas: %w", err)
	}
	r.Fleet.Status.CurrentImage = r.ToImage
	r.Fleet.Status.CurrentReplicas = r.Fleet.Spec.Replicas
	if err := r.checkThreshold(ctx, pods); err != nil {
		return err
	}
	if r.FromImage != "" {
		_ = r.Exec.TearDown(ctx, r.Fleet, r.FromImage)
	}
	r.setPhase(PhaseComplete, "canary complete")
	return nil
}

// -----------------------------------------------------------------------------------
// Strategy: blue-green
// -----------------------------------------------------------------------------------

func (r *Rollout) runBlueGreen(ctx context.Context) error {
	// Stand up the green fleet (ToImage) at full replica count.
	r.setPhase(PhaseProgressing, "blue-green: bringing up green")
	greenPods, err := r.Exec.SetReplicas(ctx, r.Fleet, r.ToImage, r.Fleet.Spec.Replicas)
	if err != nil {
		return fmt.Errorf("green SetReplicas: %w", err)
	}
	// Dwell on green before cutover.
	r.setPhase(PhaseDwell, "blue-green dwell")
	if err := r.Exec.Sleep(ctx, r.Fleet.Spec.BlueGreenDwell); err != nil {
		return fmt.Errorf("dwell: %w", err)
	}
	if err := r.checkThreshold(ctx, greenPods); err != nil {
		return err
	}
	// Cutover: 100% traffic to green.
	if err := r.Exec.SteerTraffic(ctx, r.Fleet, r.ToImage, 1.0); err != nil {
		return fmt.Errorf("cutover SteerTraffic: %w", err)
	}
	r.Fleet.Status.CurrentImage = r.ToImage
	r.Fleet.Status.CurrentReplicas = r.Fleet.Spec.Replicas
	// Tear down blue.
	if r.FromImage != "" {
		_ = r.Exec.TearDown(ctx, r.Fleet, r.FromImage)
	}
	r.setPhase(PhaseComplete, "blue-green complete")
	return nil
}

// -----------------------------------------------------------------------------------
// FailureThreshold helpers
// -----------------------------------------------------------------------------------

// IsThresholdExceeded returns true if `failed`/`total` exceeds `threshold`. Handles total=0.
func IsThresholdExceeded(failed, total int32, threshold float64) bool {
	if total == 0 {
		return false
	}
	if threshold >= 1.0 {
		return false
	}
	if threshold <= 0 {
		return failed > 0
	}
	return float64(failed)/float64(total) > threshold
}

// ValidateSpec returns an error if the spec is internally inconsistent. Useful as an admission
// webhook gate.
func ValidateSpec(spec ModelFleetSpec) error {
	if spec.ModelImage == "" {
		return errors.New("fleet-marshal: ModelImage is required")
	}
	if spec.Replicas <= 0 {
		return errors.New("fleet-marshal: Replicas must be > 0")
	}
	if spec.FailureThreshold < 0 || spec.FailureThreshold > 1 {
		return errors.New("fleet-marshal: FailureThreshold must be in [0, 1]")
	}
	switch spec.Strategy {
	case StrategyAllAtOnce, StrategyCanary, StrategyBlueGreen:
	default:
		return fmt.Errorf("%w: %q", ErrUnknownStrategy, spec.Strategy)
	}
	if spec.CanaryStepPct < 0 || spec.CanaryStepPct > 1 {
		return errors.New("fleet-marshal: CanaryStepPct must be in [0, 1]")
	}
	return nil
}

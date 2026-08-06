package fleetmarshal

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----- fakeExecutor ------------------------------------------------------------------

type fakeExecutor struct {
	mu sync.Mutex

	// SetReplicas log: (image, replicas) per call.
	setReplicasCalls []setReplicasCall
	// Per-image live pods.
	pods map[string][]string
	// Pod health: podID -> observation.
	health map[string]PodObservation
	// Steer log: (image, fraction).
	steerCalls []steerCall
	// TearDown log: images torn down.
	tornDown []string
	// Sleep calls.
	sleeps []time.Duration
	// Now time.
	now time.Time
	// Optional error injectors.
	setReplicasErr error
	observeErr     error
	steerErr       error
	tearDownErr   error
}

type setReplicasCall struct {
	image    string
	replicas int32
	returned []string
}

type steerCall struct {
	image    string
	fraction float64
}

func newFakeExecutor(now time.Time) *fakeExecutor {
	return &fakeExecutor{
		pods:    map[string][]string{},
		health:  map[string]PodObservation{},
	}
}

func (f *fakeExecutor) SetReplicas(_ context.Context, _ *ModelFleet, image string, replicas int32) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setReplicasErr != nil {
		return nil, f.setReplicasErr
	}
	ids := make([]string, replicas)
	for i := range ids {
		ids[i] = image + "-pod-" + string(rune('a'+i))
		if _, ok := f.health[ids[i]]; !ok {
			f.health[ids[i]] = PodObservation{PodID: ids[i], Image: image, Ready: true}
		}
	}
	f.pods[image] = ids
	call := setReplicasCall{image: image, replicas: replicas, returned: ids}
	f.setReplicasCalls = append(f.setReplicasCalls, call)
	return ids, nil
}

func (f *fakeExecutor) Observe(_ context.Context, _ *ModelFleet, podIDs []string) ([]PodObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.observeErr != nil {
		return nil, f.observeErr
	}
	out := make([]PodObservation, 0, len(podIDs))
	for _, id := range podIDs {
		out = append(out, f.health[id])
	}
	return out, nil
}

func (f *fakeExecutor) SteerTraffic(_ context.Context, _ *ModelFleet, image string, fraction float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.steerErr != nil {
		return f.steerErr
	}
	f.steerCalls = append(f.steerCalls, steerCall{image: image, fraction: fraction})
	return nil
}

func (f *fakeExecutor) TearDown(_ context.Context, _ *ModelFleet, image string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tearDownErr != nil {
		return f.tearDownErr
	}
	f.tornDown = append(f.tornDown, image)
	delete(f.pods, image)
	return nil
}

func (f *fakeExecutor) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeExecutor) Sleep(_ context.Context, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sleeps = append(f.sleeps, d)
	f.now = f.now.Add(d)
	return nil
}

// markPodFailed flips a pod's health to failed (for testing threshold rollback).
func (f *fakeExecutor) markPodFailed(podID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obs := f.health[podID]
	obs.Failed = true
	obs.Ready = false
	f.health[podID] = obs
}

// ----- Validation --------------------------------------------------------------------

func TestValidateSpecOK(t *testing.T) {
	if err := ValidateSpec(DefaultSpec("img", 3)); err != nil {
		t.Errorf("expected nil: %v", err)
	}
}

func TestValidateSpecRejectsEmptyImage(t *testing.T) {
	spec := DefaultSpec("", 3)
	if err := ValidateSpec(spec); err == nil {
		t.Error("expected error for empty image")
	}
}

func TestValidateSpecRejectsZeroReplicas(t *testing.T) {
	spec := DefaultSpec("img", 0)
	if err := ValidateSpec(spec); err == nil {
		t.Error("expected error for zero replicas")
	}
}

func TestValidateSpecRejectsBadThreshold(t *testing.T) {
	spec := DefaultSpec("img", 3)
	spec.FailureThreshold = 1.5
	if err := ValidateSpec(spec); err == nil {
		t.Error("expected error for threshold > 1")
	}
}

func TestValidateSpecRejectsUnknownStrategy(t *testing.T) {
	spec := DefaultSpec("img", 3)
	spec.Strategy = "rolling"
	if err := ValidateSpec(spec); err == nil {
		t.Error("expected error for unknown strategy")
	}
}

// ----- AllStrategies ----------------------------------------------------------------

func TestAllStrategiesContainsKnown(t *testing.T) {
	all := AllStrategies()
	want := map[RolloutStrategy]bool{
		StrategyAllAtOnce: false,
		StrategyCanary:    false,
		StrategyBlueGreen: false,
	}
	for _, s := range all {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for s, found := range want {
		if !found {
			t.Errorf("strategy %q missing", s)
		}
	}
}

// ----- IsThresholdExceeded ----------------------------------------------------------

func TestIsThresholdExceededBasic(t *testing.T) {
	if !IsThresholdExceeded(2, 10, 0.1) {
		t.Error("2/10 should exceed 0.1")
	}
	if IsThresholdExceeded(1, 10, 0.1) {
		t.Error("1/10 should NOT exceed 0.1 (strict)")
	}
}

func TestIsThresholdExceededZero(t *testing.T) {
	if !IsThresholdExceeded(1, 10, 0) {
		t.Error("any failure should exceed threshold 0")
	}
}

func TestIsThresholdExceededOne(t *testing.T) {
	if IsThresholdExceeded(10, 10, 1.0) {
		t.Error("threshold 1.0 should never trip")
	}
}

func TestIsThresholdExceededTotalZero(t *testing.T) {
	if IsThresholdExceeded(0, 0, 0.1) {
		t.Error("0/0 should not trip")
	}
}

// ----- Phase.IsTerminal -------------------------------------------------------------

func TestPhaseIsTerminal(t *testing.T) {
	if !PhaseComplete.IsTerminal() {
		t.Error("complete should be terminal")
	}
	if !PhaseRolledBack.IsTerminal() {
		t.Error("rolled_back should be terminal")
	}
	if PhaseProgressing.IsTerminal() {
		t.Error("progressing should not be terminal")
	}
}

// ----- ModelFleet.Digest -------------------------------------------------------------

func TestModelFleetDigestStable(t *testing.T) {
	m1 := &ModelFleet{Name: "f", Spec: DefaultSpec("img", 3)}
	m2 := &ModelFleet{Name: "different-name", Spec: DefaultSpec("img", 3)}
	// Digest is over spec only; name shouldn't matter.
	if m1.Digest() != m2.Digest() {
		t.Error("digest should depend on spec only")
	}
	m2.Spec.Replicas = 5
	if m1.Digest() == m2.Digest() {
		t.Error("digest should differ when spec differs")
	}
}

// ----- All-at-once strategy ----------------------------------------------------------

func TestAllAtOnceSucceeds(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyAllAtOnce
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Phase() != PhaseComplete {
		t.Errorf("phase = %q, want complete", r.Phase())
	}
	if fleet.Status.CurrentImage != "img:v2" {
		t.Errorf("current = %q", fleet.Status.CurrentImage)
	}
	if fleet.Status.CurrentReplicas != 5 {
		t.Errorf("replicas = %d", fleet.Status.CurrentReplicas)
	}
	// One SetReplicas call to the new image.
	if len(exec.setReplicasCalls) != 1 {
		t.Errorf("SetReplicas calls = %d, want 1", len(exec.setReplicasCalls))
	}
}

func TestAllAtOnceRollsBackOnFailures(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	// Pre-seed health so that when SetReplicas is called for img:v2, we can flip the failures.
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyAllAtOnce
	fleet.Spec.FailureThreshold = 0.1
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	// Hook: after SetReplicas, mark 2 pods as failed (> 10% threshold).
	wrap := &observingExec{
		Exec: exec,
		afterSetReplicas: func(image string, pods []string) {
			if image == "img:v2" && len(pods) >= 2 {
				exec.markPodFailed(pods[0])
				exec.markPodFailed(pods[1])
			}
		},
	}
	r.Exec = wrap
	err := r.Run(context.Background())
	if err == nil || !errors.Is(err, ErrRolloutAborted) {
		t.Fatalf("expected ErrRolloutAborted, got %v", err)
	}
	if r.Phase() != PhaseRolledBack {
		t.Errorf("phase = %q, want rolled_back", r.Phase())
	}
	if fleet.Status.CurrentImage != "img:v1" {
		t.Errorf("current = %q, want img:v1 after rollback", fleet.Status.CurrentImage)
	}
}

// observingExec wraps an executor with callbacks for test orchestration.
type observingExec struct {
	Exec             RolloutExecutor
	afterSetReplicas func(image string, pods []string)
}

func (o *observingExec) SetReplicas(ctx context.Context, f *ModelFleet, image string, n int32) ([]string, error) {
	pods, err := o.Exec.SetReplicas(ctx, f, image, n)
	if err == nil && o.afterSetReplicas != nil {
		o.afterSetReplicas(image, pods)
	}
	return pods, err
}

func (o *observingExec) Observe(ctx context.Context, f *ModelFleet, ids []string) ([]PodObservation, error) {
	return o.Exec.Observe(ctx, f, ids)
}

func (o *observingExec) SteerTraffic(ctx context.Context, f *ModelFleet, image string, frac float64) error {
	return o.Exec.SteerTraffic(ctx, f, image, frac)
}

func (o *observingExec) TearDown(ctx context.Context, f *ModelFleet, image string) error {
	return o.Exec.TearDown(ctx, f, image)
}

func (o *observingExec) Now() time.Time { return o.Exec.Now() }

func (o *observingExec) Sleep(ctx context.Context, d time.Duration) error {
	return o.Exec.Sleep(ctx, d)
}

// ----- Canary strategy ---------------------------------------------------------------

func TestCanarySucceeds(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 20)}
	fleet.Spec.Strategy = StrategyCanary
	fleet.Spec.CanaryStepPct = 0.25 // 4 steps: 25%, 50%, 75%, 100%
	fleet.Spec.CanaryStepInterval = 1 * time.Millisecond
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Phase() != PhaseComplete {
		t.Errorf("phase = %q", r.Phase())
	}
	// Should have steered traffic in increasing fractions.
	if len(exec.steerCalls) < 4 {
		t.Errorf("steer calls = %d, want >= 4", len(exec.steerCalls))
	}
	// Should have torn down the old image at the end.
	found := false
	for _, img := range exec.tornDown {
		if img == "img:v1" {
			found = true
		}
	}
	if !found {
		t.Error("expected img:v1 torn down after canary")
	}
}

func TestCanaryFallsBackForSmallFleet(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyCanary
	fleet.Spec.MinReplicasForCanary = 10
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Phase() != PhaseComplete {
		t.Errorf("phase = %q", r.Phase())
	}
	// Should NOT have multiple steer calls (fell back to all-at-once).
	if len(exec.steerCalls) != 0 {
		t.Errorf("steer calls = %d, want 0 (fallback)", len(exec.steerCalls))
	}
}

func TestCanaryRollsBackOnExcessFailures(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 20)}
	fleet.Spec.Strategy = StrategyCanary
	fleet.Spec.CanaryStepPct = 0.5
	fleet.Spec.CanaryStepInterval = 1 * time.Millisecond
	fleet.Spec.FailureThreshold = 0.0 // any failure rolls back
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	wrap := &observingExec{
		Exec: exec,
		afterSetReplicas: func(image string, pods []string) {
			if image == "img:v2" && len(pods) > 0 {
				exec.markPodFailed(pods[0])
			}
		},
	}
	r.Exec = wrap
	err := r.Run(context.Background())
	if err == nil || !errors.Is(err, ErrRolloutAborted) {
		t.Fatalf("expected ErrRolloutAborted, got %v", err)
	}
	if r.Phase() != PhaseRolledBack {
		t.Errorf("phase = %q", r.Phase())
	}
}

// ----- Blue-green strategy -----------------------------------------------------------

func TestBlueGreenSucceeds(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyBlueGreen
	fleet.Spec.BlueGreenDwell = 1 * time.Millisecond
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Phase() != PhaseComplete {
		t.Errorf("phase = %q", r.Phase())
	}
	// Should have steered 100% traffic to green.
	last := exec.steerCalls[len(exec.steerCalls)-1]
	if last.image != "img:v2" || last.fraction != 1.0 {
		t.Errorf("last steer = %+v, want img:v2 @ 1.0", last)
	}
	// Blue should be torn down.
	found := false
	for _, img := range exec.tornDown {
		if img == "img:v1" {
			found = true
		}
	}
	if !found {
		t.Error("expected blue (img:v1) torn down")
	}
}

func TestBlueGreenRollsBackOnDwellFailures(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 10)}
	fleet.Spec.Strategy = StrategyBlueGreen
	fleet.Spec.BlueGreenDwell = 1 * time.Millisecond
	fleet.Spec.FailureThreshold = 0.05 // 1/10 = 10% > 5%
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	wrap := &observingExec{
		Exec: exec,
		afterSetReplicas: func(image string, pods []string) {
			if image == "img:v2" && len(pods) > 0 {
				exec.markPodFailed(pods[0])
			}
		},
	}
	r.Exec = wrap
	err := r.Run(context.Background())
	if err == nil || !errors.Is(err, ErrRolloutAborted) {
		t.Fatalf("expected ErrRolloutAborted, got %v", err)
	}
	if r.Phase() != PhaseRolledBack {
		t.Errorf("phase = %q", r.Phase())
	}
	// Should NOT have steered 100% (rolled back before cutover).
	for _, c := range exec.steerCalls {
		if c.fraction == 1.0 {
			t.Error("should not have cut over before rollback")
		}
	}
}

// ----- Executor errors propagate ----------------------------------------------------

func TestExecutorErrorPropagates(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	exec.setReplicasErr = errors.New("apiserver down")
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyAllAtOnce
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	err := r.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "apiserver down") {
		t.Errorf("expected apiserver-down error, got %v", err)
	}
}

// ----- Rollout already running ------------------------------------------------------

func TestRunRejectsConcurrentSecondRun(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyAllAtOnce
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	r.phase = PhaseProgressing
	if err := r.Run(context.Background()); !errors.Is(err, ErrRolloutAlreadyRunning) {
		t.Errorf("expected ErrRolloutAlreadyRunning, got %v", err)
	}
}

// ----- Events recorded ---------------------------------------------------------------

func TestEventsRecorded(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyAllAtOnce
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	_ = r.Run(context.Background())
	events := r.Events()
	if len(events) < 2 {
		t.Errorf("events = %d, want >= 2", len(events))
	}
	// Last event should be PhaseComplete.
	last := events[len(events)-1]
	if last.Phase != PhaseComplete {
		t.Errorf("last phase = %q", last.Phase)
	}
}

// ----- OnPhase callback --------------------------------------------------------------

func TestOnPhaseCallback(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = StrategyAllAtOnce
	seen := []RolloutPhase{}
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	r.OnPhase = func(_ *ModelFleet, p RolloutPhase, _ string) {
		seen = append(seen, p)
	}
	_ = r.Run(context.Background())
	if len(seen) == 0 {
		t.Fatal("OnPhase never called")
	}
	if seen[len(seen)-1] != PhaseComplete {
		t.Errorf("last phase = %v", seen[len(seen)-1])
	}
}

// ----- Unknown strategy --------------------------------------------------------------

func TestUnknownStrategyRollsBack(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v2", 5)}
	fleet.Spec.Strategy = "rolling"
	r := NewRollout(fleet, "img:v1", "img:v2", exec)
	err := r.Run(context.Background())
	if err == nil || !errors.Is(err, ErrUnknownStrategy) {
		t.Errorf("expected ErrUnknownStrategy, got %v", err)
	}
	if r.Phase() != PhaseRolledBack {
		t.Errorf("phase = %q", r.Phase())
	}
}

// ----- First-deploy rollback (no FromImage) -----------------------------------------

func TestFirstDeployRollbackTearsDown(t *testing.T) {
	exec := newFakeExecutor(time.Unix(1000, 0))
	fleet := &ModelFleet{Name: "f", Spec: DefaultSpec("img:v1", 5)}
	fleet.Spec.Strategy = StrategyAllAtOnce
	fleet.Spec.FailureThreshold = 0.0
	r := NewRollout(fleet, "", "img:v1", exec) // first deploy
	wrap := &observingExec{
		Exec: exec,
		afterSetReplicas: func(image string, pods []string) {
			if image == "img:v1" && len(pods) > 0 {
				exec.markPodFailed(pods[0])
			}
		},
	}
	r.Exec = wrap
	err := r.Run(context.Background())
	if err == nil || !errors.Is(err, ErrRolloutAborted) {
		t.Fatalf("expected ErrRolloutAborted, got %v", err)
	}
	if fleet.Status.CurrentImage != "" {
		t.Errorf("current = %q, want empty after first-deploy rollback", fleet.Status.CurrentImage)
	}
	// img:v1 should have been torn down.
	found := false
	for _, img := range exec.tornDown {
		if img == "img:v1" {
			found = true
		}
	}
	if !found {
		t.Error("expected img:v1 torn down on first-deploy rollback")
	}
}

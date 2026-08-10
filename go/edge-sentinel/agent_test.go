package edgesentinel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ----- fakes -------------------------------------------------------------------------

type fakeAttestor struct {
	att   *Attestation
	err   error
	calls int
	delay time.Duration
}

func (f *fakeAttestor) Attest(ctx context.Context) (*Attestation, error) {
	f.calls++
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	cp := *f.att
	return &cp, nil
}

type fakeKillSwitch struct {
	called  bool
	reason  string
	actions []string
	err     error
}

func (f *fakeKillSwitch) Kill(_ context.Context, reason string) ([]string, error) {
	f.called = true
	f.reason = reason
	if f.err != nil {
		return nil, f.err
	}
	if f.actions == nil {
		return []string{"suspend-model", "unload-gpu", "kill-pod"}, nil
	}
	return f.actions, nil
}

type fakeAlerter struct {
	called bool
	inc    Incident
	err    error
}

func (f *fakeAlerter) Alert(_ context.Context, inc Incident) error {
	f.called = true
	f.inc = inc
	return f.err
}

func baseline() Baseline {
	return Baseline{
		TeeMeasurement:    "meas-A",
		GpuModel:          "H100",
		DriverVersion:     "535.104.05",
		ClientImageDigest: "sha256:client",
	}
}

func goodAttestation() *Attestation {
	return &Attestation{
		TeeKind:           "sev-snp",
		TeeMeasurement:    "meas-A",
		GpuModel:          "H100",
		DriverVersion:     "535.104.05",
		ClientImageDigest: "sha256:client",
		Timestamp:         time.Unix(1_700_000_000, 0),
	}
}

func newTestAgent(t *testing.T) (*Agent, *fakeAttestor, *fakeKillSwitch, *fakeAlerter) {
	t.Helper()
	att := &fakeAttestor{att: goodAttestation()}
	kill := &fakeKillSwitch{}
	alert := &fakeAlerter{}
	a := NewAgent("node-1", baseline(), att, kill, alert)
	a.Interval = 10 * time.Millisecond
	return a, att, kill, alert
}

// ----- Baseline.Matches --------------------------------------------------------------

func TestBaselineMatchesAllFieldsEqual(t *testing.T) {
	b := baseline()
	a := goodAttestation()
	if err := b.Matches(a); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestBaselineMismatchTeeMeasurement(t *testing.T) {
	b := baseline()
	a := goodAttestation()
	a.TeeMeasurement = "tampered"
	err := b.Matches(a)
	if err == nil || !errors.Is(err, ErrTamperDetected) {
		t.Errorf("expected ErrTamperDetected, got %v", err)
	}
}

func TestBaselineMismatchGpuModel(t *testing.T) {
	b := baseline()
	a := goodAttestation()
	a.GpuModel = "consumer-RTX"
	if err := b.Matches(a); err == nil {
		t.Error("expected mismatch")
	}
}

func TestBaselineMismatchDriver(t *testing.T) {
	b := baseline()
	a := goodAttestation()
	a.DriverVersion = "old"
	if err := b.Matches(a); err == nil {
		t.Error("expected mismatch")
	}
}

func TestBaselineMismatchClientImage(t *testing.T) {
	b := baseline()
	a := goodAttestation()
	a.ClientImageDigest = "sha256:untrusted"
	if err := b.Matches(a); err == nil {
		t.Error("expected mismatch")
	}
}

func TestBaselineEmptyFieldsNotChecked(t *testing.T) {
	b := Baseline{GpuModel: "H100"} // only check GPU
	a := &Attestation{GpuModel: "H100", TeeMeasurement: "anything"}
	if err := b.Matches(a); err != nil {
		t.Errorf("expected match when only GPU is checked, got %v", err)
	}
}

// ----- Attestation.Digest ------------------------------------------------------------

func TestAttestationDigestStable(t *testing.T) {
	a := goodAttestation()
	d1 := a.Digest()
	d2 := a.Digest()
	if d1 != d2 {
		t.Fatal("digest not stable")
	}
}

func TestAttestationDigestDiffersOnChange(t *testing.T) {
	a := goodAttestation()
	d1 := a.Digest()
	a.TeeMeasurement = "different"
	if a.Digest() == d1 {
		t.Error("digest should differ after change")
	}
}

// ----- Agent.ProbeOnce ---------------------------------------------------------------

func TestProbeOnceSuccessRecordsLastGood(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	att, err := a.ProbeOnce(context.Background())
	if err != nil {
		t.Fatalf("ProbeOnce: %v", err)
	}
	if att == nil {
		t.Fatal("nil attestation")
	}
	if a.LastGood() == nil {
		t.Error("LastGood should be set after a successful probe")
	}
	if !a.LastCheckAt().IsZero() {
		// LastCheckAt should be set.
	} else {
		t.Error("LastCheckAt should be set")
	}
	if a.ProbeFailures() != 0 {
		t.Errorf("probe failures = %d, want 0", a.ProbeFailures())
	}
}

func TestProbeOnceTransientErrorIncrementsFailures(t *testing.T) {
	a, att, _, _ := newTestAgent(t)
	att.err = errors.New("network down")
	_, err := a.ProbeOnce(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if a.ProbeFailures() != 1 {
		t.Errorf("failures = %d, want 1", a.ProbeFailures())
	}
	// Tamper count should NOT increment for transient errors.
	if a.TamperCount() != 0 {
		t.Errorf("tampers = %d, want 0", a.TamperCount())
	}
}

func TestProbeOnceTamperFiresKillSwitch(t *testing.T) {
	a, att, kill, alert := newTestAgent(t)
	// Mutate attestation so it diverges from the baseline.
	att.att.TeeMeasurement = "tampered"
	_, err := a.ProbeOnce(context.Background())
	if !errors.Is(err, ErrTamperDetected) {
		t.Fatalf("expected ErrTamperDetected, got %v", err)
	}
	if !kill.called {
		t.Error("kill switch not called")
	}
	if !alert.called {
		t.Error("alerter not called")
	}
	if !a.Killed() {
		t.Error("Killed should be true after tamper")
	}
	if a.TamperCount() != 1 {
		t.Errorf("tamper count = %d, want 1", a.TamperCount())
	}
	if len(a.ActionsTaken()) == 0 {
		t.Error("expected actions recorded")
	}
}

func TestProbeOnceTamperAlertContainsIncidentFields(t *testing.T) {
	a, att, _, alert := newTestAgent(t)
	att.att.GpuModel = "consumer"
	_, _ = a.ProbeOnce(context.Background())
	if alert.inc.NodeID != "node-1" {
		t.Errorf("node = %q", alert.inc.NodeID)
	}
	if alert.inc.Reason == "" {
		t.Error("reason empty")
	}
	if !strings.HasPrefix(alert.inc.BaselineDigest, "sha256:") {
		t.Errorf("baseline digest = %q", alert.inc.BaselineDigest)
	}
	if !strings.HasPrefix(alert.inc.ObservedDigest, "sha256:") {
		t.Errorf("observed digest = %q", alert.inc.ObservedDigest)
	}
}

func TestProbeOnceKillSwitchErrorStillAlerts(t *testing.T) {
	a, att, kill, alert := newTestAgent(t)
	att.att.GpuModel = "wrong"
	kill.err = errors.New("permission denied")
	_, err := a.ProbeOnce(context.Background())
	if !errors.Is(err, ErrTamperDetected) {
		t.Fatalf("got %v", err)
	}
	if !alert.called {
		t.Error("alerter should still be called even if kill failed")
	}
	// The kill error should appear in the actions list.
	found := false
	for _, action := range a.ActionsTaken() {
		if strings.Contains(action, "kill-switch-error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected kill-switch-error in actions: %v", a.ActionsTaken())
	}
}

func TestProbeOnceTamperTwiceIsIdempotent(t *testing.T) {
	a, att, kill, _ := newTestAgent(t)
	att.att.GpuModel = "wrong"
	_, _ = a.ProbeOnce(context.Background())
	kill.called = false // reset the fake
	// Second tamper: kill switch should NOT fire again.
	_, err := a.ProbeOnce(context.Background())
	if !errors.Is(err, ErrAlreadyKilled) && !errors.Is(err, ErrTamperDetected) {
		t.Errorf("got %v", err)
	}
	if kill.called {
		t.Error("kill switch should not fire twice")
	}
}

// ----- Agent.Run ---------------------------------------------------------------------

func TestRunTamperExitsLoop(t *testing.T) {
	a, att, _, _ := newTestAgent(t)
	att.att.GpuModel = "wrong"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := a.Run(ctx)
	if !errors.Is(err, ErrTamperDetected) {
		t.Errorf("expected ErrTamperDetected, got %v", err)
	}
}

func TestRunTransientErrorsContinueLoop(t *testing.T) {
	a, att, _, _ := newTestAgent(t)
	// First call errors; subsequent calls succeed.
	callCount := 0
	att.err = errors.New("transient")
	wrap := att
	a.Attestor = &callbackAttestor{
		fn: func(ctx context.Context) (*Attestation, error) {
			callCount++
			if callCount == 1 {
				return nil, errors.New("transient")
			}
			return wrap.Attest(ctx)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = a.Run(ctx)
	if a.ProbeFailures() < 1 {
		t.Errorf("expected at least 1 failure, got %d", a.ProbeFailures())
	}
}

// callbackAttestor adapts a closure into an Attestor for tests.
type callbackAttestor struct {
	fn func(ctx context.Context) (*Attestation, error)
}

func (c *callbackAttestor) Attest(ctx context.Context) (*Attestation, error) {
	return c.fn(ctx)
}

func TestRunContextCancelExitsCleanly(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	a.Interval = 1 * time.Hour // no probes after the first
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	err := a.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// ----- HTTP surface ------------------------------------------------------------------

func TestHealthzEndpoint(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	srv := a.Handler()
	rec := newRequest(t, srv, "GET", "/healthz")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "edge-sentinel") {
		t.Errorf("body missing component: %s", body)
	}
}

func TestLastGoodBeforeProbeReturns404(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	rec := newRequest(t, a.Handler(), "GET", "/lastgood")
	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestLastGoodAfterProbeReturns200(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	if _, err := a.ProbeOnce(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	rec := newRequest(t, a.Handler(), "GET", "/lastgood")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestKilledEndpoint(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	rec := newRequest(t, a.Handler(), "GET", "/killed")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
}

// ----- SanityCheck -------------------------------------------------------------------

func TestSanityCheckEmptyNodeID(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	a.NodeID = ""
	if err := a.SanityCheck(); err == nil {
		t.Error("expected error for empty NodeID")
	}
}

func TestSanityCheckNilDeps(t *testing.T) {
	a := &Agent{NodeID: "n", Baseline: baseline()}
	if err := a.SanityCheck(); err == nil {
		t.Error("expected error for nil deps")
	}
}

func TestSanityCheckEmptyBaseline(t *testing.T) {
	a := NewAgent("n", Baseline{}, &fakeAttestor{att: goodAttestation()}, &fakeKillSwitch{}, &fakeAlerter{})
	if err := a.SanityCheck(); err == nil {
		t.Error("expected error for empty baseline")
	}
}

func TestSanityCheckPassesWithValidConfig(t *testing.T) {
	a, _, _, _ := newTestAgent(t)
	if err := a.SanityCheck(); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

// ----- DefaultDetector ----------------------------------------------------------------

func TestDefaultDetectorDelegatesToBaseline(t *testing.T) {
	d := DefaultDetector{}
	b := baseline()
	if err := d.Check(&b, goodAttestation()); err != nil {
		t.Errorf("expected match, got %v", err)
	}
	bad := goodAttestation()
	bad.TeeMeasurement = "x"
	if err := d.Check(&b, bad); err == nil {
		t.Error("expected mismatch")
	}
}

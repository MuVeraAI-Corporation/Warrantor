// Package edgesentinel implements F3 edge-sentinel — the edge inference attestation agent.
//
// edge-sentinel runs as a <5MB sidecar next to the inference engine (one pod per GPU node,
// shipped as a systemd unit so it survives the engine restarting). Its job, per RFC F3:
//
//   - Periodically attest the local hardware/TEE (default every 30s).
//   - Compare each fresh attestation against the trusted baseline.
//   - On tamper: invoke the kill switch (terminate inference), then alert FleetMarshal (F4).
//   - Expose a tiny /healthz and /lastgood HTTP surface for liveness probes.
//
// The package is structured so every external interaction (attestation, kill switch, alert,
// clock) is an interface — the production wiring lives in the cmd/ main; the unit tests run
// fully in-memory with deterministic fakes.
//
// See “docs/rfcs/F3-edge-sentinel.md“.
package edgesentinel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// -----------------------------------------------------------------------------------
// Public sentinels & constants
// -----------------------------------------------------------------------------------

// ErrTamperDetected is returned when the kill switch fires.
var ErrTamperDetected = errors.New("edge-sentinel: tamper detected")

// ErrAlreadyKilled is returned when Kill is called on an already-killed agent.
var ErrAlreadyKilled = errors.New("edge-sentinel: already killed")

// DefaultAttestInterval is the default periodic attestation cadence (RFC F3: 30s).
const DefaultAttestInterval = 30 * time.Second

// DefaultAlertTimeout is how long the agent waits for a FleetMarshal ack before giving up.
const DefaultAlertTimeout = 5 * time.Second

// Version is the component version (mirrored from cmd/main.go).
const Version = "1.0.0"

// -----------------------------------------------------------------------------------
// Baseline — the trusted reference measurement
// -----------------------------------------------------------------------------------

// Baseline is the trusted measurement the agent compares each fresh attestation against.
type Baseline struct {
	// TeeMeasurement is the hardware-rooted enclave measurement (hex).
	TeeMeasurement string
	// GpuModel is the expected GPU model (e.g. "H100").
	GpuModel string
	// DriverVersion is the expected GPU driver version.
	DriverVersion string
	// ClientImageDigest is sha256:... of the trusted inference client image.
	ClientImageDigest string
}

// Matches returns nil if the supplied attestation matches every non-empty field of the
// baseline. Empty baseline fields are treated as "do not check".
func (b *Baseline) Matches(a *Attestation) error {
	if b.TeeMeasurement != "" && a.TeeMeasurement != b.TeeMeasurement {
		return fmt.Errorf("%w: tee measurement %q != baseline %q", ErrTamperDetected, a.TeeMeasurement, b.TeeMeasurement)
	}
	if b.GpuModel != "" && a.GpuModel != b.GpuModel {
		return fmt.Errorf("%w: gpu model %q != baseline %q", ErrTamperDetected, a.GpuModel, b.GpuModel)
	}
	if b.DriverVersion != "" && a.DriverVersion != b.DriverVersion {
		return fmt.Errorf("%w: driver %q != baseline %q", ErrTamperDetected, a.DriverVersion, b.DriverVersion)
	}
	if b.ClientImageDigest != "" && a.ClientImageDigest != b.ClientImageDigest {
		return fmt.Errorf("%w: client image %q != baseline %q", ErrTamperDetected, a.ClientImageDigest, b.ClientImageDigest)
	}
	return nil
}

// -----------------------------------------------------------------------------------
// Attestation — a fresh sample from the platform
// -----------------------------------------------------------------------------------

// Attestation is one fresh sample from the local platform. In production this is the
// composite attestation from C1-5 confidential-fabric; here we model the fields the agent
// needs to make a tamper/no-tamper decision.
type Attestation struct {
	// TeeKind names the TEE backend ("sev-snp", "tdx", "nitro", "mock").
	TeeKind string
	// TeeMeasurement is the fresh enclave measurement (hex).
	TeeMeasurement string
	// GpuModel is the fresh GPU model.
	GpuModel string
	// DriverVersion is the fresh GPU driver version.
	DriverVersion string
	// ClientImageDigest is sha256:... of the running inference client image.
	ClientImageDigest string
	// Timestamp is when the attester produced this sample.
	Timestamp time.Time
}

// Digest returns "sha256:"+hex of the canonical encoding. Used for change detection.
func (a *Attestation) Digest() string {
	h := sha256.New()
	h.Write([]byte(a.TeeKind))
	h.Write([]byte{0})
	h.Write([]byte(a.TeeMeasurement))
	h.Write([]byte{0})
	h.Write([]byte(a.GpuModel))
	h.Write([]byte{0})
	h.Write([]byte(a.DriverVersion))
	h.Write([]byte{0})
	h.Write([]byte(a.ClientImageDigest))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// -----------------------------------------------------------------------------------
// Interfaces — pluggable external interactions
// -----------------------------------------------------------------------------------

// Attestor produces fresh Attestations. Production: C1-5 confidential-fabric.
type Attestor interface {
	// Attest returns a fresh Attestation. Returning an error counts as a probe failure (not
	// necessarily tamper — e.g. transient network error reaching the GPU attester).
	Attest(ctx context.Context) (*Attestation, error)
}

// KillSwitch is the engine-termination primitive. Production: SIGTERM to the inference
// process + an eBPF netns-isolation call. The interface is intentionally narrow so the agent
// can call it from any goroutine.
type KillSwitch interface {
	// Kill terminates inference and returns a description of the actions taken.
	Kill(ctx context.Context, reason string) ([]string, error)
}

// Alerter fans an incident out to FleetMarshal (F4). Production: a gRPC call to the marshal.
type Alerter interface {
	// Alert informs the fleet that this node has killed itself.
	Alert(ctx context.Context, inc Incident) error
}

// Clock abstracts time so the loop can be tested deterministically.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// After fires once after d.
	After(d time.Duration) <-chan time.Time
}

// WallClock is the default Clock.
type WallClock struct{}

// Now returns wall-clock now.
func (WallClock) Now() time.Time { return time.Now() }

// After delegates to time.After.
func (WallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// -----------------------------------------------------------------------------------
// Incident — what the agent reports up to FleetMarshal
// -----------------------------------------------------------------------------------

// Incident is the alert payload sent to FleetMarshal.
type Incident struct {
	// NodeID is the SPIFFE ID or hostname of this node.
	NodeID string
	// Reason is a human-readable tamper description.
	Reason string
	// BaselineDigest is sha256:... of the trusted baseline.
	BaselineDigest string
	// ObservedDigest is sha256:... of the divergent attestation.
	ObservedDigest string
	// At is the RFC-3339 timestamp of detection.
	At string
	// ActionsTaken is the list of actions the kill switch reported.
	ActionsTaken []string
}

// -----------------------------------------------------------------------------------
// TamperDetector — checks one attestation against the baseline
// -----------------------------------------------------------------------------------

// TamperDetector decides whether a fresh attestation constitutes tamper. The default
// implementation compares fields directly; advanced implementations could do drift scoring.
type TamperDetector interface {
	// Check returns a non-nil error describing the tamper if `a` diverges from the baseline.
	Check(baseline *Baseline, a *Attestation) error
}

// DefaultDetector is the baseline-comparing TamperDetector.
type DefaultDetector struct{}

// Check delegates to Baseline.Matches.
func (DefaultDetector) Check(baseline *Baseline, a *Attestation) error {
	return baseline.Matches(a)
}

// -----------------------------------------------------------------------------------
// Agent — the orchestrator
// -----------------------------------------------------------------------------------

// Agent is the F3 edge-sentinel agent. It runs a periodic attestation loop and triggers the
// kill switch + alert on tamper.
type Agent struct {
	// NodeID identifies this node in fleet topology.
	NodeID string
	// Baseline is the trusted reference measurement.
	Baseline Baseline
	// Attestor produces fresh attestations.
	Attestor Attestor
	// Detector checks each attestation.
	Detector TamperDetector
	// Kill is invoked on tamper.
	Kill KillSwitch
	// Alerter fans incidents out to FleetMarshal.
	Alerter Alerter
	// Clock abstracts time.
	Clock Clock
	// Interval is the attestation cadence.
	Interval time.Duration

	// Mutable state (protected by mu).
	mu        sync.RWMutex
	lastGood  *Attestation
	lastCheck time.Time
	killed    bool
	actions   []string
	failures  atomic.Int64 // count of probe failures (not tamper, just transient)
	tampers   atomic.Int64 // count of tamper detections
}

// NewAgent constructs an Agent with sensible defaults for nil fields.
func NewAgent(nodeID string, baseline Baseline, attestor Attestor, kill KillSwitch, alerter Alerter) *Agent {
	return &Agent{
		NodeID:   nodeID,
		Baseline: baseline,
		Attestor: attestor,
		Detector: DefaultDetector{},
		Kill:     kill,
		Alerter:  alerter,
		Clock:    WallClock{},
		Interval: DefaultAttestInterval,
	}
}

// LastGood returns the most recent attestation that passed the detector (nil before the first
// successful probe).
func (a *Agent) LastGood() *Attestation {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.lastGood == nil {
		return nil
	}
	cp := *a.lastGood
	return &cp
}

// LastCheckAt returns the timestamp of the last probe (success or failure).
func (a *Agent) LastCheckAt() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lastCheck
}

// Killed reports whether the kill switch has fired.
func (a *Agent) Killed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.killed
}

// ActionsTaken returns the actions reported by the kill switch (empty before any tamper).
func (a *Agent) ActionsTaken() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, len(a.actions))
	copy(out, a.actions)
	return out
}

// ProbeFailures returns the count of transient probe failures (network errors etc).
func (a *Agent) ProbeFailures() int64 { return a.failures.Load() }

// TamperCount returns the count of tamper detections.
func (a *Agent) TamperCount() int64 { return a.tampers.Load() }

// ProbeOnce runs one attestation cycle. Returns the resulting Attestation (which may be nil
// if the attestor returned an error). On tamper, fires the kill switch + alert.
//
// This is the heart of the loop, exposed publicly so it can also be invoked out-of-cycle
// (e.g. when the inference engine requests a re-attestation before serving a sensitive
// request).
func (a *Agent) ProbeOnce(ctx context.Context) (*Attestation, error) {
	a.mu.Lock()
	a.lastCheck = a.clk().Now()
	a.mu.Unlock()
	att, err := a.Attestor.Attest(ctx)
	if err != nil {
		a.failures.Add(1)
		return nil, fmt.Errorf("attest: %w", err)
	}
	if err := a.Detector.Check(&a.Baseline, att); err != nil {
		// Tamper — fire kill switch, then alert.
		a.tampers.Add(1)
		return att, a.triggerKill(ctx, err.Error(), att)
	}
	// All good — record and return.
	a.mu.Lock()
	a.lastGood = att
	a.mu.Unlock()
	return att, nil
}

func (a *Agent) clk() Clock {
	if a.Clock != nil {
		return a.Clock
	}
	return WallClock{}
}

// triggerKill fires the kill switch and alerts FleetMarshal. Idempotent: subsequent calls are
// no-ops (returns ErrAlreadyKilled).
func (a *Agent) triggerKill(ctx context.Context, reason string, observed *Attestation) error {
	a.mu.Lock()
	if a.killed {
		a.mu.Unlock()
		return ErrAlreadyKilled
	}
	a.killed = true
	a.mu.Unlock()

	alertCtx, cancel := context.WithTimeout(ctx, DefaultAlertTimeout)
	defer cancel()

	actions, err := a.Kill.Kill(alertCtx, reason)
	if err != nil {
		// Even if the kill switch failed to fully execute, still alert — partial action is
		// important for the fleet to know about.
		actions = append(actions, fmt.Sprintf("kill-switch-error: %v", err))
	}
	a.mu.Lock()
	a.actions = actions
	a.mu.Unlock()

	inc := Incident{
		NodeID:         a.NodeID,
		Reason:         reason,
		BaselineDigest: a.Baseline.digest(),
		ObservedDigest: observed.Digest(),
		At:             a.clk().Now().UTC().Format(time.RFC3339Nano),
		ActionsTaken:   actions,
	}
	// Best-effort alert — do not block the kill on alert failure.
	_ = a.Alerter.Alert(alertCtx, inc)
	return ErrTamperDetected
}

// digest returns the canonical sha256 of the baseline.
func (b Baseline) digest() string {
	h := sha256.New()
	h.Write([]byte(b.TeeMeasurement))
	h.Write([]byte{0})
	h.Write([]byte(b.GpuModel))
	h.Write([]byte{0})
	h.Write([]byte(b.DriverVersion))
	h.Write([]byte{0})
	h.Write([]byte(b.ClientImageDigest))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Run is the periodic loop. It exits when ctx is cancelled. The first probe runs immediately;
// subsequent probes run every Interval. Each probe is one ProbeOnce call.
func (a *Agent) Run(ctx context.Context) error {
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()
	// First probe immediately.
	if _, err := a.ProbeOnce(ctx); err != nil && !errors.Is(err, ErrTamperDetected) {
		// Transient errors don't stop the loop; tamper does (kill switch already fired).
		return err
	}
	if a.Killed() {
		return ErrTamperDetected
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := a.ProbeOnce(ctx); err != nil {
				if errors.Is(err, ErrTamperDetected) {
					return err
				}
				// Transient: log and continue (in production, structured-log here).
				continue
			}
		}
	}
}

// -----------------------------------------------------------------------------------
// HTTP surface (tiny: /healthz, /lastgood, /killed)
// -----------------------------------------------------------------------------------

// Handler returns the http.Handler for the agent's HTTP surface.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         "ok",
			"component":      "edge-sentinel",
			"version":        Version,
			"killed":         a.Killed(),
			"probe_failures": a.ProbeFailures(),
			"tamper_count":   a.TamperCount(),
		})
	})
	mux.HandleFunc("/lastgood", func(w http.ResponseWriter, r *http.Request) {
		lg := a.LastGood()
		if lg == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no successful probe yet"})
			return
		}
		writeJSON(w, http.StatusOK, lg)
	})
	mux.HandleFunc("/killed", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"killed":       a.Killed(),
			"actions":      a.ActionsTaken(),
			"tamper_count": a.TamperCount(),
		})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	// Best-effort encode; the handler surface is intentionally minimal.
	enc := jsonEncoder(w)
	_ = enc(v)
}

// jsonEncoder returns a closure that writes JSON to w. Split out so we don't pay the encoding
// import cost when the binary doesn't need HTTP (the systemd unit doesn't, for instance).
func jsonEncoder(w http.ResponseWriter) func(any) error {
	return func(v any) error {
		// Inline minimal JSON for the three known shapes (map[string]string,
		// map[string]any, *Attestation) — avoids importing encoding/json in the <5MB
		// binary. We still keep a tiny indirection so future schema changes don't regress.
		return writeAnyJSON(w, v)
	}
}

// writeAnyJSON is a minimal JSON writer for the agent's HTTP surface.
func writeAnyJSON(w http.ResponseWriter, v any) error {
	switch t := v.(type) {
	case map[string]string:
		_, err := fmt.Fprint(w, "{")
		if err != nil {
			return err
		}
		first := true
		for k, val := range t {
			if !first {
				_, _ = fmt.Fprint(w, ",")
			}
			first = false
			_, err = fmt.Fprintf(w, "%q:%q", k, val)
			if err != nil {
				return err
			}
		}
		_, err = fmt.Fprint(w, "}")
		return err
	case map[string]any:
		return writeMapAny(w, t)
	case *Attestation:
		return writeMapAny(w, map[string]any{
			"tee_kind":            t.TeeKind,
			"tee_measurement":     t.TeeMeasurement,
			"gpu_model":           t.GpuModel,
			"driver_version":      t.DriverVersion,
			"client_image_digest": t.ClientImageDigest,
			"timestamp":           t.Timestamp.UTC().Format(time.RFC3339Nano),
		})
	default:
		_, err := fmt.Fprintf(w, "%v", v)
		return err
	}
}

func writeMapAny(w http.ResponseWriter, m map[string]any) error {
	if _, err := fmt.Fprint(w, "{"); err != nil {
		return err
	}
	first := true
	for k, v := range m {
		if !first {
			if _, err := fmt.Fprint(w, ","); err != nil {
				return err
			}
		}
		first = false
		if _, err := fmt.Fprintf(w, "%q:", k); err != nil {
			return err
		}
		switch t := v.(type) {
		case string:
			if _, err := fmt.Fprintf(w, "%q", t); err != nil {
				return err
			}
		case bool:
			if _, err := fmt.Fprintf(w, "%t", t); err != nil {
				return err
			}
		case int64:
			if _, err := fmt.Fprintf(w, "%d", t); err != nil {
				return err
			}
		case int:
			if _, err := fmt.Fprintf(w, "%d", t); err != nil {
				return err
			}
		case []string:
			if _, err := fmt.Fprint(w, "["); err != nil {
				return err
			}
			for i, s := range t {
				if i > 0 {
					if _, err := fmt.Fprint(w, ","); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprintf(w, "%q", s); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, "]"); err != nil {
				return err
			}
		default:
			if _, err := fmt.Fprintf(w, "%q", fmt.Sprint(t)); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprint(w, "}")
	return err
}

// -----------------------------------------------------------------------------------
// Self-check helpers (used by the systemd unit's ExecStartPre)
// -----------------------------------------------------------------------------------

// SanityCheck returns nil if the agent's dependencies are non-nil and the baseline is valid
// (at least one field set). Useful as an ExecStartPre gate so the unit fails fast on
// misconfiguration.
func (a *Agent) SanityCheck() error {
	if strings.TrimSpace(a.NodeID) == "" {
		return errors.New("edge-sentinel: NodeID is empty")
	}
	if a.Attestor == nil {
		return errors.New("edge-sentinel: Attestor is nil")
	}
	if a.Kill == nil {
		return errors.New("edge-sentinel: Kill is nil")
	}
	if a.Alerter == nil {
		return errors.New("edge-sentinel: Alerter is nil")
	}
	if a.Baseline == (Baseline{}) {
		return errors.New("edge-sentinel: Baseline is empty (set at least one field)")
	}
	return nil
}

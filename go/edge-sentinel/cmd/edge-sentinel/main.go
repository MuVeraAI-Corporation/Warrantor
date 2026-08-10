// Command edge-sentinel is the F3 edge inference attestation agent.
//
// Runs as a <5MB sidecar next to the inference engine. In production it is shipped as a
// systemd unit (see deploy/edge-sentinel.service) so it survives the inference engine
// restarting.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"muveraai.com/go/edge-sentinel"
)

// mockAttestor is a placeholder for the C1-5 composite-attestation client. The real client
// is wired in production via build tags (see task 03).
type mockAttestor struct {
	att *edgesentinel.Attestation
}

func (m *mockAttestor) Attest(ctx context.Context) (*edgesentinel.Attestation, error) {
	cp := *m.att
	return &cp, nil
}

// stdioKillSwitch logs the kill action. Production wires SIGTERM-to-inference + eBPF netns.
type stdioKillSwitch struct{}

func (stdioKillSwitch) Kill(_ context.Context, reason string) ([]string, error) {
	log.Printf("edge-sentinel: KILL reason=%q", reason)
	return []string{"logged-kill"}, nil
}

// stdioAlerter logs the alert. Production wires gRPC-to-FleetMarshal.
type stdioAlerter struct{}

func (stdioAlerter) Alert(_ context.Context, inc edgesentinel.Incident) error {
	log.Printf("edge-sentinel: ALERT node=%s reason=%s", inc.NodeID, inc.Reason)
	return nil
}

func main() {
	nodeID := flag.String("node-id", "", "this node's SPIFFE ID or hostname (required)")
	teeMeasurement := flag.String("tee-measurement", "", "trusted TEE measurement (hex)")
	gpuModel := flag.String("gpu-model", "H100", "trusted GPU model")
	driverVersion := flag.String("driver-version", "", "trusted GPU driver version")
	clientImageDigest := flag.String("client-image-digest", "", "trusted inference client image digest (sha256:...)")
	interval := flag.Duration("interval", edgesentinel.DefaultAttestInterval, "attestation interval")
	httpAddr := flag.String("http-addr", ":8445", "HTTP surface (liveness, /lastgood, /killed)")
	flag.Parse()

	if *nodeID == "" {
		*nodeID = hostnameOrUnknown()
	}
	if *teeMeasurement == "" && *clientImageDigest == "" {
		log.Printf("edge-sentinel: WARNING — empty baseline; running in observe-only mode")
	}

	baseline := edgesentinel.Baseline{
		TeeMeasurement:    *teeMeasurement,
		GpuModel:          *gpuModel,
		DriverVersion:     *driverVersion,
		ClientImageDigest: *clientImageDigest,
	}
	att := &mockAttestor{att: &edgesentinel.Attestation{
		TeeKind:           "mock",
		TeeMeasurement:    *teeMeasurement,
		GpuModel:          *gpuModel,
		DriverVersion:     *driverVersion,
		ClientImageDigest: *clientImageDigest,
		Timestamp:         time.Now(),
	}}
	agent := edgesentinel.NewAgent(*nodeID, baseline, att, stdioKillSwitch{}, stdioAlerter{})
	agent.Interval = *interval
	if err := agent.SanityCheck(); err != nil {
		// In observe-only mode the baseline is intentionally empty, so we don't fail.
		log.Printf("edge-sentinel: sanity check (advisory): %v", err)
	}

	// HTTP surface (separate goroutine so Run can block).
	go func() {
		srv := &http.Server{Addr: *httpAddr, Handler: agent.Handler(), ReadHeaderTimeout: 5 * time.Second}
		log.Printf("edge-sentinel: HTTP on %s", *httpAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("edge-sentinel: http: %v", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("edge-sentinel: starting (node=%s interval=%s)", *nodeID, *interval)
	if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("edge-sentinel: exited: %v", err)
	}
}

func hostnameOrUnknown() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-node"
	}
	return h
}

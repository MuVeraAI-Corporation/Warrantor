// Command fleet-marshal is the F4 Kubernetes operator entrypoint.
//
// In v1.0 the K8s API binding (controller-runtime) is intentionally elided from this file —
// the rollout logic is fully exercised via the in-package RolloutExecutor surface (see
// fleet_test.go). Production wiring lands in task 03 once the cluster CRD is registered.
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

	"aumos.dev/fleet-marshal"
)

// dryRunExecutor implements RolloutExecutor by logging each call (no K8s API).
type dryRunExecutor struct {
	now time.Time
}

func (d *dryRunExecutor) SetReplicas(_ context.Context, f *fleetmarshal.ModelFleet, image string, n int32) ([]string, error) {
	log.Printf("fleet-marshal [dryrun]: SetReplicas(%s/%s, image=%s, replicas=%d)", f.Namespace, f.Name, image, n)
	out := make([]string, n)
	for i := range out {
		out[i] = image + "-pod-" + string(rune('a'+i))
	}
	return out, nil
}

func (d *dryRunExecutor) Observe(_ context.Context, _ *fleetmarshal.ModelFleet, ids []string) ([]fleetmarshal.PodObservation, error) {
	out := make([]fleetmarshal.PodObservation, len(ids))
	for i, id := range ids {
		out[i] = fleetmarshal.PodObservation{PodID: id, Ready: true}
	}
	return out, nil
}

func (d *dryRunExecutor) SteerTraffic(_ context.Context, f *fleetmarshal.ModelFleet, image string, frac float64) error {
	log.Printf("fleet-marshal [dryrun]: SteerTraffic(%s/%s, image=%s, fraction=%.2f)", f.Namespace, f.Name, image, frac)
	return nil
}

func (d *dryRunExecutor) TearDown(_ context.Context, f *fleetmarshal.ModelFleet, image string) error {
	log.Printf("fleet-marshal [dryrun]: TearDown(%s/%s, image=%s)", f.Namespace, f.Name, image)
	return nil
}

func (d *dryRunExecutor) Now() time.Time                  { return d.now }
func (d *dryRunExecutor) Sleep(_ context.Context, dur time.Duration) error {
	d.now = d.now.Add(dur)
	return nil
}

func main() {
	name := flag.String("name", "falcon-fleet", "ModelFleet name")
	namespace := flag.String("namespace", "default", "ModelFleet namespace")
	fromImage := flag.String("from-image", "", "image being replaced (empty for first deploy)")
	toImage := flag.String("to-image", "", "image being rolled out (required)")
	strategy := flag.String("strategy", string(fleetmarshal.StrategyCanary), "rollout strategy")
	replicas := flag.Int("replicas", 4, "desired replica count")
	httpAddr := flag.String("http-addr", ":8446", "HTTP surface")
	flag.Parse()

	if *toImage == "" {
		log.Fatal("fleet-marshal: --to-image is required")
	}
	spec := fleetmarshal.DefaultSpec(*toImage, int32(*replicas))
	spec.Strategy = fleetmarshal.RolloutStrategy(*strategy)
	if err := fleetmarshal.ValidateSpec(spec); err != nil {
		log.Fatalf("fleet-marshal: invalid spec: %v", err)
	}

	fleet := &fleetmarshal.ModelFleet{
		Name:      *name,
		Namespace: *namespace,
		Spec:      spec,
		Status:    fleetmarshal.ModelFleetStatus{CurrentImage: *fromImage, CurrentReplicas: int32(*replicas), Phase: fleetmarshal.PhaseIdle},
	}
	exec := &dryRunExecutor{now: time.Now()}
	rollout := fleetmarshal.NewRollout(fleet, *fromImage, *toImage, exec)

	// Tiny HTTP surface for the dry-run mode (production has metrics + CRD status).
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"status":"ok","component":"fleet-marshal"}`))
		})
		srv := &http.Server{Addr: *httpAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		log.Printf("fleet-marshal: HTTP on %s", *httpAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("fleet-marshal: http: %v", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("fleet-marshal: rolling out %s → %s (%s)", *fromImage, *toImage, spec.Strategy)
	if err := rollout.Run(ctx); err != nil {
		if errors.Is(err, fleetmarshal.ErrRolloutAborted) {
			log.Printf("fleet-marshal: rolled back: %v", err)
			os.Exit(2)
		}
		log.Fatalf("fleet-marshal: run: %v", err)
	}
	log.Printf("fleet-marshal: complete; phase=%q", rollout.Phase())
}

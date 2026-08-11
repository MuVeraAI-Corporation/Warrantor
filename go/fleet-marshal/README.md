# aumos fleet-marshal (F4)

Kubernetes operator that rolls model updates out across the inference fleet safely. Manages
the `ModelFleet` CRD with three rollout strategies and automatic rollback.

## Strategies

| Strategy      | How it works                                                        | When to use                         |
|---------------|---------------------------------------------------------------------|-------------------------------------|
| `all_at_once` | Swap every pod in one pass.                                         | Risk-tolerant dev / staging fleets. |
| `canary`      | Ramp traffic pod-by-pod (default 10%/step), dwell, observe, repeat. | Production default.                 |
| `blue_green`  | Stand up a parallel "green" fleet, dwell, then cut traffic over.    | High-stakes single-shot rollouts.   |

Auto-rollback fires when the observed failure fraction exceeds `FailureThreshold`. On
rollback the fleet returns to its previous image (or, for first deploys, tears the new pods
down).

## Quickstart (dry-run)

```bash
go run ./cmd/fleet-marshal \
    --name falcon-fleet \
    --namespace default \
    --from-image registry/falcon-7b:v1 \
    --to-image registry/falcon-7b:v2 \
    --strategy canary \
    --replicas 20 \
    --http-addr :8446
```

## CRD shape

```yaml
apiVersion: muveraai.com/v1
kind: ModelFleet
metadata:
  name: falcon-fleet
  namespace: default
spec:
  modelImage: registry/falcon-7b:v2
  replicas: 20
  strategy: canary
  failureThreshold: 0.1
  canaryStepPct: 0.1
  canaryStepInterval: 60s
  blueGreenDwell: 5m
  minReplicasForCanary: 10
status:
  currentImage: registry/falcon-7b:v1
  currentReplicas: 20
  readyReplicas: 20
  failedReplicas: 0
  phase: idle
  lastTransitionAt: "2026-08-05T12:00:00Z"
```

## Architecture

Every K8s interaction is the `RolloutExecutor` interface, so the rollout maths is testable
fully in-memory. Production wiring (controller-runtime, pod patching, service-mesh traffic
weights) lives in `cmd/fleet-marshal` and is intentionally thin.

| Method          | K8s action                                          |
|-----------------|-----------------------------------------------------|
| `SetReplicas`   | `Deployment` scale subresource.                     |
| `Observe`       | Pod list watch + readiness probe results.           |
| `SteerTraffic`  | Istio `VirtualService` weight patch.                |
| `TearDown`      | `Deployment` delete (blue) / scale-to-0.            |

## References

- RFC `docs/rfcs/F4-fleet-marshal.md`
- Receives `Incident` alerts from F3 `edge-sentinel` via gRPC.

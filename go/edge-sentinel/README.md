# aumos edge-sentinel (F3)

Edge inference attestation agent. Runs as a <5MB sidecar next to the inference engine on
every GPU node. Periodically (every 30s by default) attests the local hardware/TEE, compares
each fresh attestation against the trusted baseline, and on tamper:

1. Fires the kill switch (terminates inference).
2. Alerts FleetMarshal (F4) with a structured `Incident`.

Designed to be shipped as a systemd unit (`deploy/edge-sentinel.service`) so it survives the
inference engine restarting.

## Quickstart (dev)

```bash
go run ./cmd/edge-sentinel \
    --node-id spiffe://aumos.dev/node/gpu-1 \
    --tee-measurement deadbeef \
    --gpu-model H100 \
    --driver-version 535.104.05 \
    --client-image-digest sha256:abc \
    --interval 30s \
    --http-addr :8445
```

## HTTP surface

| Method | Path        | Description                                                    |
|--------|-------------|----------------------------------------------------------------|
| GET    | `/healthz`  | Liveness + component version + killed flag + counters.         |
| GET    | `/lastgood` | The most recent attestation that passed the detector (404 first). |
| GET    | `/killed`   | Whether the kill switch has fired, with the actions taken.     |

## Architecture

Every external interaction is an interface, so the production wiring is isolated to `cmd/`:

| Interface     | Production wiring                              |
|---------------|-------------------------------------------------|
| `Attestor`    | C1-5 confidential-fabric composite attestation. |
| `KillSwitch`  | SIGTERM to inference + eBPF netns isolation.    |
| `Alerter`     | gRPC to FleetMarshal (F4).                      |
| `Clock`       | Wall-clock (overridden in tests).               |

The kill switch is idempotent — subsequent tamper detections after the first kill are
no-ops (`ErrAlreadyKilled`).

## References

- RFC `docs/rfcs/F3-edge-sentinel.md`
- Composes C1-5 `confidential-fabric` for the attestation source.
- Alerts F4 `fleet-marshal` on tamper.

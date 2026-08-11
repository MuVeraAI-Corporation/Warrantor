# warrantor-fed-core (F1)

Attested federated training orchestration. Three roles collaborate:

- **Aggregator** (runs in a TEE) — collects updates, runs `FedAvg`, verifies the aggregate,
  publishes the new global model.
- **Trainer** (one per participant) — runs local training (PyTorch / NeMo / JAX via the
  `TrainingEngine` protocol), emits a signed `ModelUpdate`.
- **Verifier** — stateless checker: NaN/Inf, norm caps (poisoning / free-rider), and
  trusted-client-image match.

A participant may not join a round without presenting a `TeeAttestation` whose signature covers
the round nonce. Differential privacy is delegated to F2 `dp-crate` via `DPNoiseCallback`.

## Quickstart

```python
from fed_core import Federation, Participant, Role, TeeAttestation, ModelUpdate

fed = Federation("demo", initial_parameters=[0.0, 0.0], min_participants=1)
att = TeeAttestation(
    participant_id="t1", tee_kind="mock", tee_measurement="m",
    client_image_digest="sha256:trusted",
    issued_at="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z",
    signature_hex=...,  # covers (participant_id | measurement | nonce)
)
fed.register(Participant("t1", Role.TRAINER, "pk", att))
result = fed.run_round(updates=[ModelUpdate("t1", [1.0, 2.0], 10, 0.5)])
assert result.verification_passed
```

## References

- RFC `docs/rfcs/F1-fed-core.md`
- Integrates C1-3 `attesta-flow` for TEE attestation and F2 `dp-crate` for differential privacy.

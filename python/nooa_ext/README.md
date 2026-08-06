# aumos-nooa-ext (X2)

Production extensions to NVIDIA NOOA. NOOA itself is NVIDIA's agent harness; this package
extends it with four production-grade components:

- **PolicyEnforcer** — OPA/Rego integration point for in-harness policy enforcement.
- **AuditStreamer** — Kafka / Kinesis / webhook sink protocol for streaming audit events.
- **IdentityBinder** — SPIFFE SVID binding for agent identity propagation.
- **AttestationHook** — Hardware attestation gate invoked at harness boundaries.

See `docs/rfcs/X2-nooa-ext.md`.

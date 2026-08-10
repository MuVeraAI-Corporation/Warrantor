# aumos-confidential-fabric (C1-5)

The composite attestation fabric. Folds three independent attestation streams into a single
`CompositeAttestation` and gates the release of model-wrapping keys behind a `KeyReleasePolicy`.

## Streams

| Leaf | Source | What it proves |
|------|--------|----------------|
| `GpuAttestation` | C1-1 `nvtrust-bridge` | GPU identity + driver version + nonce-bound report |
| `RuntimeAttestation` | C1-3 `attesta-flow` | TEE backend + measurement + runtime image digest |
| `AgentIdentity` | I1 `agent-identity` | SPIFFE SVID + publisher + capabilities + TTL |

## API

```rust
use aumos_confidential_fabric::{Fabric, KeyReleasePolicy, ConfidentialContainer};

let fabric = Fabric::new("muveraai.com");
let composite = fabric.assemble(Some(gpu), runtime, agent, now);

let policy = KeyReleasePolicy {
    required_gpu_model: "H100".to_string(),
    required_tee_measurement: "meas-A".to_string(),
    ..Default::default()
};
assert!(policy.evaluate(&composite, now).is_ok());

let bundle = ConfidentialContainer::new("falcon-7b", "sha256:plain", "ct", policy, "salt", now);
let key = bundle.release_key(&composite, now)?;
```

## Decisions

- **Freshness**: default 10-minute window; 60-second clock-skew tolerance.
- **Digest**: SHA-256 of the deterministic canonical encoding of the leaves (GPU|runtime|agent).
- **Key derivation**: SHA-256 of `(domain-sep | policy-salt | digest | tee-measurement | runtime-digest)`.
- **CPU-only inference**: GPU leaf may be `None`; policy still applies.

## References

- RFC `docs/rfcs/C1-5-confidential-fabric.md`
- Composes C1-1 `nvtrust-bridge`, C1-3 `attesta-flow`, I1 `agent-identity`.

# T1 — `trust-core` RFC

> The Rust trusted core that owns every allow/deny, sign, and verify operation. The single
> authoritative implementation of all security invariants. *No security invariant may have two
> authoritative implementations.*

| Field | Value |
|---|---|
| **Canonical ID** | T1 |
| **Name** | trust-core |
| **Wave** | 1 (M0–M3) |
| **Languages** | Rust (sole owner) + PyO3/napi-rs/FFI bindings |
| **DefStack origin** | C2.2 ModelNotary + signing half of C4.4 |
| **AumSecure origin** | `agent-evidence` (V3 repo #2) + AATM signing |
| **Sentinel origin** | atlas-sign + sentinel-artifact |
| **Dependencies** | none (foundation) |
| **Dependents** | I1, R2, R3, R4, S1, S2, S4, E1, N3, all protocol consumers |

## Background

The four source portfolios each named a "trusted core" differently: DefStack's `ModelNotary` (Rust
CLI for model signing), AumSecure's `agent-evidence` (Rust verifier + bindings), Sentinel's
`atlas-sign` and `sentinel-artifact`. All describe the same thing — the single Rust crate that owns
signing, verification, and canonicalization. AumOS collapses them into **one** component per the
polyglot stack pressure test's load-bearing rule.

## Goals

- Provide the **single** implementation of: Ed25519 / Ed448 signing & verification, Sigstore Rekor
  integration, KMS integration (AWS/GCP/Azure), YubiKey support, canonical CBOR encoding for
  deterministic receipts, Merkle-tree provenance primitives.
- Expose via PyO3 (Python), napi-rs (Node/TypeScript), and C FFI (Go/cgo).
- Achieve ≥85% test coverage; pass fuzzing (cargo-fuzz) on every parser and crypto path.
- Ship a `trust-core` CLI: `sign`, `verify`, `key-gen`, `notarize`.

## Non-Goals

- Policy decisions (those live in R5/R6 and call trust-core to verify signatures).
- Key management UI (the console, X7, exposes this; trust-core just uses KMS).
- A second implementation in any other language (forbidden by stack test).

## Detailed Design

### Crate layout
```
rust/trust-core/
├── Cargo.toml
├── src/
│   ├── lib.rs              # public API surface
│   ├── signing.rs          # Ed25519/Ed448, KMS, YubiKey, HSM
│   ├── verification.rs     # verify, batch verify, key rotation
│   ├── canonical.rs        # deterministic CBOR encoding (RFC 8949)
│   ├── rekor.rs            # Sigstore Rekor transparency log
│   ├── merkle.rs           # Merkle tree primitives (for S2 provena-chain)
│   ├── attestation.rs      # attestation report types (consumed from C1-1/C1-2)
│   └── cli.rs              # `trust-core sign|verify|key-gen|notarize`
├── bindings/
│   ├── python/             # PyO3 (maturin)
│   ├── node/               # napi-rs
│   └── go/                 # cgo to C FFI
├── fuzz/                   # cargo-fuzz targets
└── tests/                  # integration + golden vectors
```

### Public API (sketch)
```rust
pub fn sign(payload: &[u8], key: &SigningKey) -> Result<Signature>;
pub fn verify(payload: &[u8], sig: &Signature, key: &VerifyingKey) -> Result<()>;
pub fn canonical_cbor(value: &serde_cbor::Value) -> Vec<u8>;  // deterministic
pub fn notarize(payload: &[u8], key: &SigningKey, rekor: &RekorClient) -> Result<RekorEntry>;
pub fn merkle_root(leaves: &[ &[u8] ]) -> [u8; 32];
```

### Deterministic encoding
Every AAR (P2), AAE (P1), and signed artifact is canonicalized to **deterministic CBOR** (RFC 8949
§4.2.2) before signing. This guarantees that a receipt signed in Rust verifies identically when
re-canonicalized in Python or Go. The golden vectors in `testvectors/trust-core/` lock this.

### KMS / HSM integration
- AWS KMS, GCP KMS, Azure Key Vault (envelope encryption).
- YubiKey (PIV slots) for offline signing.
- HSM via PKCS#11 for FedRAMP / regulated deployments.
- Always: the private key never leaves the KMS/HSM; trust-core signs via the KMS API.

## Dependencies

- **External:** `ed25519-dalek`, `p256` (for fallback ECDSA), `serde_cbor`, `sigstore` crate,
  `pkcs11` crate, `merkle_light`.
- **AumOS:** none (this is the foundation).

## Threat Model (STRIDE — security-critical component, full)

| Threat | Surface | Mitigation |
|---|---|---|
| **Spoofing** | Forged signature accepted | Ed25519 verification constant-time; fail-closed on any verify error |
| **Tampering** | Payload modified after signing | Content-digest in signature; canonical CBOR |
| **Repudiation** | Signer denies signing | Sigstore Rekor transparency log entry returned with every signature |
| **Information disclosure** | Private key leakage | Key never leaves KMS/HSM; in-memory zeroization |
| **Denial of service** | Verify call slow | Batch verify; constant-time guarantees no timing oracle |
| **Elevation of privilege** | Unauthorized signing | Key access gated by I1 AAE; KMS key policy scoped to AumOS service |

## API / CLI

```
trust-core sign --payload <file> --key <key-ref> [--rekor]
trust-core verify --payload <file> --sig <sig> --key <key-ref> [--rekor-entry <entry>]
trust-core key-gen --algorithm ed25519 [--kms aws://...]
trust-core notarize --payload <file> --key <key-ref>
```

Wire: gRPC service `warrantor.trust.v1.Trust` (see `proto/warrantor/trust/v1/signing.proto`).

## Testing

- **Unit:** ≥90% coverage on signing/verification/canonical (security-critical).
- **Golden vectors:** `testvectors/trust-core/` — sign in Rust, verify the signature in Python and
  Go; the conformance suite (A6) enforces this cross-language.
- **Fuzz:** cargo-fuzz targets on CBOR parser, signature decoder, Rekor response parser.
- **Property tests:** `proptest` on canonical encoding (round-trip + determinism).
- **Adversarial:** malformed signatures, downgrade attempts, key-confusion attacks.
- **Exit gate:** ≥85% coverage, zero clippy warnings, all fuzz targets run 1M iterations clean in
  nightly CI.

## Deployment

- Library: published as `aumos-trust-core` crate (crates.io after Wave-1 signoff; locally during
  Wave-1).
- Bindings: `aumos-trust-core` on PyPI, npm, and Go module path (all locally until signoff).
- Not a deployable service (other components embed it as a library). When the trust-core gRPC
  service is needed (e.g., for batch verify), it ships as a sidecar with OTel instrumentation.
- SBOM: CycloneDX generated in CI; SLSA L3 build provenance.

## Milestones

| Milestone | Target | Deliverable |
|---|---|---|
| Week 2 (MVP) | M0+2wk | Ed25519 sign/verify + canonical CBOR + CLI `sign`/`verify`; 1 golden vector |
| Week 4 (Alpha) | M0+4wk | KMS integration (AWS); Rekor; Python binding; 5 golden vectors; cargo-fuzz targets |
| Week 6 (Beta) | M0+6wk | GCP/Azure KMS; YubiKey; Node binding; Go binding; conformance green |
| Week 8 (v1.0) | M1 | All features; ≥90% coverage; external security review scheduled; v1.0 tagged |

## Cross-references

- Reconciliation: [`../00-reconciliation-matrix.md`](../00-reconciliation-matrix.md#T1)
- Architecture: [`../02-architecture.md`](../02-architecture.md) §5 (trusted core boundary)
- Protocol specs: P1 AAE, P2 AAR, P6 AATM (this crate signs/verifies them all)
- Stack test doctrine: this crate is the "one trusted semantic core"

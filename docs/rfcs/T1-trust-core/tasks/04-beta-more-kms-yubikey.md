# Task 04-beta-more-kms-yubikey — T1 trust-core

> **Sprint:** Beta week 5–6. **Acceptance:** GCP + Azure KMS, YubiKey, Merkle primitives, conformance green.

## Objective
Complete the KMS/HSM matrix, add Merkle-tree primitives (for S2 to consume), and pass the
cross-language conformance suite.

## Steps
1. GCP KMS via `google-cloud-kms`; Azure Key Vault via `azure_security_keyvault`.
2. YubiKey via `yubikey` crate (PIV slots). HSM via `pkcs11` crate.
3. `src/merkle.rs` — `pub fn merkle_root(leaves: &[&[u8]]) -> [u8; 32]` (SHA-256, RFC 6962
   ordering).
4. Run the conformance suite (`make conformance`); all golden vectors must verify in Rust, Python,
   and (once task 07 lands) Go.
5. Performance: benchmark `verify` at ≥10,000 ops/sec on a single core.

## Acceptance criteria
- [ ] All four KMS/HSM backends work against mocks in CI.
- [ ] YubiKey integration test passes on hardware (mark `#[ignore]` for CI; document in README).
- [ ] Merkle root matches RFC 6962 test vectors.
- [ ] Conformance green across Rust + Python.
- [ ] Coverage ≥88%.

## Out of scope
- Fuzz targets (task 06).
- Node binding (task 05).

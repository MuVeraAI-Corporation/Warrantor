# Task 02-mvp-sign-verify — T1 trust-core

> **Sprint:** MVP week 2. **Acceptance:** Ed25519 sign/verify + canonical CBOR working locally.

## Objective
Implement the core signing/verification path with deterministic canonical CBOR encoding.

## Steps
1. `src/canonical.rs` — `pub fn canonical_cbor(value: &serde_cbor::Value) -> Vec<u8>` implementing
   RFC 8949 §4.2.2 (length-first map key ordering, shortest forms, deterministic floats).
2. `src/signing.rs` — `SigningKey` and `VerifyingKey` wrappers around `ed25519-dalek`;
   `pub fn sign(payload: &[u8], key: &SigningKey) -> Result<Signature>`;
   `pub fn key_gen() -> SigningKey`.
3. `src/verification.rs` — `pub fn verify(payload: &[u8], sig: &Signature, key: &VerifyingKey)
   -> Result<()>`. Constant-time. Returns `thiserror`-typed errors.
4. `src/lib.rs` — re-export the public API.
5. Wire `cli.rs` `sign` and `verify` subcommands to call these.
6. Tests: unit tests for canonical encoding (round-trip, determinism, ordering); unit tests for
   sign/verify (positive + tampered-payload negative + wrong-key negative).

## Acceptance criteria
- [ ] `cargo test` covers canonical, signing, verification — all green.
- [ ] `trust-core key-gen | trust-core sign --payload x --key -` round-trips through `verify`.
- [ ] Tampering the payload between sign and verify fails verification with a typed error.
- [ ] Coverage ≥80% on these three modules.
- [ ] Property tests: `proptest` confirms canonical encoding round-trips for 1000 random CBOR values.

## Out of scope
- KMS/HSM (task 03).
- Rekor transparency log (task 03).
- Bindings (tasks 05–07).

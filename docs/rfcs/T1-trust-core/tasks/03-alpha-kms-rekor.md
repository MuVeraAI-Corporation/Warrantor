# Task 03-alpha-kms-rekor — T1 trust-core

> **Sprint:** Alpha week 3–4. **Acceptance:** AWS KMS + Rekor integration; Python binding.

## Objective
Add KMS-backed signing (AWS first), Sigstore Rekor transparency log, and the Python binding.

## Steps
1. `src/signing.rs` — add `KmsSigningKey` enum: `Aws(arn)`, `Gcp(arn)`, `Azure(uri)`, `Yubikey(slot)`,
   `Pkcs11(slot)`. Wire AWS KMS via `aws-sdk-kms`.
2. `src/rekor.rs` — `RekorClient` with `pub fn notarize(payload, sig) -> Result<RekorEntry>`.
3. Wire `notarize` CLI subcommand.
4. `bindings/python/` — PyO3 wrapper via `maturin`. Expose `sign`, `verify`, `canonical_cbor`,
   `notarize`. Publishable as `aumos-trust-core` Python wheel (local only during Wave-1).
5. Tests: mock KMS (use `aws-smithy-mocks-experimental`); Rekor integration test against the
   public Rekor instance (mark `#[ignore]` for offline CI).
6. Add the first 5 golden vectors in `testvectors/T1/`: each is a `(payload, canonical_cbor,
   signature)` triple. Python binding verifies each.

## Acceptance criteria
- [ ] `trust-core sign --key aws://<arn> --payload x` works against a mock KMS.
- [ ] `trust-core notarize --payload x --key aws://<arn>` returns a Rekor entry (in online tests).
- [ ] Python binding installs via `maturin develop` and verifies all 5 golden vectors.
- [ ] Coverage ≥85%.

## Out of scope
- GCP/Azure KMS (task 04).
- YubiKey / HSM (task 04).
- Node and Go bindings (tasks 05, 07).

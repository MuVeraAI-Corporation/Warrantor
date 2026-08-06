# Task 06-fuzz — T1 trust-core

> **Sprint:** Beta week 6. **Acceptance:** cargo-fuzz targets land; nightly CI runs 1M iterations clean.

## Objective
Fuzz every parser and crypto path.

## Steps
1. `fuzz/` — `cargo +nightly fuzz init`.
2. Targets: `fuzz_canonical_cbor` (arbitrary CBOR input), `fuzz_signature_decode` (arbitrary bytes
   as a signature), `fuzz_rekor_response` (arbitrary JSON as a Rekor entry).
3. Nightly CI job: each target runs 1M iterations; failures file a security advisory.
4. Add a regression corpus from any early findings.

## Acceptance criteria
- [ ] Three fuzz targets committed.
- [ ] Nightly CI job runs them; first run completes 1M iterations clean (or files regressions).
- [ ] Any finding is filed per `docs/cross-cutting/14-security-disclosure-policy.md`.

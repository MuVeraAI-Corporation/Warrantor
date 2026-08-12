# PROMPT.md — T1 trust-core master prompt

> Paste this entire file into Claude Code / Cursor / Codex to build T1 trust-core from scratch.

---

You are implementing **T1 trust-core**, the Rust trusted core of Warrantor. This is the single
authoritative implementation of every security invariant in the system. *No security invariant may
have two authoritative implementations.*

## Context

Read these files in this repository before writing any code:
1. `docs/rfcs/T1-trust-core.md` — your spec (the 10-section RFC).
2. `docs/00-reconciliation-matrix.md` — what T1 is and its dependents.
3. `docs/02-architecture.md` §5 — the trusted-core boundary.
4. `docs/cross-cutting/19-inter-component-protocol.md` — wire format rules.
5. `docs/rfcs/T1-trust-core/CLAUDE.md` — build conventions.
6. `docs/rfcs/T1-trust-core/AGENTS.md` — anti-patterns to avoid.
7. `docs/rfcs/T1-trust-core/tasks/` — the 8 sequenced tickets. **Work them in order.**

## What to build

A Rust crate at `rust/trust-core/` providing:
- Ed25519 / Ed448 signing & verification (via `ed25519-dalek`).
- Canonical CBOR encoding (deterministic, RFC 8949 §4.2.2) for receipt canonicalization.
- Sigstore Rekor transparency-log integration.
- KMS integration (AWS, GCP, Azure) + YubiKey + PKCS#11 HSM.
- Merkle-tree primitives (for S2 provena-chain to consume).
- A CLI: `trust-core sign|verify|key-gen|notarize`.
- Bindings: Python (PyO3/maturin), Node (napi-rs), Go (cgo to C FFI).

## Hard rules

- **Constant-time** crypto. No timing leaks.
- **Deterministic** encoding before signing. Never derive.
- **Private keys never leave** the KMS/HSM. Zeroize on drop.
- **≥90% coverage** on signing/verification/canonical (security-critical).
- **Zero clippy warnings** with `-D warnings`.
- **DCO sign-off** on every commit (`git commit -s`).
- **No second implementation** in any other language. Bindings call this crate.

## Test discipline

- Unit tests for every public function.
- Golden vectors in `testvectors/T1/` — sign in Rust, verify in Python and Go (cross-language
  conformance is enforced by A6).
- cargo-fuzz targets on every parser and crypto path; 1M iterations clean in nightly CI.
- proptest on canonical encoding (round-trip + determinism).

## Exit gate (Definition of Done)

- All 8 task tickets closed.
- v1.0 tag cut and signed.
- CycloneDX SBOM attached to the release.
- SLSA L3 build provenance in CI.
- External security review scheduled (Trail of Bits / NCC Group).

Start with task `tasks/01-setup.md`. Do not skip ahead. Each task has explicit acceptance criteria.

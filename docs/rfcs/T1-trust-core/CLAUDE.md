# CLAUDE.md — T1 trust-core build instructions

> Paste-target for Claude Code / Cursor / any coding agent building T1 trust-core.

## What you are building

The **Rust trusted core** — the single authoritative implementation of every security invariant in
Warrantor. You are implementing [`docs/rfcs/T1-trust-core.md`](../T1-trust-core.md). Read it first.

## Repo context (read these before coding)

- [`../../00-reconciliation-matrix.md`](../../00-reconciliation-matrix.md) — what T1 is and where it
  fits
- [`../../02-architecture.md`](../../02-architecture.md) §5 — the trusted-core boundary
- [`../../cross-cutting/19-inter-component-protocol.md`](../../cross-cutting/19-inter-component-protocol.md)
  — wire format rules
- [`../../cross-cutting/18-developer-experience.md`](../../cross-cutting/18-developer-experience.md)
  — contribution workflow, DCO, ≥85% coverage gate
- [`../../cross-cutting/13-compliance-frameworks.md`](../../cross-cutting/13-compliance-frameworks.md)
  — SLSA L3, FedRAMP, FIPS

## Toolchain

- **Rust** stable (install via https://rustup.rs if missing).
- Targets: `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --all`.
- Fuzz: `cargo +nightly fuzz run <target>` once fuzz targets land (week 4).

## Build entrypoint

```bash
cd rust/trust-core
cargo build
cargo test
cargo clippy --all-targets -- --deny warnings
```

The crate lives at `rust/trust-core/` (created in Phase 0.7 scaffolding). Bindings
(`bindings/python`, `bindings/node`, `bindings/go`) are separate workspaces.

## Conventions

- **Deterministic CBOR** (RFC 8949 §4.2.2) for canonical encoding before signing — never derive.
- All crypto operations constant-time (`ed25519-dalek` is constant-time by default; do not introduce
  timing leaks).
- Private keys never leave the KMS/HSM; in-memory key material is zeroized on drop (`zeroize` crate).
- Every public function has a doc comment and a unit test.
- Error type is `thiserror`-derived; no `unwrap()`/`expect()` in production paths.
- Sign commits with `git commit -s` (DCO).

## What NOT to do (anti-patterns)

See [`AGENTS.md`](AGENTS.md).

## Definition of done

The exit gate (per RFC milestones): ≥90% coverage on signing/verification/canonical; zero clippy
warnings; all fuzz targets pass 1M iterations; v1.0 tag; CycloneDX SBOM attached; SLSA L3 provenance.

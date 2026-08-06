# CLAUDE.md — C1-2 cuda-gram build instructions

> Paste-target for Claude Code / Cursor / any coding agent building C1-2 cuda-gram.

## What you are building

**C1-2 cuda-gram** — Python (PyO3). You are implementing [`docs/rfcs/C1-2-cuda-gram.md`](../C1-2-cuda-gram.md).
Read it first.

## Repo context (read before coding)

- [`../../00-reconciliation-matrix.md`](../../00-reconciliation-matrix.md) — component's place in the portfolio
- [`../../02-architecture.md`](../../02-architecture.md) — planes and invariants
- [`../../cross-cutting/18-developer-experience.md`](../../cross-cutting/18-developer-experience.md) — workflow, ≥85% coverage, DCO
- [`../../cross-cutting/19-inter-component-protocol.md`](../../cross-cutting/19-inter-component-protocol.md) — wire format
- [`../../cross-cutting/17-data-classification-privacy.md`](../../cross-cutting/17-data-classification-privacy.md) — data handling

## Component-specific context

High-level GPU attestation SDK. Exposes AttestationReport, CCSession, AttestationVerifier. Consumes C1-1's Rust core via PyO3 (do not use ctypes — that's the DefStack original we are migrating away from).

## Dependencies

- **AumOS internal:** C1-1
- **External:** enumerated during MVP (task 02); record in the RFC.

## Build entrypoint

See `tasks/01-setup.md`. The component lives under the language folder matching its primary
language (e.g. `rust/cuda_gram/`, `python/cuda_gram/`).

## Conventions

- Consume the contract plane (`proto/`, `specs/`, `testvectors/`); generate bindings, don't hand-write.
- OTel instrumentation on every RPC and long-running operation.
- CycloneDX SBOM in CI; SLSA L3 provenance.
- Sign commits with `git commit -s` (DCO).
- No second authoritative implementation of any security invariant (T1 owns those).

## Anti-patterns

See [`AGENTS.md`](AGENTS.md).

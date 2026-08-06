# CLAUDE.md — C1-1 nvtrust-bridge build instructions

> Paste-target for Claude Code / Cursor / any coding agent building C1-1 nvtrust-bridge.

## What you are building

**C1-1 nvtrust-bridge** — Rust core + Python + Go bindings. You are implementing [`docs/rfcs/C1-1-nvtrust-bridge.md`](../C1-1-nvtrust-bridge.md).
Read it first.

## Repo context (read before coding)

- [`../../00-reconciliation-matrix.md`](../../00-reconciliation-matrix.md) — component's place in the portfolio
- [`../../02-architecture.md`](../../02-architecture.md) — planes and invariants
- [`../../cross-cutting/18-developer-experience.md`](../../cross-cutting/18-developer-experience.md) — workflow, ≥85% coverage, DCO
- [`../../cross-cutting/19-inter-component-protocol.md`](../../cross-cutting/19-inter-component-protocol.md) — wire format
- [`../../cross-cutting/17-data-classification-privacy.md`](../../cross-cutting/17-data-classification-privacy.md) — data handling

## Component-specific context

NVTrust FFI bindings + nvtrust-verify CLI. NVTrust is NVIDIA's GPU attestation library. Offline/mock mode for CI is mandatory — do NOT attempt to download the real NVTrust SDK (NDA-gated). Define a Trait NVTrustBackend with Mock and Real impls.

## Dependencies

- **AumOS internal:** none
- **External:** enumerated during MVP (task 02); record in the RFC.

## Build entrypoint

See `tasks/01-setup.md`. The component lives under the language folder matching its primary
language (e.g. `rust/nvtrust_bridge/`, `python/nvtrust_bridge/`).

## Conventions

- Consume the contract plane (`proto/`, `specs/`, `testvectors/`); generate bindings, don't hand-write.
- OTel instrumentation on every RPC and long-running operation.
- CycloneDX SBOM in CI; SLSA L3 provenance.
- Sign commits with `git commit -s` (DCO).
- No second authoritative implementation of any security invariant (T1 owns those).

## Anti-patterns

See [`AGENTS.md`](AGENTS.md).

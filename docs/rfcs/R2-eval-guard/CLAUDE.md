# CLAUDE.md — R2 eval-guard build instructions

> Paste-target for Claude Code / Cursor / any coding agent building R2 eval-guard.

## What you are building

**R2 eval-guard** — Rust + eBPF (aya). You are implementing [`docs/rfcs/R2-eval-guard.md`](../R2-eval-guard.md).
Read it first.

## Repo context (read before coding)

- [`../../00-reconciliation-matrix.md`](../../00-reconciliation-matrix.md) — component's place in the portfolio
- [`../../02-architecture.md`](../../02-architecture.md) — planes and invariants
- [`../../cross-cutting/18-developer-experience.md`](../../cross-cutting/18-developer-experience.md) — workflow, ≥85% coverage, DCO
- [`../../cross-cutting/19-inter-component-protocol.md`](../../cross-cutting/19-inter-component-protocol.md) — wire format
- [`../../cross-cutting/17-data-classification-privacy.md`](../../cross-cutting/17-data-classification-privacy.md) — data handling

## Component-specific context

Sandbox boundary attestation. Four pre-flight checks: NetworkIsolation (canary IPs: huggingface.co, pypi.org, 1.1.1.1), FilesystemBoundary, ProcessIsolation, EgressAttestation (eBPF iptables rules, deny-all default). Emits signed SandboxAttestation via T1. Warrantor moved from Go to Rust per trusted-core doctrine. Requires Linux 5.13+ for eBPF; document this in the README.

## Dependencies

- **Warrantor internal:** C1-2
- **External:** enumerated during MVP (task 02); record in the RFC.

## Build entrypoint

See `tasks/01-setup.md`. The component lives under the language folder matching its primary
language (e.g. `rust/eval_guard/`, `python/eval_guard/`).

## Conventions

- Consume the contract plane (`proto/`, `specs/`, `testvectors/`); generate bindings, don't hand-write.
- OTel instrumentation on every RPC and long-running operation.
- CycloneDX SBOM in CI; SLSA L3 provenance.
- Sign commits with `git commit -s` (DCO).
- No second authoritative implementation of any security invariant (T1 owns those).

## Anti-patterns

See [`AGENTS.md`](AGENTS.md).

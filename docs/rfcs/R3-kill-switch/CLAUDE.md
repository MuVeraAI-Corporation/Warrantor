# CLAUDE.md — R3 kill-switch build instructions

> Paste-target for Claude Code / Cursor / any coding agent building R3 kill-switch.

## What you are building

**R3 kill-switch** — Rust core + Python policy. You are implementing [`docs/rfcs/R3-kill-switch.md`](../R3-kill-switch.md).
Read it first.

## Repo context (read before coding)

- [`../../00-reconciliation-matrix.md`](../../00-reconciliation-matrix.md) — component's place in the portfolio
- [`../../02-architecture.md`](../../02-architecture.md) — planes and invariants
- [`../../cross-cutting/18-developer-experience.md`](../../cross-cutting/18-developer-experience.md) — workflow, ≥85% coverage, DCO
- [`../../cross-cutting/19-inter-component-protocol.md`](../../cross-cutting/19-inter-component-protocol.md) — wire format
- [`../../cross-cutting/17-data-classification-privacy.md`](../../cross-cutting/17-data-classification-privacy.md) — data handling

## Component-specific context

Three layers: Policy (OPA Rego, evaluated via regorus crate), Decision Engine, Execution (vLLM/Triton/K8s/eBPF). <5s end-to-end. Government Compliance API stub for the AI Kill Switch Act (H.R. 9917). Wave-1 uses the mock I1 from proto/warrantor/identity/v1/agent.proto.

## Dependencies

- **Warrantor internal:** I1 (mock)
- **External:** enumerated during MVP (task 02); record in the RFC.

## Build entrypoint

See `tasks/01-setup.md`. The component lives under the language folder matching its primary
language (e.g. `rust/kill_switch/`, `python/kill_switch/`).

## Conventions

- Consume the contract plane (`proto/`, `specs/`, `testvectors/`); generate bindings, don't hand-write.
- OTel instrumentation on every RPC and long-running operation.
- CycloneDX SBOM in CI; SLSA L3 provenance.
- Sign commits with `git commit -s` (DCO).
- No second authoritative implementation of any security invariant (T1 owns those).

## Anti-patterns

See [`AGENTS.md`](AGENTS.md).

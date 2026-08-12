# CLAUDE.md — X1 defstack-cli build instructions

> Paste-target for Claude Code / Cursor / any coding agent building X1 defstack-cli.

## What you are building

**X1 defstack-cli** — Rust (clap). You are implementing [`docs/rfcs/X1-defstack-cli.md`](../X1-defstack-cli.md).
Read it first.

## Repo context (read before coding)

- [`../../00-reconciliation-matrix.md`](../../00-reconciliation-matrix.md) — component's place in the portfolio
- [`../../02-architecture.md`](../../02-architecture.md) — planes and invariants
- [`../../cross-cutting/18-developer-experience.md`](../../cross-cutting/18-developer-experience.md) — workflow, ≥85% coverage, DCO
- [`../../cross-cutting/19-inter-component-protocol.md`](../../cross-cutting/19-inter-component-protocol.md) — wire format
- [`../../cross-cutting/17-data-classification-privacy.md`](../../cross-cutting/17-data-classification-privacy.md) — data handling

## Component-specific context

The unified installer/orchestrator. Subcommands: install/verify/upgrade/compliance-report. Reads from a single ~/.aumos/config.yaml. Warrantor moved from Go/Cobra to Rust/clap per stack-test consolidation.

## Dependencies

- **Warrantor internal:** none
- **External:** enumerated during MVP (task 02); record in the RFC.

## Build entrypoint

See `tasks/01-setup.md`. The component lives under the language folder matching its primary
language (e.g. `rust/defstack_cli/`, `python/defstack_cli/`).

## Conventions

- Consume the contract plane (`proto/`, `specs/`, `testvectors/`); generate bindings, don't hand-write.
- OTel instrumentation on every RPC and long-running operation.
- CycloneDX SBOM in CI; SLSA L3 provenance.
- Sign commits with `git commit -s` (DCO).
- No second authoritative implementation of any security invariant (T1 owns those).

## Anti-patterns

See [`AGENTS.md`](AGENTS.md).

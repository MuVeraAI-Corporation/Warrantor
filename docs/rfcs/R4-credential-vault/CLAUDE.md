# CLAUDE.md — R4 credential-vault build instructions

> Paste-target for Claude Code / Cursor / any coding agent building R4 credential-vault.

## What you are building

**R4 credential-vault** — Rust. You are implementing [`docs/rfcs/R4-credential-vault.md`](../R4-credential-vault.md).
Read it first.

## Repo context (read before coding)

- [`../../00-reconciliation-matrix.md`](../../00-reconciliation-matrix.md) — component's place in the portfolio
- [`../../02-architecture.md`](../../02-architecture.md) — planes and invariants
- [`../../cross-cutting/18-developer-experience.md`](../../cross-cutting/18-developer-experience.md) — workflow, ≥85% coverage, DCO
- [`../../cross-cutting/19-inter-component-protocol.md`](../../cross-cutting/19-inter-component-protocol.md) — wire format
- [`../../cross-cutting/17-data-classification-privacy.md`](../../cross-cutting/17-data-classification-privacy.md) — data handling

## Component-specific context

Agent-scoped credential brokering. 15-min TTL scoped tokens bound to SPIFFE identity + task + IP. Integrates HashiCorp Vault, AWS Secrets Manager, K8s Secrets via trait CredentialBackend. Revokes all tokens <1s on kill-switch trigger. AumOS moved from Go to Rust.

## Dependencies

- **AumOS internal:** R3 (mock)
- **External:** enumerated during MVP (task 02); record in the RFC.

## Build entrypoint

See `tasks/01-setup.md`. The component lives under the language folder matching its primary
language (e.g. `rust/credential_vault/`, `python/credential_vault/`).

## Conventions

- Consume the contract plane (`proto/`, `specs/`, `testvectors/`); generate bindings, don't hand-write.
- OTel instrumentation on every RPC and long-running operation.
- CycloneDX SBOM in CI; SLSA L3 provenance.
- Sign commits with `git commit -s` (DCO).
- No second authoritative implementation of any security invariant (T1 owns those).

## Anti-patterns

See [`AGENTS.md`](AGENTS.md).

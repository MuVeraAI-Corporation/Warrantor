# PROMPT.md — R4 credential-vault master prompt

> Paste this entire file into Claude Code / Cursor / Codex to build R4 credential-vault from scratch.

---

You are implementing **R4 credential-vault** for AumOS. Language: Rust. Dependencies: R3 (mock).

## Component context

Agent-scoped credential brokering. 15-min TTL scoped tokens bound to SPIFFE identity + task + IP. Integrates HashiCorp Vault, AWS Secrets Manager, K8s Secrets via trait CredentialBackend. Revokes all tokens <1s on kill-switch trigger. AumOS moved from Go to Rust.

## Read first

1. `docs/rfcs/R4-credential-vault.md` — your spec.
2. `docs/rfcs/R4-credential-vault/CLAUDE.md` — build conventions.
3. `docs/rfcs/R4-credential-vault/AGENTS.md` — anti-patterns.
4. `docs/rfcs/R4-credential-vault/tasks/` — 8 sequenced tickets. **Work them in order.**
5. `docs/00-reconciliation-matrix.md` — where this component fits.
6. `docs/02-architecture.md` — planes and invariants that apply.

## Hard rules

- Consume the contract plane; generate bindings.
- Call T1 trust-core for any sign/verify operation (do not re-implement).
- Respect invariant I-09: failure is safe = fail closed.
- ≥85% coverage; zero clippy warnings; DCO on every commit.
- No second authoritative implementation of any security invariant.

## Exit gate (Definition of Done)

- All 8 task tickets closed.
- v1.0 tag cut and signed.
- CycloneDX SBOM attached; SLSA L3 provenance.
- `defstack install credential-vault` works.

Start with `tasks/01-setup.md`. Do not skip ahead.

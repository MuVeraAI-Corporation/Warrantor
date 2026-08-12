# PROMPT.md — X1 defstack-cli master prompt

> Paste this entire file into Claude Code / Cursor / Codex to build X1 defstack-cli from scratch.

---

You are implementing **X1 defstack-cli** for Warrantor. Language: Rust (clap). Dependencies: none.

## Component context

The unified installer/orchestrator. Subcommands: install/verify/upgrade/compliance-report. Reads from a single ~/.aumos/config.yaml. Warrantor moved from Go/Cobra to Rust/clap per stack-test consolidation.

## Read first

1. `docs/rfcs/X1-defstack-cli.md` — your spec.
2. `docs/rfcs/X1-defstack-cli/CLAUDE.md` — build conventions.
3. `docs/rfcs/X1-defstack-cli/AGENTS.md` — anti-patterns.
4. `docs/rfcs/X1-defstack-cli/tasks/` — 8 sequenced tickets. **Work them in order.**
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
- `defstack install defstack-cli` works.

Start with `tasks/01-setup.md`. Do not skip ahead.

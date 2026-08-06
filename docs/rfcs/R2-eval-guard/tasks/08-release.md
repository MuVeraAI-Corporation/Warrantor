# Task 08-release — R2 eval-guard

> **v1.0 tag signed, SBOM attached, SLSA L3, external review scheduled if security-critical**. Acceptance criteria below.

## Objective

v1.0 tag signed, SBOM attached, SLSA L3, external review scheduled if security-critical for R2 eval-guard.

## Steps

1. Implement per the RFC [`docs/rfcs/R2-eval-guard.md`](../../R2-eval-guard.md).
2. Follow conventions in [`CLAUDE.md`](../CLAUDE.md); avoid anti-patterns in [`AGENTS.md`](../AGENTS.md).
3. Add unit tests for every public surface.
4. Add at least one golden vector in `testvectors/R2/`.
5. Wire CI to run lint + test + conformance.
6. Update CHANGELOG.md.

## Acceptance criteria

- [ ] Feature implemented per the RFC.
- [ ] `cargo test` / `pytest` / `npm test` green (per language).
- [ ] Lint clean (`cargo clippy -D warnings` / `ruff` / `eslint`).
- [ ] Coverage ≥85% on new code.
- [ ] Golden vector present.
- [ ] CHANGELOG updated.
- [ ] Commit signed (`-s`).

## Out of scope

Anything listed in a later task. Do not skip ahead.

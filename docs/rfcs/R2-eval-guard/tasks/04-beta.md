# Task 04-beta — R2 eval-guard

> **All features, conformance green, perf targets measured**. Acceptance criteria below.

## Objective

All features, conformance green, perf targets measured for R2 eval-guard.

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

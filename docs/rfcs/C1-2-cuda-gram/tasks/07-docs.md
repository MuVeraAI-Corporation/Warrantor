# Task 07-docs — C1-2 cuda-gram

> **README, architecture notes, ADRs, RFC update with final status**. Acceptance criteria below.

## Objective

README, architecture notes, ADRs, RFC update with final status for C1-2 cuda-gram.

## Steps

1. Implement per the RFC [`docs/rfcs/C1-2-cuda-gram.md`](../../C1-2-cuda-gram.md).
2. Follow conventions in [`CLAUDE.md`](../CLAUDE.md); avoid anti-patterns in [`AGENTS.md`](../AGENTS.md).
3. Add unit tests for every public surface.
4. Add at least one golden vector in `testvectors/C1-2/`.
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

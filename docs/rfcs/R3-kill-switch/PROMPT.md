# PROMPT.md — R3 kill-switch master prompt

> Paste this entire file into Claude Code / Cursor / Codex to build R3 kill-switch from scratch.

---

You are implementing **R3 kill-switch** for AumOS. Language: Rust core + Python policy. Dependencies: I1 (mock).

## Component context

Three layers: Policy (OPA Rego, evaluated via regorus crate), Decision Engine, Execution (vLLM/Triton/K8s/eBPF). <5s end-to-end. Government Compliance API stub for the AI Kill Switch Act (H.R. 9917). Wave-1 uses the mock I1 from proto/warrantor/identity/v1/agent.proto.

## Read first

1. `docs/rfcs/R3-kill-switch.md` — your spec.
2. `docs/rfcs/R3-kill-switch/CLAUDE.md` — build conventions.
3. `docs/rfcs/R3-kill-switch/AGENTS.md` — anti-patterns.
4. `docs/rfcs/R3-kill-switch/tasks/` — 8 sequenced tickets. **Work them in order.**
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
- `defstack install kill-switch` works.

Start with `tasks/01-setup.md`. Do not skip ahead.

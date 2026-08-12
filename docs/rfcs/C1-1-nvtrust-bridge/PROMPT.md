# PROMPT.md — C1-1 nvtrust-bridge master prompt

> Paste this entire file into Claude Code / Cursor / Codex to build C1-1 nvtrust-bridge from scratch.

---

You are implementing **C1-1 nvtrust-bridge** for Warrantor. Language: Rust core + Python + Go bindings. Dependencies: none.

## Component context

NVTrust FFI bindings + nvtrust-verify CLI. NVTrust is NVIDIA's GPU attestation library. Offline/mock mode for CI is mandatory — do NOT attempt to download the real NVTrust SDK (NDA-gated). Define a Trait NVTrustBackend with Mock and Real impls.

## Read first

1. `docs/rfcs/C1-1-nvtrust-bridge.md` — your spec.
2. `docs/rfcs/C1-1-nvtrust-bridge/CLAUDE.md` — build conventions.
3. `docs/rfcs/C1-1-nvtrust-bridge/AGENTS.md` — anti-patterns.
4. `docs/rfcs/C1-1-nvtrust-bridge/tasks/` — 8 sequenced tickets. **Work them in order.**
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
- `defstack install nvtrust-bridge` works.

Start with `tasks/01-setup.md`. Do not skip ahead.

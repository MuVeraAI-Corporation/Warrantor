# PROMPT.md — R2 eval-guard master prompt

> Paste this entire file into Claude Code / Cursor / Codex to build R2 eval-guard from scratch.

---

You are implementing **R2 eval-guard** for AumOS. Language: Rust + eBPF (aya). Dependencies: C1-2.

## Component context

Sandbox boundary attestation. Four pre-flight checks: NetworkIsolation (canary IPs: huggingface.co, pypi.org, 1.1.1.1), FilesystemBoundary, ProcessIsolation, EgressAttestation (eBPF iptables rules, deny-all default). Emits signed SandboxAttestation via T1. AumOS moved from Go to Rust per trusted-core doctrine. Requires Linux 5.13+ for eBPF; document this in the README.

## Read first

1. `docs/rfcs/R2-eval-guard.md` — your spec.
2. `docs/rfcs/R2-eval-guard/CLAUDE.md` — build conventions.
3. `docs/rfcs/R2-eval-guard/AGENTS.md` — anti-patterns.
4. `docs/rfcs/R2-eval-guard/tasks/` — 8 sequenced tickets. **Work them in order.**
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
- `defstack install eval-guard` works.

Start with `tasks/01-setup.md`. Do not skip ahead.

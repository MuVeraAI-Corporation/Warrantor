# C3 — `specialist-corpora` RFC

> Per-plane specialist corpora (build-catalogue **C-3**, Domain C, loop L1): repeat the winning domain-corpus
> recipe across the enforcement planes, each corpus gated independently and every refusal recorded as
> negative evidence — no plane ships an ungated model.

| Field | Value |
|---|---|
| **Canonical ID** | C3 (catalogue C-3) |
| **Name** | specialist-corpora |
| **Wave** | 1 (model intelligence) |
| **Languages** | Rust |
| **Catalogue item** | C-3 |
| **Dependencies** | `rust/training-extractor` (C-2) builds the corpora; `rust/promotion-pipeline` (C-1) gates them |

## Background

The flywheel's proven path is *domain corpora*, not general fine-tunes (the general-corpus recipe went
0-for-3 and is an anti-goal). C-3 scales that proven path plane by plane — egress classification, retrieval
poisoning, semantic scope, cost prediction, CIB graph patterns — but the discipline that makes it safe is
that each plane's model must clear its own parity gate, and a refusal is recorded, not hidden. This crate
models the corpus/gate bookkeeping so "did every plane get gated, and what happened" is answerable from the
record.

## Goals and Non-Goals

**Goals:**
- A [`PlaneCorpus`](rust/specialist-corpora/src/lib.rs): a plane's corpus digest and its [`GateOutcome`](rust/specialist-corpora/src/lib.rs) — `Promoted` or `Refused { floor_failed }`.
- [`all_gated`](rust/specialist-corpora/src/lib.rs) asserts no corpus is ungated; [`ungated_planes`](rust/specialist-corpora/src/lib.rs) lists the offenders; [`promotion_report`](rust/specialist-corpora/src/lib.rs)
  summarizes each plane's fate.

**Non-Goals:**
- Training or evaluating (the `ml/` pipeline); deciding parity floors.
- Hiding refusals — a `Refused` outcome is first-class evidence.

## Detailed Design

`gate` attaches an outcome to a corpus. `all_gated` is true only when every corpus has `Some(outcome)`.
`promotion_report` maps each plane to "promoted", "refused:<floor>", or "ungated". `corpora_digest` hashes
the whole set's state for the run record, so gating changes the digest.

## Threat Boundary

The adversary is a plane shipping a model that never cleared its gate — the exact failure the parity gate
exists to prevent, multiplied across planes. `all_gated` makes an ungated plane a visible, assertable
violation, and recording refusals with their failed floor preserves the negative evidence that keeps the
programme honest. The crate trusts the supplied gate verdicts (the gate computes them); it enforces only the
bookkeeping.

## API

Library: `warrantor_specialist_corpora::{GateOutcome, PlaneCorpus, gate, all_gated, ungated_planes,
promotion_report, corpora_digest}`.

## Testing

8 unit tests: fresh corpora are ungated; gating all satisfies the rule; a refusal records its floor; the
report summarizes each plane; one ungated plane blocks the rule; the corpora digest is deterministic and
changes after gating; an empty set is trivially gated.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-3.
- Intake: `rust/training-extractor` (C-2); gate: `rust/promotion-pipeline` (C-1).
- Planes: W5 egress, W7 retrieval, W8 computer-use, W9 spend, W12 CIB.

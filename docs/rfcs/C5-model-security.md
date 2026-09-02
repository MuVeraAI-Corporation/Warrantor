# C5 — `model-security` RFC

> The model-security plane (build-catalogue **C-5**, Domain C, loop L1): defenses for the flywheel's own
> attack surface — exposure control via rate/cost-scoped guard-model warrants, and poisoning resistance via
> corpus-level integrity (manifest digests, source pins).

| Field | Value |
|---|---|
| **Canonical ID** | C5 (catalogue C-5) |
| **Name** | model-security |
| **Wave** | 2 (model intelligence) |
| **Languages** | Rust |
| **Catalogue item** | C-5 |
| **Dependencies** | `rust/spend` (W9 prices token spend; guards get budgets too) |

## Background

The critical-gaps analysis named the flywheel's own attack surface: a model that is the moat is also a
target — for extraction (query it until you can imitate it) and for poisoning (corrupt its training data).
Both defenses are economic and cryptographic rather than clever: extraction is bounded by a spend budget that
makes bulk querying visible and receipted, and poisoning is caught by pinning every corpus source to a digest
so any change is a mismatch.

## Goals and Non-Goals

**Goals:**
- [`ExtractionBudget`](rust/model-security/src/lib.rs): a sliding-window rate budget; [`authorize`](ExtractionBudget::authorize) admits queries until the limit, then
  throttles with a retry-after.
- [`CorpusManifest`](rust/model-security/src/lib.rs): pins each source to a digest; [`detect_poison`](rust/model-security/src/lib.rs) returns sources whose observed digest
  differs from the pin (changed or missing).

**Non-Goals:**
- Running the guard model or pricing tokens (the spend engine and gate do).
- Deciding which sources are trusted — the manifest's pins are the source of truth.

## Detailed Design

`authorize` rolls the window when `now >= start + window`, resetting the count; it admits while `used <
limit` (incrementing) and otherwise returns `Throttled { retry_after_ms }`. `detect_poison` compares each
pinned source's observed digest, flagging mismatches and missing sources, sorted.

## Threat Boundary

The adversary is an extraction bot (bounded by the budget, which makes bulk querying economically visible and
receipted) and a poisoning attacker (caught by source-pin mismatch before the gate ever sees the corpus). The
crate trusts the supplied `now_ms` and the observed digests (the corpus builder computes them); it enforces
the budget and the integrity comparison, not the model itself.

## API

Library: `warrantor_model_security::{ExtractionDecision, ExtractionBudget, CorpusManifest, detect_poison}`.
`ExtractionBudget::{new, authorize}`; `CorpusManifest::{new, pin, pin_of, len, is_empty}`.

## Testing

11 unit tests: the budget admits until the limit then throttles; the window rolls and resets; throttle
reports retry-after; a zero limit throttles immediately; a clean corpus has no poison; a changed or missing
source is poison; multiple poisoned sources are all flagged sorted; pin lookup and repin-overwrite; an empty
manifest detects nothing.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-5.
- Budgets priced by: `rust/spend` (W9); corpus integrity feeds: `rust/training-extractor` (C-2), C-3.
- Gate: `rust/promotion-pipeline` (C-1) refuses a poisoned corpus pre-gate.

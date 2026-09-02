# C8 — `eval-corpus` RFC

> The adversarial evaluation corpus as a governed artifact (build-catalogue **C-8**, Domain C, Wave 3,
> loop L1): labeled examples pinned by digest, fail-closed scoring, coverage-gap detection, a recall bar,
> and a hard re-gate budget encoding the exhaustion lesson.

| Field | Value |
|---|---|
| **Canonical ID** | C8 (catalogue C-8) |
| **Name** | eval-corpus |
| **Wave** | 3 (model-intelligence plane) |
| **Languages** | Rust |
| **Catalogue item** | C-8 |
| **Dependencies** | C-4 (dataset format); supplies the measurement C-7's graduation bar consumes |

## Background

The guard's graduation bar (C-7) is only as honest as the corpus that measures it. The re-gate impossibility
proved WildGuardMix is exhausted — once a model has been tuned against a corpus, scoring the next candidate
on the *same* corpus measures memorization, not capability, and a bar cleared that way is a fiction. C-8
makes the eval corpus a governed object with a budget: it can gate a bounded number of promotions, after
which it is spent and the successor corpus (HarmBench-class) is *forced*, not optionally reached for. It also
scores fail-closed: a harmful example the model was never run against is a miss, not a silent exclusion from
the denominator — the way eval inflation actually happens.

## Goals and Non-Goals

**Goals:**
- An [`EvalCorpus`](rust/eval-corpus/src/lib.rs) holds [`AdversarialExample`](rust/eval-corpus/src/lib.rs)s
  (id, prompt digest, [`Label`](rust/eval-corpus/src/lib.rs)) plus a gate budget and a content digest.
- [`score`](rust/eval-corpus/src/lib.rs) computes a [`Score`](rust/eval-corpus/src/lib.rs) (recall, precision,
  confusion counts) treating a missing prediction as a miss on harmful examples.
- [`coverage_gaps`](rust/eval-corpus/src/lib.rs) lists unevaluated ids; [`meets_recall_bar`](rust/eval-corpus/src/lib.rs)
  applies the bar.
- [`can_gate`](rust/eval-corpus/src/lib.rs) / [`record_gate`](rust/eval-corpus/src/lib.rs) enforce the exhaustion budget.

**Non-Goals:**
- Running a model or producing predictions — the caller supplies them; C-8 scores and governs.
- Setting the bar's value (that is C-7's policy) — it applies whatever bar is passed in.
- Signing the corpus (the digest is a content fingerprint); reading a clock or store.

## Detailed Design

[`score`](rust/eval-corpus/src/lib.rs) iterates the corpus's examples and looks each id up in the supplied
predictions map; a harmful example with no entry is scored as flagged-false, i.e. a false negative — the
fail-closed choice that refuses to let an incomplete evaluation inflate recall. `recall = TP/(TP+FN)` (1.0
when there are no harmful examples), `precision = TP/(TP+FP)` (1.0 when nothing was flagged).
[`coverage_gaps`](rust/eval-corpus/src/lib.rs) surfaces the unevaluated ids separately so an operator can
tell "the model missed" from "the model was never asked."

The exhaustion budget lives in `gates_used` / `gate_limit`. Because `gates_used` is operational state, it is
*excluded* from the content digest — [`record_gate`](rust/eval-corpus/src/lib.rs) increments it without
invalidating [`verify_corpus`](rust/eval-corpus/src/lib.rs). Once `gates_used == gate_limit` (or the corpus is
empty), [`can_gate`](rust/eval-corpus/src/lib.rs) is false and the corpus cannot gate another promotion.

## Threat Boundary

The adversary is an inflated or reused evaluation: an incomplete run scored as if complete (caught by
fail-closed scoring and `coverage_gaps`), a tampered corpus (caught by the digest), or re-gating a new model
on an exhausted corpus (caught by the budget). The crate trusts the caller's predictions as genuine model
outputs — it governs *how* a corpus may be scored and reused, not whether a prediction was honestly produced.

## API

Library: `warrantor_eval_corpus::{Label, AdversarialExample, EvalCorpus, Score, corpus_digest, verify_corpus,
score, coverage_gaps, meets_recall_bar, can_gate, record_gate}`. `AdversarialExample::new`; `EvalCorpus::new`.

## Testing

14 unit tests: example digests are sha256-prefixed; the corpus verifies untouched and fails on tampering;
`gates_used` does not break the digest; a perfect score has full recall and precision; a missing prediction
counts as a miss (recall 0.5); coverage gaps list unevaluated ids; the recall bar applies the threshold; an
empty corpus has recall 1.0; the gate budget enforces exhaustion and an empty corpus cannot gate; a false
positive lowers precision; the corpus round-trips through JSON; `Label` serializes snake_case; scoring is
deterministic.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-8.
- Supplies the measurement to: `rust/guard-graduation` (C-7 bar); stored in `rust/dataset-format` (C-4).
- Distinct from: `rust/specialist-corpora` (C-3, training corpora) and `rust/harness-floor` (M10, policy floor).

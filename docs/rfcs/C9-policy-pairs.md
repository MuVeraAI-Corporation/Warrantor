# C9 — `policy-pairs` RFC

> The policy-compilation dataset (build-catalogue **C-9**, Domain C, loop L1): the named missing dataset —
> no NL→Cedar/Rego pairs exist — teacher-generated pairs validated through the simulator, a human-reviewed
> gold slice, and the compiler model gated on pair accuracy + simulation equivalence.

| Field | Value |
|---|---|
| **Canonical ID** | C9 (catalogue C-9) |
| **Name** | policy-pairs |
| **Wave** | 2 (model intelligence) |
| **Languages** | Rust |
| **Catalogue item** | C-9 |
| **Dependencies** | `rust/authority-simulator` (A-11) supplies `simulated_equivalent`; A-1 consumes the dataset |

## Background

A-1 (the policy compiler) needs training data that does not exist anywhere: natural-language intent paired
with a correct compiled policy. C-9 is how that dataset is built *safely* — not by trusting the teacher
model's output, but by checking each pair against the authority simulator (A-11): if the compiled policy does
not reproduce the described bind/refuse behavior under simulation, the pair is not valid, no matter how
plausible it looks. The gold slice anchors human judgment; the gate is accuracy + equivalence.

## Goals and Non-Goals

**Goals:**
- A [`PolicyPair`](rust/policy-pairs/src/lib.rs): NL intent, compiled policy, `simulated_equivalent`, `gold_reviewed`.
- [`assess`](rust/policy-pairs/src/lib.rs): a [`DatasetQuality`](rust/policy-pairs/src/lib.rs) summary (total, valid, gold, accuracy).
- [`gate_passes`](rust/policy-pairs/src/lib.rs): the compiler may promote only if every pair is simulated-equivalent, accuracy meets the floor, and
  enough pairs are gold-reviewed.

**Non-Goals:**
- Generating pairs or running the simulator (A-11 supplies equivalence).
- Replacing human review — the gold slice is exactly that.

## Detailed Design

A pair `is_valid` iff `simulated_equivalent`. `assess` counts valid and gold-reviewed pairs and computes
accuracy as `valid/total × 100` (0 when empty). `gate_passes` requires `valid == total` (no invalid pair in
the training set), `accuracy >= floor`, and `gold_reviewed >= min_gold` — so a single non-equivalent pair
fails the gate regardless of the average.

## Threat Boundary

The adversary is a compiler trained on plausible-but-wrong pairs — a teacher model that produces a policy
that *looks* right but doesn't reproduce the described behavior. Simulator-equivalence validation catches it
pair by pair, and the all-valid gate requirement means one bad pair blocks promotion. The crate trusts the
supplied `simulated_equivalent` (A-11's verdict) and the gold-review flags; it enforces the dataset gate.

## API

Library: `warrantor_policy_pairs::{PolicyPair, DatasetQuality, assess, gate_passes}`. `PolicyPair::is_valid`.

## Testing

10 unit tests: validity is simulation equivalence; assess counts valid and gold; an empty dataset has zero
accuracy; the gate passes on a fully-equivalent reviewed set and fails with any invalid pair, without enough
gold review, or below the accuracy floor; a perfect dataset is 100%; gold count tracks reviewed pairs; zero
floors pass an empty set.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-9.
- Validated by: `rust/authority-simulator` (A-11); consumed by: A-1 policy compiler.
- Feeds: `rust/training-extractor` (C-2) corpora; gated by `rust/promotion-pipeline` (C-1).

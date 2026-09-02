# C2 — `training-extractor` RFC

> The receipt-graph → training-set extractor (build-catalogue **C-2**, Domain C, Wave 1, loop L1): the
> flywheel's intake valve. Pulls signed verdict history and emits a candidate fine-tuning corpus with
> leakage controls and privacy tiers, so a day of platform operation becomes a day of training data at
> command speed — and the corpus never needs to leave the deployment.

| Field | Value |
|---|---|
| **Canonical ID** | C2 (catalogue C-2) |
| **Name** | training-extractor |
| **Wave** | 1 (model intelligence) |
| **Languages** | Rust |
| **Catalogue item** | C-2 |
| **Dependencies** | none (operates on verdict records the archive already validated) |

## Background

The ledger is explicit that the flywheel is manual: *"promotion is a human-run ceremony; per-plane
specialist corpora don't exist; the receipt graph isn't yet flowing automatically into training."* The
receipt graph is the platform's moat — first-party data no one else has — but a moat you can't draw from
automatically is just a lake. C-2 is the intake valve: `warrantor_ml extract --plane W10 --since …`
converts verdict history into a corpus in one command.

Two properties make this safe in regulated deployments, and both are built in rather than bolted on.
**Leakage control** excludes eval hold-out digests from the training corpus, so a fine-tune can never be
scored on data it trained on — the parity gate's fingerprint stays honest, which is the whole reason the
gate's promotions mean anything. **Privacy tiering** includes raw payload only under an explicit opt-in;
digests and labels are always present, so a corpus can be assembled (and even moved) without exposing the
underlying content.

## Goals and Non-Goals

**Goals:**
- [`extract`](rust/training-extractor/src/lib.rs) filters [`VerdictRecord`](rust/training-extractor/src/lib.rs)s by plane and time, drops any whose input digest is in the [`HoldoutSet`](rust/training-extractor/src/lib.rs), and
  projects survivors to a [`TrainingExample`](rust/training-extractor/src/lib.rs) at the requested [`PrivacyTier`](rust/training-extractor/src/lib.rs).
- Preserve **label integrity at every tier** — the training target is always present; only metadata and
  payload are gated.
- Emit a [`TrainingCorpus`](rust/training-extractor/src/lib.rs) with a sorted **leakage fingerprint** (the input digests it contains) and a content digest.
- [`assert_no_collision`](rust/training-extractor/src/lib.rs) confirms the corpus and hold-out set are disjoint — the gate's "zero train/eval collision."

**Non-Goals:**
- Training or evaluating — the `ml/` pipeline consumes the corpus; this crate only builds it.
- Verifying signatures — it operates on already-validated verdict records.
- Deciding the privacy policy — the caller picks the tier; the extractor enforces that lower tiers never
  leak payload.

## Detailed Design

[`PrivacyTier`](rust/training-extractor/src/lib.rs) is ordered `DigestsOnly < Metadata < FullPayload`. Projection is monotone in revelation: `DigestsOnly` carries `input_digest` + `label`; `Metadata` adds `plane` + `at_ms`; `FullPayload` adds the raw `payload`. Because the comparison is `tier >= X`, a lower tier can never accidentally include a higher tier's field.

`extract` walks records, skips non-matching plane/time, and **before** projecting checks the hold-out set:
a record whose `input_digest` is held out is counted in `excluded_holdout_count` and dropped — so the
corpus is leakage-free by construction, not by a later filter. The `leakage_fingerprint` is the sorted set
of included input digests; `assert_no_collision` intersects it against the hold-out set. The corpus digest
is `sha256:` over the canonical JSON of `(plane, tier, examples, excluded_count, fingerprint)`.

## Threat Boundary

Two adversaries shape this design. The first is **accidental self-deception**: a fine-tune that scores
well because it memorized the eval set. Hold-out exclusion by digest — the same identity the parity gate
fingerprints — closes it, and `assert_no_collision` makes the property checkable. The second is **privacy
over-disclosure**: a corpus that carries regulated payload when it didn't need to. The tier ladder makes
the safe default (digests + labels) the floor and payload an explicit opt-in, so a corpus built for a
regulated plane can be shipped or shared without exposing content. The crate trusts its input records to
be the archive's validated verdicts; it does not re-verify signatures, and it takes `since_ms` from the
caller so it is deterministic.

## API

Library: `warrantor_training_extractor::{PrivacyTier, VerdictRecord, HoldoutSet, ExtractRequest,
TrainingExample, TrainingCorpus, extract, assert_no_collision}`. `HoldoutSet::{new, insert, contains, len,
is_empty}`.

## Testing

14 unit tests: extraction filters by plane and by `since`; the hold-out set excludes eval inputs and is
counted; `DigestsOnly` hides payload and metadata but retains the label; `Metadata` adds plane/time but
not payload; `FullPayload` includes payload; the tier ordering gates revelation; the leakage fingerprint is
the sorted input digests; collision is detected when a hold-out overlaps a corpus built without exclusion;
an empty match yields an empty corpus; the corpus digest is deterministic and distinguishes privacy tiers;
the hold-out set tracks membership; multiple collisions are all excluded and counted.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-2; §17.2 flywheel chain head.
- Feeds: `ml/` / `warrantor_ml` (the parity gate and promotion pipeline); C-1 (continuous promotion), C-3
  (per-plane corpora), C-9 (policy-pairs dataset) all consume this intake.
- Source of records: `rust/archive` (signed verdict history), `rust/evidence` / `rust/flight-recorder`.
- Leakage control mirrors: the parity gate's hold-out fingerprint (the mechanism this reuses).

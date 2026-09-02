# C4 — `dataset-format` RFC

> The canonical dataset format as a verifiable data structure (build-catalogue **C-4**, Domain C, Wave 2,
> loop L1): split-tagged records pinned by content digest, a manifest digest over the corpus, structural
> hold-out leakage detection, split accounting, and provenance source-pins.

| Field | Value |
|---|---|
| **Canonical ID** | C4 (catalogue C-4) |
| **Name** | dataset-format |
| **Wave** | 2 (model-intelligence plane) |
| **Languages** | Rust |
| **Catalogue item** | C-4 |
| **Dependencies** | none (a format); consumed by C-2 intake, C-1 promotion, C-3 corpora, C-8 eval |

## Background

C-2 (training-extractor) controls leakage *at intake* — it refuses to admit a hold-out example into a
training corpus. But intake is a process, and a process can be bypassed or a corpus assembled by hand. The
guarantee then lives in whoever ran the intake, not in the artifact. C-4 moves the guarantee into the file:
a dataset becomes a self-describing manifest whose integrity is a digest and whose leakage is a structural
defect the format itself reports. A downstream consumer — the promotion pipeline, a specialist-corpus gate,
an eval harness — can verify provenance and leakage-freeness from the manifest alone, without trusting
whoever built it. This is the difference between "we promise we held out the test set" and "the format
proves it."

## Goals and Non-Goals

**Goals:**
- A [`Record`](rust/dataset-format/src/lib.rs) is a `(record_id, content_digest, split)` triple; a
  [`DatasetManifest`](rust/dataset-format/src/lib.rs) collects records plus [`SourcePin`](rust/dataset-format/src/lib.rs)
  provenance and a `sha256:` digest over its own content.
- [`verify_manifest`](rust/dataset-format/src/lib.rs) recomputes the digest (tamper detection).
- [`leakage`](rust/dataset-format/src/lib.rs) and [`holdout_leakage`](rust/dataset-format/src/lib.rs) report
  record ids appearing in more than one split — the latter the critical train↔holdout case.
- [`counts`](rust/dataset-format/src/lib.rs), [`is_well_formed`](rust/dataset-format/src/lib.rs), and
  [`provenance_complete`](rust/dataset-format/src/lib.rs) give accounting and structural checks.

**Non-Goals:**
- Storing payloads — a record carries the *digest* of its content, so the manifest stays small and shareable.
- Signing the manifest — the digest is a content fingerprint; signing is the notary's concern.
- Reading files or a clock — pure verification over caller-supplied data.

## Detailed Design

A [`Split`](rust/dataset-format/src/lib.rs) is `Train | Val | Test | Holdout` (ordered). The leakage key is
the `record_id`: [`leakage`](rust/dataset-format/src/lib.rs) groups records by id and reports any id whose
split set has more than one member; [`holdout_leakage`](rust/dataset-format/src/lib.rs) intersects the
holdout id-set with the non-holdout id-set — the defect that silently inflates eval scores. An empty result
from both is the leakage-free guarantee, computable from the file.

The manifest digest is computed over the canonical JSON of the content fields (name, version, schema,
license, records, source-pins), excluding the digest field itself, so [`verify_manifest`](rust/dataset-format/src/lib.rs)
detects any edit. [`is_well_formed`](rust/dataset-format/src/lib.rs) rejects a malformed record digest or a
record id repeated within a single split; [`provenance_complete`](rust/dataset-format/src/lib.rs) requires at
least one well-formed source pin.

## Threat Boundary

The adversary is a dataset that misrepresents itself: a tampered manifest (caught by the digest), a hold-out
example that also appears in training (caught by `holdout_leakage`), a corpus with no provenance (caught by
`provenance_complete`), or a duplicate record smuggled into one split (caught by `is_well_formed`). The crate
trusts the caller's record digests as measured — it verifies the *structure* and *self-consistency* of the
manifest, not that a given content digest matches some external payload it never sees.

## API

Library: `warrantor_dataset_format::{Split, Record, SourcePin, DatasetManifest, content_digest(private),
manifest_digest, verify_manifest, leakage, holdout_leakage, counts, is_well_formed, provenance_complete}`.
`Record::new`; `DatasetManifest::new`.

## Testing

14 unit tests: record digests are sha256-prefixed; the manifest verifies untouched and fails on tampering;
`leakage` flags an id in two splits; `holdout_leakage` flags a train↔holdout overlap; a clean dataset has
neither; `counts` partitions by split; well-formedness rejects a malformed digest and a same-split duplicate;
provenance requires a pin and rejects a malformed one; the empty dataset is well-formed and verifies; the
manifest round-trips through JSON; `Split` orders and serializes snake_case.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-4.
- Consumed by: `rust/training-extractor` (C-2 intake), `rust/promotion-pipeline` (C-1), `rust/specialist-corpora`
  (C-3), `rust/eval-corpus` (C-8).
- Flywheel chain: C-2 → C-1 → C-3 → C-7; C-4 is the format the corpora are stored in.

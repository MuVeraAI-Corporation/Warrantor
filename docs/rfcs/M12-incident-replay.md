# M12 — `incident-replay` RFC

> Investigation-grade evidence as a native property: reconstruct any agent's action history as a
> *query*, and export scoped, verifiable, privacy-preserving evidence packs for external investigators.
> Derived from the OpenAI–Hugging Face incident, where the investigation that should have taken minutes
> took METR six on-premises days, ~$400K in API credits, 1,300 transcripts, and AI-assisted analysis of
> 1.2 million event entries.

| Field | Value |
|---|---|
| **Canonical ID** | M12 |
| **Name** | incident-replay |
| **Wave** | 2 (governance) |
| **Languages** | Rust |
| **Incident requirement** | R12 |
| **Catalogue item** | M-12 |
| **Dependencies** | none (operates on a receipt slice the host supplies from the durable log) |

## Background

The incident report states the bar plainly: *"reconstructing any incident should be a query, not a
research program."* The evidence substrate already makes that possible — every consequential action is a
signed, hash-chained receipt written below agent reach (`rust/flight-recorder`, `rust/evidence`), and the
report's own L7 layer is *"signed receipts for every consequential action ... replayable. The agent may
lie; the substrate cannot."* What the substrate lacks is the investigation layer on top of it: the replay
query that projects a causal timeline, and the productized export that gives an independent auditor —
METR's model, which several commentators want to become standard practice — a bundle they can verify
without being handed the raw private content.

METR's six-day, $400K, 1.2M-entry effort is the cost of *not* having this layer. This crate makes the
same reconstruction a function call and a signed bundle.

## Goals and Non-Goals

**Goals:**
- [`replay`](rust/incident-replay/src/lib.rs): filter a set of [`Receipt`](rust/incident-replay/src/lib.rs)s by [`ReplayQuery`](rust/incident-replay/src/lib.rs) (agents, time window), order by time, and project to a
  [`ReplayTimeline`](rust/incident-replay/src/lib.rs) of who / what / authority / path / evidence — the
  reconstruction, with a content digest.
- [`build_pack`](rust/incident-replay/src/lib.rs): produce an [`EvidencePack`](rust/incident-replay/src/lib.rs) for an external investigator — receipts inside a [`PackScope`](rust/incident-replay/src/lib.rs), private fields
  redacted, each reduced to a leaf digest and bound by a Merkle root.
- [`verify_pack`](rust/incident-replay/src/lib.rs): let the auditor confirm the bundle is internally consistent — the Merkle root
  recomputes and the receipts are ordered — without seeing the redacted content.
- Preserve verifiability through redaction: signatures and evidence digests stay in the pack; only named
  private field *values* are replaced with [`REDACTED`](rust/incident-replay/src/lib.rs).

**Non-Goals:**
- Verifying issuer signatures — the pack carries them opaquely; the auditor checks them against the
  issuer's key. This crate proves *integrity and membership*, not authorship.
- Storing or fetching receipts — the host supplies the slice from the durable log.
- Deciding what is private — the [`PackScope::redact_fields`](rust/incident-replay/src/lib.rs) list and each receipt's [`Receipt::pii`](rust/incident-replay/src/lib.rs) do.
- Signing the pack — the digests are content fingerprints the host records in the audit chain.

## Detailed Design

A [`Receipt`](rust/incident-replay/src/lib.rs) is the investigation projection of a substrate record:
`seq`, `agent_id`, `action`, `authority`, `path`, `evidence_digest`, `at_ms`, an opaque `signature`, a
`pii` field-name list, and a `BTreeMap` of raw `fields`. `BTreeMap` (not `HashMap`) is deliberate — it
makes the canonical JSON, and therefore every digest, deterministic.

`replay` filters by the inclusive time window and, when `agents` is `Some`, by membership in that set; it
sorts by `(at_ms, seq)` and maps each receipt to a [`ReplayEvent`](rust/incident-replay/src/lib.rs) that
drops the signature and raw fields — the timeline is the *what-happened* view, not the evidence bundle.

`build_pack` selects receipts the same way, then for each copies the fields and replaces the value of every
key in `pii ∪ redact_fields` with `REDACTED`, producing a [`RedactedReceipt`](rust/incident-replay/src/lib.rs) that keeps `signature` and `evidence_digest`. Each redacted receipt's `leaf_digest` is the
`sha256:` of its canonical JSON; the pack's `merkle_root` folds those leaves pairwise (an odd trailing
node pairs with itself), so membership of any receipt is provable and any tampering changes the root.
`verify_pack` recomputes the root from the pack's own receipts and checks it matches, plus the ordering
invariant.

## Threat Boundary

The adversary this layer serves is the *investigation itself*: after §7's finding that ~7% of transcripts
were spoofed and that tampering "may, by design, not have been detectable from the transcript at all,"
the evidence an auditor receives must be verifiable independently of the party that produced it. The
Merkle root gives an external investigator a single value to check against the substrate's anchored chain,
so a pack that has been edited, reordered, or have receipts silently dropped fails `verify_pack`. Redaction
is the reciprocal concern — the auditor needs the *structure* of what happened, not the users' private
content — so the export hides values while preserving the digests and signatures that make the structure
checkable. The crate trusts its input slice to be the durable log's contents; it does not, and cannot,
re-derive signatures it was not given.

## API

Library: `warrantor_incident_replay::{Receipt, ReplayQuery, ReplayEvent, ReplayTimeline, PackScope,
RedactedReceipt, EvidencePack, REDACTED, replay, build_pack, verify_pack}`.
`RedactedReceipt::leaf_digest`.

## Testing

18 unit tests: replay orders by time-then-seq, filters by agent and by time window, projects the
authority/path/evidence view, has a deterministic digest, and handles empty input; build_pack redacts named
PII fields while preserving signature and evidence digest, honors extra scope redaction, filters by scope,
and is deterministic; verify_pack accepts a well-formed pack and rejects a tampered receipt or a reordered
one; the Merkle root changes with membership; an empty pack has a stable root and verifies; an odd leaf
count pairs the last node with itself; redaction survives a serialization roundtrip (the raw email never
appears in the JSON).

## Cross-references

- Incident analysis: `warrantor-incident-analysis-agent-collective-2026-09-01.html` §8, §13 R12, §14 M-12.
- Substrate it reads: `rust/flight-recorder` (signed AARs, hash-chained durable log), `rust/evidence`
  (signed pre_commit→post_commit envelopes).
- Redaction mechanism: `rust/data-plane` (erasure/redaction records).
- Transparency-log lineage: B-1 + B-9 (evidence packs) in the build catalogue — evidence must be below
  agent reach and externally verifiable.

# B10 — `proof-of-erasure` RFC

> Proof-of-erasure (build-catalogue **B-10**, Domain B, loop L4): when personal data is erased from receipts
> under a data-subject request, emit a signed attestation that payloads with given digests were destroyed,
> re-linking the graph through digest commitments so chain integrity survives erasure.

| Field | Value |
|---|---|
| **Canonical ID** | B10 (catalogue B-10) |
| **Name** | proof-of-erasure |
| **Wave** | 2 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-10 |
| **Dependencies** | `rust/data-plane` (DP1 tiered storage + erasure) — this is its evidence half |

## Background

GDPR erasure and an append-only, hash-chained evidence graph are in tension: you must destroy personal data,
but you must not break the chain that makes the graph trustworthy. The resolution is to destroy the *payload*
while retaining its *digest* as a commitment — the link survives, the content does not — and to record an
erasure proof so a data subject or regulator can verify the destruction happened without recovering the data.

## Goals and Non-Goals

**Goals:**
- [`erase`](rust/proof-of-erasure/src/lib.rs): null the payload of every [`Receipt`](rust/proof-of-erasure/src/lib.rs) for a subject, keep each digest as a commitment, and return an
  [`ErasureProof`](rust/proof-of-erasure/src/lib.rs) attesting which digests were destroyed.
- [`chain_intact`](rust/proof-of-erasure/src/lib.rs): every receipt still carries a digest (no orphaned references).
- [`verify_untouched`](rust/proof-of-erasure/src/lib.rs): a non-erased receipt's digest still recomputes from its payload.

**Non-Goals:**
- Deleting the digest — the commitment is what preserves the chain and the "data existed" proof.
- Recovering erased payloads (that is the point).

## Detailed Design

A [`Receipt`](rust/proof-of-erasure/src/lib.rs) holds an optional payload and a `digest` computed over it at creation. `erase` walks the receipts, and for each
matching, not-yet-erased subject receipt, records its digest as destroyed and nulls the payload; the proof's
digest covers `(subject, sorted erased ids, sorted destroyed digests, at_ms)`. Erasing an unknown subject or
an already-erased receipt is a no-op (idempotent). `chain_intact` holds because digests are never removed;
`verify_untouched` returns false for an erased receipt (payload gone) and true otherwise.

## Threat Boundary

The adversary is a regulator or data subject who needs proof that erasure actually happened, and a chain
that must not break when it does. Retaining the digest commitment means the graph stays verifiable end to
end while the personal content is gone; the erasure proof is the attestation of destruction. The crate trusts
the host to actually delete the payload from storage (this models the evidence contract, not the disk
operation) and does not sign the proof.

## API

Library: `warrantor_proof_of_erasure::{Receipt, ErasureProof, erase, chain_intact, verify_untouched}`.

## Testing

11 unit tests: erase nulls the payload for a subject only; the digest commitment survives; the chain stays
intact after erasure; an untouched receipt verifies; an erased one does not recompute; the proof lists
destroyed digests; erasing an unknown subject is a no-op; double erase is idempotent; the proof digest is
deterministic and distinguishes subjects; a subject-less receipt is never erased.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-10.
- Extends: `rust/data-plane` (DP1 erasure/redaction), `rust/archive` (retention + tombstones).
- Enables: J-6 cross-border data mapping, the regulator portal's erasure attestations.

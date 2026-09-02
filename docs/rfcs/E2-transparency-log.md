# E2 — `transparency-log` RFC

> The transparency log (build-catalogue **B-1**, Domain B, Wave 1, loop L2): an append-only Merkle-tree
> log of receipt digests — the Certificate-Transparency / Sigstore-Rekor pattern — so anyone holding the
> published head can verify inclusion and consistency, converting "verify this receipt" from trusting the
> issuer's storage into trusting publicly auditable mathematics.

| Field | Value |
|---|---|
| **Canonical ID** | E2 (catalogue B-1) |
| **Name** | transparency-log |
| **Wave** | 1 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-1 |
| **Dependencies** | none (consumes receipt digests the archive/flight-recorder already produce) |

## Background

The current-state ledger names the ceiling exactly: the archive is shipped and self-hosted, but there is
*"no transparency log, no time anchoring, no cross-org verification, no federation. Trust radius = one
machine."* A receipt signed by an issuer is only as trustworthy as that issuer's storage — an issuer who
wants to quietly edit history can, and nothing outside the machine would notice.

The transparency log is the standard fix and the option §2.1's root-of-trust analysis wrote three choices
for that composes with all of them: it is *verification*, not a signing root, so it does not recreate the
centralized point of failure the platform exists to abolish (an explicit anti-goal). Every settled
receipt's digest is appended to a Merkle tree; the published head commits to the whole history; a receipt
once logged can never be un-logged without the inconsistency being third-party-detectable.

## Goals and Non-Goals

**Goals:**
- An append-only [`MerkleLog`](rust/transparency-log/src/lib.rs) over leaf hashes with fold-up inclusion
  proofs and a standalone [`verify_inclusion`](rust/transparency-log/src/lib.rs) that needs no log access.
- A [`TransparencyLog`](rust/transparency-log/src/lib.rs) that layers a leaf log (receipt digests) with a
  checkpoint log (the sequence of published heads), so each [`Head`](rust/transparency-log/src/lib.rs)
  commits to both the leaf-tree root and the checkpoint-tree root.
- [`inclusion`](rust/transparency-log/src/lib.rs): prove a receipt is in the log *as of a specific epoch*,
  binding to the historical root, not just the current head.
- [`consistency`](rust/transparency-log/src/lib.rs): prove an older head is a prefix of a newer one by
  showing the older head's commitment is included in the checkpoint tree at the newer head — a rewritten
  history changes the checkpoint tree and fails verification.
- Keep it pure and testable: digests are content fingerprints; signing and gossip/mirroring are the
  operator's job.

**Non-Goals:**
- Signing heads or running the gossip/mirror fan-out for multi-witness — the host signs the head.
- Storing receipts — only their digests are logged; the archive holds the bodies.
- Being a trust directory or a signing service — deliberately not, per the anti-goals.
- Time anchoring (B-2) and cross-org federation (B-5) — this log is the substrate they build on.

## Detailed Design

Leaves are domain-separated (RFC 6962 style): `leaf_hash(d) = sha256(0x00 || d)`,
`node_hash(l,r) = sha256(0x01 || l || r)`, empty tree = `sha256("")`. The tree is built pairwise with
**duplicate-last** (an odd node at a level pairs with itself), which makes every prefix a well-defined
subtree and reduces an inclusion proof to a fold: at each level take the pair partner as the sibling and
record whether it is left or right; verification folds the leaf up and compares to the root. Proof length
is `tree_levels(size) - 1`, i.e. logarithmic.

`TransparencyLog::append_receipt` hashes the receipt digest into the leaf log, computes the new leaf root,
derives a provisional head commitment from `(epoch, size, leaf_root)`, appends that commitment to the
checkpoint log, then finalizes the head with the checkpoint-tree root. The head's `digest` covers only the
leaf commitment, so its checkpoint-log leaf hash is stable regardless of when the checkpoint root is
folded in (no circular dependency).

`consistency(old, new)` returns the fold-up path of the old head's commitment within the checkpoint tree
truncated to `new.epoch + 1` leaves; `verify_consistency` checks that path folds the old head's leaf hash
to the new head's published `checkpoint_root`. Because the checkpoint tree is itself append-only, a
different history produces a different checkpoint root, so a forged or truncated log fails verification —
exercised directly by the `consistency_rejects_rewritten_history` test.

## Threat Boundary

The adversary is a log operator who wants to present different histories to different parties, or to
silently edit a past receipt. Append-only Merkle commitments plus third-party-verifiable consistency make
that detectable: any two heads the operator publishes must be consistent (one a prefix of the later), and
the check needs only the published heads and a proof, not the operator's cooperation. The log trusts its
own append-only discipline (there is no remove/modify API); a compromised host that mutates the in-memory
leaf vector out from under the API is outside this crate's boundary, which is why the head digest is a
fingerprint the operator signs and mirrors. Inclusion proofs bind to historical epochs so a receipt
verifiable at epoch *t* stays verifiable forever, which is the property auditors and counterparties need.

## API

Library: `warrantor_transparency_log::{leaf_hash, node_hash, empty_hash, tree_levels, ProofStep,
MerkleLog, verify_inclusion, Head, InclusionProof, ConsistencyProof, TransparencyLog,
verify_inclusion_proof, verify_consistency}`.

## Testing

20 unit tests: empty log commits to the empty hash; root is deterministic and grows with appends;
inclusion verifies for every index and fails for a wrong digest or a tampered root; inclusion binds to a
historical epoch and rejects an out-of-range index; proof length is logarithmic; consistency verifies
across epochs and first-to-last, is trivially true for the same epoch, rejects reversed epochs, rejects a
tampered old head, and **rejects a rewritten history** (a rebuilt log with a changed early receipt fails
the old head's consistency proof); append-only cannot shrink; the head digest is deterministic; single-leaf
and odd-size folds match the root; a third party verifies membership with no log access.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-1; §17.2 trust chain head.
- Substrate it logs: `rust/flight-recorder` (E1, signed AARs), `rust/evidence` (signed envelopes),
  `rust/archive` (SUP-15, the durable store whose digests are logged).
- Built on top: B-2 time anchoring, B-4 cross-org chains, B-5 federation, N15 regulator portal.
- Merkle convention shared with: `rust/incident-replay` (M12) evidence-pack Merkle root.

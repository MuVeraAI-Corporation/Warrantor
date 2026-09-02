# A3 — `quorum-warrants` RFC

> Quorum warrants (build-catalogue **A-3**, Domain A, loop L2): exercise requires t of n designated
> operator signatures — the two-person rule generalized and made programmable — emitting a combined receipt
> citing exactly the quorum that signed.

| Field | Value |
|---|---|
| **Canonical ID** | A3 (catalogue A-3) |
| **Name** | quorum-warrants |
| **Wave** | 3 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-3 |
| **Dependencies** | none (pairs with I-6 threshold signing for high-stakes issuers) |

## Background

The identity layer ships a two-person rule for one narrow case. A-3 makes quorum authority a programmable
property of any warrant: payouts, firewall opens, and model promotions can require a t-of-n set rather than
a single holder. It is the *decision* counterpart to I-6's threshold *key* — together they let a
systemically-important issuer require multiple humans (or multiple key shares) before a high-stakes action
settles.

## Goals and Non-Goals

**Goals:**
- A [`QuorumWarrant`](rust/quorum-warrants/src/lib.rs) naming its signers and a threshold.
- [`exercise`](rust/quorum-warrants/src/lib.rs) returns a [`QuorumReceipt`](rust/quorum-warrants/src/lib.rs) listing exactly the distinct authorized signers that met the quorum, or a
  [`QuorumDenial`](rust/quorum-warrants/src/lib.rs) — a non-signer, or too few valid approvals (with the count and threshold, so the refusal is legible).
- Duplicate approvals count once.

**Non-Goals:**
- Verifying the signatures — the settle flow presents already-authenticated approvals; this enforces the
  quorum policy.
- Splitting keys (I-6).

## Detailed Design

`exercise` builds the designated-signer set, then for each approval: a non-designated approver is an
immediate `NotASigner`; valid approvals accumulate into a `HashSet` (deduplicating). If the distinct count
is below the threshold, `InsufficientQuorum { gathered, threshold }`. Otherwise the sorted quorum is
emitted with a `sha256:` digest over `(warrant_id, quorum, action)`. Because the quorum is a set, t−1
distinct approvals (even with duplicates) refuse, and the receipt lists exactly who signed.

## Threat Boundary

The adversary is a single compromised operator unilaterally exercising a warrant that should need several.
The quorum check makes that impossible without colluding `t` signers, and the legible `InsufficientQuorum`
means a near-miss (t−1) is visibly refused rather than silently allowed. The crate trusts the presented
approvals to be authenticated (the settle flow's job); it enforces only the count and membership.

## API

Library: `warrantor_quorum_warrants::{QuorumWarrant, QuorumReceipt, QuorumDenial, exercise}`.

## Testing

11 unit tests: 2-of-3 exercises; 1-of-2 is insufficient with the count reported; a non-signer is refused;
duplicates count once; 3-of-3 exercises; the receipt lists exactly the quorum; the digest is deterministic
and distinguishes actions; a 1-of-1 quorum; empty approvals are insufficient; a threshold above the signer
count is never met.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-3.
- Pairs with: I-6 threshold issuance; `rust/root-of-trust` (I-1) threshold mode.
- Used by: `rust/credential-vault` payouts, `rust/kill-switch` high-stakes halts, E-9 payments.

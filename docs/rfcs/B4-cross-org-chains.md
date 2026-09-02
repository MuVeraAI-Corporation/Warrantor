# B4 — `cross-org-chains` RFC

> Cross-organizational receipt chains (build-catalogue **B-4**, Domain B, Wave 2, loop L2): receipts that
> reference other organizations' receipts — org A's warrant cites org B's receipt as a precondition, verified
> transitively across organizations without either exposing its internals. The moment the platform stops
> being a log and starts being a network.

| Field | Value |
|---|---|
| **Canonical ID** | B4 (catalogue B-4) |
| **Name** | cross-org-chains |
| **Wave** | 2 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-4 |
| **Dependencies** | `rust/delegation-chain` (A-2) intersection semantics; `rust/transparency-log` (B-1) common proof surface |

## Background

The FS stress-test named this as the missing piece for bank→processor→clearing-house flows: a payment
processor's KYC-agent receipt (verified) is cited by a bank's onboarding-agent warrant; the bank's agent
acts; its receipt cites the processor's by digest; an auditor replays the whole chain across both orgs from
digests alone. Internally the platform already chains receipts (delegation, A-2). B-4 extends the same
reference-by-digest discipline *across* trust boundaries, so inter-organizational trust rests on verifiable
evidence rather than contracts and phone calls — the highest-impact FS item after open banking.

## Goals and Non-Goals

**Goals:**
- Model an [`OrgReceipt`](rust/cross-org-chains/src/lib.rs) with a [`ReceiptState`](rust/cross-org-chains/src/lib.rs) (Verified / Revoked / Unknown) as reported by the issuing org's verifier.
- Model a [`CrossOrgReference`](rust/cross-org-chains/src/lib.rs): "the citing receipt depends on the cited receipt," possibly another org's.
- [`verify_chain`](rust/cross-org-chains/src/lib.rs): walk a root's dependency closure across the references and return [`ChainVerdict::Valid`](rust/cross-org-chains/src/lib.rs) only
  if every cited receipt is Verified; the first revoked or unknown citation yields [`ChainVerdict::Broken`](rust/cross-org-chains/src/lib.rs) — the gate's
  "org B revokes → org A's dependent step refuses."
- Keep it internals-free: a chain is digests and states only.

**Non-Goals:**
- Verifying signatures — it consumes receipt states the per-org verifiers and B-1 already established; it
  reasons about the cross-org *dependency graph*.
- Deciding what may cite what — the caller supplies the references.

## Detailed Design

`verify_chain` builds a citing→cited adjacency from the references and does an iterative DFS from the root,
tracking visited digests (so diamonds visit a node once and cycles terminate). At each node it checks
`state_of`: Verified continues; Revoked returns `Broken{Revoked}`; Unknown returns `Broken{Unknown}`. The
root itself is checked first, so a revoked root breaks immediately. `depth` reports the longest citation
path traversed. `revoke` flips a receipt's state, which is what makes a downstream dependent refuse on the
next verification.

## Threat Boundary

The adversary is a broken inter-org precondition: org A acting on the strength of an org B step that was
never verified, or was later revoked. Transitive closure verification means A's chain is only as good as the
weakest citation in it — a revoked clearing-house receipt breaks the bank's onboarding chain even though the
bank only directly cited the processor. Because the chain carries only digests and states, neither org
exposes internals to the other; trust flows through the B-1 proof surface, not through data sharing. The
verifier trusts the supplied receipt states (a lying org's verifier is outside this boundary — that is what
B-1's third-party-verifiable log and B-2's anchoring are for); it guarantees only that the *dependency
logic* is correct and fail-closed.

## API

Library: `warrantor_cross_org_chains::{ReceiptState, OrgReceipt, CrossOrgReference, ChainVerdict,
ChainFailure, ChainVerifier}`. `ChainVerifier::{new, add_receipt, revoke, state_of, verify_chain}`.

## Testing

11 unit tests: an all-verified bank→processor→clearing chain is valid with the right depth; a revoked deep
citation breaks the chain at the offending digest; an unknown citation breaks it; a revoked root breaks
immediately; a single receipt with no references is valid at depth 0; a diamond citation visits each node
once; a cycle terminates; `state_of` reports membership and unknown; revoke changes state; depth reports the
longest path; verification exposes no internals.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-4; §17.2 trust chain (B-1 → B-2 → B-4 → B-5).
- Semantics from: `rust/delegation-chain` (A-2); proof surface from: `rust/transparency-log` (B-1), `rust/time-anchoring` (B-2).
- Enables: B-5 receipt federation protocol, H-5 agent organizations, the open-banking (G2) consent chain.

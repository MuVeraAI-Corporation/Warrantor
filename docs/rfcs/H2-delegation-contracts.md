# H2 — `delegation-contracts` RFC

> Agent-to-agent delegation contracts (build-catalogue **H-2**, Domain H, Wave 3): the bilateral terms that
> ride on top of an A-2 warrant delegation, with an explicit state machine, fail-closed settlement against
> the budget, and a revocation-notice window.

| Field | Value |
|---|---|
| **Canonical ID** | H2 (catalogue H-2) |
| **Name** | delegation-contracts |
| **Wave** | 3 (agent plane) |
| **Languages** | Rust |
| **Catalogue item** | H-2 |
| **Dependencies** | A-2 (the warrant this delegation rides on); H-1 (identity of the parties) |

## Background

A-2 answers a narrow question: *may* this delegation be authorized (is the child scope a subset of the
parent's)? It deliberately says nothing about the *terms* of the arrangement — what it costs, when it ends,
how either side gets out, what the delegate is owed if work already started. Those are the terms that make
agent-to-agent delegation safe to actually transact, and leaving them to prose is where disputes are born.
H-2 is the commercial envelope: a digest-sealed contract with a budget, a deadline, and a notice period,
whose settlement is checked fail-closed against the budget and whose revocation protects a delegate who has
already begun.

## Goals and Non-Goals

**Goals:**
- A [`DelegationContract`](rust/delegation-contracts/src/lib.rs) binds a delegator, a delegate, a parent
  warrant, and [`ContractTerms`](rust/delegation-contracts/src/lib.rs) under a [`ContractState`](rust/delegation-contracts/src/lib.rs) machine.
- [`accept`](rust/delegation-contracts/src/lib.rs), [`settle`](rust/delegation-contracts/src/lib.rs), and
  [`revoke`](rust/delegation-contracts/src/lib.rs) move the contract along legal edges only — settlement over
  budget or after the deadline is refused, and revoking an accepted contract inside its notice window is
  refused — each emitting a digest-bound [`SettlementRecord`](rust/delegation-contracts/src/lib.rs) where relevant.

**Non-Goals:**
- Computing authority — whether the delegated *scope* is legal is A-2's intersection test; H-2 carries the
  `parent_warrant_id` as a reference and governs the terms.
- Moving money — settlement is a recorded, digest-bound claim the ledger acts on.
- Reading a wall clock (every transition takes `now_ms`); signing (digests are content fingerprints).

## Detailed Design

The lifecycle is a small state machine — `Offered → Accepted → Settled`, with `Offered/Accepted → Revoked`
and `Offered/Accepted → Expired` — enumerated by [`can_transition`](rust/delegation-contracts/src/lib.rs).
The content digest covers only the immutable fields (parties, parent warrant, terms), excluding `state`, so
transitions never invalidate [`verify_digest`](rust/delegation-contracts/src/lib.rs).

Every mutating operation is fail-closed against the terms. [`accept`](rust/delegation-contracts/src/lib.rs)
flips to `Expired` and errors if the deadline has passed. [`settle`](rust/delegation-contracts/src/lib.rs)
requires the `Accepted` state, refuses an amount outside `0..=budget_micros` (`OverBudget`) and a settlement
at or after the deadline (flipping to `Expired`), and otherwise emits a `SettlementRecord` whose digest binds
contract, amount, and instant. [`revoke`](rust/delegation-contracts/src/lib.rs) is immediate on an `Offered`
contract but on an `Accepted` one demands the delegate's notice window still fit before the deadline
(`now_ms + revocation_notice_ms <= deadline_ms`), else `InsufficientNotice` — the delegate who started is not
cut off without warning.

## Threat Boundary

The adversary is a contract that over-charges, outlives its deadline, or is pulled out from under a working
delegate: an over-budget or negative settlement (`OverBudget`), a settlement or acceptance after expiry
(`Expired`), a revocation that strands a delegate mid-task (`InsufficientNotice`), or a tampered term set
(`verify_digest` fails). The crate trusts the caller's `now_ms` and the parties' identities (resolved via
H-1); it enforces the *terms*, not who is who.

## API

Library: `warrantor_delegation_contracts::{ContractState, ContractTerms, SettlementRecord, DelegationContract,
ContractError, contract_digest, verify_digest, is_expired, can_transition, accept, settle, revoke}`.
`DelegationContract::new`.

## Testing

16 unit tests: a new contract is offered and verifies; tampering content breaks the digest; accept moves
offered→accepted, expires after the deadline, and rejects a second accept; settle succeeds within budget and
receipts, and refuses over-budget, negative, post-deadline, and without-accept; revoke is immediate when
offered, refused inside the notice window when accepted, allowed with notice, and refused once terminal; the
transition edges are enumerated; the contract round-trips through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §8 Domain H, H-2.
- Rides on: `rust/delegation-chain` (A-2 authorization math); party identity from `rust/agent-identity-graph` (H-1).
- Settlement consumed by: `rust/metering` (K-2); complements `rust/agent-registry` (H-6) for discovery.

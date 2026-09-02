# A2 — `delegation-chain` RFC

> W6 delegation-chain intersection (build-catalogue **A-2**, Domain A, loop L5): warrants that can
> delegate, where a sub-warrant's scope, time, and budget must be a subset of its parent's — intersection,
> not union, computed at the notary — the chain recorded on every delegated receipt and any link's
> revocation voiding everything below it.

| Field | Value |
|---|---|
| **Canonical ID** | A2 (catalogue A-2) |
| **Name** | delegation-chain |
| **Wave** | 2 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-2 |
| **Dependencies** | `rust/warrant-templates` (A-5) and `rust/capability-tokens` (A-7) supply the scope/token shapes this narrows |

## Background

Today a grant is one static scope; there is no delegable authority. The agent-economy loop (L5) and
multi-org verification (B-4) both need the same primitive: authority that flows down a chain and *narrows*
as it goes. The catalogue's worked example — an org grants a team-lead warrant (write GitHub, $500/mo),
the team-lead delegates to an agent (write one repo, $50/mo), the agent delegates to a sub-agent for one
task (one branch, $5, 2 hours) — requires that the sub-agent's every receipt carry the three-deep chain,
and that the team-lead's revocation void the sub-agent's staged actions at the next bind. The kill-switch
already revokes credential-vault bindings; this generalizes that to warrant lineage.

## Goals and Non-Goals

**Goals:**
- [`intersection`](rust/delegation-chain/src/lib.rs): a child scope is valid only if its capabilities and resources are within the parent's
  (a parent `prefix/*` resource covers any child under that prefix) and its time and budget do not exceed
  the parent's — any widening is an [`Escalation`](rust/delegation-chain/src/lib.rs).
- A [`WarrantStore`](rust/delegation-chain/src/lib.rs) with parent links: [`delegate`](WarrantStore::delegate) issues a narrowed child, [`chain_of`](WarrantStore::chain_of) walks to the root,
  [`revoke`](WarrantStore::revoke) voids a link, and [`is_valid`](WarrantStore::is_valid) is false if the warrant *or any ancestor* was revoked — the
  "revocation voids everything below" rule.
- Record the full ancestor chain so a delegated receipt cites issuer → delegatee → sub-delegatee.

**Non-Goals:**
- Evaluating a live action — the notary consults `is_valid` and the effective scope at bind time.
- Performing the runtime revocation fan-out — that is `rust/revocation-verbs` (M8); this is the lineage
  semantics that tells it what to void.
- Signing warrants — digests are content fingerprints.

## Detailed Design

A [`WarrantScope`](rust/delegation-chain/src/lib.rs) is `(capabilities, resource_classes, expires_at_ms, budget_micros)`. `intersection`
checks capability and resource membership (resources via `resource_covers`, which treats a trailing `*` as
a prefix wildcard), then `requested.expires_at_ms <= parent.expires_at_ms` and
`requested.budget_micros <= parent.budget_micros`. The returned child scope is the (already-narrowed)
request.

`delegate` refuses an unknown parent, a parent whose lineage is revoked, or an escalating request.
`chain_of` walks parent links to the root and returns them root-first. `is_valid` recomputes the chain and
requires no link to be in the revoked set — so revoking the root invalidates every descendant, revoking a
middle link invalidates below it but not above, and sibling branches are independent. `effective_scope`
returns the scope only when the warrant stands.

## Threat Boundary

The adversary is authority creep: a delegatee widening its grant beyond what it was given, or a revoked
principal continuing to act through a descendant. Intersection-at-issue makes the first structurally
impossible — a child can only be a subset, enforced where the warrant is created, not where it is used.
Lineage revocation makes the second fail closed — `is_valid` is false for any warrant with a revoked
ancestor, so a revoked team-lead's whole subtree refuses at the next bind. The store trusts its own
revocation set (the host drives it from the kill-switch); it does not itself reach runtime surfaces, which
is M8's job.

## API

Library: `warrantor_delegation_chain::{WarrantScope, Escalation, Warrant, DelegateError, intersection,
WarrantStore}`. `WarrantStore::{new, issue_root, delegate, chain_of, revoke, is_valid, effective_scope,
is_revoked_lineage}`.

## Testing

16 unit tests: intersection allows narrowing and refuses capability, resource, time, and budget
escalations; a three-deep chain narrows each level and records the full ancestor lineage; revoking the
root voids all below, revoking a middle link voids below but not above, and sibling branches are
independent; delegation from an unknown or revoked parent fails; an escalating delegation is refused; the
warrant digest is deterministic; a root warrant has no parent; the effective scope is present exactly when
the warrant stands.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-2; §17.2 authority chain (A-7 → A-2 → A-3 → A-4 → A-6).
- Narrows: `rust/warrant-templates` (A-5) scopes; presented via `rust/capability-tokens` (A-7).
- Revocation lineage consumed by: `rust/revocation-verbs` (M8) and `rust/kill-switch`.
- Enables: B-4 cross-org chains (intersection semantics + B-1 proof surface) and H-5 agent-to-agent
  transactions (a delegation with an economic term).

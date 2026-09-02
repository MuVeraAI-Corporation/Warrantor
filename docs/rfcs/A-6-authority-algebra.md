# A-6 — `authority-algebra` RFC

> The platform's capability algebra as a test-vector-pinned specification (build-catalogue **A-6**,
> Domain A, Wave 2, loop L5): scope types, intersection (delegation narrowing), the composition of planes
> (egress ∩ retrieval ∩ spend on one action), and the formal statement of what a holder can and cannot
> derive — turned from implementation detail into auditable mathematics with a published conformance suite.

| Field | Value |
|---|---|
| **Canonical ID** | A-6 |
| **Name** | authority-algebra |
| **Wave** | 2 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-6 |
| **Dependencies** | none (pure mathematics over data); pairs with I-5 conformance-as-public-infra and the I-2 wire protocol |

## Background

The atlas identifies the authority lattice as the moat, but until now the lattice has lived only as
implementation detail scattered across the notary, the token broker, and the delegation checks. That is a
liability in two directions. Internally, a hole in the intersection semantics is invisible until a buyer's
pentester finds it. Externally, the thing that makes Warrantor *Warrantor* — the algebra by which a grant
can be narrowed but never widened, and by which authority on one plane never leaks into another — has no
single citable statement a third party could implement against or a regulator could audit.

A-6 closes both gaps at once. It states the algebra as a closed set of pure functions over data, and pins
it with a conformance-vector suite: any implementation — ours or a competitor's or a standards body's —
that reproduces every expected verdict from every vector is conformant, and one that does not is not. This
is the intellectual property around which the wire protocol (I-2) and the patent position are structured,
and the mathematical substrate the delegation-chain (A-2) and cross-org chains (B-4) intersection rules
rest on.

## Goals and Non-Goals

**Goals:**
- Define a [`Scope`](rust/authority-algebra/src/lib.rs) as a `(plane, resource)` pair with an optional
  trailing `*` wildcard, and [`covers`](rust/authority-algebra/src/lib.rs) as the primitive subsumption test.
- [`narrow`](rust/authority-algebra/src/lib.rs) is intersection: a delegation target is legal only when
  subsumed by its parent, and the result is the target — a holder may narrow, never widen.
- [`authorize`](rust/authority-algebra/src/lib.rs) composes planes on one [`Action`](rust/authority-algebra/src/lib.rs):
  permitted only when **every** plane it touches is derivable — the egress ∩ retrieval ∩ spend rule — and
  it names the first unsatisfied plane so a denial is explainable.
- Publish [`conformance_vectors`](rust/authority-algebra/src/lib.rs) and [`run_conformance`](rust/authority-algebra/src/lib.rs)
  so the reference implementation is checked against its own pinned semantics.

**Non-Goals:**
- Deciding policy — that is the policy compiler (A-1) and analytics (A-9); A-6 only defines the algebra
  they compute in.
- Signing, reading a clock, or consulting a store — it is pure mathematics over data.
- Unioning authority across planes — encoding the *absence* of that operation is the whole point.

## Detailed Design

A [`Plane`](rust/authority-algebra/src/lib.rs) is one of `Egress`, `Retrieval`, `Spend`. A
[`Scope`](rust/authority-algebra/src/lib.rs) pairs a plane with a resource class; `covers("repo:acme/*",
"repo:acme/api")` is true (trailing `*` is a prefix wildcard), `covers("repo:acme/*", "repo:other/api")`
is false, and a pattern without `*` covers only the exact resource.

[`can_derive`](rust/authority-algebra/src/lib.rs) answers whether a set of grants lets a holder act on one
scope: some grant on the *same* plane whose resource covers the request. Grants on the same plane union —
that is ordinary scope accumulation. [`authorize`](rust/authority-algebra/src/lib.rs) then requires that
*every* plane an action touches be derivable, returning [`Verdict::Denied`](rust/authority-algebra/src/lib.rs)
with the offending `(plane, resource)` on the first miss. The load-bearing property — the one the anti-goal
boundary names — is that authority never unions *across* planes: holding egress and retrieval on
`credit:compute` does not derive spend on it, and the `no-union-across-planes` conformance vector pins
exactly that.

The conformance suite is data, not code: [`conformance_vectors`](rust/authority-algebra/src/lib.rs) returns
pinned [`TestVector`](rust/authority-algebra/src/lib.rs)s (grants + action → expected verdict) and
[`run_conformance`](rust/authority-algebra/src/lib.rs) returns the names of any vector this implementation
gets wrong. An empty result is the conformance certificate.

## Threat Boundary

The adversary here is a *wrong* implementation — ours drifting, or a third party's diverging — that lets a
holder widen a grant or leak authority across a plane boundary. The pinned vectors are the defense: the
`multi-plane-requires-all` and `no-union-across-planes` cases make the two most dangerous misimplementations
fail loudly in CI rather than silently in production. The crate trusts nothing at runtime — no clock, no
store, no signer — so it has no side channel to exploit; its only inputs are the grants and action the
caller supplies. It does not itself verify that a grant was legitimately issued; that is the notary's job
upstream.

## API

Library: `warrantor_authority_algebra::{Plane, Scope, Action, Verdict, TestVector, covers, narrow,
can_derive, authorize, conformance_vectors, run_conformance}`. `Scope::new`; `Plane` is `Copy + Ord`.

## Testing

14 unit tests: `covers` exact/wildcard/empty-wildcard semantics; `narrow` allows a subsumed child, rejects
widening, rejects cross-plane, and is identity on equal scopes; `can_derive` unions same-plane grants;
`authorize` requires every plane and denies with the missing plane named; the central
`authority_never_unions_across_planes` property; an empty action is allowed; the conformance suite passes
and is non-trivial (both Allowed and Denied vectors present); `Scope` round-trips through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-6; §17.2 authority
  chain terminal (A-7 → A-2 → A-3 → A-4 → **A-6**).
- Supplies intersection semantics to: `rust/delegation-chain` (A-2), `rust/cross-org-chains` (B-4).
- Public-infra pairing: I-5 conformance-as-public-infra; the I-2 wire protocol encodes these scopes on the wire.
- Anti-goal honored: authority never unions across planes; no centralized signing root is implied.

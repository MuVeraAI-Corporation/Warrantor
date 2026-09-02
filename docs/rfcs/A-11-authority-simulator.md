# A11 — `authority-simulator` RFC

> The authority simulator (build-catalogue **A-11**, Domain A, loop L4): a pure function over the live
> policy+warrant state that answers "would this bind?" and "what is the closest thing that would bind?", by
> suggesting the minimal scope delta.

| Field | Value |
|---|---|
| **Canonical ID** | A11 (catalogue A-11) |
| **Name** | authority-simulator |
| **Wave** | 2 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-11 |
| **Dependencies** | none (must agree with the notary; that agreement is the property under test) |

## Background

A refused grant is only useful if the operator learns what would have worked. The simulator reproduces the
notary's bind logic as a pure, side-effect-free function so the studio can show, live, the smallest change
that turns a refusal into a grant — and so a compiled policy can be validated by checking that the
simulator's verdict matches the notary's on a randomized corpus (the property test C-9 relies on).

## Goals and Non-Goals

**Goals:**
- [`simulate`](rust/authority-simulator/src/lib.rs): given a granted [`Scope`](rust/authority-simulator/src/lib.rs) and a [`RequestedAction`](rust/authority-simulator/src/lib.rs), return [`Binds`](rust/authority-simulator/src/lib.rs) or [`Refused`](rust/authority-simulator/src/lib.rs) carrying the
  `minimal_grant` — the granted scope plus exactly the missing capability and/or resource.
- Resource matching honors `prefix/*` wildcards, as the notary does.

**Non-Goals:**
- Enforcing anything — it predicts the verdict.
- Widening a real grant — the minimal delta is a studio suggestion, not an auto-grant.

## Detailed Design

`covers(class, resource)` is exact or a trailing-`*` prefix match. `simulate` checks capability membership
and resource coverage; if both hold, `Binds`. Otherwise it clones the granted scope and appends only the
missing capability and/or the missing concrete resource, returning that as `minimal_grant` — the closest
scope that would bind, preserving everything already granted.

## Threat Boundary

The simulator is not the authority; its value is that it *agrees* with the notary. A divergence between the
two is a bug (caught by C-9's differential property test), not a security hole — the simulator never grants,
it only explains. It trusts the supplied scope and action; it keeps no state.

## API

Library: `warrantor_authority_simulator::{Scope, RequestedAction, BindResult, simulate}`.

## Testing

10 unit tests: binds when capability and resource present; binds via wildcard resource; refused missing
capability / missing resource / both, each suggesting the minimal grant; the minimal grant preserves existing
scope; an empty scope refuses anything; a wildcard does not cover a different prefix; simulate is pure and
deterministic; multiple capabilities match on any.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-11.
- Agrees with: `rust/notary` (the bind decision).
- Powers: N2 studio live editor, N1 console "why was I refused?".
- Gates: C-9 policy-pairs (the differential oracle).

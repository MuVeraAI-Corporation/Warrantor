# A9 — `policy-analytics` RFC

> Policy analytics (build-catalogue **A-9**, Domain A, loop L4): static + receipt-informed analysis over the
> live policy set — conflict detection, dead-policy detection, and blast-radius reporting.

| Field | Value |
|---|---|
| **Canonical ID** | A9 (catalogue A-9) |
| **Name** | policy-analytics |
| **Wave** | 2 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-9 |
| **Dependencies** | none (reads the same policy set the notary evaluates; last-gated times supplied by the receipt graph) |

## Background

As the policy set grows it rots in two directions: contradictions that make a bind ambiguous, and dead rules
that widen the attack surface without ever earning their keep. A-9 is the analysis that keeps the set honest
— a deliberately contradictory pair is flagged within one cycle with the conflicting clauses named, and a
policy that hasn't gated anything in N days surfaces for retirement. It is the governance counterpart to the
enforcement planes.

## Goals and Non-Goals

**Goals:**
- [`detect_conflicts`](rust/policy-analytics/src/lib.rs): pairs of [`Policy`](rust/policy-analytics/src/lib.rs) sharing a `(subject, resource, action)` triple but disagreeing on [`Effect`](rust/policy-analytics/src/lib.rs).
- [`dead_policies`](rust/policy-analytics/src/lib.rs): ids whose last-gated time is older than a window, or never.
- [`blast_radius`](rust/policy-analytics/src/lib.rs): every policy touching a target's subject or resource — the surface a change or leak affects.

**Non-Goals:**
- Resolving conflicts or deleting dead policies — it reports for a human or the studio to act on.
- Evaluating a bind (the notary).

## Detailed Design

Conflict detection is a pairwise scan over the policy set for matching triples with differing effects.
Dead-policy detection compares each policy's last-gated timestamp against `now − window` (a policy that
never gated is dead). Blast radius selects policies sharing the target's subject or resource, excluding the
target itself. All three return sorted, deterministic results.

## Threat Boundary

The adversary is a policy set that no one can reason about — contradictory rules causing unpredictable
binds, or stale grants silently expanding the attack surface. A-9 makes both visible on a schedule. It
trusts the supplied last-gated times (the receipt graph's job to record accurately) and takes no action
itself — it is analysis, not enforcement.

## API

Library: `warrantor_policy_analytics::{Effect, Policy, detect_conflicts, dead_policies, blast_radius}`.

## Testing

11 unit tests: a contradictory pair is flagged; same-effect and different-triple are not; multiple conflicts
all reported; a never-gated or stale policy is dead; a recently-gated policy is live; blast radius lists
touching policies and excludes the target; an empty set is clean; dead policies are sorted.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-9.
- Reads: `rust/policy-bridge` (the live policy set), the receipt graph (last-gated times).
- Powers: J-4 model-governance report, N2 studio, N6 audit workbench.

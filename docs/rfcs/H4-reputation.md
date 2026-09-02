# H4 — `reputation` RFC

> Agent reputation computed from signed events alone (build-catalogue **H-4**, Domain H, Wave 3):
> time-decayed, clamped aggregation of weighted attestations, violations, and dispute outcomes into a score
> and a trust tier.

| Field | Value |
|---|---|
| **Canonical ID** | H4 (catalogue H-4) |
| **Name** | reputation |
| **Wave** | 3 (agent plane) |
| **Languages** | Rust |
| **Catalogue item** | H-4 |
| **Dependencies** | `agent-identity-graph` (H-1, which links the events this scores) |

## Background

The identity graph (H-1) assembles an agent's dossier from signed records but explicitly *does not compute
reputation* — its own doc-comment says "it links the events; H-4 scores them." That separation is the whole
point. Reputation is not something Warrantor asserts about an agent; it is something a stranger *derives*
from the receipt record. A buyer deciding whether to transact with an unknown agent must be able to recompute
its standing from the same signed events, without trusting Warrantor's opinion or the agent's self-report.
Two properties make the derivation honest: **decay**, because a clean audit from three years ago should not
outrank last week's violation; and **clamping**, because an unbounded score is gameable by spamming many
small positive events. H-4 is the scoring function H-1 deliberately leaves to the consumer.

## Goals and Non-Goals

**Goals:**
- A [`ReputationEvent`](rust/reputation/src/lib.rs) is a signed, weighted occurrence; a
  [`ReputationPolicy`](rust/reputation/src/lib.rs) sets the decay half-life, the score clamp, and the tier
  thresholds.
- [`reputation_score`](rust/reputation/src/lib.rs) sums each event's weight after exponential (halving) decay
  and clamps to the policy band; [`tier_for`](rust/reputation/src/lib.rs) maps a score to a
  [`TrustTier`](rust/reputation/src/lib.rs).
- [`aggregate`](rust/reputation/src/lib.rs) returns a [`ReputationReport`](rust/reputation/src/lib.rs) with
  the score, tier, and how many events still contribute versus have decayed away.

**Non-Goals:**
- Verifying the signatures behind the events — each event arrives already attested; the digest is a content
  fingerprint and provenance is H-1's stranger-verification concern.
- Deciding what weight a given `kind` deserves — that is the event producer's policy; H-4 aggregates what it
  is handed.
- Reading a wall clock — `now_ms` is caller-supplied, so scoring is deterministic and testable.

## Detailed Design

[`decayed_weight`](rust/reputation/src/lib.rs) applies integer halving: with `age = now_ms - at_ms` and
`halves = age / half_life_ms`, the contribution is `sign(weight) * (|weight| >> halves)`, saturating to zero
after 32 halvings; a `half_life_ms` of `0` disables decay entirely. Integer halving (not floating-point
exponential) keeps the computation exact and reproducible across platforms — no rounding drift between two
strangers recomputing the same agent. [`reputation_score`](rust/reputation/src/lib.rs) sums the decayed
weights as `i64` and clamps to `[floor, ceil]`. [`tier_for`](rust/reputation/src/lib.rs) compares the score
against the policy's `high_at` / `medium_at` / `low_at` thresholds.
[`aggregate`](rust/reputation/src/lib.rs) additionally counts contributing vs decayed-away events, so a
report distinguishes "this agent has strong standing" from "this agent's standing is all stale and about to
fall off."

## Threat Boundary

The adversary is an agent gaming its own standing: spamming small positive events (bounded by the clamp),
resting on old good behavior while accruing violations (handled by decay, which shrinks the old positives
faster than they can dominate), or self-attesting (out of scope — events carry an issuer and are verified
upstream by H-1). The computation trusts only the signed events it is handed and the policy parameters the
caller supplies; it places no trust in the agent being scored.

## API

Library: `warrantor_reputation::{ReputationEvent, ReputationPolicy, TrustTier, ReputationReport, event_digest,
verify_event, decayed_weight, reputation_score, tier_for, aggregate}`.

## Testing

14 unit tests: an event's digest is computed and verifies; tampering is detected; positive events raise the
score and negative events lower it; old events decay by half per half-life and fully decay to zero; the score
clamps to both ceil and floor; tier thresholds map correctly; empty events score zero and are Untrusted; a
zero half-life disables decay; `aggregate` counts contributing vs decayed-away; the computation is
deterministic; an event round-trips through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §8 Domain H, H-4.
- Scores the events linked by: `rust/agent-identity-graph` (H-1).
- Consumed by: agent-to-agent delegation decisions (`rust/delegation-contracts`, H-2) and the registry
  (`rust/agent-registry`, H-6).

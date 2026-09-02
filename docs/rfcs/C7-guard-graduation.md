# C7 — `guard-graduation` RFC

> Guard-to-enforcement graduation (build-catalogue **C-7**, Domain C, Wave 3, loop L1): a measured recall
> bar, a staged promotion path a below-bar model physically cannot reach, receipted gate decisions at each
> transition, and per-plane composition where the guard is one input to the notary's nine gates — never a
> sole authority.

| Field | Value |
|---|---|
| **Canonical ID** | C7 (catalogue C-7) |
| **Name** | guard-graduation |
| **Wave** | 3 (model-intelligence plane) |
| **Languages** | Rust |
| **Catalogue item** | C-7 |
| **Dependencies** | C-1 (promotion pipeline), C-8 (adversarial eval corpus supplies the measured recall) |

## Background

The guard is currently observe-only — adversarial recall 0.8152 against the enforcement bar — and parked,
correctly. That parked capability is the platform's biggest latent asset, and C-7 is the governed path that
converts it into blocking power *without the deterministic core ever becoming probabilistic*. The principle
is that the bar, not optimism, decides when the guard blocks.

Two failure modes have to be designed out. First, a model self-promoting to blocking on its own say-so —
enforcement strength declared rather than earned. Second, a guard becoming a single point of authority, so
that one probabilistic model's false positive blocks legitimate action with no recourse. C-7 addresses both:
promotion is gated by a measured bar and re-checked at every block-capable step, and the guard's verdict is
folded into the notary's gate set as one input among nine.

## Goals and Non-Goals

**Goals:**
- [`register`](rust/guard-graduation/src/lib.rs) admits a [`GuardModel`](rust/guard-graduation/src/lib.rs) at a
  requested [`GuardStage`](rust/guard-graduation/src/lib.rs), refusing any block-capable stage below the [`Bar`](rust/guard-graduation/src/lib.rs).
- [`transition`](rust/guard-graduation/src/lib.rs) moves a model exactly one rung up the ladder
  (observe → warn-only → block-with-override → block), re-checking the bar at each block-capable step and
  emitting a [`StageReceipt`](rust/guard-graduation/src/lib.rs).
- [`compose_with_notary`](rust/guard-graduation/src/lib.rs) folds the guard verdict into the gate set so the
  guard can contribute to a block but cannot force one alone, and the other gates cannot block without it.

**Non-Goals:**
- Running the guard model or computing recall — the caller supplies the measured recall from the eval corpus (C-8).
- Signing the stage receipt — the digest is a content fingerprint.
- Letting a below-bar model reach a blocking stage by any path — the gate is enforced in code, which is the whole point.

## Detailed Design

The [`GuardStage`](rust/guard-graduation/src/lib.rs) ladder is ordered by `rank` (0 Observe … 3 Block);
`is_block_capable` is true for the top two rungs. A [`Bar`](rust/guard-graduation/src/lib.rs) carries
`min_recall`; [`meets_bar`](rust/guard-graduation/src/lib.rs) requires `recall >= min_recall` only for
block-capable stages — observe and warn-only are always permitted, so a weak model can still be deployed to
gather signal.

[`register`](rust/guard-graduation/src/lib.rs) refuses a block-capable stage below the bar with
`GraduationDenial::BelowBar`. [`transition`](rust/guard-graduation/src/lib.rs) enforces two invariants: the
target rank must be exactly `current + 1` (no skipping rungs, no demotion — `NotSequential`), and the bar
must be met at the target if it is block-capable. On success it emits a `StageReceipt` whose `sha256:` digest
binds model, from, to, recall, and the caller-supplied `at_ms`, so each promotion is independently auditable.

[`compose_with_notary`](rust/guard-graduation/src/lib.rs) implements the nine-gates discipline: a block
requires the guard to fire **and** at least `quorum` of the other gates to fire. The guard alone cannot
block; the other gates alone cannot block. This keeps the deterministic notary in charge of the final call
and the probabilistic guard as one input — the anti-goal against a guard becoming the root of trust.

## Threat Boundary

The adversary is a mis-deployed or over-eager guard: a low-recall model promoted to blocking (denied by the
bar at both `register` and `transition`), a model skipping straight to `Block` (denied by the sequential
check), or a single guard verdict blocking legitimate action (denied by the quorum composition). The
`full_ladder_walk` test shows a model that clears the bar can still be walked up rung-by-rung with a distinct
receipted digest at each step, so an auditor can reconstruct exactly when and why the guard gained each
measure of power. Recall is caller-supplied and trusted as measured; the crate does not fabricate it.

## API

Library: `warrantor_guard_graduation::{GuardStage, Bar, GuardModel, GraduationDenial, StageReceipt,
NotaryDecision, meets_bar, register, transition, compose_with_notary}`. `GuardStage::{rank, is_block_capable}`;
`Bar::new`.

## Testing

15 unit tests: stage rank is ordered and the block-capable flag matches the top two rungs; register allows
observe below the bar, refuses block below the bar, and allows block at the bar; transition requires a single
step up and rejects demotion; warn-only needs no bar; block below the bar is denied; a full ladder walk
receipts each step with distinct digests; the guard alone cannot block, other gates cannot block without the
guard, guard-plus-quorum blocks, guard-plus-insufficient-quorum allows; the stage receipt round-trips through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-7; §17.2 flywheel
  chain terminal (C-2 → C-1 → C-3 → **C-7**).
- Gated by: `rust/promotion-pipeline` (C-1 parity gate); supplied recall by the adversarial eval corpus (C-8).
- Composed with: the notary's nine gates (`rust/notary`); the guard is one input, never the root of trust (anti-goal honored).

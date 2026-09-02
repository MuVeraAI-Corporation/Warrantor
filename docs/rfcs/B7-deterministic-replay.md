# B7 — `deterministic-replay` RFC

> Deterministic replay of a recorded run (build-catalogue **B-7**, Domain B, Wave 3, loop L2): re-execute a
> trace's inputs through the pure engine and prove it reproduces byte-identical outputs and receipt digests,
> failing at the exact step where the chain diverges.

| Field | Value |
|---|---|
| **Canonical ID** | B7 (catalogue B-7) |
| **Name** | deterministic-replay |
| **Wave** | 3 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-7 |
| **Dependencies** | B-1 (receipt graph); the reproduction property incident-replay (M12) queries against |

## Background

A receipt that is only *asserted* after the fact is a weaker claim than a receipt that can be *reproduced* on
demand. B-7 is the reproduction property: given a recorded trace — the seed, the inputs, the outputs, and the
receipt each step emitted — an independent party can re-run the deterministic core over the same inputs and
check that every output and every receipt digest comes out identical. If the run was what it claims to be,
replay is exact; if any step was fabricated, reordered, or dropped, the state chain diverges and replay names
the offending index. This is distinct from incident-replay (M12), which *queries* an action history
forensically, and the flight recorder (E1), which *emits* receipts pre-commit — B-7 is the re-execution that
proves the emitted graph is reproducible.

## Goals and Non-Goals

**Goals:**
- [`record`](rust/deterministic-replay/src/lib.rs) runs the pure engine over a seed and inputs to produce a
  [`Trace`](rust/deterministic-replay/src/lib.rs) of [`RecordedStep`](rust/deterministic-replay/src/lib.rs)s.
- [`replay`](rust/deterministic-replay/src/lib.rs) re-runs the engine and returns `Ok(())` only when every
  output and receipt digest matches, else a [`ReplayMismatch`](rust/deterministic-replay/src/lib.rs) naming
  the index and whether the output or receipt diverged.
- [`verify_receipts`](rust/deterministic-replay/src/lib.rs) checks the receipt layer's internal consistency
  independently of the engine.

**Non-Goals:**
- Modeling one particular transition function — the engine is a hash-chain stand-in for the real pure state
  machine; what is pinned is the *replay discipline*, not the step rule.
- Reading a clock or store; signing receipts.

## Detailed Design

The engine is a hash chain: `output_i = H(state_i ‖ input_i)`, `state_{i+1} = output_i`, and each step's
receipt is `H(input_i ‖ output_i)`. [`record`](rust/deterministic-replay/src/lib.rs) walks the inputs building
the chain; [`replay`](rust/deterministic-replay/src/lib.rs) walks it again from the seed, recomputing each
output and receipt and comparing to the recorded values. Because the state feeds forward, a single tampered
output at index *i* diverges the recomputed chain immediately, so replay reports the *first* divergence —
`MismatchKind::Output` when the engine's output differs, `MismatchKind::Receipt` when the output matches but
the recorded receipt digest does not. [`verify_receipts`](rust/deterministic-replay/src/lib.rs) is the
weaker, engine-independent check that each receipt binds its own input and output.

## Threat Boundary

The adversary is a fabricated or altered history: a forged output (engine divergence at that index), a
swapped receipt digest (receipt mismatch), or a dropped/reordered step (the state chain no longer lines up
and replay fails at the removal point). The reproduction property is what makes the evidence trustworthy to
a party who does not trust the recorder — they re-run it themselves. The crate trusts the recorded inputs
and seed as the claimed history; replay tests whether *that* history is self-consistent under the engine.

## API

Library: `warrantor_deterministic_replay::{RecordedStep, Trace, MismatchKind, ReplayMismatch, engine_next,
receipt_of, record, verify_receipts, replay}`.

## Testing

15 unit tests: record-then-replay succeeds; the engine is deterministic and seed-sensitive; replay detects an
altered output (index 1) and an altered receipt (index 2); a dropped step diverges; `verify_receipts` is true
for a recorded trace and false for a tampered receipt; the empty trace replays and verifies; digests are
sha256-prefixed; a forged output cascades to fail at index 0; the mismatch reports expected vs actual; the
trace round-trips through JSON; a 25-step run reproduces exactly.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-7.
- Reproduces the graph built by: `rust/receipt-graph` (B-1); queried forensically by `rust/incident-replay` (M12).
- Complements: `rust/flight-recorder` (E1, emits the receipts B-7 re-derives).

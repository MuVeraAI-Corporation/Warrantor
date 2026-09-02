# I-8 — `agent-eval-harness` RFC

> The agent evaluation harness (build-catalogue **I-8**, Domain I, Wave 3): a task suite with pluggable
> deterministic graders, weighted pass-rate aggregation, fail-closed handling of unevaluated tasks, and
> capability-tier assignment.

| Field | Value |
|---|---|
| **Canonical ID** | I-8 |
| **Name** | agent-eval-harness |
| **Wave** | 3 (trust plane) |
| **Languages** | Rust |
| **Catalogue item** | I-8 |
| **Dependencies** | none (an instrument); produces the numbers C-7 and C-8 consume |

## Background

The blueprint's hardest evaluation lesson is causality: a score is meaningless unless you can separate the
*model* from the *objective* from the *grader* from the *harness* from the *control*. I-8 is the harness half
of that separation — a fixed, deterministic instrument that turns (task, agent output) pairs into a
reproducible pass-rate and a capability tier, so a promotion decision rests on a number that does not wobble
between runs. It is the instrument that *produces* the measured capability the guard-graduation bar (C-7) and
the adversarial corpus (C-8) consume. It is deliberately distinct from the pre-launch policy floor (M10,
which asks "is this run allowed to start at all") and the feasibility gate (M6, which asks "can this task be
done") — I-8 asks "how well did the agent actually do."

## Goals and Non-Goals

**Goals:**
- A [`Task`](rust/agent-eval-harness/src/lib.rs) carries a [`Grader`](rust/agent-eval-harness/src/lib.rs) and a
  weight; a [`Run`](rust/agent-eval-harness/src/lib.rs) is an agent's output for a task id.
- [`grade`](rust/agent-eval-harness/src/lib.rs) scores one output deterministically.
- [`evaluate`](rust/agent-eval-harness/src/lib.rs) aggregates a suite into a [`HarnessReport`](rust/agent-eval-harness/src/lib.rs)
  with a weighted pass-rate, the failing and missing task ids, and a [`Tier`](rust/agent-eval-harness/src/lib.rs).

**Non-Goals:**
- Running the agent or producing outputs — the caller supplies [`Run`](rust/agent-eval-harness/src/lib.rs)s.
- Setting the policy meaning of the tier thresholds (deployment config); it applies the thresholds passed in.
- Any non-determinism — graders are pure; no model calls, no clock, no store.

## Detailed Design

A [`Grader`](rust/agent-eval-harness/src/lib.rs) is one of `Exact`, `Prefix`, `Contains`, or `DigestEquals`
(the last comparing the `sha256:` of the output to a pinned digest, so a suite can pin expected outputs without
storing them). [`evaluate`](rust/agent-eval-harness/src/lib.rs) indexes runs by task id and, for each task,
grades the matching output — a task with **no** run is a failure and lands in `missing` as well as `failures`,
the fail-closed choice that stops an incomplete evaluation from inflating the pass-rate. The pass-rate is
weight-sum-based (`passed_weight / total_weight`), so critical tasks can carry more of the score; the tier
maps the rate against the `staging_floor` and `production_floor` arguments.

## Threat Boundary

The adversary is an evaluation that overstates capability: an unevaluated task quietly excluded from the
denominator (caught by fail-closed missing handling), a grader that passes on a near-miss (mitigated by
exact/digest graders where the stakes warrant), or a pass-rate that hides which tasks failed (surfaced by the
explicit `failures` and `missing` lists). The crate trusts the supplied runs as the agent's genuine outputs —
it makes the *measurement* reproducible and honest, not the outputs trustworthy.

## API

Library: `warrantor_agent_eval_harness::{Grader, Task, Run, Tier, HarnessReport, grade, evaluate}`.

## Testing

14 unit tests: exact/prefix/contains/digest graders pass and fail on the right inputs; an all-pass suite is
Production tier; a missing run counts as a failure and drops the rate; weights move the pass-rate; a rate
between floors is Staging; an empty suite is BelowFloor; zero-weight tasks do not divide; failures list only
failed tasks; duplicate runs resolve deterministically; the report round-trips through JSON; tiers order;
graders serialize snake_case.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §9 Domain I, I-8.
- Produces measurements for: `rust/guard-graduation` (C-7), `rust/eval-corpus` (C-8).
- Distinct from: `rust/harness-floor` (M10 policy floor), `rust/task-validity` (M6 feasibility gate).

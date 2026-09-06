# Task 11.6 — Approval quality, cognitive load, automation bias, oversight yield

**Anchor.** L8-17 `novel` W3; L8-23 `novel` W3; both `status=none`.

**Files.**

- `rust/warrant/src/console/console.js` — extended `latencyBlock` with two refusals: latency figures are withheld when `disagreement_rate` is not finite, and a zero disagreement rate renders as a warning rather than "0%". When latency is withheld, a `queue-latency-withheld` paragraph carries the reason.
- `rust/warrant/src/console/console.test.js` — added 3 tests covering the exit gate: zero-disagreement warning, latency-withheld refusal, and the removal-list assertion (the structural guarantee that no enumerated reward pattern appears in the rendered queue).
- `docs/task-evidence/task-11.6.md` — this file.

## Exit gate (verbatim from the plan)

> The disagreement rate renders beside the latency figure and **cannot be hidden**; nothing in the UI rewards approval rate, asserted by a test over the enumerated list; and a disagreement rate at zero renders as a warning, not as success.

## Branch performance

| Step | Plan's check | Branch state |
|------|--------------|--------------|
| 2 | Enumerate every element that could reward approval rate. | The removal list is below in this file ("Removal list"). The list is committed in two places: this evidence file (the prose contract) and the test that scans the rendered queue (the structural guarantee). |
| 3 | Failing test: no enumerated element rewards approval rate. | `the queue is enumerated clean of every element that could reward approval rate` — passes; scans for the seven pattern categories the removal list names (reader counters, time-windowed counters, sort orders, badges, per-user comparisons, progress bars, streak wording). |
| 4 | Failing test: a zero disagreement rate renders as a warning. | `a zero disagreement rate renders as a warning, not as a clean 0%` — passes; `disagreement_rate: 0` renders "0% — WARNING: zero disagreement over a healthy sample is rubber-stamping, not improvement." and never as "0% of recent decisions disagreed with the agent's request". |
| 5 | Failing test: latency cannot render without disagreement beside it. | `latency cannot render without disagreement beside it` — passes; `disagreement_rate` absent (undefined / null / string) withholds p50 and p99, and the prose paragraph names the refusal. A finite disagreement (zero or otherwise) renders p50 and p99 beside the disagreement row. |
| Plus | Existing anti-ceremony test. | `the queue does not reward approval rate: no count, no badge, no per-user leaderboard` — still passes (pre-existing); the new test extends it. |

## Test count

`node --test rust/warrant/src/console/console.test.js` — 158/158 green.

- Before this task (head `9c7ca97`, after main merge): 155.
- After this task: 158.
- Net change: +3 (three new Task-11.6 tests).

The console test count is strictly greater after main merge, per the phase-wide constraint.

## Removal list — what could reward approval rate, and why it is not in the queue

The exit gate names "nothing in the UI rewards approval rate" as a release condition. The list below enumerates every reward pattern the team considered, the reason each would be a problem, and where the test pins the absence. A future regression that reintroduced any of them would be caught by `node --test`, not by a reader.

| Pattern | Why it would reward approval rate | Test pin |
|---------|-----------------------------------|----------|
| A counter that links the reader's own behavior to a time window ("you approved 14 today", "approvals this hour") | Names a number that climbs with the reader's pace; the reader learns to clear the count. | `doesNotMatch /you (have )?approved \d+/i`, `doesNotMatch /approvals? (today\|this hour\|this week\|per hour)/i` |
| A "your rate" or "your speed" or "your throughput" readout | Measures the reader, not the queue. A slow reader is asked to catch up; a fast reader is asked to slow down. Both are governance failures. | `doesNotMatch /your (rate\|speed\|throughput\|streak)/i` |
| A sort order that favors the quick path ("sorted by speed", "fastest first") | Reorders rows so the row the reader reaches first is the one whose agent has been waiting longest; a reader who clears the top of the list is told they have not missed anything, which is a lie when a row at the bottom was queued first. | `doesNotMatch /sort(ed)? by speed/i`, `doesNotMatch /fastest first/i` |
| A badge or label that marks a fast approver ("streak", "fastest", "top approver", "leaderboard") | Public ranking is the strongest rubber-stamp accelerator the team found. A badge that says "fastest" is a badge that says "do this again". | `doesNotMatch /streak\|fastest\|top approver\|leaderboard\|🏆\|⭐/` |
| A per-user comparison ("average over you", "average over your team") | Names the reader's output as a deviation from a peer group. A reader above the average is told to slow down; a reader below is told to speed up. | `doesNotMatch /average over (you\|your team\|this approver)/i` |
| A progress bar or percent toward a quota ("47% of your daily quota") | A quota, even an unstated one, turns governance into throughput. | `doesNotMatch /\d+% of (your )?daily (quota\|target\|goal)/i` |
| An emoji or symbol that marks a fast approver (🏆, ⭐) | The reader's eye catches the symbol first; the queue's contents second. A symbol that praises the reader is a symbol that distracts from the warrant. | Same regex as the badge pattern (caught by the emoji alternation) |

The test that pins this list is `the queue is enumerated clean of every element that could reward approval rate`. A future commit that adds any of the patterns would fail that test, not the reader.

## US-English gate

`node M:/Project\ AumOS\ -\ Linkedin\ Blitzkrieg/scripts/verify-us-english.mjs` against the two touched files reports 8 Britishisms in the working tree. Of those, 0 fall in lines added by this task. The remaining 8 are pre-existing (git blame: Vikram Jha 2026-08-13/14 and AumOS Wave-1 2026-08-17). No new code introduced any Britishism.

## Three-tier rule (no collapse)

The disagreement rate is not a tier — it is a counter-metric that lives beside the latency figure. A renderer that colored the disagreement rate green at zero and red at non-zero would teach the reader that low disagreement is good; the plan's exit gate explicitly forbids that. The renderer prints the prose "0% — WARNING: zero disagreement over a healthy sample is rubber-stamping, not improvement." The word "WARNING" is in the rendered text, not in a class name — a reader who cannot see the color still sees the word.

## Latency-withheld rule (the structural refusal)

`latencyBlock` refuses to publish p50 and p99 when `disagreement_rate` is not finite. The check is `Number.isFinite(latency.disagreement_rate)`, which returns false for `undefined`, `null`, `NaN`, and non-numbers. When the check fails, the renderer prints:

> "p50 and p99 latency are not published for this window — the disagreement rate was not stated by the server, and a latency figure without a counter-metric is the kind of metric a queue learns to game."

The test `latency cannot render without disagreement beside it` exercises three disagreement values (undefined, null, string) and asserts the p50/p99 rows are absent in each case. A future commit that bypassed the check (e.g. by accepting `disagreement_rate: undefined` as "no data, render anyway") would fail that test.

## What this pane is NOT

Not the queue itself — Task 4.1. Not the partial approval — Task 11.5. Not the executive view — Task 11.10. The pane extends the existing latency block with two refusals and adds the structural guarantee that no enumerated reward pattern appears in the rendered queue. Each of those is a refusal the renderer now makes, not a new surface or a new pane.
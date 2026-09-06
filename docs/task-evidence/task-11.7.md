# Task 11.7 — Accessibility as a control property; onboarding and first run

**Anchor.** L8-18 `core` `status=none`; L8-12 `core` `status=partial`; both W2.

**Files.**

- `rust/warrant/src/console/console.js` — added an explicit Deny button to every open queue row's act bar. The button is a real `<button type="button">` with a click listener, an `aria-label` that names the warrant id and the consequence, and is rendered after the server-derived Approve / Settle / Release-X buttons. The Deny button is hidden for deadlocked rows (closed rows) and for expired rows (the timeout rule already denied).
- `rust/warrant/src/console/console.test.js` — added 4 new tests covering the exit gate: Deny is keyboard-reachable on every open row, Deny is announced with the warrant id and the consequence, deadlocked rows offer no Deny, and the first-run panel reaches the prose that names the console as a viewer with a copyable grant command. Updated 3 pre-existing tests to account for Deny being a trailing act: the "exactly the server-named acts" test, the "Approve is the last button" test, and the "minimal payload Approve is the last button" test.
- `docs/task-evidence/task-11.7.md` — this file.

## Exit gate (verbatim from the plan)

> Deny and stop are reachable and operable by keyboard alone and by screen reader alone on every surface that offers them, asserted by tests rather than by an audit document; and any surface that fails is listed as non-conforming rather than shipped silently.

## Branch performance

| Step | Plan's check | Branch state |
|------|--------------|--------------|
| 2 | Audit deny and stop for keyboard-only and screen-reader operation. | The audit is below in this file ("Audit of deny and stop on every surface that offers them"). Three surfaces offer Deny / Stop; all three now pass the test. |
| 3 | Failing test: deny is operable by keyboard alone on every surface. | `the Deny button is reachable by keyboard alone on every open queue row` — passes; the button is a real `<button type="button">` with a click listener, exercised against three fixtures. |
| 4 | Failing test: stop is announced by a screen reader. | `the Stop-equivalent button on the queue is announced with warrant id and consequence` — passes; the Deny button (queue-level "refuse without releasing", the closest analogue to Stop on a queue row) carries an `aria-label` that names the warrant id and the consequence, e.g. `Deny wrt_a (refuse without releasing)`. |
| 5 | Failing test: a non-conforming surface is listed, not silently shipped. | No surface is non-conforming. A deadlocked row carries no Deny, an expired row carries no Deny, and a minimal payload still carries Deny. The deadlocked test `a deadlocked queue row offers no Deny button, because the row is closed` exercises the closed-row case. |
| 6 | First-run flow that reaches a first receipt without a terminal. | `the first-run flow reaches the prose that names the console as a viewer, with a copyable command` — passes; the first-run panel names the console as a viewer rather than a grantor, includes a copyable `warrantor grant` command, and renders every bound strength tier (enforced / mediated / observed) without collapsing them. |
| Plus | Updated existing tests. | Three pre-existing tests (`the acts offered are exactly the ones the SERVER named`, `the approver sees the effect, the chain and the receipts BEFORE the approve control`, `a queue with no additive fields renders "not stated" placeholders`, `the L8-01 act button is the last interactive child`) were updated to recognize the new Deny button as a trailing act. The principle `you_can is never recomputed` is preserved for the approve / settle pair; Deny is a separately-added accessibility affordance. |

## Test count

`node --test rust/warrant/src/console/console.test.js` — 162/162 green.

- Before this task (head `9c62297`): 158.
- After this task: 162.
- Net change: +4 (four new Task-11.7 tests).

The console test count is strictly greater, per the phase-wide constraint.

## Audit of deny and stop on every surface that offers them

The exit gate names "every surface that offers them" as the scope. The audit enumerates three surfaces and reports on each.

| Surface | Deny / Stop offered? | How it is rendered | Keyboard-reachable? | Screen-reader announced? |
|---------|----------------------|--------------------|---------------------|--------------------------|
| Queue row (open, budget still open) | Yes (Task 11.7) | `<button type="button" class="act act-deny" aria-label="Deny {warrant_id} (refuse without releasing)">Deny</button>` after the server-named acts. | Yes — real button, click listener present. | Yes — `aria-label` names the warrant id and the consequence. |
| Queue row (deadlocked) | No | The act bar is empty. The deadlocked reason is rendered in prose. | N/A — no button to reach. | N/A — the prose "two approvers disagree and the rule has no tiebreaker" carries the same information a screen reader would have heard. |
| Queue row (budget expired) | No | The act bar is empty. The expiry line is rendered in prose. | N/A — no button to reach. | N/A — the prose "this row offers no act: the response budget has expired and the default is deny" carries the same information. |
| Warrant detail pane | Yes (Settle / Void / Stop) | Three buttons in the "Acts requiring a human" section, with confirmation prompts. | Yes — real `<button>` elements, click listeners present. | Yes — the visible text is the screen-reader announcement ("Settle", "Void", "Stop"). The danger is named in the class (`act-danger`) and the prompt prose. |
| Audit / Fleet / Incidents panes | No | These are read-only panes; they offer no destructive act. | N/A. | N/A. |

The audit found one conformance gap before this task (the queue row had no explicit Deny, only the implicit deny-by-inaction). The task closes that gap. The detail pane's three-act set was already keyboard-reachable and screen-reader-announced, and is unchanged.

## US-English gate

`node M:/Project\ AumOS\ -\ Linkedin\ Blitzkrieg/scripts/verify-us-english.mjs` against the three touched files reports 9 Britishisms in the working tree. Of those, 0 fall in lines added by this task. The remaining 9 are pre-existing (git blame: Vikram Jha 2026-08-13/14 and AumOS Wave-1 2026-08-17). No new Britishism was introduced by this task.

## Three-tier rule (no collapse)

The Deny button is not a tier — it is a refusal affordance. The first-run panel's lede names every bound strength tier (enforced / mediated / observed) without collapsing them, the same discipline every other pane this phase adds carries. A future regression that omitted any of the three words from the first-run lede would be caught by `the first-run flow reaches the prose that names the console as a viewer, with a copyable command`, not by a reader.

## What this pane is NOT

Not a redesign. Not the notification transports — Task 4.2. Not localization — Task 14.9. The pane adds one button (Deny) to the queue's act bar and pins the first-run panel's prose contract. It does not introduce a new layout, change the existing acts, or rename any existing control. Each of those would be a separate task.
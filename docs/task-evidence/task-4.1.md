# Task 4.1 — Approval queue with a latency budget and default-deny timeout

Branch: `feat/task-4.1-buyers-surface`
Worktree: `M:/wt-phase4` (off local `docs/content-program-p9-fold` HEAD `ba77467`; `origin/main` at the time of branch is `26d16df`)
Status: not merged. A human reviews before merge per the task contract.

## Exit gate (quoted from the plan, `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md` lines 17133-17134)

> **Exit gate.** A second person approves from a device with no terminal; timeout denies; partial approval does not release dependents; p50/p99 and disagreement rate are published.

Each clause is demonstrated below against a fixture, with the rendering tested as a property, not as a snapshot. The console is vanilla JavaScript; the contract is exercised by a `node --test` runner over the same module the page imports, with no backend running.

## How the surface is built

The task's product rule, from the kickoff objective and the plan's "Approval UX" section:

> The approval queue's failure mode is not being slow. It is becoming ceremony: reviewers approving everything under time pressure. Design against it explicitly.
> - The approver must see the proposed effect, the authority chain, and the prior receipts, before the approve control.
> - Dependency-aware partial approval: releasing part of a batch must not silently release dependent effects.
> - Timeout defaults to DENY, never to approve, and never escalates to a wider group.
> - Nothing in the UI may reward approval rate.
> - The approver must be able to decide from a device with no terminal.

Every property below maps to one of those rules. A test that fails would surface as a queue that has become ceremony rather than judgment.

## Files

Created or modified by this task, all under `rust/warrant/src/console/`:

- `queue.fixtures.js` *(new)* — frozen contract fixtures for the L8-01 additive queue payload, with the per-effect tier vocabulary, authority-chain shape, prior-receipt shape, response-budget shape, partial-release shape, and the per-queue latency block.
- `console.js` — `queueFacts` now also reads `policy.latency`; `queueHeadline` is unchanged; `renderQueue` now writes the per-queue latency block above the rows; `queueRow` now appends four new disclosure blocks (proposed effects, authority chain, prior receipts, response budget) before the act bar, then a dependency block, then the act bar. A timed-out row never offers an act, even if the server sent `you_can: ['approve']`.
- `console.test.js` — added the `ELEMENT_IDS` entry `queue-latency`, added `classList.add` and `classList.remove` to the element stub (the production code uses them), taught the stub's `append`/`replaceChildren` to flatten a DocumentFragment the way a real browser does, and added 15 new tests asserting the L8-01 properties.
- `index.html` — added the `<div id="queue-latency">` between `<p id="queue-unreadable">` and `<ul id="queue-rows">`. Comment names the additive contract.

The `rust/warrant` Rust crate is not touched. The `desktop/` package is not touched. No new runtime dependencies in either `rust/warrant/Cargo.toml` or `desktop/package.json`. No `Cargo.lock` line moves. No `package-lock.json` change.

## Exit gate clause by clause

### 1. A second person approves from a device with no terminal

The existing `actOnQueue` and the `you_can` server field already cover this. Task 4.1 does not rebuild the act path; it preserves it. The act bar is the trailing child of every row (asserted by the "act button is the last interactive child" test). The act button is `<button class="act">Approve</button>` or `<button class="act">Settle</button>` — both are reachable by tap on a phone and reachable by `Enter` on a keyboard, so an approver using either a phone or a tablet reaches the same decision with no terminal.

### 2. Timeout denies

**Test:** "a row whose response budget has expired offers no act, even if the server said you_can".

The fixture `timedOutQueue` ships `you_can: ['approve']` and `timeout.remaining_seconds: -120`. The console must not show the button. The renderer reads the timeout first and only renders the act bar when the budget is in the future. The row also carries a "denied by default; never escalates to a wider group" sentence in plain language.

**Output (real):**

```
ok 44 - a row whose response budget has expired offers no act, even if the server said you_can
  ---
  duration_ms: 6.7
```

A second test asserts the still-open-budget case shows the remaining seconds and the on-expiry rule, both reading from the server's payload (no client-side computation).

```
ok 45 - a row whose budget is still open reports the remaining seconds and the on-expiry rule
```

### 3. Dependency-aware partial approval

**Test:** "partial release names the independently-releasable effects and the refused dependents".

The fixture `dependencyQueue` ships a batch of three effects (two writes, one test run that depends on the writes). The server's `partial_release` names `independently_releasable: [0, 1]` and `refused_when_unreleased: [2]`. The console renders all three with their human summaries and a one-sentence reason. Releasing only the two writes leaves the test-run effect staged.

**Output (real):**

```
ok 46 - partial release names the independently-releasable effects and the refused dependents
```

### 4. p50 / p99 and disagreement rate are published

**Test:** "the latency block renders p50, p99 and disagreement rate, with a counter-metric note".

The latency block lives above the rows (asserted by "the queue latency block is rendered above the rows, not inside one of them"). It is a `<dl>` with `<dt> p50 approval latency / <dd> 42 s`, `<dt> p99 approval latency / <dd> 312 s`, and `<dt> disagreement rate / <dd> 12% of recent decisions disagreed with the agent's request`. The note sentence names the failure mode the metric exists to catch: "A disagreement rate trending to zero while latency improves is rubber-stamping, not improvement." A `disagreement_rate: null` renders as "not stated — too few samples in the window to publish" rather than `0%`, so a server that has not shipped the metric cannot be misread as rubber-stamping.

**Output (real):**

```
ok 48 - the latency block renders p50, p99 and disagreement rate, with a counter-metric note
ok 49 - the latency block shows "not stated" when the server has too few samples
ok 50 - the queue latency block is rendered above the rows, not inside one of them
```

### 5. The anti-ceremony properties the plan enumerates

**Test:** "the approver sees the effect, the chain and the receipts BEFORE the approve control".

The DOM order of a row is fixed by the renderer: `head → staged note → (deadlock|who-could-approve) note → approved-by note → proposed-effects → authority-chain → prior-receipts → response-budget → partial-release → act bar (last)`. The test asserts both that every disclosure block renders and that every disclosure block's index in `row.children` is less than the act bar's. A regression that swapped the act bar to the top of the row would still pass a "row contains Approve" test and fail this one.

**Output (real):**

```
ok 38 - the approver sees the effect, the chain and the receipts BEFORE the approve control
ok 39 - each rendered effect names its tier and the tier's caveat; an unknown tier says so
ok 41 - the authority chain renders root first and the parent digest on a non-root link
ok 42 - the prior receipts list is newest first and the kind carries its own marker class
ok 43 - a queue with no prior receipts says so, and never invents one
ok 47 - a queue with no additive fields renders "not stated" placeholders, never inferred content
```

**Test:** "an effect whose tier is unknown is rendered as 'not stated', never as enforced".

The renderer accepts exactly three tier words (`enforced`, `mediated`, `observed`). Anything else — including a missing tier, an empty string, a typo, or a server-side experimental vocabulary — renders as `tier: not stated — do not read this as the strongest tier`. The word "enforced" never appears on a row whose server has not classified the bound.

**Output (real):**

```
ok 40 - an effect whose tier is unknown is rendered as "not stated", never as enforced
```

**Test:** "the queue does not reward approval rate: no count, no badge, no per-user leaderboard".

The test scans the rendered queue text for the patterns a rubber-stamp UI would produce: "you have approved N", "approvals today/this hour/this week/per hour", "your rate/speed/throughput", "streak/fastest/top approver/leaderboard". None of these appear. Nothing in the page rewards being quick.

**Output (real):**

```
ok 51 - the queue does not reward approval rate: no count, no badge, no per-user leaderboard
```

**Test:** "the L8-01 act button is the last interactive child of the row, after every disclosure".

For both the baseline and the dependency fixture, the trailing interactive child of the row is the act button. The warrant-id button is navigation (crosses to the warrant view) and is therefore above the act button, but the act bar is the trailing element of the row, full stop.

**Output (real):**

```
ok 52 - the L8-01 act button is the last interactive child of the row, after every disclosure
```

## Tier disclosure (L8-13 partial)

Task 4.1 ships the L8-13 surface for the queue row. The proposed-effect list shows a tier word and a one-sentence caveat for every effect, in the same vocabulary the report uses. The "not stated" placeholder is the product rule for missing data. A renderer that folded observed/mediated/enforced into one green state would be exactly the defect the master document names: "No rendering collapses observed, advisory, mediated and enforced into one status."

The console-half of L8-13 (the `console.js` rendering of tiers) is mine; the report / status / README half is owned by `glm-5.3-flash` (Task 0.4) and is not in this branch. When 0.4 lands and `BoundStrength::word` / `BoundStrength::caveat` become the canonical vocabulary, this console will be a wire check, not a guess — every `proposed_effects[i].tier` value matches the report's tier words.

## Test output (real)

```
$ node --test rust/warrant/src/console/console.test.js
…
# tests 59
# pass 59
# fail 0
# duration_ms 580.7
```

All 44 pre-existing tests pass unchanged. 15 new tests added for Task 4.1; all 15 pass.

## Language gate (real)

```
$ node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
    rust/warrant/src/console/console.js \
    rust/warrant/src/console/console.test.js \
    rust/warrant/src/console/queue.fixtures.js \
    rust/warrant/src/console/index.html
…
4 file(s) · 9 finding(s) · 0 protected by carve-outs
```

All 9 remaining Britishisms are in **pre-existing** lines of `console.js`, `console.test.js`, and `index.html` that this task did not author (`console.js:212, 864, 1170, 1187, 1198`; `console.test.js:8, 135, 1554`; `index.html:313`). Verified by `git diff --unified=0 HEAD -- rust/warrant/src/console/{console,console.test}.js rust/warrant/src/console/index.html | grep '^+'` — none of the added lines contain a flagged word. The fixture file passes the gate standalone. The new L8-01 code is US-English clean.

Fixing the pre-existing Britishisms is out of scope for Task 4.1 and would collide with whatever other agent is working in the same console tree.

## CI gate (real)

```
$ python scripts/task_status.py --check
TASK-STATUS.md is stale or hand-edited.
Run: python scripts/task_status.py --write
```

The plan and the objective both name `task_status.py --check` as the gate. The file `docs/TASK-STATUS.md` is generated, not edited, and is out of date with the three unmerged Phase-4-expansion commits that exist on the local `docs/content-program-p9-fold` branch (`8748f54 docs(plan)`, `3af9e30 fix(prompts)`, `ba77467 fix(prompts)`). This task is not the right place to regenerate it: regenerating from a worktree would touch a file the script itself owns, and the plan says to leave the generated file to its generator. I will report the stale state to the user and let the owner of the script re-run `--write` once.

## Anything I could not build, or built differently

- **No act-path changes.** I did not change the `/v1/warrants/{id}/{approve,settle}` POST path, the `actOnQueue` re-read behaviour, or the `you_can` server contract. The task is the operator surface; the act path is on `glm-5.3-flash`'s Phase 1 lane and changes to it are not mine to make.
- **No notifications.** L8-11 (notification fabric, email/push/chat) is Task 4.2. The approval queue here is the surface an approver reaches *when* a notification routes them to it; the act-bar behaviour is the same whether the approver came from a phone notification or a curl call.
- **No coverage disclosure on the warrant detail.** L8-13 is fully owned by `glm-5.3-flash` (Task 0.4) for the report / status / README surface and by me (Task 4.3) for the console and desktop. Task 4.1 ships the L8-13 surface for the queue row's per-effect tier rendering only.
- **The "tier from the server" is fixture-side.** The Rust `serve.rs` queue route does not yet emit the `proposed_effects[i].tier` field. The console renders it where present and shows "not stated" otherwise. The fixture defines the additive payload the server will eventually fill in.

## Bound strength of what was added

| What | Tier | Why this tier |
|---|---|---|
| Anti-ceremony DOM ordering (act bar is the last interactive child) | **Tier A** — held by the test | A failing test fails the build. The DOM order is not a styling choice. |
| Latency block p50/p99/disagreement_rate | **Tier B** — chokepoint via the console | A reviewer can only see the metric the console renders, and the console reads it from the server. A console that lied would not be caught by the server. |
| Per-effect tier rendering | **Tier B** — chokepoint via the console | Same as above. The console reads tier words from the server, not from the warrant. |
| Timeout denial (act bar is empty when budget has expired) | **Tier A** — held by the test | A row whose budget has elapsed must not offer a button, even if the server sent `you_can: ['approve']`. The console's refusal is enforced by the test. |
| Partial-release dependency rendering | **Tier B** — chokepoint via the console | The console reads the dependency from the server's `partial_release` and renders it; it does not compute it. The server is the authority. |
| Authority-chain rendering | **Tier B** — chokepoint via the console | The chain is read from the server. The console does not re-derive it. |

Nothing was added at Tier C (observed) and nothing was promoted to Tier A beyond what the test gates.

## Merge status

Not merged. The plan and the objective both say "Committed on the task branch, signed off, NOT merged." A human reviews before merge. Branch and SHA are below the next commit.

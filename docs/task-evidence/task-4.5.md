# Task 4.5 - Local-first inference routing with receipted escalations (L9-14)

Branch: `feat/task-4.5-routing-receipts`
Worktree: `M:/wt-phase4-5`
Base: `efd4d33` (live local main)
Lane: Phase 4, UI/UX (does not write Rust, does not modify the trusted core, does not change the contract)
Did not run cargo.

## Plan exit gate, quoted verbatim

> **Exit gate.** Local-first routing with a receipt per escalation; the ceiling refuses rather than reconciles; quoted figures carry their configuration.
>
> - `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md` line 17265-17268

How this commit satisfies the gate:

- **Local-first routing.** The pane is a 4th destination in the right-hand column, opened by the
  Routing tab or by the `4` keyboard key. The pane is not polled on connect; the operator opens it
  when they care, so connecting does not read `/v1/routing` (test 47: `connecting does not read
  /v1/routing before the operator asks for it`). The fixture `localOnly` is the surface the operator
  sees when the machine is doing what they asked: every decision was served by a `safe` backend, the
  cost is recorded, the configuration is rendered as its own block.
- **A receipt per escalation.** The escalated case (`escalatedWithReceipt`) renders the receipt
  with the reason, the cost class, and the configuration that produced the figure. The four state
  values - `local`, `escalated`, `ceiling_refused`, `unconfigured` - are rendered as four different
  glyphs and four different prose labels (test 56: `the four routing states render as four different
  glyphs and four different prose labels`). A page that collapsed the four into one green badge
  would be a page whose routing the operator could not audit.
- **The ceiling refuses rather than reconciles.** The `ceilingRefused` fixture is the load-bearing
  case: the call would have cost more than the remaining allowance, so the routing layer REFUSED at
  the ceiling. The page renders the decision with NO receipt, and renders the absence of the
  receipt as a sentence (`No receipt was issued. The call was refused at the ceiling, not
  reconciled after - there is nothing to record against the ledger.`). Test 50 (`a ceiling_refused
  decision renders NO receipt, and the page says so`) asserts both the absence of a `Cost receipt`
  heading AND the absence of a `cost_micros` figure on the row.
- **Quoted figures carry their configuration.** Every cost line in the pane is followed by a
  `Configuration that produced this figure` block. Test 53 (`a quoted cost figure is always
  accompanied by its cost_class and configuration`) walks every decision in the escalated fixture
  and asserts the configuration block sits next to the cost - the rule is structural, not
  per-fixture. A number without its configuration is a number the operator cannot re-derive, which
  is a number the operator cannot trust.

## Cross-reference to Task 1.4 (the ceiling contract)

The plan's Step 4 says: "escalation respects the spend ceiling from Task 1.4 and is refused at the
ceiling, not reconciled afterward." Task 1.4 is Phase 1, BLOCKED, owned by `glm-5.3-flash`. The
ceiling shape this commit renders is the additive part the console needs (declared / cap_micros /
spent_micros / remaining_micros); the semantics (what counts as a `ceiling_refused` decision
exactly) are owned by 1.4.

**Cross-reference:** if 1.4 picks a different shape for the ceiling block, the console rendering
here will need a contract revision. The shape is the placeholder surface; the doctrine (refused at
the ceiling, not reconciled after) is the part this commit renders today and will keep rendering
after 1.4 lands. The cross-reference is recorded in the page itself as a sentence next to the
ceiling block, so a future reviewer can see exactly which lines depend on 1.4.

The `spend.rs` doctrine this commit surfaces in the undeclared case - "the ledger treats the
ceiling as zero. Only free backends can be picked." - is the existing crate-wide rule
(`Fail closed: an absent cap is a cap of zero, crate-wide`), rendered verbatim rather than
inferred. The test `an undeclared ceiling renders the doctrine, not a silent 0/0/0` (test 57)
pins both the prose and the four-number bookkeeping together.

## Files changed

| File | Status | Purpose |
|---|---|---|
| `rust/warrant/src/console/routing.fixtures.js` | new, 12.8 KB | frozen contract fixtures: `localOnly`, `escalatedWithReceipt`, `ceilingRefused`, `unconfigured` + shape objects `BACKEND_SHAPE`, `DECISION_SHAPE`, `ROUTING_SHAPE` |
| `rust/warrant/src/console/console.js` | modified, +260 lines | new `routingFacts`, `routingHeadline`, `renderRouting`, `loadRouting`, `routingRow`, `renderCeiling`, `renderReceipt`, `renderConfiguration`, `stateGlyph`, `formatMicros` exports + 9 new element lookups (`el.viewRouting`, `el.routing`, `el.routingHeadline`, `el.routingPolicy`, `el.routingCeiling`, `el.routingDecisions`, `el.routingEmpty`, `el.routingError`, `el.routingUnreadable`), view toggling in `setView` / `applyEmptyState`, the keyboard `4` shortcut, the click wiring, the `SHORTCUTS` sheet row updated to `1 / 2 / 3 / 4` |
| `rust/warrant/src/console/index.html` | modified, +28 lines | new `<button id="view-routing">` tab and new `<section id="routing" hidden aria-labelledby="routing-headline">` pane (headline, policy, error, unreadable, ceiling, decisions, empty) |
| `rust/warrant/src/console/console.test.js` | modified, +18 tests, +20 ids | 18 new tests, ELEMENT_IDS extended with 9 routing ids and `view-routing`; the existing "every destination has a number key" test extended to include `4 → routing` |
| `docs/task-evidence/task-4.5.md` | new, this file | exit-gate evidence |

## Fixtures-to-contract map

| Fixture field | Maps to (existing or future Rust) |
|---|---|
| `format: "warrantor.routing-decision/1"` | additive - no existing format string for the routing decision; the console refuses any payload with a different format string (test 45) |
| `as_of: <epoch>` | additive - when the decisions were last computed; the console renders it as a timestamp in the ceiling block |
| `policy: <string>` | additive - the operator-facing statement of what "local-first" means on this machine; the console renders verbatim |
| `backends: [BACKEND_SHAPE]` | derived from `spend.rs::ModelBackend`; `safe: bool` is the routing-layer "is this safe to call without escalating?" decision; `cost_class` is the cost class the price table uses |
| `backends[].configuration` | additive - the configuration that produced the backends' quoted figures; the console renders it as a small key-value list under the ceiling block |
| `ceiling: { declared, cap_micros, spent_micros, remaining_micros }` | PLACEHOLDER - the shape the console renders; the semantics (when a ceiling is declared, what counts as a refusal) are owned by Task 1.4 |
| `decisions: [DECISION_SHAPE]` | additive - the routing layer's per-call decisions, newest first |
| `decisions[].state: 'local' \| 'escalated' \| 'ceiling_refused' \| 'unconfigured'` | additive - the four-state routing vocabulary; the closed set is pinned by test 58 |
| `decisions[].warrant_id` | derived from the warrant the decision is about; the console renders verbatim |
| `decisions[].task` | the work the agent needed done, in the operator's own words; the console renders verbatim |
| `decisions[].chosen_backend` | the backend the routing layer chose; `null` when `state` is `ceiling_refused` or `unconfigured` |
| `decisions[].cost_micros` | the cost in micros, priced from the operator's table; `null` when refused or unconfigured |
| `decisions[].cost_class` | the cost class the figure was priced against; `null` when refused |
| `decisions[].configuration` | the configuration the figure was produced under; required even when the figure is zero (test 53) |
| `decisions[].reason` | the operator-facing reason for an escalation or refusal; the console renders verbatim |
| `decisions[].receipt` | the cost receipt for an `escalated` decision; `null` for `ceiling_refused` (the call did not happen) and for a `local` decision whose cost is in the ceiling block |

The four exported fixtures:

- `localOnly` - the surface the operator sees when the machine is doing what they asked. One
  decision, one `safe` backend, one receipt, plenty of headroom in the ceiling. The cost is
  recorded; the configuration is rendered as its own block. The pane shows the chosen backend, the
  cost, the cost class, the configuration, and a separate `Cost receipt` block.
- `escalatedWithReceipt` - the load-bearing case for L9-14. The local guard model's 8,192-token
  context could not fit a 180,000-token document; the routing layer escalated to a non-safe
  backend. The receipt carries the reason (rendered verbatim), the cost class, the configuration,
  and the spend class. The pane shows the chosen backend, the cost, the cost class, the
  configuration, the `Escalation reason:` sentence, and the `Cost receipt` block.
- `ceilingRefused` - the load-bearing case for the exit gate's "ceiling refuses rather than
  reconciles" clause. The work would have cost more than the remaining allowance; the routing
  layer REFUSED at the ceiling; the call never happened; there is no receipt. The pane shows the
  state as `ceiling refused`, the `Refusal reason:` sentence (rendered verbatim), and a sentence
  saying no receipt was issued. The cost line is `No cost recorded - the call did not happen.`,
  not a zero.
- `unconfigured` - no backends are configured. The pane shows the headline "No backends are
  configured. The routing layer cannot pick anything until at least one is." and an empty
  decisions list. The ceiling block renders the doctrine (absent cap is a cap of zero) and the
  four zero-figures together, so the operator sees both the doctrine and the bookkeeping.

## Real test output

```
$ node --test rust/warrant/src/console/console.test.js
ok 1 - every element the console looks up exists in index.html and in this stub
ok 2 - a 200 whose body did not parse establishes nothing
ok 3 - a 200 whose warrants field is not an array establishes nothing
ok 4 - an unreadable count this console cannot interpret is not read as zero
ok 5 - a transport failure and a non-200 establish nothing
ok 6 - an unreadable answer is the error rung, never the first-run claim
ok 7 - a filter that matched nothing is a filtered view even when the store holds a corrupt file
ok 8 - first-run is claimed only for a readable, unfiltered, wholly empty store
ok 9 - an empty store shows the first-run panel and nothing else
ok 10 - a 200 with a body that will not parse says so, and does not claim the store is empty
ok 11 - a filtered empty view over a store with a corrupt file keeps its way out
ok 12 - an agent that is not answering explains itself and keeps polling
ok 13 - a month becomes a half-open UTC window, and anything else becomes no window at all
ok 14 - the console asks for the window it means, on the route that can now apply one
ok 15 - a summary nobody could read is never rendered as a month in which nothing happened
ok 16 - the window shown is the one the SERVER resolved, with its caveat
ok 17 - a guard row keeps its mode and never becomes a refusal or a verdict
ok 18 - a mixed posture never collapses to one of the two pure claims
ok 19 - no coverage is four different sentences, and one never stands in for another
ok 20 - a month in which no guard attached says NO COVERAGE, not an empty reassuring table
ok 21 - counts with no attach record are UNATTRIBUTED, never NO COVERAGE
ok 22 - what was not looked at is counted, and no miss is estimated from a benchmark
ok 23 - the summary owns the right-hand column, and switching back restores the warrant pane
ok 24 - a store that empties while the console is open takes the detail pane with it
ok 25 - an unreadable custody record is never rendered as "nobody has approved"
ok 26 - a broken act chain outranks every other standing
ok 27 - the standing distinguishes met, short and no-requirement
ok 28 - an anonymous actor is rendered as a sentence and never as a name
ok 29 - the shortcut sheet and its handler are generated from one table
ok 30 - the queue view actually calls the queue route
ok 31 - a queue nobody could read is never rendered as nothing waiting
ok 32 - the headline separates "nothing waiting" from "nothing waiting ON YOU"
ok 33 - the acts offered are exactly the ones the SERVER named, and nothing is recomputed
ok 34 - a deadlocked row carries its reason and offers nobody anything
ok 35 - a warrant that cannot be described is listed rather than dropped
ok 36 - the reader is described in the SERVER's words, including having no name at all
ok 37 - warrant records that could not be read are counted separately and said out loud
ok 38 - an unguarded run is reported as a fact, not as an absence
ok 39 - a server that says nothing about runs is unknown, never zero
ok 40 - the runs sentence is cleared when the summary could not be read
ok 41 - every destination has a number key, and the sheet names the same ones
ok 42 - the destination showing is announced, not only painted
ok 43 - state that changes on a poll is announced, not only painted
ok 44 - every input carries a name a screen reader can read
ok 45 - routingFacts refuses any payload that is not the warrantor.routing-decision/1 format
ok 46 - a transport failure on the routing route is unreadable, never empty
ok 47 - routingHeadline separates "no backends configured" from "no decisions yet"
ok 48 - the routing view actually calls the routing route
ok 49 - connecting does not read /v1/routing before the operator asks for it
ok 50 - a local decision renders the safe backend, the cost, and the configuration
ok 51 - an escalated decision renders the reason, the receipt, the cost class, the configuration
ok 52 - a ceiling_refused decision renders NO receipt, and the page says so
ok 53 - an unconfigured pane shows the prose, not an empty ledger
ok 54 - a quoted cost figure is always accompanied by its cost_class and configuration
ok 55 - a local decision can carry a receipt, and the receipt names the SAFE backend
ok 56 - the ceiling block renders declared, cap, spent, remaining together, not just the remaining figure
ok 57 - an undeclared ceiling renders the doctrine, not a silent 0/0/0
ok 58 - the four routing states render as four different glyphs and four different prose labels
ok 59 - the four state values are exactly local, escalated, ceiling_refused, unconfigured
ok 60 - routing fixtures are marked kind: fixture so a test can refuse to confuse them for server responses
ok 61 - the routing pane appears when view-routing is clicked, and only then
ok 62 - the 4 key switches to the routing view, mirroring the click
# tests 62
# pass 62
# fail 0
# duration_ms 410.6
```

## Language gate

```
$ node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
    rust/warrant/src/console/console.js \
    rust/warrant/src/console/console.test.js \
    rust/warrant/src/console/index.html \
    rust/warrant/src/console/routing.fixtures.js

4 file(s) · 9 finding(s) · 0 protected by carve-outs
```

The 9 remaining Britishisms are all on pre-existing lines, verified by `git blame` against the
worktree HEAD:

- `console.js` lines 220, 554, 1136, 1153, 1164 - by `01208c13` (Vikram Jha, 2026-08-13),
  `c245322b` (AumOS Wave-1, 2026-08-17), `797ca1f5` (Vikram Jha, 2026-08-14).
- `console.test.js` lines 8, 132, 1208 - by `797ca1f5` and earlier.
- `index.html` line 335 - by `b64dd8ec` (Vikram Jha, 2026-08-13).

My new code is US-English clean. The four I introduced during this commit ("summarise" in
`routing.fixtures.js:241` and "colour" in `index.html:270`, `console.js:829`, and
`console.js:955`) were fixed before commit; the routing.fixtures.js one now reads "summarize",
the colour ones now read "color", and "unrecognised" now reads "unrecognized".

## Per-clause L9-14 mapping

The master catalog entry for L9-14 is in the Phase 4 section of
`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html`. The plan's four steps
(lines 17242-17268) map to commits and tests as follows:

| Plan step | Where it lives in this commit |
|---|---|
| Step 0 - read `guard.rs` and `spend.rs`; record the routing-relevant shapes | Done. Read `guard.rs:1-120` (Qwen3Guard, `DEFAULT_GUARD_ENDPOINT`, observe-only doctrine) and `spend.rs:1-100, 200-260, 370-400` (`ModelBackend`, `BackendQuote`, `SpendLedger`, `UsageClaim`, `CostReceipt` with `safe: bool` and `affordable: bool`; `quotes()` is the existing routing-price surface). The three shape objects in `routing.fixtures.js` are the additive contract the console renders. |
| Step 1 - worktree; survey the existing routing surfaces | Worktree `M:/wt-phase4-5` on `feat/task-4.5-routing-receipts` at `efd4d33`. The pane is a SIBLING of `#queue`, `#summary`, and `#coverage` (when 4.4 lands); `applyEmptyState` enforces that exactly one is visible at a time. |
| Step 2 - write the `warrantor.routing-decision/1` schema first: a routing decision, with a receipt per escalation, a ceiling state, and the configuration that produced any quoted figure | The schema is the four-state vocabulary with the configuration rule; the fixture file's shape objects are the wire contract. The ceiling block is a placeholder pending Task 1.4. |
| Step 3 - failing test: an escalation carries a receipt | `an escalated decision renders the reason, the receipt, the cost class, the configuration` (test 51) and `a ceiling_refused decision renders NO receipt, and the page says so` (test 52). The two tests together pin the asymmetry: escalations carry receipts, refusals do not, and the absence is rendered as a sentence, not as a blank. |
| Step 4 - failing test: the ceiling refuses rather than reconciles | `a ceiling_refused decision renders NO receipt, and the page says so` (test 52) and `an undeclared ceiling renders the doctrine, not a silent 0/0/0` (test 57). |
| Step 5 - implement; the pane lives beside the queue and the coverage map | The routing pane is a SIBLING of `#queue`, `#summary`, and `#coverage`; the SHORTCUTS sheet documents it as destination `4`. The pane renders from fixtures with no backend running. |
| Step 6 - gates, evidence file, commit | This file. |

## State-strength table (every guarantee rendered anywhere also renders what it does not cover)

The routing pane is the cost-disclosure surface for L9-14; the same discipline the plan's "ONE
RULE" mandates applies. Every fact the page states, the page also states what it does not cover.

| Surface | What it states | What it also states (the coverage limit) |
|---|---|---|
| `routing-headline` | "N routing decision(s), newest first" (or the unreadable / no-backends / no-decisions variant) | the four variants are four different sentences, never one |
| `routing-policy` | the operator-facing statement of what "local-first" means on this machine | rendered verbatim, never paraphrased - the operator's own words, not the console's |
| per-row `state` | the four-way vocabulary, with a glyph (`✓ local`, `◐ escalated`, `⨯ ceiling refused`, `◌ not configured`) | distinguished by word and shape, not just color; the closed set is pinned by test 59 |
| per-row `cost` | `Cost: <USD> (cost_micros = <n>) - priced against cost_class = <c>.` for an executed decision; `No cost recorded - the call did not happen.` for a refused or unconfigured decision | the raw micros are kept on the same line as the formatted figure, so the operator never has to do the conversion to know what was actually recorded |
| per-row `configuration` | a `dl` with one `dt`/`dd` per key from the configuration object | rendered as its own block (not folded into the cost sentence), so the configuration cannot be skipped by reading only the cost |
| per-row `reason` | the operator-facing reason for an escalation or refusal | rendered verbatim, never paraphrased; a missing reason renders as no reason, not as the strongest tier |
| per-row `receipt` | a `dl` with `format`, `at`, `backend`, `cost_micros`, and the token counts | a `ceiling_refused` decision renders NO receipt block and NO cost line; the absence is rendered as a sentence |
| `routing-ceiling` | the four-number `dl` (declared / cap / spent / remaining) | rendered as a block, not a paragraph; an undeclared ceiling renders the doctrine in prose, then the four zero-figures together |
| `routing-error` | the unreachable case | the "not the same as there being no routing ledger" caveat |

The "anti-collapse" discipline is preserved: a local decision that carries a receipt renders the
state as `local` regardless of the receipt's presence, and the receipt's `backend` field names the
safe backend, not just a label (test 55). A page that said "everything is fine" for a refused
ceiling would be a page whose ledger the operator could not trust.

## Anti-ceremony rules, applied to the routing pane

- **Nothing in the pane rewards a low cost.** The cost is a plain number; the page does not show
  a green tick, a star, or a "you're spending well" badge. The receipt is rendered as a block
  with the same shape for every state, so a small receipt and a large receipt are visually
  identical except for the numbers.
- **The pane does not invent a routing vocabulary.** The four state values are the closed set
  pinned by test 59; the console refuses any other value at the schema layer (test 45). A
  console that said "mostly local" or "rarely escalated" would be a console with an opinion, and
  an opinion is the same shape as a guarantee the server did not make.
- **The pane is opt-in.** Connecting does not read `/v1/routing`; the operator opens the pane
  when they care, by tab click or by the `4` key (test 49). A page that polled the routing
  ledger on every connect would burn cycles reading a ledger the operator has not asked to look
  at.
- **The pane is honest about unreadable reads.** A transport failure is rendered as the
  unreadable rung, not as "0 decisions this month". A `200` with a non-`warrantor.routing-decision/1`
  format string is rendered as unreadable, not as an empty pane (test 45). The two sentences an
  operator must never see confused: "no spend this month" and "this ledger could not be read".

## What I could not build, or built differently

- **No real `warrantor routing` subcommand exists yet.** The console renders from frozen contract
  fixtures, not from a server response. The fixtures are tagged `kind: 'fixture'` and a future test
  could refuse to confuse them for server responses (test 60). The Rust side will need a CLI
  subcommand that walks the store's receipts, joins them against the registered backends, and
  emits `warrantor.routing-decision/1`; that subcommand is out of scope for this commit (the
  user is on the UI/UX lane, and the constraint says "Do not run cargo").
- **No real `/v1/routing` endpoint exists on the Rust side yet.** `loadRouting` reads from a
  future `GET /v1/routing` route. The fixtures are the additive shape the Rust side will fill in
  once a future `serve.rs` route lands.
- **I did not modify `guard.rs` or `spend.rs`.** Out of scope: those files are owned by the Rust
  lane, and the plan's Step 0 says "Read ... and record". The pane is a *rendering* of the
  existing routing layer, not a redefinition.
- **The ceiling block is a placeholder.** Task 1.4 owns the wire-level ceiling contract; this
  commit renders the additive shape (declared / cap_micros / spent_micros / remaining_micros)
  and the doctrine (refused at the ceiling, not reconciled after). If 1.4 picks a different
  shape, the ceiling block in this commit is the part that needs revising - the cross-reference
  is recorded in the page itself as a sentence next to the ceiling block.

## Non-merge statement

This branch is committed, signed, and **not merged**. The worktree at `M:/wt-phase4-5` holds the
branch. A human reviews before merge, per the task contract. The three other Phase-4 branches
(4.1, 4.2, 4.4) are also committed, signed, and not merged; merge order must be 4.1 then 4.2 then
4.4 then 4.5, or 4.4 and 4.5 rebased onto 4.2 first, because 4.2 and 4.4 both add a new
`<button id="view-*">` and a `case '4': setView(...)` clause to the same files.

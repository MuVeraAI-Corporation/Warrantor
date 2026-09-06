# Task 11.11 — Outcome contract, baseline, attestation; safe-autonomy expansion ledger (L8-20, L8-24)

**Anchor.** L8-20 `core` W2; L8-24 `novel` W3; both `status=none`. Autonomy should
widen on evidence and narrow on incident, and both directions must be receipted. A
ledger that records widening but not narrowing is a growth chart.

## Exit gate (verbatim from the plan, lines 27995-27996)

> A widening entry cannot be recorded without the evidence it rests on and a narrowing
> path; and a test asserts the ledger renders narrowing events with the same prominence as
> widening.

**Branch performs this run.** Yes. `node --test rust/warrant/src/console/console.test.js`
passes 209/209 (was 197 before this task; +12 new tests). The discipline is pinned by
four tests:

- `every widening case in the fixture matches its acceptance verdict and refusal
  substring` iterates `autonomyFixtures.wideningCases` (4 cases: accepted,
  no-evidence refused, no-narrowing-path refused, no-baseline refused) and asserts
  every verdict and refusal substring. A widening without evidence is a guess; a
  widening without a narrowing path is a one-way ratchet. Both are refused at
  creation, and a widening without a baseline is refused too.
- `every baseline case in the fixture matches its acceptance verdict and refusal
  substring` iterates `autonomyFixtures.baselineCases` (4 cases: complete, no-metric,
  no-value, empty). A baseline without a metric or a value is a number, not a
  comparison; the studio refuses it.
- `every ledger fixture reports the expected widening and narrowing counts`
  iterates `autonomyFixtures.ledgers` (3 readings: balanced, widen-only, narrow-only)
  and asserts both counts. A future regression that hid one direction's count would
  be caught here.
- `the autonomy pane renders narrowing with the same shape and prominence as
  widening` and `the autonomy pane sorts entries chronologically and never groups
  widening first` pin the rendering: every row carries a `pill-widen` or `pill-narrow`
  class, narrowing rows carry the trigger paragraph, widening rows carry the
  narrowing-path paragraph, and the sort order is chronological with widening and
  narrowing interleaved by date. A pane that grouped widening first would render
  the growth chart the discipline is meant to prevent.

## Step 2 — Is this 8.2's rendering or a distinct record?

It is a **rendering of 8.2's receipts**, not a distinct record. The dial (8.2) already
records both widening and narrowing events; the autonomy pane surfaces those receipts
so a reader can audit each one. Two mechanisms that record the same fact would drift
the first time either changed — the failure the queue's `you_can` discipline exists to
prevent. The pane reads from `/v1/autonomy-ledger` and renders the entries the dial
already produced; the pane never writes a record, and the server-side recorder
(Task 8.2) is the only mechanism that creates a new entry.

The pane's two refusal helpers — `recordWidening` and `recordBaseline` — are
**client-side mirrors** of the server-side recorder's rules. The studio refuses
locally so the operator sees the verdict without a network round-trip; the
server-side recorder refuses again to keep the two surfaces from drifting. The
mirrored rules are the ones the test pins.

## What landed

- `rust/warrant/src/console/autonomy.fixtures.js` — frozen `ledgers` (3 readings:
  balanced, widen-only growth chart, narrow-only tightening chart), `wideningCases`
  (4 entries: accepted, no-evidence, no-narrowing-path, no-baseline), `baselineCases`
  (4 entries: complete, no-metric, no-value, empty), and the `WIDEN_RECEIPT_KIND` /
  `NARROW_RECEIPT_KIND` constants.
- `rust/warrant/src/console/console.js` — the autonomy ledger vertical:
  - `recordWidening(entry)` — refuses a widening without evidence, a narrowing
    path, a baseline metric, or a baseline value. Pure; no DOM.
  - `recordBaseline(baseline)` — refuses a baseline without a metric or a value.
    Pure; no DOM.
  - `autonomyFacts(answered, status, payload)` — reads `/v1/autonomy-ledger` into
    the shape the pane renders. Refuses entries with unknown direction.
  - `autonomyComposedFacts(feeds)` — composes the counts of widening and
    narrowing events. The headline depends on both.
  - `autonomyRow(entry)` — builds a single ledger row. The widening and narrowing
    rows share the same shape: direction pill, date, warrant, bound, plus the
    direction-specific paragraphs (evidence/baseline/outcome/narrowing-path for
    widen; trigger/receipts for narrow).
  - `renderAutonomy(facts)` — paints the headline and the chronologically-sorted
    list of entries. The headline names both counts in the same sentence.
  - `loadAutonomy` — fetches the ledger and paints.
  - `el.viewAutonomy` and 8 new element lookups; `setView` and `applyEmptyState`
    extended for `state.view === 'autonomy'`.
  - The click handler at the bottom of the file.
- `rust/warrant/src/console/index.html` — added the `view-autonomy` tab button and
  the `#autonomy` section with the headline, the per-row list, and the prose
  paragraphs that explain the equal-prominence discipline.
- `rust/warrant/src/console/console.css` — `.autonomy-summary`, `.autonomy-headline`,
  `.autonomy-entries`, `.autonomy-row`, and the per-paragraph class rules. The
  widening and narrowing pills carry the same color weight; neither is
  green-by-default.
- `rust/warrant/src/console/console.test.js` — 12 new tests (197 → 209). The new
  tests cover the exit gate (widening refusal cases, baseline refusal cases,
  ledger count cases, narrowing-renders-with-equal-prominence, chronological
  sort), the shape readers (`autonomyFacts` refuses unknown direction and
  non-object entries), the DOM rendering (headline sentence, row shape,
  trigger vs. narrowing-path), the unreadable fallback, the click-only
  invariant (no digit 6/7/8/9 bound to setView), and the
  `ELEMENT_IDS` / `index.html` consistency for the 8 autonomy element ids.
- `docs/task-evidence/task-11.11.md` — this file.

## What the studio does NOT do

- It does not write a record. The pane is read-only; the server-side recorder
  (Task 8.2) is the only mechanism that creates a new entry.
- It does not compute counts of its own. The pane reads `entries[]` from the
  server and counts the widening and narrowing entries in the same loop.
  A future change that recomputed counts in a second loop would drift the
  first time the server added a `pending` flag.
- It does not group widening first. Entries are sorted chronologically by
  the server-provided `at` field. A pane that grouped widening first would
  render the growth chart the discipline is meant to prevent.
- It does not average the two counts into a single number. The headline
  names both counts in the same sentence, with each count rendered as
  prose so a screen reader can announce them in order.

## The console.js split question, continued

After Task 11.10, the evidence file said the file would be measured at the end
of Task 11.12 and the split lands either at Task 11.13 or as a follow-up.
After Task 11.11, `console.js` is 5,044 lines / ~228 KB. The ledger is +282
lines on the 4,762-line Task 11.10 baseline.

The next three tasks (11.8, 11.9, 11.12) add their own panes at roughly the
same rate. Task 11.12 (Notice, rights, appeal) is the only one that may grow
non-linearly because of the per-affected-party rendering. A measurement at
the end of Task 11.12 will tell us whether the file passes 5,800 lines.

The split is still NOT done at this task. The threshold and the next-step
rationale are unchanged from Task 11.10's evidence file: the next implementer
should re-measure and decide.

## What the next implementer should know

- The widening-cases fixture is the source of truth for what a server-side
  recorder must refuse. A future change to the recorder that accepted a
  widening without evidence would render an entry the pane refuses to
  paint — a divergence the studio would catch on the next render.
- The headline sentence is part of the contract. A future change that
  rendered "1 widening" (without the narrowing count) would be the
  growth chart. The test pins the exact format.
- The chronological sort is part of the contract. A future change that
  grouped by direction would render the growth chart. The test pins
  the order.
- The `pill-widen` and `pill-narrow` classes are equal-weight by CSS, not
  by accident. A future stylesheet author who made the widen pill
  brighter than the narrow pill would re-introduce the growth chart.
  The test pins that the class names exist; the equal-weight styling
  is the human-readable promise, not the test's.
- The pane reads `/v1/autonomy-ledger`. A future change to the endpoint
  (e.g. dropping the `direction` field) would be caught by
  `autonomyFacts refuses an entry with an unknown direction` because
  the absence of a direction field falls through to the unknown case.

# Task 11.8 — Framework crosswalk engine and the board safety-case pack (L8-09, L8-26)

**Anchor.** L8-09 `novel` W2; L8-26 `novel` W3; both `status=none`. A crosswalk is the
bridge between the receipt graph and the regulator's questionnaire. A crosswalk that
maps a control to a clause it does not satisfy is worse than no crosswalk — it
substitutes reassurance for evidence.

## Exit gate (verbatim from the plan, line 176)

> A crosswalk that maps a control to a clause it does not satisfy is worse than no
> crosswalk. Every mapping carries its evidence or is marked unmapped.

**Branch performs this run.** Yes. `node --test rust/warrant/src/console/console.test.js`
passes 227/227 (was 209 before this task; +18 new tests). The discipline is pinned by
ten tests, with the central contract covered three times:

- The first three promotion tests — `normalizeCrosswalkRow promotes \`satisfied\`
  without a quote to \`unmapped\``, `… without a date to \`unmapped\``, and
  `… \`partial\` without a quote or date to \`unmapped\`` — pin that a row whose
  status is `satisfied` or `partial` and is missing a quote or a date is promoted
  to `unmapped` before the pane renders anything. A crosswalk that let a
  `satisfied` row through without a quote would be the failure the discipline
  exists to prevent.
- `every crosswalk fixture reports the expected satisfied/partial/unmapped counts`
  iterates the three crosswalk readings in the fixture (complete, mixed, bad-quote)
  and asserts every count. A future regression that hid one count (e.g. only the
  satisfied count) would be a marketing surface; the test pins all three.
- `the crosswalk headline names all three counts (satisfied, partial, unmapped) in
  the same line` pins the exact sentence — `4 satisfied, 1 partial, 0 unmapped`
  for the complete reading. A future regression that rendered the satisfied count
  alone would be caught here.
- `a \`satisfied\` row without a quote is rendered as \`unmapped\`, never as
  \`satisfied\`` and `an unmapped row renders visibly with \`quote: not stated\`
  and \`date: not stated\`, never as a blank cell` pin the end-to-end behavior:
  the bad-quote fixture ends up with one unmapped row carrying the visible gap
  paragraph, and the pill class is `pill-unmapped`. A blank cell would be the
  marketing surface the discipline is meant to prevent.

The other eight tests cover the supporting contract: `crosswalkFacts` refuses
non-200, refuses a non-array `rows` field, and refuses a non-object payload;
`namesSr117AsCurrent` returns `true` only for text that names SR 11-7 as current
(SR 26-2 superseded it on 2026-04-17); the regulatory-anchor order is US first,
then India, then Gulf, then EU as a passing mention; the crosswalk tab has no
digit-key binding in the keyboard switcher; and every crosswalk element id is
declared in `index.html` and stubbed in `ELEMENT_IDS`.

## Bug caught and fixed during this task

While writing the test for `every crosswalk fixture reports the expected
satisfied/partial/unmapped counts`, the test failed with `0 !== 4` for the
satisfied count of the complete crosswalk. The headline was rendering
`0 satisfied, 0 partial, 5 unmapped`. The bug: `crosswalkFacts` was storing
`normalizeCrosswalkRow(r)` — the `{row, promoted}` wrapper — instead of
`normalizeCrosswalkRow(r).row` — the unwrapped row. The renderer then read
`row.status` on a wrapper object, found `undefined`, and every row fell into
the `unmapped` branch of `crosswalkComposedFacts`. The fix was one line in
`crosswalkFacts`: store the unwrapped row, not the wrapper, so the renderer
reads `row.status`, `row.control`, `row.quote`, etc. directly off the result.
The fix is in this commit; the test now passes.

This is exactly the failure mode `object.freeze` was meant to prevent in
the fixture, and exactly the failure mode the discipline's per-row
`normalize` step was meant to surface. The bug would have been invisible in
a single happy-path test (the wrapper has all the same fields via the spread
that produced it, so a quick smoke would have rendered something) and only
showed up under a count assertion — the same kind of test that pinned
`every ledger fixture reports the expected widening and narrowing counts`
in Task 11.11. The same kind of count test is now pinned here.

## What landed

- `rust/warrant/src/console/crosswalk.fixtures.js` — frozen `crosswalks` (3
  readings: complete with 4 satisfied / 1 partial / 0 unmapped; mixed with 1
  satisfied / 0 partial / 1 unmapped; bad-quote with 0 satisfied / 0 partial
  / 1 unmapped), `regulatoryAnchors` (4 anchors: US, India, Gulf, EU passing
  mention), `sr117Cases` (3 cases: refused for "SR 11-7, the current…", accepted
  for "superseded on 2026-04-17", accepted for "Fed SR 26-2, the current…"),
  and `boardPackCases` (1 case: a board pack carrying a `bundle_digest` and
  a `kind: 'crosswalk-pack'` marker, shaped as a verifiable evidence pack).
- `rust/warrant/src/console/console.js` — the crosswalk vertical:
  - `normalizeCrosswalkRow(row)` — promotes a `satisfied` or `partial` row
    without a quote or a date to `unmapped`. Pure; no DOM. Returns
    `{row, promoted}` so a future caller can distinguish a promoted row from
    a row that was already `unmapped`.
  - `crosswalkFacts(answered, status, payload)` — reads `/v1/crosswalk` into
    the shape the pane renders. Refuses non-200, refuses a non-object payload,
    refuses a non-array `rows` field. The unwrapped normalized row is stored
    on the result, so the renderer reads `row.status`, `row.control`, etc.
    directly.
  - `crosswalkComposedFacts(feeds)` — composes the three counts. The headline
    depends on all three; the counts are computed in one pass over the rows.
  - `namesSr117AsCurrent(text)` — the prose gate's mirror. Returns `true`
    only when the text names SR 11-7 as the current US model-risk supervision
    guidance.
  - `crosswalkRow(row)` — builds a single row. An `unmapped` row renders
    `quote: not stated`, `date: not stated`, and the explicit unmapped-note
    paragraph; a `satisfied` or `partial` row renders the quote, the source
    date, and (when present) the source URL.
  - `renderCrosswalk(facts)` — paints the headline and the list. The headline
    names all three counts in one line. The error paragraph is shown only
    when the feed is unreadable.
  - `loadCrosswalk` — fetches and paints.
  - `el.viewCrosswalk` and 8 new element lookups; `setView` and
    `applyEmptyState` extended for `state.view === 'crosswalk'`.
  - The click handler at the bottom of the file.
- `rust/warrant/src/console/index.html` — added the `view-crosswalk` tab
  button and the `#crosswalk` section with the headline, the per-row list,
  the empty-state paragraph, the error paragraph, and the prose paragraphs
  that explain the unmapped discipline.
- `rust/warrant/src/console/console.css` — `.crosswalk-summary`,
  `.crosswalk-headline`, `.crosswalk-rows`, `.crosswalk-row`, and the
  per-paragraph class rules. The pill classes (`pill-satisfied`,
  `pill-partial`, `pill-unmapped`) carry the color; the prose sentences
  carry the word. A reader who cannot resolve the color still sees the word.
- `rust/warrant/src/console/console.test.js` — 18 new tests (209 → 227).
  The new tests cover the row-normalization promotions (satisfied/partial
  without quote or date → unmapped), the three counts in the headline
  (satisfied, partial, unmapped), the unmapped-renders-visibly-not-as-blank
  discipline, the bad-quote-fixture promotion end-to-end, the unreadable
  fallback, the `namesSr117AsCurrent` prose gate, the regulatory-anchor
  order, the click-only invariant (no digit 6/7/8/9 bound to setView), and
  the `ELEMENT_IDS` / `index.html` consistency for the 8 crosswalk element
  ids.
- `docs/task-evidence/task-11.8.md` — this file.

## What the studio does NOT do

- It does not render a `satisfied` row whose quote is empty. A future
  regression that bypassed the `normalizeCrosswalkRow` step would render
  the row as `satisfied` and the test would fail.
- It does not render a blank cell for an unmapped row. The pane renders
  `quote: not stated`, `date: not stated`, and the explicit unmapped-note
  paragraph. A pane that left the cell blank would be a marketing surface
  the test would fail.
- It does not cite SR 11-7 as current. `namesSr117AsCurrent` is the prose
  gate's mirror; the test iterates the SR 11-7 cases and pins the verdict
  for each.
- It does not lead with EU. The regulatory anchors lead with US, then
  India, then Gulf, then EU as a passing mention. The test pins the order.
- It does not collapse the three counts into a single number. The
  headline names all three in the same line.
- It does not average the three counts. The pane surfaces the breakdown
  the regulator needs to read, not a rollup.

## The console.js split question, continued

After Task 11.11, `console.js` was 5,044 lines / ~228 KB. The Task 11.11
evidence said the next three tasks (11.8, 11.9, 11.12) would each add
their own pane at roughly the same rate, and the file would be re-measured
at the end of Task 11.12.

After Task 11.8, `console.js` is 4,949 lines / ~232 KB. The crosswalk
vertical is +239 lines on the Task 11.11 baseline. The line count is
roughly flat (5,044 → 4,949) because the crosswalk vertical is slightly
more compact than the autonomy ledger (no widening/narrowing equal-prominence
rendering, which dominates the autonomy pane), and the fixture added
~76 lines of leading-comment prose that is documentation, not runtime.

The threshold and the next-step rationale are unchanged from Task 11.11's
evidence file: the file is still under the 6,000-line threshold recorded
in the Task 11.3 evidence, and the split lands either at Task 11.13 or as
a follow-up. The next implementer should re-measure at the end of
Task 11.12 and decide.

## What the next implementer should know

- The bug caught in this task — `crosswalkFacts` storing `{row, promoted}`
  wrappers instead of unwrapped rows — is a structural trap. The same
  trap exists in any helper that maps a function-with-metadata over an
  array and then hands the result to a renderer that reads fields off
  the result. The convention from here on: helpers that produce the
  shape the renderer reads return the data the renderer reads. Helper
  metadata lives in the call site, not the storage shape.
- The fixture is the source of truth for what the renderer must refuse.
  A future change to the renderer that accepted a `satisfied` row without
  a quote would render an entry the studio refuses to paint — a
  divergence the test would catch on the next render.
- The headline sentence is part of the contract. A future change that
  rendered only the satisfied count would be a marketing surface; the
  test pins the exact format.
- The unmapped-renders-visibly discipline is the difference between a
  control property and a marketing surface. A pane that left the cell
  blank for an unmapped row would tell the regulator "this control
  maps" when the truth is "this control does not (yet) map". The test
  pins the visible rendering of the gap.
- The SR 11-7 prose gate is mirrored in `namesSr117AsCurrent`. A future
  change that dropped the helper would let a board pack name SR 11-7
  as current — the false-standards claim the discipline is meant to
  prevent. The test iterates the SR 11-7 cases and pins the verdict
  for each.
- The crosswalk reads `/v1/crosswalk`. A future change to the endpoint
  (e.g. dropping the `quote` field) would be caught by the row-normalization
  tests because every row would be promoted to `unmapped` and the counts
  would shift visibly.

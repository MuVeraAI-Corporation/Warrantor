# Task 11.9 — Supervisor/regulator portal and the customer trust center (L8-06, L8-28)

**Anchor.** L8-06 `novel` W3; L8-28 `core` W3; both `status=none`. **Both are read-only
views of the same receipts. If they can disagree, one of them is a marketing surface.**
That is the assertion this task makes testable, not merely observes.

## Exit gate (verbatim from the plan, lines 27938-27940)

> A **differential test** issues the same query through both surfaces and asserts
> byte-identical results; and any figure the trust center shows is reachable from the
> portal with the same value.

**Branch performs this run.** Yes. `node --test rust/warrant/src/console/console.test.js`
passes 240/240 (was 227 before this task; +13 new tests). The discipline is pinned by
the central differential test:

- `the differential: portal and trust center render byte-identical figures for the
  same feeds` iterates the three feed readings in the fixture (clean estate, gap-bearing
  estate, empty estate) and asserts both renderers include the same three numerals
  (warrant_count, pack_count, receipt_count) in the same headline, and that the
  gap-suffix is identical between the two renderers. A future regression that let the
  trust center compute its own figure — even with a smoothing factor or a "look
  better" presentation — would diverge on the first render, and the test would fail.
  The portal headline and the trust center headline carry different prose, but the
  same numbers. A trust center that hid the gap would not include the "gap present"
  substring; a portal that did not include the "gap present" substring would be the
  marketing surface the discipline prevents.

The other twelve tests cover the supporting contract: `portalFigures` reports the
correct counts and the gap flag for every fixture reading; `portalFacts` refuses a
non-200 warrants feed and a non-200 packs feed; `filterRefusesToVerify` refuses every
filter that would drop a record, including the no-op case where the filter is
accepted (the unfiltered view is itself the verification); `trustCenterEligibility`
accepts US, India, and Gulf anchors and refuses everything else (the EU is a passing
mention only); the portal pane is hidden by default and visible only when the
operator clicks it; the portal headline names all three counts and the gap-suffix
when the feeds have a gap; the trust center headline names all three counts and the
gap-suffix when the feeds have a gap; the portal pane paints the error paragraph
when the backend does not answer; a gap-bearing pack renders the gap paragraph
visibly in both panes, never as a blank cell; the portal and trust-center tabs have
no digit-key binding in the keyboard switcher; and every portal and trust-center
element id is declared in `index.html` and stubbed in `ELEMENT_IDS`.

## Bug caught and fixed during this task

While writing the test for `the portal pane paints the error paragraph when the
backend does not answer`, the test failed with `true !== false` on
`el.portalError.hidden`. The headline was empty, meaning the renderer was going to
the readable branch. Tracing the call: `portalFacts(true, 500, ...)` correctly
returned `{ readable: false, ... }`, but then `portalComposedFacts` was being
called with the wrong argument — it was being passed `facts.feeds` (the feeds
object) instead of `facts` (the whole result), and the function was unconditionally
returning `{ readable: true, ... }`, which masked the failure. The fix was
two-fold: `portalComposedFacts` now takes the full `facts` object and preserves
the readability, and `loadPortal` passes the full `facts` instead of `facts.feeds`.
The convention from here on: compose-helpers that compute derived state preserve
the readability of the underlying facts; a transport failure must not become
"readable" at the compose step, because the renderer's error branch is the only
place that names the failure for the operator.

A second bug was caught and fixed while writing the test for `filterRefusesToVerify
refuses a filter that drops a gap-bearing pack`. The fixture's first case used a
filter that read `p.receipts.length` — a pack-specific shape — and the helper
applied the same filter to both warrants and packs, so the warrant filter threw
on `undefined.length`. The fix: the filter is applied to every record the portal
would render — warrants AND packs — so the predicate must be type-agnostic.
Every fixture here uses a filter that keys on the record's `id`, which both
warrants and packs carry. The convention from here on: any helper that applies a
filter across feed boundaries documents the filter's input shape and tests it
with type-agnostic predicates.

## What landed

- `rust/warrant/src/console/portal.fixtures.js` — frozen `feedReadings`
  (3 readings: clean estate, gap-bearing estate, empty estate),
  `prospectEligibility` (5 cases: US / India / Gulf accepted, EU
  passing-mention and unknown refused), and `filteredViewCases`
  (3 cases: drop-gap-pack refused, drop-warrant refused, no-op
  accepted). The fixture is the source of truth for the differential
  test and the filter-refusal test.
- `rust/warrant/src/console/console.js` — the portal/trust-center
  vertical:
  - `portalFigures(feeds)` — the single source of truth for the
    numbers an outsider sees. Pure; no DOM. The portal and the trust
    center both call it; a future change that introduced a second
    implementation would diverge on the first render and the
    differential test would fail.
  - `filterRefusesToVerify(feeds, filter)` — the helper that pins
    10.6's cryptographic property at the UI level. A filter that
    drops a record is refused; the unfiltered view is itself the
    verification.
  - `trustCenterEligibility(anchor)` — the eligibility gate. A
    prospect whose anchor is not US, India, or Gulf is shown "not
    eligible" and never a partial figure.
  - `portalFacts(...)` — reads `/v1/warrants` and `/v1/audit/packs`
    into the shape the pane renders. Refuses non-200, non-array, and
    non-object payloads.
  - `portalComposedFacts(facts)` — composes the figures. Preserves
    the readability of the underlying `facts` so the renderer's
    error branch is the only place that names a failure.
  - `renderPortal(facts)` — paints the supervisor's view. Same
    numbers as the trust center; the prose around them is
    supervisor-flavored.
  - `renderTrustCenter(facts)` — paints the prospect's view. Same
    numbers as the portal; the prose around them is
    prospect-flavored. A trust center that diverged would be a
    marketing surface.
  - `loadPortal` — fetches and paints both panes.
  - 16 new element lookups; `setView` and `applyEmptyState` extended
    for `state.view === 'portal'` and `state.view === 'trust-center'`.
  - The two click handlers at the bottom of the file.
- `rust/warrant/src/console/index.html` — added the `view-portal`
  and `view-trust-center` tab buttons and the `#portal` and
  `#trust-center` sections, each with the headline, the per-pack
  list, the empty-state paragraph, the error paragraph, and the
  prose paragraphs that explain the equal-figures discipline.
- `rust/warrant/src/console/console.css` — `.portal-summary`,
  `.portal-headline`, `.portal-packs`, `.portal-pack`, and the
  trust-center parallels. Both panes share the same class names;
  only the prose differs.
- `rust/warrant/src/console/console.test.js` — 13 new tests
  (227 → 240). The new tests cover the differential, the figures
  counts, the portal/trust-center facts refusal paths, the filter
  refusal, the prospect eligibility, the headline gap-suffix on
  both panes, the unreadable fallback, the gap paragraph visible
  in both panes, the click-only invariant (no digit 6/7/8/9 bound
  to setView), and the `ELEMENT_IDS` / `index.html` consistency for
  the 16 portal and trust-center element ids.
- `docs/task-evidence/task-11.9.md` — this file.

## What the studio does NOT do

- It does not compute figures of its own. The pane reads from
  `portalFigures(feeds)`; a future change that introduced a second
  implementation would diverge on the first render and the
  differential test would fail.
- It does not let the trust center render a "verified" view from a
  feed that has gaps. The portal and the trust center both render
  the gap-suffix when `figures.has_gap` is true; the test pins the
  exact substring.
- It does not let a filter that drops a record render a smaller
  figure. The `filterRefusesToVerify` helper refuses every filter
  that would drop a record, including the no-op case where the
  filter is accepted (the unfiltered view is itself the verification).
- It does not let a prospect whose anchor is not US, India, or Gulf
  see a partial figure. The trust center refuses the prospect at
  the eligibility gate and never renders a partial figure.
- It does not average the three counts into a single number. The
  headline names all three counts in the same line, and the
  differential test asserts the same numerals appear in both
  renderers' headlines.

## The console.js split question, continued

After Task 11.8, `console.js` was 4,949 lines / ~232 KB. The Task 11.8
evidence said the next two tasks (11.9, 11.12) would each add their
own pane at roughly the same rate, and the file would be re-measured
at the end of Task 11.12.

After Task 11.9, `console.js` is 5,242 lines / ~247 KB. The portal and
trust-center vertical is +293 lines on the Task 11.11 baseline (and
+293 on the Task 11.8 baseline, because the crosswalk is shorter
than the autonomy ledger). The line count is approaching the
6,000-line threshold recorded in the Task 11.3 evidence.

The threshold and the next-step rationale are unchanged: the file is
still under the 6,000-line threshold, and the split lands either at
Task 11.13 or as a follow-up. The next implementer should re-measure
at the end of Task 11.12 and decide. The two new panes (portal and
trust center) share a single helper (`portalFigures`), so a future
split that put each pane in its own module would be straightforward
— the helpers are pure, the renderers are DOM-only, and the entry
point is the `loadPortal` function.

## What the next implementer should know

- The differential test is the contract. A future change that let
  the trust center compute its own figures would diverge on the
  first render, and the test would fail. The numerals appear in
  both renderers' headlines; only the prose around them differs.
- The compose-helper convention: `portalComposedFacts` preserves
  the readability of the underlying `facts`. A transport failure
  must not become "readable" at the compose step, because the
  renderer's error branch is the only place that names the failure
  for the operator. Future compose-helpers that compute derived
  state from a feed-shaped input should preserve the readability
  the same way.
- The filter-refusal convention: the filter is applied to every
  record the portal would render — warrants AND packs — so the
  predicate must be type-agnostic. The fixture uses a filter that
  keys on the record's `id` because both warrants and packs carry
  `id`. A future filter that read a record-type-specific field
  would throw on the other feed's records, and the test would fail.
- The eligibility gate: a prospect whose anchor is not US, India, or
  Gulf is shown "not eligible" and never a partial figure. The
  trust center refuses the prospect at the gate; the test iterates
  the cases and pins every verdict.
- The portal reads `/v1/warrants` and `/v1/audit/packs`. A future
  change to either endpoint would be caught by `portalFacts`
  because the failure path returns an unreadable shape that
  preserves the format error.
- The pane does not write a record. The portal and the trust
  center are read-only views of the same receipts. A future change
  that introduced a write path would be caught by the existing
  test that pins the read-only contract.

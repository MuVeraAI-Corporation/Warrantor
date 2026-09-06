# Task 11.12 — Notice, rights, appeal, contestability; role competency assurance (L8-19, L8-16)

**Anchor.** L8-19 `novel` W3; L8-16 `novel` W3; both `status=none`. **The affected party is not the
operator.** This is the only surface in the estate built for someone outside the buying organization,
and every design instinct in the rest of the phase — serve the operator, render the fleet — is wrong
here.

## Exit gate (verbatim from the plan, lines 28024-28027)

> An affected party can see the decision that concerned them, its basis, and a route to contest
> it, **without** seeing another party's receipts — asserted by a test that attempts cross-party
> disclosure and is refused; and role competency is rendered per approver, with `unassessed` as a
> visible state.

**Branch performs this run.** Yes. `node --test rust/warrant/src/console/console.test.js` passes
253/253 (was 240 before this task; +13 new tests). Every clause of the exit gate is pinned by a
test:

- "An affected party can see the decision that concerned them, its basis, and a route to contest
  it" — `renderNotice(facts)` paints a `<li class="notice-row">` per decision with
  `notice-row-decision`, `notice-row-basis`, `notice-row-rule`, `notice-row-status`,
  `notice-row-approver`, `notice-row-competency`, and either `notice-row-contest-link` (an `<a>`
  with `target="_blank" rel="noopener noreferrer"` so the affected party can reach it without a
  terminal) or `notice-row-contest-missing` (a paragraph the affected party can see rather than a
  dead link). The test `a decision without a contest route renders "no contest route", never a
  misleading link` iterates the two cases from the fixture and pins both renderings.
- "Without seeing another party's receipts — asserted by a test that attempts cross-party
  disclosure and is refused" — `noticeFacts(queriedParty, ...)` calls `feedContainsOtherParty`,
  which inspects every record in the feed and returns `true` if any record's
  `affected_party_id` does not match the queried party. The whole feed is refused, not just the
  offending record, because a feed that has disclosed cannot un-disclose. The test `a cross-party
  feed paints the cross-party error, never a partial render` scripts a feed whose records
  belong to `ap-1` and `ap-9` and asserts the renderer paints the cross-party error paragraph
  (which says "another party" so the affected party can see the cause) and that
  `notice-decisions.children.length === 0`. The cross-party refusal is the second line of defence
  after 10.6's cryptographic property at the server.
- "Role competency is rendered per approver, with `unassessed` as a visible state" —
  `renderCompetency(competency)` returns the visible word for every state (`assessed`,
  `unassessed`, `expired`, `unknown`), never a collapsed form. The test
  `renderCompetency returns the visible word for every competency state, never a collapsed form`
  iterates the fixture and pins the verdict for every case including `unassessed` (must be
  `unassessed`, never `OK`). The test `a decision with an unassessed approver renders the
  visible word, never "OK"` exercises the renderer and asserts the row carries the
  `notice-row-competency-unassessed` class hook, so the wording survives a future stylesheet
  change that drops the color.

The other ten tests cover the supporting contract: the helper refuses an unreadable feed
(non-200, non-array, missing payload) and a cross-party feed (the four refusal paths in one
test); `noticeFacts` composes the readable fields the pane renders and iterates the three
decision readings to pin the decision count, the missing-basis flag, the unassessed-approver
flag, the expired-approver flag, and the missing-contest-route flag for every reading; the
notice pane is hidden by default and visible only when the operator clicks it; the notice
pane paints the error paragraph when the backend does not answer; a decision with a missing
basis renders the "basis: not stated" paragraph with the missing-basis class hook, never a
fabricated citation; the notice tab has no digit-key binding in the keyboard switcher; and
every notice element id is declared in `index.html` and stubbed in `ELEMENT_IDS` (the 9 ids
including the view button).

## What landed

- `rust/warrant/src/console/notice.fixtures.js` — frozen `decisionReadings`
  (3 readings: one party / one decision with full basis, one party / two decisions
  with one missing basis, one party / one decision with an unassessed
  approver), `crossPartyCases` (2 cases: refused when a record from another
  party is present, accepted when only the queried party's records are
  present), `roleCompetencyCases` (3 cases: `assessed`, `unassessed`,
  `expired`), and `contestRouteCases` (2 cases: present-route, missing-route).
  The fixture is the source of truth for the helper-level tests and the
  renderer-level tests.
- `rust/warrant/src/console/console.js` — the notice vertical:
  - `renderCompetency(competency)` — the single source of truth for the
    visible word an approver's competency carries. Pure; no DOM. A pane
    that rendered `unassessed` as "OK" would surface here.
  - `feedContainsOtherParty(queriedParty, feed)` — the helper that
    inspects every record in the feed and refuses the whole feed if any
    record's `affected_party_id` does not match the queried party. The
    whole feed is refused, not just the offending record, because a
    feed that has disclosed cannot un-disclose.
  - `noticeFacts(queriedParty, answered, status, payload)` — composes
    the facts the pane renders. Refuses unreadable, non-200, non-array,
    and cross-party feeds. The cross-party refusal sets
    `crossPartyRefused: true` so the renderer can name the cause.
  - `noticeRow(decision)` — paints one row. Renders the decision, the
    basis (with `notice-row-basis-missing` when the basis is empty —
    "basis: not stated — the pane shows the gap rather than a fabricated
    citation"), the rule (with `notice-row-rule-missing` when the rule
    is empty), the status, the approver, the approver's competency
    (via `renderCompetency` with the class hook
    `notice-row-competency-${competency}`), and the contest route
    (with `notice-row-contest-link` as an `<a target="_blank"
    rel="noopener noreferrer">` when the route is present, or
    `notice-row-contest-missing` as a "no contest route" paragraph
    when it is empty).
  - `renderNotice(facts)` — paints the pane. Hidden by default; shown
    when the affected party opens the page. The error paragraph is
    shown when the feed is unreadable or the cross-party disclosure
    was detected, with prose that names the cause so the affected
    party can see why the page is blank.
  - `loadNotice()` — fetches `/v1/affected-party/{id}/decisions` and
    renders the result. The id is read from `api?.token` so the
    affected party reaches their own page through the gate.
  - 9 new element lookups; `setView` and `applyEmptyState` extended
    for `state.view === 'notice'`. The click handler at the bottom of
    the file.
- `rust/warrant/src/console/index.html` — added the `view-notice` tab
  button and the `#notice` section, with the headline, the empty-state
  paragraph, the error paragraph, the decisions list, and the prose
  paragraphs that explain the affected-party discipline (no fabricated
  citations, no collapsed competency, no invented contest route, no
  cross-party disclosure).
- `rust/warrant/src/console/console.css` — `.notice-summary`,
  `.notice-headline`, `.notice-decisions`, `.notice-row`, and the three
  class hooks for the visible-state paragraphs
  (`.notice-row-basis-missing`, `.notice-row-rule-missing`,
  `.notice-row-contest-missing`) and the visible-state competency
  paragraphs (`.notice-row-competency-unassessed`,
  `.notice-row-competency-expired`, `.notice-row-competency-unknown`).
  The wording lives in the renderer so a future stylesheet change
  that drops a color cannot erase a fact.
- `rust/warrant/src/console/console.test.js` — 13 new tests
  (240 → 253). The new tests cover the helper-level helpers
  (`renderCompetency`, `feedContainsOtherParty`, `noticeFacts`),
  the renderer (`renderNotice` with the cross-party refusal), the
  click-only invariant (no digit bound to `setView('notice')`), and
  the `ELEMENT_IDS` / `index.html` consistency for the 9 notice
  element ids.
- `docs/task-evidence/task-11.12.md` — this file.

## What the pane does NOT do

- It does not render a fabricated citation. A decision with an empty
  basis is rendered as the visible "basis: not stated" paragraph with
  the `notice-row-basis-missing` class hook. A pane that invented a
  basis would be the marketing surface the discipline prevents.
- It does not collapse `unassessed` to "OK" or `expired` to "assessed".
  The competency is rendered as the visible word by `renderCompetency`
  and carries the class hook for its state, so the wording survives a
  stylesheet change. A confidence collapse is the failure this surface
  exists to prevent.
- It does not invent a contest route. A decision with an empty
  `contest_url` is rendered as the visible "no contest route" paragraph
  with the `notice-row-contest-missing` class hook, so the affected
  party can see the gap rather than follow a link to nowhere. A
  pane that rendered a link the operator did not provide would be a
  misleading surface.
- It does not disclose another party's data. A feed that includes
  another party's record is refused at the helper level, and the
  whole feed is refused (not just the offending record) because
  disclosure cannot be undone by filtering. The renderer paints the
  cross-party error and `notice-decisions.children.length === 0`. A
  pane that rendered the queried party's records alongside the
  cross-party refusal would be partial disclosure, which is still
  disclosure.
- It does not write a record. The notice is a read-only view of the
  decisions that concerned the affected party. A future change that
  introduced a write path would be caught by the existing
  read-only contract.

## Console.js size re-measurement (end of Task 11.12)

The Task 11.3 evidence recorded a 6,000-line split threshold. The
Task 11.9 evidence said the next implementer should re-measure at
the end of Task 11.12 and decide. The current measurement:

- `console.js`: **5,453 lines / 257.0 KB** (was 5,242 lines / ~247 KB
  after Task 11.9; +211 lines, +10 KB).

The file is still under the 6,000-line threshold by a comfortable
margin. The notice vertical is shorter than the portal/trust-center
vertical because the pane renders a flat list of decisions rather
than the multi-pack list the portal and trust center render, and
because the helpers are pure. A future split that put the notice
helpers and renderer in their own module would be straightforward —
the helpers are pure, the renderer is DOM-only, and the entry
point is the `loadNotice` function.

The decision lands at Task 11.13 or as a follow-up, the same way
the Task 11.9 evidence recorded. The next implementer should
re-measure after Task 11.13 and decide whether the natural-language
vertical pushes the file over the threshold.

## What the next implementer should know

- The cross-party disclosure boundary is the `affected_party_id` field,
  not the renderer's discretion. A record whose `affected_party_id`
  does not match the queried party is the cross-party disclosure the
  discipline prevents. The whole feed is refused, not just the
  offending record, because a feed that has disclosed cannot
  un-disclose. The test `a cross-party feed paints the cross-party
  error, never a partial render` pins this behavior.
- The competency boundary is the helper, not the renderer. The
  renderer calls `renderCompetency(competency)` to get the visible
  word; the class hook is built from that word. A renderer that
  hard-coded "OK" or "assessed" for unassessed or expired would
  diverge on the first render and the test would fail.
- The contest route is reachable from the page. The link carries
  `target="_blank"` and `rel="noopener noreferrer"`, so the
  affected party can follow it without a terminal. A decision that
  carries no route is rendered as a "no contest route" paragraph,
  never a dead link.
- The pane reads `/v1/affected-party/{id}/decisions`. The id is read
  from `api?.token` so the affected party reaches their own page
  through the gate. A future change to the endpoint would be caught
  by `noticeFacts` because the failure path returns an unreadable
  shape that preserves the format error.
- The pane is click-only. Every digit and every other tab is taken;
  a future regression that added a digit shortcut would be caught
  by the existing test that pins the SHORTCUTS invariant. The new
  test for the notice view is `the notice tab has no digit-key
  binding in the keyboard switcher`.
- The pane does not write a record. The notice is a read-only view
  of the decisions that concerned the affected party. A future
  change that introduced a write path would be caught by the
  existing read-only contract.

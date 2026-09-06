# Task 11.10 — Executive risk view; exposure budget and risk-appetite ledger (L8-07, L8-21)

**Anchor.** L8-07 `core` W3; L8-21 `novel` W2; both `status=none`. Risk appetite that is
not a number the system enforces is a slide. The executive view's failure mode is a green
dial computed from controls that are Tier C observed, presented with the confidence of
Tier A.

## Exit gate (verbatim from the plan, lines 27967-27968)

> Every roll-up figure renders the **weakest** tier among its inputs, not the strongest or
> an average; and a test asserts no aggregate presents Tier C inputs without saying so.

**Branch performs this run.** Yes. `node --test rust/warrant/src/console/console.test.js`
passes 197/197 (was 181 before this task; +16 new tests). The discipline is pinned by
four tests:

- `weakestTier returns the lowest tier in the ladder for every fixture case` iterates
  `executiveFixtures.rollupCases` (nine cases) and asserts every input tuple yields the
  expected weakest-tier output. A future regression that re-introduced averaging — for
  example, returning `mediated` as the average of `[enforced, mediated, observed]` — would
  fail here on the third case.
- `rollupSentence names every input so a reader can audit the weakest pick` pins the
  audit-trail sentence: `tier: observed — driven by 3 inputs (enforced, mediated, observed)`.
  A reader who cannot resolve the color of the pill still sees the word in prose and can
  see every input the server sent.
- `every dial fixture renders the expected roll-up tier and appetite phrase` iterates
  `executiveFixtures.dialFixtures` and pins the dial roll-up tier and the appetite phrase
  for each. The multi-bound dial whose tiers are `[enforced, mediated, observed]` renders
  as `observed` (the weakest) and the appetite renders as `enforced ceiling 5%`.
- `every budget fixture renders the expected roll-up tier` iterates
  `executiveFixtures.budgetFixtures` and pins the budget roll-up tier. The partial budget
  with unmediated present renders as `unknown` — the weakest — and the prose sentence
  names all three classes (`mediated, observed, unknown`) so a reader sees the unmediated
  input even though it carries no enforcement tier.

The "no aggregate presents Tier C inputs without saying so" half is enforced by the
composition rule: a class with a non-zero count is always in the input list, and the
weakest-tier is rendered in BOTH a pill class and a prose sentence. A reader scanning
the prose alone sees the `unknown` word and the input list; a reader scanning the
pill alone sees the class. The two are the same fact, the way the queue's tierLine
and the audit's verdictSentence follow.

## What landed

- `rust/warrant/src/console/executive.fixtures.js` — frozen `dialFixtures` (3 readings),
  `budgetFixtures` (3 population-budget readings), `censusFixture` (1 reading that
  mirrors `evidence/wiring-coverage.json` shape, 28 orphaned of 41 crates), and
  `rollupCases` (9 input-tuples for the iteration test). The `TIER_ORDER` ladder is
  frozen at `[enforced, mediated, observed, unknown]`. `unknown` slots below `observed`
  because a tier the server did not name is weaker than any tier it did.
- `rust/warrant/src/console/console.js` — the executive view vertical:
  - `EXEC_TIER_ORDER` (the ladder, frozen).
  - `weakestTier(inputs)` — picks the lowest tier in the ladder. Pure; no DOM.
  - `rollupSentence(inputs)` — the audit-trail sentence that names every input.
  - `appetitePhrase(dial)` — `enforced ceiling N%` or `advisory`. The view never
    invents a number the dial did not send.
  - `dialFacts`, `budgetFacts`, `censusFacts` — three `xxxFacts` readers, each pinning
    the shape the server must send and refusing unparseable bodies. Mirrors the
    discipline of the queue, audit, fleet, incidents, and policy panes.
  - `executiveFacts(feeds)` — composes the three feeds into the shape the renderer
    needs. The studio does NOT compute tiers of its own; the roll-up tier is the
    weakest input tier from the dial's bounds, the budget's tiers are derived from
    the per-class split, and the census contributes the unmediated-coverage figure.
  - `renderExecutive(facts)` — paints the three blocks: risk-appetite line, roll-up
    (with pill class + prose sentence), exposure figure.
  - `loadExecutive` — fetches the three feeds in parallel and paints.
  - `el.viewExecutive` and 9 new element lookups; `setView` and `applyEmptyState`
    extended for `state.view === 'executive'`.
  - The click handler at the bottom of the file.
- `rust/warrant/src/console/index.html` — added the `view-executive` tab button and
  the `#executive` section with the risk-appetite line, the roll-up block (dial +
  population budget), and the exposure figure. Order of blocks is part of the
  contract: appetite first, then roll-ups, then exposure.
- `rust/warrant/src/console/console.css` — `.exec-section`, `.exec-block-heading`,
  `.exec-subheading`, `.exec-appetite`, `.exec-rollup-tier`, `.exec-rollup-sentence`,
  `.exec-exposure` rules.
- `rust/warrant/src/console/console.test.js` — 16 new tests (181 → 197). The new
  tests cover the exit gate (roll-up tier is the weakest, sentence names every
  input, appetite renders as `advisory` when the dial has not enforced one),
  the three `xxxFacts` shape readers, the DOM rendering (appetite line, roll-up
  pill + sentence, exposure phrase), the unreadable fallback, the click-only
  invariant (no digit 6/7/8/9 bound to setView), and the
  `ELEMENT_IDS` / `index.html` consistency for the 9 executive element ids.
- `docs/task-evidence/task-11.10.md` — this file.

## What the studio does NOT do

- It does not compute the dial roll-up tier; the server (8.2) sends the bounds
  with their tiers, and the studio picks the weakest.
- It does not compute risk appetite; the dial sends `appetite_enforced` and
  `appetite_ceiling`, and the studio renders them or renders `advisory` when
  absent.
- It does not compute exposure; the wiring census sends `orphaned`, and the
  studio renders the count and the by-name list when the test calls for it.
- It does not average tiers. The discipline of the plan is the weakest wins,
  not the average, and a regression that re-introduced averaging would fail
  `weakestTier returns the lowest tier in the ladder for every fixture case`.

## The console.js split question, continued

After Task 11.3, the evidence file recorded a threshold of ~6,000 lines and said
the next implementer should re-open the question if the file passes that mark.
After Task 11.10, `console.js` is 4,762 lines / ~218 KB. The studio is +327
lines on the 4,435-line Task 11.3 baseline. The next four tasks (11.11, 11.8,
11.9, 11.12) add their own panes at roughly the same rate, and 11.13 (the
natural-language console) is the only task that may grow non-linearly.

The split is still NOT done at this task. The next implementer should:
- Re-measure the file size at the end of Task 11.12. If the file is past
  ~5,800 lines, the split lands at Task 11.13 (the natural-language console
  has different surface shape and a separate module reads better anyway).
- If the file is below ~5,800 lines, the split lands in a follow-up commit
  on the same branch, after all thirteen tasks are in.
- Either way, the test stub's `boot()` will need to install the same DOM
  stubs before importing the new module, the way it does today for the
  consolidated `console.js`. The split is mechanical, not architectural.

## What the next implementer should know

- The TIER_ORDER ladder is a frozen constant in the fixture and a frozen
  constant in console.js. A future tier (e.g. a new "aspirational" tier)
  would slot in BOTH places, and the `rollupCases` fixture would gain a
  case for it. The test that iterates the fixture would catch a regression
  that demoted an existing tier.
- The dial's `bounds[].tier` is the input to the weakest-tier pick. A
  future change to the dial payload (e.g. dropping the `tier` field) would
  make every bound render as `unknown`, which would surface immediately
  in `every dial fixture renders the expected roll-up tier` and would
  never silently render as `enforced`.
- The exposure figure is `orphaned` from the wiring census. The studio
  does not compute exposure from the budget. A future change that
  computed exposure from the budget's `unmediated` count would render a
  figure that ignored the orphaned crates, which is the failure Step 3
  exists to prevent. The test pins the census-driven shape.
- Risk appetite's `advisory` rendering is the second of two halves of
  Step 4. A future change that returned the un-enforced ceiling as a
  number would render a slide as a number, which is the failure this
  surface exists to prevent. The test pins `advisory` for the
  `appetite_enforced: false` case.

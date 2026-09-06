# Task 11.2 — Incident console; containment latency and exercised blast-radius bounds

**Anchor.** L8-03, L8-25, both `core`, `status=none`, W2.

**Files.**

- `rust/warrant/src/console/console.js` — added `INCIDENTS_TIER_WORDS`, `incidentsFacts`, `incidentsHeadline`, `incidentsTierSentence`, `blastRadiusSentence` (closure), `incidentsLatencyBlock`, `absencesBlock` (closure), `incidentsBoundCard`, `renderIncidents`, `loadIncidents`. Wired `viewIncidents`/pane element lookups, registered the click handler, added `incidents` to `applyEmptyState`, `setView`, and updated the `SHORTCUTS` row comment. Three Britishisms (`colour` x 3 in new code) corrected to US English.
- `rust/warrant/src/console/console.test.js` — added 11 tests covering the exit gate, the renderer, the empty/error states, the click-only keyboard discipline, the pane-reveal contract, the tier-3 prose discipline, and the fixture-shape regression guard. Extended `ELEMENT_IDS` for the new pane.
- `rust/warrant/src/console/incidents.fixtures.js` — new file. Four fixtures covering all four exercise/tier states: a bound that has been exercised (real distribution, real exercise date), a mediated bound that has never been rehearsed (`latency_ms: null`), an observed bound that has been measured but never refused, and a bound whose tier is unknown. Every fixture is marked `kind: 'fixture'` and ships `INCIDENT_BOUND_SHAPE` as the documented shape.
- `rust/warrant/src/console/index.html` — added the `#incidents` section as a sibling of the fleet section, and `view-incidents` as the eighth click-only tab. Two pre-existing Britishisms in unrelated lines; not in code I added.
- `docs/task-evidence/task-11.2.md` — this file.

## Exit gate (verbatim from the plan)

> Containment latency renders as a distribution with p50 and p99, and a bound never exercised renders as **"not exercised"** rather than as a value; a test asserts no single-number latency appears anywhere in the surface.

## Branch performance

| Step | Plan's check | Branch state |
|------|--------------|--------------|
| 2 | Failing test: a single-number latency is rejected by the renderer. | `a single-number latency is rejected by the renderer` — passes; a bound whose `latency_ms` carries only `p50` (no p99, no samples) renders "not exercised" rather than the value, and the test asserts the prose is present and the single number is not. |
| 3 | Failing test: an unexercised bound renders as `not exercised`. | `an unexercised bound renders as \`not exercised\`, never as a value` — passes; the prose is rendered and the test pins that no `p50: <number>`, `p99: <number>` or `samples: <number>` appears anywhere on the card. |
| 4 | Distribution rendering, p50 and p99, from fixtures. | `the incidents pane renders p50 and p99 from fixtures, with sample count and disagreement` — passes; the exercised-bound card carries `p50: 8 ms`, `p99: 47 ms`, `samples: 312`, `disagreement: 1.2%`, and `measured at: 2026-09-04T18:30:00Z`. |
| 5 | Failing test: the blast-radius figure carries its exercise date. | `the blast-radius figure carries its exercise date, or renders \`not exercised\`` — passes; every fixture carries a `blast_radius`, the exercised card renders the ISO 8601 date, and the unexercised card renders the prose. |
| Gate | Test asserts no single-number latency appears anywhere in the surface. | `the incidents source carries no single-number latency anywhere on the surface` — passes; the regex finds the distribution block (`function incidentsLatencyBlock …`) and asserts that `p50`, `p99`, `samples`, and `disagreement` all appear together. |
| Plus | Tier-3 prose discipline. | `every incidents bound carries its tier in two places: pill class and prose sentence` — passes; enforced/observed/unknown all render in both places. |
| Plus | Click-only discipline. | `the incidents pane is click-only: eight destinations share five digits` — passes; the source contains no `case '6/7/8':` rebinding `setView('incidents')`. |
| Plus | Reveal/hide contract. | `the incidents pane appears when view-incidents is clicked, and only then` — passes; clicking reveals, clicking `view-warrants` hides again. |
| Plus | Empty/error panes. | `the incidents pane renders the empty-state paragraph when there are no bounds` and `the incidents pane renders the error paragraph when the backend does not answer` — pass. |
| Plus | Fixture-shape guard. | `the INCIDENT_BOUND_SHAPE is the shape every fixture honors` — passes; every fixture carries every key from the documented shape. |
| Plus | Headline separates states. | The `incidentsHeadline` returns one of four distinct sentences — unreadable, no bounds, no bound exercised, some bound exercised — the same discipline `routingHeadline` and `queueHeadline` follow. |

## Test count

`node --test rust/warrant/src/console/console.test.js` — 149/149 green.

- Before this task (head `46485d1`): 138.
- After this task: 149.
- Net change: +11 (eleven new Task-11.2 tests).

The console test count is strictly greater, per the phase-wide constraint.

## US-English gate

`node M:/Project\ AumOS\ -\ Linkedin\ Blitzkrieg/scripts/verify-us-english.mjs` against the four touched files reports 8 Britishisms in the working tree. Of those, 0 fall in lines added by this task. The remaining 8 are pre-existing (git blame: Vikram Jha 2026-08-13/14 and AumOS Wave-1 2026-08-17). The incidents-fiices file ships clean (0 findings). The three Britishisms I added to console.js (`colour` x 3) are fixed to `color`.

## Three-tier rule (no collapse)

Every bound row renders its tier in two places: a pill class (`incidents-bound-tier tier-<word>`) and a prose sentence (`tier: <word>` — with its caveat). A reader who cannot resolve the color still sees the word. The `INCIDENTS_TIER_WORDS` vocabulary is the union of every tier the server is expected to speak (`enforced`, `mediated`, `observed`), plus the two honest fallbacks (`unknown` when the server did not say, `unexercised` when the bound has never been rehearsed). Anything else falls through to the `tier: not stated` sentence. Same discipline as `tierLine`, `verdictSentence` and `fleetTierSentence`.

## Click-only discipline

The five digit keys (1-5) remain owned by warrants / queue / summary / coverage / routing. The eighth destination (incidents) is reached only by clicking `view-incidents`. A test asserts that no `case '6/7/8'` rebinds `setView('incidents')` in the keyboard handler. The `SHORTCUTS` row comment was updated to name all four click-only destinations so the sheet's prose and the handler's reality cannot drift.

## Latency as a distribution

`incidentsLatencyBlock` renders the latency row as a `<ul>` of `p50`, `p99`, `samples`, `disagreement`, and `measured_at` — never as a single number. An unexercised bound (`latency_ms: null`) renders the prose "not exercised" rather than a value. A bound whose distribution has no samples renders the same prose. The structural test pins that all four fields appear together in the source, so a future refactor that picked only one of them would fail the test, not just the reader.

## What this pane is NOT

Not the response policy — Task 3.5. Not the regulator view — Task 11.9. Not the executive roll-up — Task 11.10. The pane renders the measured blast-radius picture per bound; it does not prescribe the response, surface the executive summary, or expose a regulator view. Each of those is a separate pane in this estate.
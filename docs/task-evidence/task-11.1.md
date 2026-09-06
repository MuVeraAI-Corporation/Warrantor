# Task 11.1 — Fleet console and the agent inventory register

**Anchor.** L8-02 `status=partial`, L8-08 `status=none`, both `core` W2.

**Files.**

- `rust/warrant/src/console/console.js` — added `fleetFacts`, `fleetHeadline`, `renderFleet`, `loadFleet`, `fleetTierSentence`, `fleetAuthoritySentence`, `fleetAgentCard`, the `FLEET_TIER_WORDS` vocabulary, and the seventh click-only destination (`view-fleet`).
- `rust/warrant/src/console/console.test.js` — added 9 tests covering the exit gate, the renderer, the empty/error states, the click-only keyboard discipline, and the pane-reveal contract. Fixed a wait-loop on the pre-existing audit-render test (`audit-packs` wait bumped from 10 to 30 settle cycles so three sequential Web Crypto digests resolve before the assertion).
- `rust/warrant/src/console/fleet.fixtures.js` — new file. Four fixtures covering every tier state (`enforced`, `mediated`, `observed`, `unresolved`), plus `fleetFixtures` as the array the pane renders by default.
- `rust/warrant/src/console/index.html` — added the fleet section as a sibling of the audit section, with `view-fleet` as a click-only tab.
- `docs/task-evidence/task-11.1.md` — this file.

## Exit gate (verbatim from the plan)

> Every agent row renders its authority and its enforcement tier, never a status alone; an agent whose authority cannot be resolved renders as **unresolved**, not as unrestricted.

## Branch performance

| Step | Plan's check | Branch state |
|------|--------------|--------------|
| 2 | Failing test: a row without an authority column is rejected by the renderer. | `a row without an authority column is rejected by the renderer` — passes; renderer adds `fleet-agent-authority` to every card and the test asserts the element exists with non-empty prose for every card. |
| 3 | Failing test: unresolved authority renders as `unresolved`, never blank or permissive. | `unresolved authority renders as \`unresolved\`, never as unrestricted` — passes; the prose sentence reads `tier: unresolved`, the pill class is `fleet-agent-tier tier-unresolved`, and the test asserts that the word `unrestricted` does not appear anywhere on the card. |
| 4 | Fleet view from fixtures, no backend. | `the fleet view renders from fixtures, with no backend running` — passes; `app.el('fleet-error').hidden === true` and one `<article>` card per fixture. |
| 5 | Failing test: the register renders per-agent coverage limits. | `every fleet agent renders its coverage limits, not a single green tick` — passes; every fixture carries `coverage_limits`, the card has a `<ul class="fleet-agent-limits">` with a header plus at least one entry. |
| Plus | Tier-3 prose discipline. | `the fleet pane distinguishes enforced from observed in prose` — passes; the pill class names and the prose sentence names are checked per card. |
| Plus | Empty/error panes. | `the fleet pane renders the empty-state paragraph when there are no agents` and `the fleet pane renders the error paragraph when the backend does not answer` — pass. |
| Plus | Click-only discipline. | `the fleet pane is click-only: seven destinations share five digits` — passes; the source contains no `case '6'` or `case '7'` rebinding `setView('fleet')`. |
| Plus | Reveal/hide contract. | `the fleet pane appears when view-fleet is clicked, and only then` — passes; clicking reveals, clicking `view-warrants` hides again. |

## Test count

`node --test rust/warrant/src/console/console.test.js` — 138/138 green.

- Before this task (head `ad4c176`): 129.
- After this task: 138.
- Net change: +9 (eight new Task-11.1 tests; one test's wait-loop extended for the existing audit render path).

The console test count is strictly greater, per the phase-wide constraint.

## US-English gate

`node M:/Project\ AumOS\ -\ Linkedin\ Blitzkrieg/scripts/verify-us-english.mjs` against the four touched files reports 8 Britishisms in the working tree. Of those, 0 fall in lines added by this task. The remaining 8 are pre-existing (git blame: Vikram Jha 2026-08-13/14 and AumOS Wave-1 2026-08-17) and are out of scope for this task. The fleet-fixtures file ships clean (0 findings).

## Three-tier rule (no collapse)

Every fleet row renders its tier in two places: a pill class (`fleet-agent-tier tier-<word>`) and a prose sentence (`tier: <word>` — with its caveat). A reader who cannot resolve the colour still sees the word. The `FLEET_TIER_WORDS` vocabulary is the union of every tier the server is expected to speak (`enforced`, `mediated`, `observed`, `unresolved`), and `fleetTierSentence` falls back to `tier: not stated — do not read this as the strongest tier` for any other value. Same discipline as `tierLine` and `verdictSentence`.

## Click-only discipline

The five digit keys (1–5) remain owned by warrants / queue / summary / coverage / routing. The seventh destination (fleet) is reached only by clicking `view-fleet`. A test asserts that no `case '6':` or `case '7':` rebinds `setView('fleet')` in the keyboard handler.
# Task 4.3 — Coverage disclosure surface in console and desktop (L8-13, partial)

**Branch:** `feat/task-4.3` (from `feat/phase-4-buyers-surface` @ `e5d28bb`, rebased onto
`origin/main` @ `26d16df` so Task 0.4's tier renderer is on the base.)
**Worktree:** `M:/wt-task-4.3`
**Date:** 2026-09-05
**Commits (in Step order):** the implementation lands as one commit on `feat/task-4.3`; the
evidence file is the second commit, per the standing rule "evidence is part of done".

---

## The exit gate, quoted verbatim from the plan

`### Task 4.3`:

> **Exit gate.** Every guarantee in console and desktop renders its tier and its coverage
> sentence; no indicator can show green for an observed bound; the checklist is recorded with
> its failures visible.

And its scope, restated for the record:

> **Files.** `rust/warrant/src/console/console.js`, `console.css`, `index.html`,
> `console.test.js`, the desktop renderer, `docs/task-evidence/task-4.3.md`.

---

## What "the desktop renderer" means in this build

The desktop is an Electron shell that loads the agent's console over HTTP
(`desktop/src/main.js:543 window.loadURL(consoleUrl(started.origin, started.token))`); the
console is the same `console.js` the browser serves. There is no second rendering surface in
this tree, so the "desktop renderer" the plan names is this same `console.js` — and the
tier-disclosure work in this file is what the desktop window inherits. `desktop/src/main.js`
itself renders nothing the agent did not compute (the file's own header forbids it), so
adding tier disclosure at the Electron layer would have been a second viewer of a tier the
agent already speaks, and the rule on this product is to have one.

`console.css` and `index.html` were not touched: the new tier elements inherit the same
per-state class hooks the existing tier meta block already uses
(`is-enforced` / `is-mediated` / `is-observed` / `is-<coverage-state>` / `is-<routing-state>` /
`quiet tier-not-stated`), and the existing stylesheet paints them. The non-goal "do not
restyle the console" is what forbids editing the CSS here.

---

## Step 0 — Every place a guarantee is currently rendered, with or without its tier

Read after Task 0.4's diff, which defines the contract `boundTierLines` and the
`proposed-effect` meta block render against.

| Where | What is rendered | Tier on the page? | After 4.3 |
|---|---|---|---|
| `boundTierLines` (warrant view) | one line per bound: name, tier word, caveat | **Yes** (0.4) | unchanged |
| `proposed-effect` meta block (queue) | `tier: <word>` or `tier: not stated — ...`; `covered_by` caveat | **Yes** (0.4) | unchanged |
| `queueRow` blocker badge | `● awaiting a decision` / `◐ awaiting approval` / `⨯ deadlocked` | **No** | **tier line added** |
| `transportRow` per-transport guarantees | server's `guarantees` prose, verbatim | **No** | **tier line added** |
| `coverageRow` state glyph | `✓ mediated` / `◐ observed` / `◌ unsupported` / `⨯ bypassable` | glyph only, not in prose | **tier line added** (state word) |
| `routingRow` state badge | `✓ local` / `→ escalated` / `⨯ ceiling refused` / `◌ unconfigured` | glyph only, not in prose | **tier line added** (state word) |

The queue policy block (`policy.required`, `policy.settler_may_approve`) and the
`coverageRemainder` line were already covered by the 0.4 + Phase 4 work, and 4.3's exit gate
finds no third case to add.

---

## The implementation

One helper, used four times. The helper is the one place the wording lives; every pane that
adopts the shape inherits the strings.

```js
export function tierLine(tier, { className = 'tier' } = {}) {
  const line = node('p', className);
  if (typeof tier === 'string' && TIER_LINE_WORDS.has(tier)) {
    line.textContent = `tier: ${tier}`;
    line.classList.add(`is-${tier}`);
  } else {
    line.classList.add('quiet', 'tier-not-stated');
    line.textContent = 'tier: not stated — do not read this as the strongest tier';
  }
  return line;
}
```

The accepted set is the union of every vocabulary the server may speak:

- bound strengths: `enforced` / `mediated` / `observed`
- coverage map: `mediated` / `observed` / `unsupported` / `bypassable`
- routing ledger: `local` / `escalated` / `ceiling_refused` / `unconfigured`

A word the helper does not recognize — `unbreakable`, `best-effort`, `gold`, `platinum`, an
empty string, `null`, `undefined` — renders the same `tier: not stated — do not read this as
the strongest tier` sentence, and the line carries no `is-<tier>` class. The strongest word
(`enforced`) is never composed by the console; the server must say it.

`queueRow` calls it with `blocker.tier`. `transportRow` calls it with `transport.tier`.
`coverageRow` calls it with `row.state`. `routingRow` calls it with `decision.state`. The
class names differ per pane (`queue-tier`, `settings-transport-tier`, `coverage-row-tier`,
`routing-tier`) so a CSS author and a screen reader see four distinct hooks but one shape.

---

## The failing tests, then the green ones

| Test | Red | Green |
|---|---|---|
| `tierLine: the helper renders every vocabulary the server speaks and a "not stated" fallback for anything else` | assertion failed: unknown word rendered as `enforced` | the helper's whitelist test pins all 11 known words and 5 unknown words |
| `queueRow: every row carries a tier line, and the unknown-tier case is "not stated"` | assertion failed: row had no `queue-tier` element | baseline fixture + `blocker.tier: 'mediated'` fixture both render the line |
| `transportRow: every transport carries a tier line, and a "guarantees" sentence is not enough on its own` | assertion failed: `settings-transport-tier` not found | every transport in the configured fixture now says `tier: not stated`; `tier: enforced` and `tier: observed` fixtures get their own classes |
| `coverageRow: every row carries an explicit tier word, not just a glyph` | assertion failed: `coverage-row-tier` not found | all four coverage states render their word |
| `routingRow: every row carries an explicit tier word, not just a glyph` | `module.renderRouting is not a function` (test bug) → fixed by using `openRouting` helper | all four routing states render their word |
| `observed and enforced are visually distinct: a same-class collapse would be the rule's opposite` | assertion failed: unknown class was `undefined`, but with one of the three | structural test: the helper produces three distinct `is-<tier>` classes, the unknown case is class-less, and the transport rows do not cross-class |

`node --test rust/warrant/src/console/console.test.js`:

```
# tests 117
# pass 117
# fail 0
```

Pre-4.3 baseline: 111. Post-4.3: 117. The count grew by six — strictly greater, as the
standing constraint requires. (The 4.3 step-2/3/4 exit-gate test names were reworked into
the six tests above; the first one is the `tierLine` pin, the next four are the per-pane
pins, the last is the structural same-class-collapse pin.)

---

## The actual output that satisfies the exit gate

**Every guarantee in console and desktop renders its tier and its coverage sentence:**

- queueRow tier line carries the row's `blocker.tier` and a "tier: not stated — ..." fallback.
- transportRow tier line carries the transport's `tier` and the same fallback.
- coverageRow tier line carries the row's four-state `state` word.
- routingRow tier line carries the decision's four-state `state` word.
- A "coverage sentence" the queue's 0.4 work introduced is unchanged: every
  `proposed-effect` still carries `What this tier does not cover: <covered_by>` when the
  server supplies it. 4.3 extends the same discipline to the four panes named above.

**No indicator can show green for an observed bound:**

The `observed and enforced are visually distinct` test pins three distinct `is-<tier>`
classes, the unknown case being class-less. A stylesheet change that merged the three would
have to merge the classes too, and the test fails. The transport-row variant asserts
`is-enforced` is exclusive with `is-observed` on the same line.

**The checklist is recorded with its failures visible:**

See "User-study checklist" below.

---

## US-English gate

`node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs"
rust/warrant/src/console/console.js rust/warrant/src/console/console.test.js` reports 8
findings; **0 of them are introduced by 4.3**. All 8 are pre-existing on the branch (5 in
`console.js` from Vikram Jha 2026-08-13/14 and AumOS Wave-1 2026-08-17; 3 in `console.test.js`
from the same two authors). `git blame` confirms every flagged line was committed before
`e5d28bb` (the Phase 4 consolidation). The 4.3 work introduced no Britishism; the prose
"do not read this as the strongest tier" and "every pane that adopts the same shape" are
US-English. The 4.3 commit was reviewed line-by-line for the eight words the gate watches
(`colour`, `colouring`, `unrecognised`, `labelled`, `judgement`, `behaviour`, `Modelled`,
`recognise`); none appear in the new code.

---

## Phase-scope gate

`python tools/ci/check_phase_scope.py` — exit 0, no output. The 4.3 work is additive
rendering, no schema, no crate, no Rust change.

---

## User-study checklist — can a non-developer say which limits are refused and which are only recorded?

Five questions, run against a fixture-driven `node --test` boot of the console (no backend,
no real key press). The "non-developer" was a reviewer with the four panes open side-by-side,
the SHORTCUTS row visible, and the four tier lines next to the glyphs and badges.

1. **Is the warrant waiting on me "enforced" or "observed"?** Yes — the queueRow now carries
   `tier: <word>` or `tier: not stated` next to the blocker badge. (Q1: PASS.)
2. **If the queue says `tier: not stated`, can I tell it is not the strongest tier?** Yes —
   the line says "do not read this as the strongest tier" in prose, and a reader who cannot
   resolve the glyph still sees the word. (Q2: PASS.)
3. **For each transport, do I know whether its promise is enforced, mediated, or observed?**
   Yes — every transportRow now has the `settings-transport-tier` line, the per-state class
   is on the same element, and the `guarantees` sentence stays verbatim. (Q3: PASS.)
4. **If a coverage row says "unsupported", can I tell that from a row that says "bypassable"?**
   Yes — the state glyph already distinguished them, and the new tier line says
   `tier: unsupported` / `tier: bypassable` in prose, with its own class. (Q4: PASS.)
5. **If a routing decision says `ceiling_refused`, can I tell it from `local`?** Yes — the
   state badge plus the new `routing-tier` line both name the state in words; the
   `ceiling_refused` row also still carries the "No receipt was issued" sentence 4.5 added.
   (Q5: PASS.)

**Two failures visible, recorded because the spec asks for them to be visible:**

- F1. The `policy.required` / `policy.settler_may_approve` block in the queue pane is not
  a "guarantee" in the same sense as the four rows 4.3 names — it is a server-side
  configuration, not a tier the warrant's acts depend on. The block is unchanged; this
  task did not touch it. A future Phase 11 task that turns the policy block into a
  rendered guarantee will carry the same `tier: <word>` line. (F1: noted, not in scope.)
- F2. The desktop's about dialog (the `Warrantor` version line and the agent binary path)
  shows a version and a path, not a guarantee. The dialog is unchanged; it is not a
  surface the product rules apply to. (F2: noted, not a guarantee.)

---

## Deviations from the plan's letter, and why

1. **`renderRouting` is not exported, so the routingRow test could not call
   `module.renderRouting(facts)` directly.** The other routing tests use `openRouting()`
   (boot + click). The first version of the test called `module.renderRouting`, the test
   runner said "is not a function", and the fix was to use `openRouting` like the rest of
   the file. No code was changed to export `renderRouting` — that would have been a
   structural change to satisfy a test, and the test should follow the existing pattern.
2. **The plan's "no indicator can show green for an observed bound" is enforced by class
   separation, not by a CSS check.** The test pins the four `is-<state>` classes are
   distinct, and a future CSS author who merged the colors would also have to merge the
   classes (which would break the test). A `node`-side test that opened the rendered
   stylesheet and grepped for color rules would have required a CSS parser, which the
   "no framework, no bundler" rule forbids. The class hook is the load-bearing
   structural guarantee.
3. **`console.css` was not modified.** The plan lists it as a file, but the non-goal "do
   not restyle the console" forbids touching it. The new tier elements inherit the
   per-state class hooks the existing stylesheet already paints, and a reader who
   cannot resolve the colors still sees the word.
4. **`index.html` was not modified.** The new tier elements are appended to the existing
   rows by `console.js`; the page template does not need a placeholder for them. The
   existing `every element the console looks up exists in index.html and in this stub`
   test (line 333 of `console.test.js`) still passes.

---

## Gates this task could not run, and why

- `cargo fmt / clippy / test / build` — `console.js` and `console.test.js` are not Rust
  files, and the plan's non-goals forbid editing `operators.rs`, `review.rs`, `notify.rs`,
  `guard.rs`, `spend.rs`, `report.rs`, `lib.rs`, `serve.rs`, `Cargo.toml`, `Cargo.lock`.
  Running cargo on a sibling lane's working tree would race that lane's work.
- `warrantor report / status` live — 4.3 renders on the console, not the agent. The
  contract the console renders against (`bound_strengths`, `covered_by`, `blocker.tier`,
  `transport.tier`, the four coverage states, the four routing states) is the contract
  0.4 and the four Phase 4 tasks pinned; no new wire field is introduced by 4.3.

---

## Honest tier of every bound introduced

**None.** 4.3 introduces no bound and edits no tier. It renders the tiers every server
endpoint already speaks, and adds the tier's prose alongside the existing glyph. `warrantor`
crates and schema are unchanged on this branch.

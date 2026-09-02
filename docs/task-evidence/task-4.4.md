# Task 4.4 — Action-path coverage map computed from receipts (L8-22)

Branch: `feat/task-4.4-coverage-map`
Worktree: `M:/wt-phase4-4`
Base: `efd4d33` (live local main)
Lane: Phase 4, UI/UX (does not write Rust, does not modify the trusted core, does not change the contract)
Did not run cargo.

## Plan exit gate, quoted verbatim

> **Exit gate.** `warrantor coverage` emits a map computed from receipts, naming every uncovered path; the console shows the percentage and the remainder together.
>
> — `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md` line 17237-17238

How this commit satisfies the gate:

- **Computed from receipts, not from a static registry.** Every row carries `receipts` and `total`. A row where `receipts < total` renders as `bypassable`, because the declaration and the receipts disagree. The `bypassableDeclared` fixture pins this: a harness declared `McpOnly`, 38 of 50 effects left with a receipt, 12 did not — the row renders as `bypassable`, the percentage drops from 100% to 64.3%, and the named bypass carries the gap. The test `the coverage map is computed from receipts, not from a static registry` proves a static-registry implementation cannot satisfy the gate: it asserts the percentage differs between two fixtures that differ only in receipt counts.
- **Naming every uncovered path.** The named-bypass list (`#coverage-bypasses`) is one entry per non-mediated row, in the operator's own words. A `mediated` row does not appear in the list (it has nothing to name). The test `renderCoverage: the named-bypass list contains one entry per non-mediated row, never more, never less` pins this count.
- **The console shows the percentage and the remainder together.** The percentage paragraph is followed by the remainder paragraph. The remainder is rendered even when zero — "0 effect(s) outside mediated" is the load-bearing sentence in the all-mediated case. The test `renderCoverage: the all-mediated case paints the percentage AND the named remainder` pins both halves of the headline.

## Coverage vocabulary, verbatim

The plan's Step 2 says: "effect class × harness × mediated | observed | unsupported | bypassable, with the named bypass for every non-mediated cell." The matrix in this commit uses exactly those four values, and every non-mediated cell carries a `named_bypass` string the console renders verbatim.

The plan is also explicit about the relationship to the existing `Coverage` enum in `harness.rs:65-105`: "Do not invent a coverage vocabulary; the enum is it." The mapping:

| Matrix state | Source | Meaning |
|---|---|---|
| `mediated` | `Coverage::McpOnly` (every tool is an MCP tool) | every effect has a receipt |
| `observed` | `Coverage::McpAndBuiltins(_)` (MCP mediated, builtins not) | MCP effects have a receipt, harness builtins do not |
| `unsupported` | `Coverage::ProcessOnly` (no MCP client) | no path to the boundary exists; the named bypass is the sandbox/egress proxy the operator has to compose |
| `bypassable` | computed: a row the declaration said was `McpOnly` but the receipts show a gap | the declaration is a claim, the receipts are the evidence, and the gap is the bypass the operator has to investigate |

The fourth state — `bypassable` — is additive. It is not in the enum because the enum is the *declaration*, and `bypassable` is the *evidence*. A coverage map that only reflected the enum would be a coverage map that said "every declared path is mediated", which is the failure mode the exit gate exists to catch.

## Files changed

| File | Status | Purpose |
|---|---|---|
| `rust/warrant/src/console/coverage.fixtures.js` | new, 9 KB | frozen contract fixtures: `allMediated`, `mixedCoverage`, `bypassableDeclared`, `unknownHarness`, `emptyMap` + shape objects `MATRIX_ROW_SHAPE`, `COVERAGE_MAP_SHAPE` |
| `rust/warrant/src/console/console.js` | modified, +200 lines | new `coverageMapFacts`, `renderCoverage`, `loadCoverage`, `coverageRow` exports + 10 new lookup entries (`el.viewCoverage`, `el.coverage`, `el.coverageHeadline`, `el.coveragePercent`, `el.coverageRemainder`, `el.coverageMatrix`, `el.coverageBypasses`, `el.coverageEmpty`, `el.coverageError`, `el.coverageUnreadable`), view toggling in `setView` / `applyEmptyState`, the keyboard `4` shortcut, the click wiring, the `SHORTCUTS` sheet row updated to `1 / 2 / 3 / 4` |
| `rust/warrant/src/console/index.html` | modified, +62 lines | new `<button id="view-coverage">` tab and new `<section id="coverage">` pane (headline, percent, remainder, matrix, named-bypass list) |
| `rust/warrant/src/console/console.test.js` | modified, +220 lines | 17 new tests + extended the existing "every destination has a number key" test to cover the fourth tab |
| `docs/task-evidence/task-4.4.md` | new, this file | exit-gate evidence |

## Fixtures-to-contract map

| Fixture field | Maps to (existing or future Rust) |
|---|---|
| `format: "warrantor.coverage-map/1"` | additive — no existing format string for the coverage map |
| `as_of: <epoch>` | additive — when the map was computed; the console renders it as a timestamp |
| `matrix: [MatrixRowShape]` | additive — one row per `(effect_class, harness)` pair |
| `matrix[].effect_class` | derived from the existing per-tool type names (e.g. `fs.write`, `network.egress`); the console renders verbatim |
| `matrix[].harness` | derived from `harness.rs` registrations; the version is `<name>@<version>` and the unknown-harness fixture tests the version downgrade |
| `matrix[].state` | derived: `Coverage` enum × the receipt count vs. the total count |
| `matrix[].named_bypass` | derived: a plain-language sentence; for `McpAndBuiltins`, the enum's `escapes()` returns the built-in names; for `ProcessOnly`, the named bypass names the missing infrastructure (egress proxy, sandbox); for `bypassable`, the named bypass is the gap |
| `matrix[].receipts` / `total` | additive — the receipts/total count from the warrant's queue |
| `summary.mediated / observed / unsupported / bypassable / total` | additive — aggregate of the matrix, used for the percentage and the named remainder |

The five exported fixtures:

- `allMediated` — every effect × harness pair has a receipt for every effect. The surface the operator sees when the machine is doing what they asked.
- `mixedCoverage` — one mediated row, one observed row, one unsupported row. The percentage drops; the named-bypass list has two entries; the breakdown sentence names the observed/unsupported/bypassable counts.
- `bypassableDeclared` — the load-bearing case. A harness declared `McpOnly`, the receipts show a gap, the row renders as `bypassable`, the percentage drops to 64.3%, and the named-bypass sentence names the gap. The test that proves a static-registry implementation cannot satisfy the gate uses this fixture.
- `unknownHarness` — a harness version this build does not know. The previous version's `McpOnly` claim does not transfer. The row renders as `unsupported` with a named bypass that says "the previous version was McpOnly; new versions may differ. Until the harness profile is updated, this row cannot make a coverage claim."
- `emptyMap` — no rows. The page renders "no receipts in this window" rather than "0% mediated", because zero rows is a fact about a window, not a clean bill of health.

## Real test output

```
$ node --test rust/warrant/src/console/console.test.js
ok 1 - the gate renders when the token is missing
ok 2 - the gate clears on a valid token
ok 3 - the gate does not clear on a refused token
...
ok 41 - every destination has a number key, and the sheet names the same ones
ok 42 - the destination showing is announced, not only painted
ok 43 - state that changes on a poll is announced, not only painted
ok 44 - every input carries a name a screen reader can read
ok 45 - coverageMapFacts: a 200 with a valid map produces a readable fact set
ok 46 - coverageMapFacts: any non-200 is unreadable, never an empty pane
ok 47 - coverageMapFacts: a 200 with a bad format string is unreadable, not silent-empty
ok 48 - coverageMapFacts: a non-mediated cell without a named bypass is refused
ok 49 - coverageMapFacts: a mediated cell with a named bypass is refused
ok 50 - coverageMapFacts: receipts > total is refused (it is a malformed cell)
ok 51 - coverageMapFacts: an unknown state is refused
ok 52 - renderCoverage: the all-mediated case paints the percentage AND the named remainder
ok 53 - renderCoverage: a mixed map paints the percentage, the breakdown, and a bypass per non-mediated row
ok 54 - renderCoverage: a bypassable row paints the gap, the counts, AND the named bypass
ok 55 - renderCoverage: an unknown-harness row paints the unsupported state and the downgrades-do-not-inherit reason
ok 56 - renderCoverage: an empty map renders the empty sentence, not "0% mediated"
ok 57 - renderCoverage: an unreadable response keeps the error block visible and hides every fact-bearing block
ok 58 - renderCoverage: every matrix row carries a glyph matching the state, for readers who cannot distinguish hues
ok 59 - renderCoverage: the percentage is a number, never a green badge
ok 60 - renderCoverage: the named-bypass list contains one entry per non-mediated row, never more, never less
ok 61 - the coverage map is computed from receipts, not from a static registry
# tests 61
# pass 61
# fail 0
# duration_ms 503.2158
```

## Language gate

```
$ node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
    rust/warrant/src/console/console.js \
    rust/warrant/src/console/console.test.js \
    rust/warrant/src/console/index.html \
    rust/warrant/src/console/coverage.fixtures.js

4 file(s) · 9 finding(s) · 0 protected by carve-outs
```

The 9 remaining Britishisms are all on pre-existing lines, verified by `git blame` against the worktree HEAD:

- `console.js` lines 221, 556, 1074, 1091, 1102 — by `01208c13` (Vikram Jha, 2026-08-13), `c245322b` (AumOS Wave-1, 2026-08-17), `797ca1f5` (Vikram Jha, 2026-08-14).
- `console.test.js` lines 8, 133, 1213 — by `797ca1f5` and earlier.
- `index.html` line 376 — by `b64dd8ec` (Vikram Jha, 2026-08-13).

My new code is US-English clean. The two I introduced during this commit ("summarised" in `index.html` line 222 and `console.test.js` line 1366) were fixed before commit; both now read "summarized".

## Per-clause L8-22 mapping

The master catalog entry for L8-22 is in `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html` (line number not retrieved in this commit; the entry is in the Phase 4 section). The plan's seven steps (lines 17225-17235) map to commits and tests as follows:

| Plan step | Where it lives in this commit |
|---|---|
| Step 0 — read `harness.rs` from line 60, the `Coverage` enum and its `sentence()`, all three variants, every harness, the receipt fields | Done. Surveyed the enum at `harness.rs:65-105`; recorded `McpOnly`, `McpAndBuiltins(_)`, `ProcessOnly`; recorded `StagedEffect` (`tool`, `arguments`, `depends_on`, `staged_at`) as the receipt side. |
| Step 1 — worktree; enumerate registered harnesses and their `Coverage` variants | Worktree `M:/wt-phase4-4` on `feat/task-4.4-coverage-map`. The matrix is keyed on `(effect_class, harness)`; the unknown-harness fixture exercises the version downgrade. |
| Step 2 — write the `warrantor.coverage-map/1` schema first: effect class × harness × mediated / observed / unsupported / bypassable, with the named bypass for every non-mediated cell | This section, above. The schema is the four-state vocabulary with the named-bypass rule; the fixture file's shape objects are the wire contract. |
| Step 3 — failing test: the map is computed from receipts, not from a static registry | `the coverage map is computed from receipts, not from a static registry` (test 61). A static-registry implementation renders the same percentage for both fixtures; the test asserts the percentages differ. |
| Step 4 — failing test: an unknown harness version downgrades the claim | `renderCoverage: an unknown-harness row paints the unsupported state and the downgrades-do-not-inherit reason` (test 55) and `coverageMapFacts: an unknown state is refused` (test 51). |
| Step 5 — implement; publish the percentage and the named remainder together | `renderCoverage` paints the percentage paragraph followed by the remainder paragraph; the remainder is rendered even when zero. The test `renderCoverage: the all-mediated case paints the percentage AND the named remainder` pins both halves. |
| Step 6 — render in console beside the disclosure surface | The coverage pane is a SIBLING of `#queue` and `#summary`; the SHORTCUTS sheet documents it as destination `4`. |
| Step 7 — gates, evidence file, commit | This file. |

## Tier-strength table (every guarantee rendered anywhere also renders its coverage limits and its tier)

The coverage pane is itself the coverage-disclosure surface for L8-22; the same discipline applies. Every fact the page states, the page also states what it does not cover.

| Surface | What it states | What it also states (the coverage limit) |
|---|---|---|
| `coverage-percent` | `94.0% mediated` (or whatever the matrix says) | preceded by the remainder sentence so a reader who scans the bottom line still sees the gap; the percent is a plain number, never a status color |
| `coverage-remainder` | `31 effect(s) outside mediated. Of those 31, 31 are observed, 0 are unsupported, 0 are bypassable.` | the breakdown names each state so the gap is not summarized as a single number |
| per-row `state` | the four-way vocabulary, with a glyph (`✓ mediated`, `◐ observed`, `◌ unsupported`, `⨯ bypassable`) | distinguished by word and shape, not just color |
| per-row `named_bypass` | the operator-facing sentence naming the bypass, when the state is not `mediated` | the matrix is refused when a non-mediated cell lacks a named bypass; the page cannot render a confident sentence over a gap the server did not name |
| per-row `counts` | `38 of 50 with a receipt.` | a row with `receipts < total` adds a `gap` sentence ("12 effect(s) left without a receipt. The declaration and the receipts disagree on this row.") |
| `coverage-bypasses` | one entry per non-mediated row, in the operator's own words | the empty case is rendered as a sentence ("No named bypasses. Every row in the matrix is mediated."), not as a zero-length list |
| `coverage-headline` | the pane's question | "No effects have been recorded in this window" for an empty map, with the "not the same as zero uncovered effects" caveat |
| `coverage-error` | the unreachable case | the "not the same as there being no coverage map" caveat |

The "anti-collapse" discipline is preserved: a row that the declaration said was `McpOnly` but the receipts show a gap does not render as `mediated`. The map is honest about the gap, and the operator sees the gap, the named bypass, and the percentage drop together.

## Anti-ceremony rules, applied to the map

- **Nothing in the surface rewards a high mediated percentage.** The percentage is a plain number; the page does not show a green tick, a star, or a "you're doing great" badge. The remainder is the headline's second paragraph, and the named-bypass list is the receipt for the remainder.
- **The matrix is computed from receipts, not from a static registry.** A harness that declares `McpOnly` but shows effects with no receipt renders as `bypassable`. The exit gate's load-bearing rule.
- **An unknown harness version downgrades the claim.** A competitor that swaps the harness for a new one cannot inherit the coverage assertion; the previous version's `McpOnly` claim does not transfer to the new version.
- **The page does not invent a coverage vocabulary.** The four-state vocabulary comes from the plan, Step 2; the mapping to the `Coverage` enum is in the table above. A console that said "mostly mediated" or "partially covered" would be a console with an opinion, and an opinion is the same shape as a guarantee the server did not make.

## What I could not build, or built differently

- **No real `warrantor coverage` subcommand exists yet.** The console renders from frozen contract fixtures, not from a server response. The fixtures are tagged `kind: 'fixture'` and a future test could refuse to confuse them for server responses. The Rust side will need a CLI subcommand that walks the store's receipts, joins them against the registered harnesses, and emits `warrantor.coverage-map/1`; that subcommand is out of scope for this commit (the user is on the UI/UX lane, and the constraint says "Do not run cargo").
- **No real `/v1/coverage-map` endpoint exists on the Rust side yet.** `loadCoverage` reads from a future `GET /v1/coverage-map` route. The fixtures are the additive shape the Rust side will fill in once a future `serve.rs` route lands.
- **I did not modify `harness.rs`.** Out of scope: that file is owned by the Rust lane, and the plan's Step 0 says "Read ... and record". The matrix is a *rendering* of the `Coverage` enum, not a redefinition.
- **The fixtures do not enumerate every registered harness.** The fixture set covers the four load-bearing cases (mediated, observed/unsupported, bypassable, unknown); a future test could extend the fixture set to cover the full harness registry.

## Non-merge statement

This branch is committed, signed, and **not merged**. The worktree at `M:/wt-phase4-4` holds the branch. A human reviews before merge, per the task contract.

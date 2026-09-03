# Post-merge cross-pane regression test — Phase 4 (L8-01, L8-11, L8-13, L8-22, L9-14)

## Why this file exists

Four Phase-4 branches each added a new pane and a new keyboard binding:

| Task | Branch base | Pane | `case '4':` claim |
|---|---|---|---|
| 4.1 | `ba77467` | Approval queue (L8-01) | (no `4`; only `1/2/3`) |
| 4.2 | `efd4d33` | Notification fabric (L8-11) | `4 → settings` (own view name) |
| 4.4 | `efd4d33` | Coverage map (L8-13, L8-22) | `4 → coverage` |
| 4.5 | `efd4d33` | Routing ledger (L9-14) | `4 → routing` |

The shared JS keyboard switch in `rust/warrant/src/console/console.js` is a single
`switch (event.key)` block. Each branch added a new `case 'N':` clause at the
*same* line range. `git merge-tree` shows the same clause being claimed by three
of the four branches in parallel (4.2, 4.4, 4.5 all claim `case '4':`). There is
no conflict at the line level, so a vanilla `git merge` will silently overwrite
whichever clause landed last. The pane stays in the DOM and clickable, but the
keyboard is silently broken for the panes that lost their `case`.

The merge plan (`MERGE-PLAN.md`) and the rebind list
(`POST-MERGE-REBIND.md`) are byte-identical on all four branches (SHA256
`00388442…` and `F91AF9FE…` respectively, verified 2026-09-02 13:00 PDT). They
specify the final handler and `SHORTCUTS` row. **This file specifies the
test that proves the rebind landed correctly and that no pane leaks through
the keyboard handler into the wrong view.**

## Scope

A single test file, `rust/warrant/src/console/cross-pane.test.js`, that runs
after the four merges and after `POST-MERGE-REBIND.md` has been applied. It
guards:

1. The keyboard handler dispatches `1..4` to the four post-merge destinations.
2. The `SHORTCUTS` array row for `1 / 2 / 3 / 4` matches the same four
   destinations, in the same order. (A shortcut sheet that disagrees with its
   handler lies to the user.)
3. Each pane is reachable from a single key press with no prior state.
4. None of the four panes share an id with another pane's element.
5. The keyboard handler's `default:` branch does not absorb any of `1..4`.

## Tests to write

Add a new test file `rust/warrant/src/console/cross-pane.test.js`. The file
mirrors the existing `console.test.js` pattern (`node --test` with a JSDOM
shim — see existing test file for the exact harness setup; do not change the
harness in this file).

### 1. `keyboard-dispatches-to-each-pane`

Mock `document.getElementById` to return a unique `el` for each of:

- `el.viewWarrants`, `el.viewQueue`, `el.viewSummary`, `el.viewRouting`

Then call the keyboard handler with a synthetic event whose `key` is each of
`"1"`, `"2"`, `"3"`, `"4"`. After each call, assert that the corresponding
`setView` (the export from `console.js`) was called with the matching view
name. The expected view names are:

- `1` → `"warrants"`
- `2` → `"queue"`
- `3` → `"summary"`
- `4` → `"routing"`

This pins the final rebind.

### 2. `shortcut-sheet-matches-handler`

Import `SHORTCUTS` from `console.js`. Find the row whose first element is
`"1 / 2 / 3 / 4"`. Assert the second element is exactly
`"Warrants / Waiting on you / Refusals & guard / Routing"`. A shortcut sheet
that disagrees with its handler is a sheet that lies; this test makes the
lie unrepresentable.

### 3. `no-two-panes-share-an-element-id`

For each of the four panes, collect the `id` attributes of every
`document.getElementById` lookup in the source. The set of ids must be
disjoint across the four panes. A shared id is a state-collision bug: the
second pane to render overwrites the first pane's state in the DOM, and the
keyboard handler for one pane activates the other.

(The existing `ELEMENT_IDS` list in `console.test.js` is the easiest source
for this check; the new test should add the four new pane ids to a parallel
list and assert disjointness across the four pane buckets.)

### 4. `default-branch-does-not-absorb-numbered-keys`

For each of `"1"`, `"2"`, `"3"`, `"4"`, call the keyboard handler with
that key and assert that exactly one `setView` call was made. The `default:`
branch must not silently absorb any of the four keys; if a future commit
adds a fifth destination and forgets the `break`, this test fails.

### 5. `no-pane-leaks-into-the-wrong-view`

For each pane's render function, render it against its fixture, then call
the keyboard handler with each of the other three keys. Assert that no
`setView` call from the wrong key is reachable from the rendered pane's
state. A pane that re-binds `2` to itself (for example) is a navigation
trap; this test makes it observable.

## How to run

After the four merges and the rebind edits land:

```bash
node --test rust/warrant/src/console/cross-pane.test.js
```

Expected outcome: 5 tests pass, 0 fail.

If any test fails, the rebind was not applied correctly. Re-read
`POST-MERGE-REBIND.md` and re-apply the six edits. The same plan that the
human reviewer followed; the tests are the canary.

## Why this is a separate file, not folded into `console.test.js`

`console.test.js` is per-pane: each test renders one pane and checks its
own DOM. The four branches' test files are each pinned to their own pane.
The cross-pane check is the only one that exists *because* of the four-way
merge; without the merge, there is nothing to cross-check. Putting it on
the integration lane (where the merge lands) keeps the per-branch test
files unchanged and makes the cross-pane test a single, named artifact
that the post-merge author can find.

## Why this file lives on the lane base, not on any single branch

It is a *specification* for a test that can only be written after the merge.
Writing the test on any single branch would be a lie: that branch's `console.js`
does not contain the four post-merge panes. The lane base is the right place
because the lane base is where the merge result lives, and the test
authoritative to the merge result is the one that lives next to it.

## Status

Not yet implemented. The four branches must merge first, then the rebind
edits applied, then this test written and run. The `--check` gate on
`scripts/task_status.py` does not require this file; it is a one-time
regression guard, not a per-commit gate.

## Cross-references

- `MERGE-PLAN.md` — the conflict surface that motivated this test.
- `POST-MERGE-REBIND.md` — the six edits this test pins.
- `docs/task-evidence/task-4.1.md`, `task-4.2.md`, `task-4.4.md`,
  `task-4.5.md` — the per-task exit-gate evidence, to be promoted onto
  the lane base as each merge lands.
- Plan reference: `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`,
  Phase 4 section, lines 17242–17268.

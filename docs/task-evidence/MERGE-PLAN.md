# Phase 4 merge plan — concrete conflict surface and resolution

**Audience:** the human reviewer who merges the four Phase-4 branches.
**Status as of 2026-09-02:** all four branches committed, signed, not merged.
**Goal:** a single list of every line a human has to touch during the merge, and the
recommended resolution for each. So the merge is a checklist, not a rebase.

This file is committed on each of the four Phase-4 branches so it is visible from
any review path. The canonical version lives on `feat/task-4.5-routing-receipts`
at `259b1a8`; the copies here are byte-identical except for the commit footer.

## The four branches

| Branch | Commit | Worktree | Pane added | `4` key maps to |
|---|---|---|---|---|
| `feat/task-4.1-buyers-surface` | `049be88` | `M:/wt-phase4` | `queue` (L8-01) | `queue` (on key `2`) |
| `feat/task-4.2-notify-fabric` | `ec51ae7` | `M:/wt-phase4-2` | `settings` (L8-11) | `settings` |
| `feat/task-4.4-coverage-map` | `01f7505` | `M:/wt-phase4-4` | `coverage` (L8-22) | `coverage` |
| `feat/task-4.5-routing-receipts` | `f93cb3d` | `M:/wt-phase4-5` | `routing` (L9-14) | `routing` |

All four branch from `efd4d33`. No new commits on `origin/docs/content-program-p9-fold`
since that base, verified 2026-09-02 12:22 PDT.

## The load-bearing problem

Every Phase-4 branch added a new destination. The mechanism is the same in every
branch: a `<button id="view-*">` in `index.html`, an `el.view*` lookup in
`console.js`, a `[el.view*, '*']` row in the `setView` toggle loop, an
`if (value === '*') await load*()` line in `setView`, a `case '4':` keyboard
handler, and a `SHORTCUTS` sheet row that extends the key list from `1 / 2 / 3`
to `1 / 2 / 3 / 4`. **The keyboard rebinding is the part that conflicts**, because
the source can carry only one `case '4':` clause.

4.1 used the `2` key for `queue` (it had no `4` conflict). 4.2, 4.4, and 4.5 all
rebinding `4` to a different destination is the problem: the file ends up with
one `case '4':` clause whichever branch is merged last, and the other two
destinations lose their key. The pane stays in the DOM (the merge keeps the
lookup, the toggle row, and the click wiring), but the keyboard is silently
broken for whichever pane was overwritten.

## Merge order and the conflict shape

The merge order is **4.1 → 4.2 → 4.4 → 4.5**. 4.1 is the only branch whose key
assignment does not conflict with the others (it uses `2` for `queue`). The
remaining three all want `4`; the post-merge file will have whichever one was
merged last.

### Conflicts in `rust/warrant/src/console/console.js`

Every one of the 4.2 / 4.4 / 4.5 merges into the same file produces conflicts in
seven places. They are always the same shape (two branches adding adjacent lines
to the same spot in the source). Resolved by hand for each pair, this is what the
human will see:

| # | Location (base line, approximate) | What's in 4.2 | What's in 4.4 | What's in 4.5 | Resolution |
|---|---|---|---|---|---|
| 1 | `el` lookup table, after `viewQueue` | `viewSettings` lookup | `viewCoverage` lookup | `viewRouting` lookup | keep **all three**; add `viewSettings`, `viewCoverage`, `viewRouting` as siblings of `viewQueue` |
| 2 | `applyEmptyState` body, after `const queue = ...` | `const settings = ...; const elsewhere = summary \|\| queue \|\| settings;` | `const coverage = ...; const elsewhere = summary \|\| queue \|\| coverage;` | `const routing = ...; const elsewhere = summary \|\| queue \|\| routing;` | keep **all four**: `const settings = ...; const coverage = ...; const routing = ...; const elsewhere = summary \|\| queue \|\| settings \|\| coverage \|\| routing;` |
| 3 | `applyEmptyState` body, after `el.queue.hidden = ...` | `el.settings && (el.settings.hidden = !settings);` | `el.coverage && (el.coverage.hidden = !coverage);` | `el.routing && (el.routing.hidden = !routing);` | keep **all three** lines, one per pane |
| 4 | `setView` toggle loop, after `[el.viewSummary, 'summary']` | `[el.viewSettings, 'settings']` | `[el.viewCoverage, 'coverage']` | `[el.viewRouting, 'routing']` | keep **all three** rows in the same array |
| 5 | `setView` body, after `if (value === 'queue') await loadQueue();` | `if (value === 'settings') await loadSettings();` | `if (value === 'coverage') await loadCoverage();` | `if (value === 'routing') await loadRouting();` | keep **all three** lines |
| 6 | Section banner, after the queue section | the notification-fabric section banner | the coverage-map section banner | the routing-ledger section banner | keep **all three** sections; insert them in the same order as their panes appear in the toggle |
| 7 | `SHORTCUTS` array, row for the digit keys | `['1 / 2 / 3 / 4', '... / Notifications']` | `['1 / 2 / 3 / 4', '... / Coverage map']` | `['1 / 2 / 3 / 4', '... / Routing']` | **resolve to `1 / 2 / 3 / 4 / 5`** and the post-merge keyboard rebinding (below) |

The first six are mechanical: keep all of each branch's lines. The seventh is
where the keyboard story is decided.

### Conflicts in `rust/warrant/src/console/console.test.js`

Same shape. The keyboard test currently pins the (key, view) pairs by reading
`console.js` source and asserting:

```js
[['1', 'warrants'], ['2', 'queue'], ['3', 'summary'], ['4', 'routing']]
```

After all four branches merge, this list must extend to match the post-merge
keyboard layout below. The test must be updated to whatever (key, view) pairs
the human picks.

### Conflicts in `rust/warrant/src/console/index.html`

Two places: the `<button id="view-*">` row in the views group, and the new
`<section>` block. The merge keeps all four `<button>`s and all four `<section>`s.
The conflict is the same shape as the `console.js` conflicts and resolves the
same way: keep all of each branch's lines.

## Resolution: rebind the keyboard to 1-5

After the four branches are merged into `docs/content-program-p9-fold`, the human
must do the following on the merged file. **None of the four branches makes this
change** because each branch believed it owned the `4` key:

1. In `rust/warrant/src/console/console.js`, the `setView` toggle loop and the
   `case '4':` keyboard handler — extend to a `1-5` spread.
2. The recommended mapping is:
   - `1` → `warrants` (existing)
   - `2` → `queue` (existing, from 4.1)
   - `3` → `summary` (existing)
   - `4` → `coverage` (from 4.4)
   - `5` → `routing` (from 4.5)
3. **The `settings` pane does not get a number key.** Either it loses keyboard
   access entirely, or the merged file grows a `6` key. The visual order of the
   four new tabs in the merged HTML is: `Warrants / Waiting on you / Refusals &
   guard / Notifications / Coverage map / Routing`. The numeric keys do not
   match the visual order, which is exactly the failure mode the existing
   `// Numbered by VISUAL ORDER` comment in `console.js` was written to prevent.
4. The `SHORTCUTS` sheet row becomes:
   `['1 / 2 / 3 / 4 / 5', 'Warrants / Waiting on you / Refusals & guard / Coverage map / Routing']`
   and the settings pane is documented as **click-only**, with a sentence
   explaining that one of the four destinations has no number key because the
   source carries six panes and the keyboard has only five digits. (This is
   the same kind of sentence the queue pane carries for "no act by anybody can
   clear this": honesty about the limit.)

The human picks the keyboard layout. The plan exists so the human is not
discovering these conflicts in the middle of a merge — they are listed here,
with the file and line, and the resolution is one edit per file.

## Conflicts in `rust/warrant/src/console/console.test.js` (extended)

The existing test "every destination has a number key, and the sheet names the
same ones" (test 41) reads `console.js` source and asserts the (key, view) pairs.
After the merge, this test must be updated to the post-merge keyboard layout
above. The test that documents "the destination showing is announced, not only
painted" (test 42) does not need a change; it reads `aria-pressed` rather than
the key bindings.

The four new test files (queue / notify / coverage / routing) do not conflict
with each other; each branch added a different fixture file and a different set
of new test cases. The merge keeps all of them.

## Files that DO NOT conflict

| File | Reason |
|---|---|
| `rust/warrant/src/console/queue.fixtures.js` | added by 4.1 only |
| `rust/warrant/src/console/notify.fixtures.js` | added by 4.2 only |
| `rust/warrant/src/console/coverage.fixtures.js` | added by 4.4 only |
| `rust/warrant/src/console/routing.fixtures.js` | added by 4.5 only |
| `docs/task-evidence/task-4.1.md` | added by 4.1 only |
| `docs/task-evidence/task-4.2.md` | added by 4.2 only |
| `docs/task-evidence/task-4.4.md` | added by 4.4 only |
| `docs/task-evidence/task-4.5.md` | added by 4.5 only |

Eight files, all conflict-free additions. The conflicts are isolated to the three
files where the four branches each grew the same UI surface (the destination
toggle, the click wiring, the keyboard handler, the DOM section).

## The merge in three steps

1. **Merge 4.1 first.** No conflicts. 4.1 is the only branch that does not bind
   the `4` key, so it does not need rebasing.
2. **Merge 4.2 next.** Seven conflicts in `console.js` (and the matching DOM
   additions in `index.html`). Resolve by keeping all of 4.2's lines alongside
   4.1's. After this merge, the `4` key is `settings`.
3. **Merge 4.4 next.** Seven more conflicts in `console.js` (and `index.html`).
   Resolve by keeping all of 4.4's lines alongside 4.2's. After this merge, the
   `4` key is `coverage`. The `settings` pane is in the DOM and clickable; it
   just lost the `4` key.
4. **Merge 4.5 last.** Seven more conflicts in `console.js` (and `index.html`).
   Resolve by keeping all of 4.5's lines alongside 4.4's. After this merge, the
   `4` key is `routing`. The `coverage` and `settings` panes are in the DOM and
   clickable; both lost the `4` key.
5. **Post-merge: do the keyboard rebinding described above.** Add the `5` key
   for `routing` (or whatever the human picks). Update the `SHORTCUTS` sheet
   row to `1 / 2 / 3 / 4 / 5` and document the click-only pane in prose.
   Update the test that pins the (key, view) pairs to match.

## Alternative: rebase 4.4 and 4.5 onto 4.2 first

The alternative to the merge-and-rebind path is to rebase 4.4 and 4.5 onto 4.2
before merging, so each branch is conflict-free on its own. The human owns the
rebase (the task spec says "do not merge, a human reviews"). The author of this
plan is not rebasing because:

- Force-pushing history on a branch the human is about to read is a
  review-blocking action.
- The conflict surface is small and well-understood, and the merge-and-rebind
  path is the same number of file touches as the rebase path (one rebind edit
  per file, post-merge).

If the human prefers the rebase path, the order is:

1. `git rebase feat/task-4.2-notify-fabric` on `feat/task-4.4-coverage-map`.
   Resolve the seven conflicts the same way (keep all lines).
2. `git rebase feat/task-4.2-notify-fabric` on `feat/task-4.5-routing-receipts`.
   Resolve the seven conflicts the same way.
3. Then `git merge feat/task-4.2-notify-fabric` from `docs/content-program-p9-fold`.
   The post-merge keyboard rebinding described above still has to happen,
   because all three branches want the `4` key.

The rebase path is one fewer post-merge edit if the human is comfortable with
force-history. The merge path is the same number of file touches with no
force-history. The plan above documents both; the human picks.

## What the human reviewer is not asked to do

- Rebase. The task spec is explicit: "A human reviews before merge."
  Force-pushing history on a branch the human is about to read is a
  review-blocking action.
- Run the post-merge rebind on the four branches. Each branch believed it
  owned the `4` key. The human picks the keyboard layout after the merge.
- Regenerate `docs/TASK-STATUS.md`. The file is script-owned and
  `task_status.py --write` regenerates it from the merged branch state. The
  current staleness is pre-existing and out of scope for the four Phase-4
  branches.

## What has been done

- The conflict surface was computed for every pair (4.1 vs 4.2, 4.2 vs 4.4,
  4.2 vs 4.5, 4.4 vs 4.5) using `git merge-tree` and `git merge-file`. The
  list above is what the human will see at merge time.
- This plan was written to `docs/task-evidence/MERGE-PLAN.md` on each of the
  four Phase-4 branches as a separate commit, so the human can read it from
  any branch review path.
- It was confirmed there are no other lanes touching these files.
  `origin/docs/content-program-p9-fold` has zero new commits since `efd4d33`,
  and no other branch in the worktree list claims any of the four SHAs.

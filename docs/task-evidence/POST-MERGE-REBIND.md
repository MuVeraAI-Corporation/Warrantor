# Post-merge keyboard rebind — concrete edit list

**Audience:** the human reviewer who, after merging 4.1 → 4.2 → 4.4 → 4.5 into
`docs/content-program-p9-fold`, needs to extend the keyboard from `1 / 2 / 3 / 4`
to `1 / 2 / 3 / 4 / 5` so all four new destinations get a number key.

**Companion to:** `MERGE-PLAN.md` on the same branch.

This file is committed on each of the four Phase-4 branches so it is visible
from any review path. The canonical version lives on
`feat/task-4.5-routing-receipts`; the copies here are byte-identical.

This is a checklist of exact-line edits, not a `git apply` patch. The post-merge
state is the result of resolving the seven conflicts in `MERGE-PLAN.md` by
keeping all of each branch's lines. The edits below are the additional changes
the human makes **after** that resolution, to fix the keyboard.

---

## Edit 1 — `rust/warrant/src/console/console.js`, the `SHORTCUTS` array

Find this line (one of the conflict resolutions):

```js
['1 / 2 / 3 / 4', 'Warrants / Waiting on you / Refusals & guard / Routing'],
```

Replace with:

```js
['1 / 2 / 3 / 4 / 5', 'Warrants / Waiting on you / Refusals & guard / Coverage map / Routing'],
```

(`Coverage map` from 4.4, `Routing` from 4.5. The `settings` pane is documented
as click-only on the line below this row — see Edit 5.)

## Edit 2 — `rust/warrant/src/console/console.js`, the keyboard handler

Find this block (one of the conflict resolutions):

```js
case '4':
  setView('routing');
  break;
```

Replace with:

```js
case '4':
  setView('coverage');
  break;
case '5':
  setView('routing');
  break;
```

The 4-way merge keeps whichever `case '4':` clause was in the last-merged branch.
The recommended post-merge binding is: `4 → coverage` (4.4 wins the keyboard,
because 4.4 is the third of three branches that want the `4` key and the human
chose to give it to the coverage map), `5 → routing` (4.5 gets a new digit).

If the human prefers a different binding, the same edit pattern applies —
`case '4':` is the load-bearing one because 4.1, 4.2, 4.4, 4.5 all touched it.

## Edit 3 — `rust/warrant/src/console/console.js`, the `applyEmptyState` body

Find this block (one of the conflict resolutions):

```js
const summary = state.view === 'summary';
const queue = state.view === 'queue';
const settings = state.view === 'settings';
const coverage = state.view === 'coverage';
const routing = state.view === 'routing';
const elsewhere = summary || queue || settings || coverage || routing;
```

Verify the line reads `summary || queue || settings || coverage || routing` —
if any of the five is missing, the post-merge file has the wrong resolution and
the corresponding pane will not toggle correctly. (The 4.5 source alone has
`summary || queue || routing`; the post-merge file should have all five.)

Then find this block:

```js
el.summary.hidden = !summary;
el.queue.hidden = !queue;
el.settings && (el.settings.hidden = !settings);
el.coverage && (el.coverage.hidden = !coverage);
el.routing && (el.routing.hidden = !routing);
```

Verify each line is present. The `&&` pattern is the existing idiom from 4.5
and is robust to a missing element (the post-merge file is guaranteed to have
all five because each branch added its own line, but the `&&` form means a
typo at merge time will not crash).

## Edit 4 — `rust/warrant/src/console/console.test.js`, the keyboard test

Find this test (test 41 in the base, "every destination has a number key, and
the sheet names the same ones"):

```js
const bound = [...source.matchAll(/case '(\d)':\s*setView\('([a-z]+)'\)/g)].map((m) => [
  m[1],
  m[2],
]);
assert.deepEqual(
  bound,
  [
    ['1', 'warrants'],
    ['2', 'queue'],
    ['3', 'summary'],
    ['4', 'coverage'],
  ],
  'the number keys must match the order the destinations appear in the nav',
);
```

Replace the `assert.deepEqual` payload with:

```js
assert.deepEqual(
  bound,
  [
    ['1', 'warrants'],
    ['2', 'queue'],
    ['3', 'summary'],
    ['4', 'coverage'],
    ['5', 'routing'],
  ],
  'the number keys must match the order the destinations appear in the nav',
);
```

The regex `/case '(\d)':\s*setView\('([a-z]+)'\)/g` reads the keyboard handler
and pulls out the (key, view) pairs. After Edit 2, the file has `case '5':` in
addition to `case '4':`, so the regex matches five pairs and the test must
expect five.

## Edit 5 — `rust/warrant/src/console/console.test.js`, the sheet row check

The test 41 also checks the `SHORTCUTS` sheet row for digit keys. Find:

```js
const row = SHORTCUTS.find((r) => /\d/.test(r[0]) && r[0].includes('/'));
assert.ok(row, 'the sheet must document the destination keys');
assert.equal(
  row[0].match(/\d/g).length,
  bound.length,
  `the sheet documents ${row[0]} while ${bound.length} destinations are bound`,
);
```

This assertion passes for the post-merge file as long as the SHORTCUTS row
reads `1 / 2 / 3 / 4 / 5` (Edit 1). No code change needed here — the assertion
is already parameterized on `bound.length`, so the digit count tracks the
binding count automatically.

## Edit 6 — `rust/warrant/src/console/console.js`, document the click-only pane

The settings pane does not get a number key after this rebind. Add a comment
next to the SHORTCUTS row, so a future reader of the file knows why:

```js
['1 / 2 / 3 / 4 / 5', 'Warrants / Waiting on you / Refusals & guard / Coverage map / Routing'],
// The settings pane is click-only: the source carries six destinations and the
// keyboard has only five digits. The pane is reached by clicking the
// "Notifications" tab in the right-hand column.
```

The comment matches the existing pattern in `setView` (`// Numbered by VISUAL
ORDER, which rebinds ...`) and the queue pane ("no act by anybody can clear
this"): honesty about the limit, not silence about it.

## What is NOT in this list

- The `el.viewSettings` lookup, the `el.viewCoverage` lookup, the
  `el.viewRouting` lookup — these are part of the conflict resolution (Edit 1
  of the table in `MERGE-PLAN.md`). The post-merge file already has all three.
- The `<button id="view-*">` rows in `index.html` — same: conflict resolution,
  not a rebind.
- The four `<section>` blocks in `index.html` — same.
- The four fixture files (`queue.fixtures.js`, `notify.fixtures.js`,
  `coverage.fixtures.js`, `routing.fixtures.js`) — these do not conflict.

## Order of operations

The recommended order is:

1. Resolve the seven conflicts in `console.js` per the table in `MERGE-PLAN.md`.
2. Resolve the corresponding conflicts in `console.test.js` and `index.html`.
3. Apply Edits 1-6 above.
4. Run `node --test rust/warrant/src/console/console.test.js`. Expect
   5-digit row in the `bound` array, all four panes in `applyEmptyState`,
   62+ tests passing.
5. Run `node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs"`
   on the three modified files.
6. Commit the rebind on the merge commit, signed off, with a message that
   names the keyboard layout as the post-merge rebind (not as a new feature).
7. `git merge --continue` to finalize the merge.
8. Run `python scripts/task_status.py --write` to regenerate the now-stale
   `docs/TASK-STATUS.md`. After this, the four Phase-4 tasks read DONE.

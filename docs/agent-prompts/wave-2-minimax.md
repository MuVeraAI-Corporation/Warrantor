# MiniMax M3 — Wave 2 assignment

Wave 1 delivered four surfaces that work: 4.1, 4.2, 4.4, 4.5, all green
(59/60/61/62 console tests, verified independently on 2026-09-05). Two jobs remain.

**Job A — consolidate the four branches into one. Do this first.**
**Job B — Task 4.3, the last Phase-4 task, once Task 0.4 lands.**

---

## Job A — one branch, rebased where it should have been

Two problems make the four branches unmergeable as they stand, and you already diagnosed the
harder one yourself.

**Problem 1 — they conflict with each other.** All four edit `console.js`, `console.test.js` and
`index.html`. `MERGE-PLAN.md` on your branches documents seven conflicts, and
`POST-MERGE-REBIND.md` documents the keyboard collision: four new panes competing for number keys
that only go up to 4. That analysis is correct and it is the job's specification — execute it.

**Problem 2 — they are rooted in the wrong place, and this one is new to you.** The instruction
said `git worktree add M:/wt-phase4 -b feat/task-4.1-buyers-surface origin/main`. The branches
were actually cut from `docs/content-program-p9-fold`: 4.1 at `ba77467`, and 4.2, 4.4, 4.5 at
`efd4d33`, so 4.1 is also one commit behind its three siblings. The consequence, measured:

```
git diff --stat origin/main..feat/task-4.1-buyers-surface
302 files changed, 213826 insertions
```

You wrote 1,388 of those insertions. The other ~212,000 are unrelated documents, papers and plan
edits that came along for the ride. **These are not independently reviewable feature branches.**

**What to build:**

```bash
git worktree add M:/wt-phase4-consolidated -b feat/phase-4-buyers-surface origin/main
```

Then port your four feature commits — `049be88`, `ec51ae7`, `01f7505`, `f93cb3d` — and their
evidence files onto it, resolving the seven conflicts by keeping all of each branch's lines, per
your own `MERGE-PLAN.md`, and then applying the `POST-MERGE-REBIND.md` edit list so the keyboard
covers `1 / 2 / 3 / 4 / 5`.

**Cherry-pick the four commits; do not merge the four branches.** Merging drags the 212,000 lines
back in. `git cherry-pick 049be88 ec51ae7 01f7505 f93cb3d` in that order is the shape of it,
resolving conflicts as they arise.

**Done when:**

1. `git diff --stat origin/main..feat/phase-4-buyers-surface` shows **only** your files:
   `console.js`, `console.test.js`, `index.html`, the four `*.fixtures.js`, and
   `docs/task-evidence/task-4.{1,2,4,5}.md`. If it shows a paper, a plan or an HTML blueprint,
   the port is wrong.
2. `node --test rust/warrant/src/console/console.test.js` passes with **at least 62 tests** — the
   union of the four branches, not the count from any one of them. A lower number means a conflict
   resolution silently dropped tests.
3. Every pane is reachable by its number key, and the shortcut row says so.
4. `docs/task-evidence/PHASE-4-CONSOLIDATION.md` records the port: which commits, which conflicts,
   the before and after test counts, and anything you had to decide rather than transcribe.
5. Not merged. A human reviews.

**Do not delete the four original branches.** They are the record of what was written; the human
reviewer compares against them.

---

## Job B — Task 4.3, after Task 0.4 lands

Verify, do not assume:

```
python scripts/task_status.py --next
```

If 4.3 still reads BLOCKED, 0.4 has not landed. GLM is implementing 0.4 now and it is that lane's
first job precisely because it gates you.

Task 4.3 is the coverage-disclosure surface in console **and desktop**. It carries Task 0.4's tier
rendering into the same console files you just consolidated, which is the whole reason it waits.
Build it on top of `feat/phase-4-buyers-surface`, not on a fifth parallel branch — the lesson of
Job A is that four branches on one file was the mistake.

The one rule still overrides every design instinct: **no screen, badge, summary, export or status
may collapse observed, advisory, mediated and enforced into one green state**, and every rendered
guarantee must also render what it does not cover. Your Wave-1 work honored this well — including
the `tier: not stated — do not read this as the strongest tier` fallback, which was the right
conservative default and is exactly what 4.3 must generalize.

---

## Standing constraints, unchanged from Wave 1

Identity, before the first commit — env vars, never `git config` (worktrees share `.git/config`
here). Wave 1 did not set these, so all four of your feature commits read
`AumOS Wave-1 <aumos@local>`:

```bash
export GIT_AUTHOR_NAME="MiniMax M3"
export GIT_AUTHOR_EMAIL="minimax@local"
export GIT_COMMITTER_NAME="MiniMax M3"
export GIT_COMMITTER_EMAIL="minimax@local"
```

- **Vanilla JavaScript.** `console.js` is 1,824 lines of plain JS served from Rust. No TypeScript,
  no framework, no bundler, no runtime dependency. Desktop is Electron with zero runtime deps.
- Do not run `cargo`. If a surface needs a Rust build, report it rather than racing the other lane.
- US English everywhere including UI copy and alt text:
  `node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <files>`
  Known false positives: the verb "forwards", the noun plural "analyses".
- `git commit -s`. Conventional prefixes. Commit messages explain WHY.
- Accessibility is a release gate. Approval and incident response are safety-critical workflows.

**Stop and report if:** the consolidated test count comes out below 62; a conflict resolution needs
a design decision rather than keeping both sides; 4.3 needs a contract field that does not exist;
or you would have to weaken the enforcement-mode distinction to make a layout work.

# GOAL — MiniMax M3: the whole operator estate

**Scope: 14 pending tasks, 96 steps.** This is a standing goal, not a single task. Loop until the
backlog is empty or you hit a stop condition.

Four of this lane's 18 tasks are already built and awaiting merge — **4.1, 4.2, 4.4 and 4.5.** Do not
rebuild them. Job A below consolidates them.

---

## The order of work, and why

| # | Work | Gate |
|---|---|---|
| **A** | Consolidate the four Phase-4 branches onto one branch cut from `origin/main` | none — do this first |
| **B** | **Task 4.3** — coverage disclosure in console and desktop | waits on Task 0.4 (GLM) |
| **C** | **Phase 11**, thirteen tasks, in the order below | waits on A |

**Phase 11 order — dependency-driven, not numeric:** 11.4 → 11.1 → 11.2 → 11.5 → 11.6 → **11.7** →
11.3 → 11.10 → 11.11 → 11.8 → 11.9 → 11.12 → 11.13.

- **11.4 first.** Its evidence pack must verify offline on a machine that never touched this
  deployment, and everything else in the estate exports through it.
- **11.7 early, not late.** Accessibility is a release gate. Auditing deny and stop for keyboard-only
  and screen-reader operation is cheap across six surfaces and expensive across thirteen.
- **11.13 last.** A natural-language layer over an invented reader is exactly the wrong order.

---

## Prerequisites — verify once per session

```bash
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git fetch origin
node --version && python --version
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" README.md
python tools/ci/check_phase_scope.py     # exit 0
python scripts/task_status.py --next
```

**Lane identity, before your first commit. Env vars, NEVER `git config`** — linked worktrees share
`.git/config` here, so `git config user.name` rewrites all four lanes at once and races them. All four
of your Wave-1 commits read `AumOS Wave-1 <aumos@local>` because this was not set:

```bash
export GIT_AUTHOR_NAME="MiniMax M3"
export GIT_AUTHOR_EMAIL="minimax@local"
export GIT_COMMITTER_NAME="MiniMax M3"
export GIT_COMMITTER_EMAIL="minimax@local"
git var GIT_AUTHOR_IDENT && git var GIT_COMMITTER_IDENT
```

---

## Job A — one branch, rooted where it should have been

Two problems make the four branches unmergeable. You diagnosed the harder one yourself.

**They conflict with each other.** All four edit `console.js`, `console.test.js` and `index.html`.
`MERGE-PLAN.md` on your branches documents seven conflicts and `POST-MERGE-REBIND.md` documents the
keyboard collision — four new panes competing for number keys that stop at 4. **That analysis is
correct and it is this job's specification.**

**They are rooted in the wrong place.** The instruction said `origin/main`. They were cut from
`docs/content-program-p9-fold`: 4.1 at `ba77467`, and 4.2, 4.4, 4.5 at `efd4d33`, so 4.1 is also one
commit behind its siblings. Measured:

```
git diff --stat origin/main..feat/task-4.1-buyers-surface
302 files changed, 213826 insertions
```

You wrote 1,388 of those. The other ~212,000 are unrelated documents that came along for the ride.

```bash
git worktree add M:/wt-phase4-consolidated -b feat/phase-4-buyers-surface origin/main
cd M:/wt-phase4-consolidated
git cherry-pick 049be88 ec51ae7 01f7505 f93cb3d      # in this order
```

**Cherry-pick; do not merge the four branches** — merging drags the 212,000 lines back. Resolve the
seven conflicts by keeping all of each branch's lines, per your own `MERGE-PLAN.md`, then apply
`POST-MERGE-REBIND.md` so the keyboard covers `1 / 2 / 3 / 4 / 5`.

**Job A is done when:**

1. `git diff --stat origin/main..feat/phase-4-buyers-surface` shows **only** your files: `console.js`,
   `console.test.js`, `index.html`, the four `*.fixtures.js`, and `docs/task-evidence/task-4.{1,2,4,5}.md`.
   A paper, a plan or an HTML blueprint in that diff means the port is wrong.
2. `node --test rust/warrant/src/console/console.test.js` passes with **at least 62 tests** — the union
   of the four branches, not any one branch's count. Lower means a conflict resolution dropped tests.
3. Every pane reachable by its number key, and the shortcut row says so.
4. `docs/task-evidence/PHASE-4-CONSOLIDATION.md` records which commits, which conflicts, before-and-after
   test counts, and anything you decided rather than transcribed.
5. **Do not delete the four original branches.** They are the record a reviewer compares against.

---

## Job B — Task 4.3, after Task 0.4 lands

**Task 0.4 landed on 2026-09-05; `origin/main` is `dbe653a` and 4.3 reads READY.** Verify anyway,
do not assume: `python scripts/task_status.py --next`. If 4.3 still reads BLOCKED, something is
wrong with your checkout — stop and report rather than working around it.

4.3 carries 0.4's tier rendering into the console **and desktop** — the same files you just
consolidated, which is why it waits. Build it on `feat/phase-4-buyers-surface`, not a fifth parallel
branch.

---

## Job C — Phase 11, thirteen tasks, ONE branch, sequential

**MERGE `origin/main` in before you start. Do not rebase.** This was tested, not assumed.

Task 0.4 landed on `origin/main`, and it edits `console.js` and `console.test.js` — your files. It
adds 24 lines: `TIER_WORDS`, `boundTierLines`, and a rendered tier list. Your branch must take that
change before Phase 11 builds on the file.

**Merge, because a rebase is the wrong operation here.** Your branch carries six commits, so a
rebase replays all six and can hit the same conflict six times, and it rewrites the SHAs your own
`PHASE-4-CONSOLIDATION.md` cites. The merge was executed in a throwaway worktree on 2026-09-05 and
is **clean**: 0.4 inserts at original lines 836 and 1270, your insertions sit at 659 and 1536, and
they do not touch.

```bash
git fetch origin
git checkout feat/phase-4-buyers-surface
node --test rust/warrant/src/console/console.test.js | grep -E "^# (tests|pass|fail)"
#   expect: tests 110, pass 110, fail 0
#   If grep prints NOTHING, the suite failed to load. Stop and report. Never read an empty
#   count as a passing one -- that is the shape of every false green in this repository.

git merge origin/main

node --test rust/warrant/src/console/console.test.js | grep -E "^# (tests|pass|fail)"
#   expect: tests 111, pass 111, fail 0
grep -c boundTierLines rust/warrant/src/console/console.js   # expect 2 -- 0.4 survived
git diff --stat origin/main..HEAD                            # expect 12 files, console only
```

**Expect NO conflict.** If you hit one, something differs from what was verified — **stop and
report rather than resolving it.** Do not go looking for a conflict that is not there. If a future
merge does conflict on `console.js`, the rule is: keep **both** sides, 0.4's `boundTierLines` and
your panes. Never drop the tier rendering to make a layout work; it is the mechanism behind this
phase's central rule, and Task 4.3 exists to carry it into the desktop.

**Order matters and it is easy to get wrong.** Commit Task 4.3 on `feat/phase-4-buyers-surface`
**first**, then create the Phase 11 worktree from it. Branching for Phase 11 before 4.3 is committed
orphans 4.3.

```bash
git worktree add M:/wt-phase11 -b feat/phase-11-operator-estate feat/phase-4-buyers-surface
```

**One branch for the whole phase.** Wave 1's four parallel branches on `console.js` conflicted seven
ways; thirteen would be that cubed. Each task is one commit on this branch.

Each Phase 11 task in the plan is a **structural** section: anchor, Step 0, non-goals, files, exit
gate, and step headings. Per task, three passes in one invocation:

1. **Read.** For each catalog item the task names, read the master blueprint's
   `<article class="item" id="L8-nn">` entry in full — its status, its novelty, what it says the gap
   is. **Quote its status verbatim in your work — `status=none` or `status=partial` — and never soften
   it.** Then read the console code the task touches.
2. **Execute Step 0 literally** and capture real output. Where the task names a dependency — Task
   10.2's query grammar, Task 8.8's exercised measurements, Task 14.4's crosswalk data — check whether
   it has landed. **If it has not, define the fixture in the shape that dependency's contract
   specifies and list it in your report. Never invent a field the contract does not have.**
3. **Build against fixtures, no backend running.** Tests in plain JS beside the source, in the
   surrounding idiom.

---

## The stack — corrected, and non-negotiable

**Not TypeScript. Not React.** The console is vanilla JavaScript served from Rust:
`rust/warrant/src/console/console.js` (1,824 lines before Wave 1), `console.test.js` (1,214),
`index.html` (365), `console.css`. No bundler, no framework, no build step. Desktop is Electron with
**zero** runtime dependencies. Adding React to a 1,824-line vanilla console is a migration, not a UI
task — if a task seems to need TypeScript, a framework, a bundler or a runtime dependency, **stop and
report.**

`console.js` passes 3,000 lines with Wave 1's four surfaces on it. Thirteen more tasks on one file is a
real design question. **Raise it before Task 11.3 and wait for a decision.** Propose plain ES modules
with no bundler if you think it is needed. Do not restructure unilaterally.

---

## The rule that overrides every design instinct

**No screen, badge, summary, export or status may collapse "observed", "advisory", "mediated" and
"enforced" into one green state.** Every rendered guarantee must also render what it does **not**
cover. A merely-observed bound must never look identical to a cryptographically enforced one. **If a
design looks better when the distinction is hidden, the design is wrong.**

Your Wave-1 `tier: not stated — do not read this as the strongest tier` fallback was the right
conservative default. Phase 11 generalizes it across thirteen surfaces, and five tasks are specifically
about not letting a summary lie:

- **11.2** renders containment latency as a **distribution**; a blast-radius bound never exercised
  renders as *"not exercised"*, never as a value.
- **11.8** may not map a control to a clause it does not satisfy. `unmapped` is a rendered state, not a
  blank cell.
- **11.9** the regulator portal and the customer trust center are read-only views of the same receipts.
  **If they can disagree, one is a marketing surface** — assert with a differential test that they
  cannot.
- **11.10** every roll-up renders the **weakest** tier among its inputs. Never the strongest, never an
  average.
- **11.13** every answer cites receipt identifiers; a question unanswerable from the graph returns
  *"not answerable from the receipts"*, never an inference.

**Bound strength for this whole phase is Tier C, observed** — a surface renders, it does not refuse —
**except** where a task names a specific refusal point in its own exit gate. Never let a rendered
guarantee imply an enforced one.

---

## Standing constraints

- **Every invented fixture goes in a committed manifest, not only in your report.** Maintain
  `docs/task-evidence/PHASE-11-FIXTURE-CONTRACT.md` and append to it in the **same commit** as the
  task that invented the fixture. One row each: the field, its shape, the task that will have to
  honor it, and whether you **read** the shape from an existing contract or **inferred** it. Thirteen
  tasks build against dependencies that do not exist yet — Task 10.2's query grammar, Task 8.8's
  exercised measurements, Task 14.4's crosswalk data — so the inferences accumulate. A fixture
  recorded only in a session report is lost, and the backend then has no way to honor what the UI
  already assumed.
- **Console test count must be strictly greater after every task.** Holding or falling means a conflict
  resolution or a refactor dropped tests. Stop and report.
- **Accessibility is a release gate, not polish.** An access barrier inside approval or incident
  response is a control failure.
- **Do not run `cargo`.** If a surface needs a Rust build, report it rather than racing the other lane's
  `Cargo.lock`. Another lane owns `operators.rs`, `review.rs`, `notify.rs`, `guard.rs`, `spend.rs`,
  `report.rs`, `lib.rs`, `serve.rs`, `Cargo.toml`, `Cargo.lock`.
- **US English everywhere**, including UI copy, labels, alt text and error strings:
  `node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <files>`. False positives,
  both correct: the verb **"forwards"**, the noun plural **"analyses"**.
- `git commit -s` — the DCO gate rejects unsigned commits. Conventional prefixes. Messages explain WHY.
  Write long messages to a file and use `git commit -F`; backticks in `-m` get executed by the shell.
- **Never edit `docs/TASK-STATUS.md` by hand.** Regenerate:
  `python scripts/task_status.py --write && python scripts/task_status.py --check`
- **When the plan and the code disagree, the code wins and you stop.** Do not repair the plan by
  assuming.

## Evidence is part of done

`docs/task-evidence/task-11.N.md` before each task's final commit, with the exit gate quoted verbatim
from the plan and the **real** output that satisfies it. **Merged is not done. Done is merged and
demonstrated.**

## Definition of done, per task

1. Surface renders from fixtures with **no backend running**.
2. A non-developer completes the workflow end to end **without a terminal**.
3. Every guarantee rendered anywhere also renders its coverage limits **and its tier**. Name the
   specific UI element that carries the distinction, per surface, in your report.
4. Console tests pass and the total is strictly greater than when you started.
5. US-English gate clean. Accessibility checks pass. **No type check — this is vanilla JavaScript.**
6. Evidence file written.
7. Committed on the phase branch, signed off, **NOT merged**. A human reviews.
8. Report: branch and SHA, every fixture you defined with the contract field it maps to, rendered
   output per surface, and anything you could not build or built differently — **stated plainly.**

## Stop conditions — halt and report

- Either Job A gate fails: no consolidated branch, or its diff carries 300+ files.
- Console test count holds or falls after a task.
- A task appears to need TypeScript, a framework, a bundler or a new runtime dependency.
- A contract field you need does not exist.
- You would have to weaken the observed/mediated/enforced distinction to make a layout work.
- `console.js` growth makes you want to restructure. **Propose it and wait.**
- Task 4.3 and Task 0.4 has not landed.
- **Two consecutive tasks fail their own exit gate, even if the test suite still passes.** This
  runs unattended across thirteen tasks; a wrong fixture shape in task 3 is invisible to a test
  ratchet and ships in task 13. Two failures in a row means stop, not push on.
- Files change under you mid-task.

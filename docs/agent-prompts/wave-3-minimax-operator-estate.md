# MiniMax M3 — Wave 3: Phase 11, the operator estate

**24 catalog items, 13 tasks, all yours.** This is the largest phase in the Phases 7–14 scope and
the one the blueprint's own data flags hardest: **24 of the 28 L8 items are uncovered**, and L8 is
the plane a buyer actually touches.

Scope document: `docs/superpowers/plans/2026-09-05-phases-7-14-scope.md`, the **Phase 11** table.

---

## Prerequisites — verify each. Two of them are hard gates.

```bash
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git fetch origin

# 1. HARD GATE — Wave 2 Job A must be done. Phase 11 builds on the consolidated Phase 4 branch,
#    not on the four originals. If this branch does not exist, do Wave 2 Job A first.
git rev-parse --verify feat/phase-4-buyers-surface

# 2. HARD GATE — the consolidated branch must be clean against origin/main. Your files only.
git diff --stat origin/main..feat/phase-4-buyers-surface
#    Expect console.js, console.test.js, index.html, four *.fixtures.js, four evidence files.
#    If it shows 300+ files and 200k insertions, the consolidation was not done. Stop.

# 3. The consolidated suite must pass, with the UNION of the four branches' tests
node --test rust/warrant/src/console/console.test.js     # expect >= 62 tests, 0 fail

# 4. Documents
ls docs/superpowers/plans/2026-09-05-phases-7-14-scope.md
ls docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html
python tools/ci/check_phase_scope.py                     # 132 of 132 · exit 0

# 5. Toolchain
node --version
python --version
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" README.md

# 6. Lane identity — env vars, NEVER `git config`. Linked worktrees SHARE .git/config here, so
#    `git config user.name` rewrites all four lanes at once and races them.
export GIT_AUTHOR_NAME="MiniMax M3"
export GIT_AUTHOR_EMAIL="minimax@local"
export GIT_COMMITTER_NAME="MiniMax M3"
export GIT_COMMITTER_EMAIL="minimax@local"
git var GIT_AUTHOR_IDENT && git var GIT_COMMITTER_IDENT

# 7. ONE worktree, ONE branch, built on the consolidated Phase 4 work
git worktree add M:/wt-phase11 -b feat/phase-11-operator-estate feat/phase-4-buyers-surface
cd M:/wt-phase11
```

**Why one branch this time.** Wave 1 ran four parallel branches that all edited `console.js`,
`console.test.js` and `index.html`. They conflicted seven ways and collided on the keyboard
shortcuts, and you had to write a merge plan and a rebind list to recover. Thirteen parallel
branches on the same three files would be that failure cubed. **Phase 11 is sequential on one
branch, one task per commit.**

---

## The stack — corrected and non-negotiable

**This is not a TypeScript or React codebase.** The console is vanilla JavaScript served from Rust:

```
rust/warrant/src/console/console.js         1,824 lines before Wave 1
rust/warrant/src/console/console.test.js    1,214 lines before Wave 1
rust/warrant/src/console/index.html           365 lines
rust/warrant/src/console/console.css
```

No bundler, no framework, no build step. Desktop is Electron with **zero** runtime dependencies in
`package.json`. Do not introduce TypeScript, a framework, a bundler or a runtime dependency. If a
task seems to need one, that is a migration decision the scope does not make: **stop and report.**

`console.js` is heading past 3,000 lines with Wave 1's four surfaces on it. Thirteen more tasks on
one file is a real design question. **Raise it before Task 11.3, not after Task 11.13** — propose a
split into plain ES modules with no bundler if you think it is needed, and wait for a decision. Do
not restructure unilaterally.

---

## The one rule that overrides every design instinct

The product's entire proposition is that claims about agent behavior must be checkable. Therefore
**no screen, badge, summary, export or status may collapse "observed", "advisory", "mediated" and
"enforced" into one green state.**

- Every rendered guarantee must also render what it does **not** cover.
- A merely-observed bound must never look identical to a cryptographically enforced one.
- If a design looks better when the distinction is hidden, the design is wrong.

Wave 1 honored this well, including the `tier: not stated — do not read this as the strongest tier`
fallback, which was the right conservative default. **Phase 11 generalizes that fallback across
thirteen surfaces**, and three tasks are specifically about not letting a summary lie:

- **11.2** renders containment latency as a *distribution*, and marks any blast-radius bound that
  has never been exercised as an estimate.
- **11.8** may not map a control to a compliance clause it does not satisfy. Unmapped is a rendered
  state, not a blank.
- **11.9** the regulator portal and the customer trust center are read-only views of the same
  receipts. **If they can ever disagree, one of them is a marketing surface** — assert they cannot.

---

## Method, per task

Each scope row is one table row: title, catalog items, one-sentence anchor. That is thinner than
Wave 1's Phase 4 stubs, so each task is three passes in one invocation:

**Pass 1 — Seed.** Write the task section into
`docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md` under
`## Phase 11 — The operator estate`, in the shape Phase 4 uses: anchor, Step 0, non-goals, files,
exit gate, and six to ten numbered step headings. **It must contain its own
`git worktree add ... -b <branch>` line in Step 1** — the board reads the branch name from there,
and a task without it resolves to an invented name. For Phase 11 that line names
`feat/phase-11-operator-estate` for every task, because you are working on one branch.

**Pass 2 — Read before writing.** For each catalog item, read the master blueprint's `<article
class="item" id="L8-nn">` entry in full: its status, its novelty, and what it says the gap is. Then
read the existing console code the task touches. **Quote the blueprint's status verbatim in your
anchor — `status=none` or `status=partial` — and never soften it.**

**Pass 3 — Build against fixtures, not a backend.** Every surface renders with no server running.
If a fixture you need does not exist, define it in the shape the contract specifies, mark it clearly
as a fixture, and list it in your report with the contract field it maps to. **Never invent a field
the contract does not have.** Tests alongside the implementation, in plain JS beside the source, in
the surrounding code's idiom.

### Order — dependency-driven, not by number

| Group | Tasks | Why |
|---|---|---|
| A | **11.4**, then 11.1, 11.2 | The evidence pack generator in 11.4 must verify **offline on a machine that never touched this deployment**. Everything else exports through it, so build it first |
| B | 11.5, 11.6 | Consequence preview and dependency-aware partial approval extend Wave 1's approval queue. 11.6's automation-bias instrumentation is what stops that queue becoming ceremony |
| C | 11.7 | Accessibility. **A release gate, not polish** — an access barrier inside approval or incident response is a control failure. Do it before the estate triples in size, not after |
| D | 11.3, 11.10, 11.11 | Policy studio and the risk ledgers. 11.3 must refuse in the policy compiler's exact words, or the two disagree and the studio wins in the user's head |
| E | 11.8, 11.9, 11.12 | Outward-facing: crosswalk, regulator portal, trust center, and the notice/appeal surface — the only one built for someone outside the buying organization |
| F | 11.13 | The natural-language console over the receipt graph. Last. It must cite receipts and **refuse to answer beyond them** |

---

## Standing constraints

- **US English everywhere**, including UI copy, labels, alt text and error strings:
  `node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <files>`
  Known false positives: the verb **"forwards"**, the noun plural **"analyses"**. Everything else
  the gate reports is real.
- **Do not run `cargo`.** If a surface needs a Rust build, report it rather than racing the other
  lane's `Cargo.lock`. Another lane owns `operators.rs`, `review.rs`, `notify.rs`, `guard.rs`,
  `spend.rs`, `report.rs`, `lib.rs`, `serve.rs`, `Cargo.toml` and `Cargo.lock`.
- `git commit -s` — the DCO gate rejects unsigned commits. Conventional prefixes. Commit messages
  explain WHY.
- **Never edit `docs/TASK-STATUS.md`** by hand. Regenerate:
  `python scripts/task_status.py --write && python scripts/task_status.py --check`
- **When the scope and the code disagree, the code wins and you stop.** Do not repair the scope by
  assuming.

## Evidence is part of done

`docs/task-evidence/task-11.N.md` before each task's final commit, with the exit gate quoted
verbatim from the section you seeded and the **real** output of the command that satisfies it. Same
gate as every other lane: `python scripts/task_status.py --check`. Merged is not done; done is
merged and demonstrated.

## Definition of done, per task

1. Task section seeded into the plan, with its `worktree add ... -b` line present.
2. Surface renders from fixtures with **no backend running**.
3. A non-developer completes the workflow end to end **without a terminal**.
4. Every guarantee rendered anywhere also renders its coverage limits **and its tier**. Name the
   specific UI element that carries the distinction, per surface, in your report.
5. Console tests pass, and the total is **strictly greater** than when you started. A count that
   holds or falls means a conflict resolution or a refactor silently dropped tests.
6. US-English gate clean. Accessibility checks pass. No type check — this is vanilla JavaScript.
7. `docs/task-evidence/task-11.N.md` written.
8. Committed on `feat/phase-11-operator-estate`, signed off, **not merged**.

## Stop and report immediately if

- Either hard-gate prerequisite fails — no consolidated Phase 4 branch, or it carries 300+ files.
- The console test count holds or falls after a task.
- A task appears to need TypeScript, a framework, a bundler, or a new runtime dependency.
- A contract field you need does not exist.
- You would need to weaken the observed/mediated/enforced distinction to make a layout work.
- `console.js` growth makes you want to restructure. Propose it and wait.
- Files change under you mid-task.

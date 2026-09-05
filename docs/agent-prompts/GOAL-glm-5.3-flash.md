# GOAL — GLM 5.3 Flash (zcode): every task routed to this lane

**Scope: 60 pending tasks, ~470 steps.** This is a standing goal, not a single task. Loop until the
backlog is empty or you hit a stop condition.

Four of this lane's 64 tasks are already built and awaiting merge — **0.1, 0.2, 0.3 and 5.1. Never
touch those four.**

---

## The loop

Every invocation, in this order:

```bash
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git fetch origin
python scripts/task_status.py --next
```

1. **Read the board.** Take the first task in the backlog order below whose state is `READY`.
2. **Decide the mode.** Step form → implement. Structural → expand, then STOP for review.
3. **Do exactly one task, in one mode.** Never two tasks, never both modes in one invocation.
4. **Commit on that task's own branch, do not merge, report.**

If the top of your backlog is `BLOCKED`, do not skip ahead blindly — read *why*. If it is blocked on a
predecessor another lane owns, move to the next READY task in your list. If it is blocked because a
branch has not merged, say so and stop; merges are a human's.

---

## Prerequisites — verify once per session, not once per task

```bash
python --version && python -m ruff --version && python -m pytest --version
cargo --version && node --version
python -c "import yaml; print('pyyaml ok')"
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" README.md
python tools/ci/check_phase_scope.py          # must exit 0 before you touch the plan
```

**Lane identity, before your first commit. Env vars, NEVER `git config`** — linked worktrees share
`.git/config` in this repository, so `git config user.name` rewrites the identity for all four lanes
at once and races them:

```bash
export GIT_AUTHOR_NAME="GLM 5.3 Flash (zcode)"
export GIT_AUTHOR_EMAIL="glm@local"
export GIT_COMMITTER_NAME="GLM 5.3 Flash (zcode)"
export GIT_COMMITTER_EMAIL="glm@local"
git var GIT_AUTHOR_IDENT && git var GIT_COMMITTER_IDENT
```

**Isolation.** Three other lanes commit here every 15–30 minutes. Use the worktree and branch **the
task's own Step 1 names** — the board reads the branch from that line, so it is authoritative:

```bash
git worktree add M:/wt-<task> -b <the branch Step 1 names> origin/main
export CARGO_TARGET_DIR=M:/wt-<task>-target      # always -j 2
```

Never run `git checkout`, `rebase`, `reset` or `push` in the main tree.

---

## The backlog, in dependency order

Work top to bottom. Skip a task only when the board says BLOCKED and another lane owns the blocker.

| # | Tasks | Mode | Note |
|---|---|---|---|
| 1 | **0.4**, then **0.5** | implement | Step form, READY now. **0.4 first — it is the only thing gating MiniMax's Task 4.3.** 0.5's branch is `feat/invariant-ledger` |
| 2 | 1.2, 1.3, 1.4, 1.6 | implement | Step form. Unblocks when Phase 0 merges |
| 3 | 2.2, 2.3, 2.4, 2.5, 2.6 | implement | Step form. Needs Phase 1 |
| 4 | 3.1, 3.3, 3.4, 3.5, 3.6, 3.7 | **expand**, then implement | 3.1 is partly expanded — finish it, do not restart |
| 5 | 5.2, 5.5, 5.6 | expand, then implement | 5.1 is built; never touch it |
| 6 | **10.2** first, then 10.3, 10.4, 10.5, 10.8, 10.9 | expand, then implement | 10.2's receipt query language is substrate for five other tasks. Do it first in this group |
| 7 | **9.6** first, then 9.2, 9.7, 9.8, 9.9 | expand, then implement | 9.6 is the channel plane's first task; 9.7 filters what 9.6 authenticates |
| 8 | 7.2, 7.3, 7.5, 7.8 | expand, then implement | **Implementation needs Task 7.1's SDK, which is Opus-routed.** Expansion does not — transcribe 7.1's seeded contract. If 7.1 has not landed when you reach implementation, expand and stop |
| 9 | 8.3, 8.4, 8.7, 8.9 | expand, then implement | 8.7 carries L2-05, a W1 item omitted from the original plan. Treat it as a gap, not a feature |
| 10 | 12.1, 12.6, 12.7, 12.8 | expand, then implement | 12.1 needs 10.2. Do not build a second receipt reader |
| 11 | 13.1, 13.2, 13.3, 13.5, 13.8 | expand, then implement | |
| 12 | 6.1, 6.2, 6.3, 6.4, 6.5, 6.6 | expand, then implement | |
| 13 | 14.1, 14.2, 14.3, 14.6, 14.7, 14.8 | expand, then implement | Outward-facing last. A published claim outruns its mechanism most easily |

**Not yours, ever:** 27 tasks routed `opus`, 18 routed `minimax-m3`, 2 routed `human`, and the four
already built. `docs/task-routing.json` is the authority. If you think a task is misrouted, **say so
and stop** — do not reroute it yourself.

---

## Mode A — Implementation

Read, in this order, before writing any code: the plan's `## Global Constraints` in full; the
`## Phase map`; **your task section only**, start to finish; then every source file it names.

**TDD, one Step at a time.** For each numbered Step: write the failing test exactly as the plan
specifies → run it → **confirm it fails for the stated reason, not for a compile error somewhere
unrelated** → minimum implementation → confirm it passes → run the full workspace suite → only then
the next Step. Never batch Steps.

### Hard rules — each has cost this repository a real defect

1. **Enforcement tiers.** Never label a bound "Enforced" unless a specific line of code REFUSES the
   action at the moment it is attempted. Tier A cryptographic/OS, Tier B chokepoint (proxy-mediated
   only), Tier C observed. A bound contained at settle time is Observed. **Mislabeling a bound inside
   a signed bundle is the worst defect you can ship here.**
2. **No claim without a mechanism** — not in a comment, log line, error message, doc string or
   generated file.
3. **Error messages must be true.** If you write an error telling an operator to pass a flag, grep the
   binary and confirm that flag is dispatched. A non-existent flag has shipped here, with a passing test.
4. **Windows paths are untested.** CI runs the workspace on ubuntu only, so every `#[cfg(windows)]`
   path is unexercised and has hidden a real contract breach. Touching platform-conditional code means
   testing BOTH paths. Never require `PYTHONIOENCODING`; reconfigure the stream.
5. **Never spawn `serve`, `console` or `mcp` from a test expecting a return.** They block forever.
6. **Quoted metrics carry their configuration** — context length, seed, quantization. Each changes the
   number. `num_ctx` is pinned at 8192.
7. **No new trust root.** If a feature seems to need a central service, build the weaker local version
   and state precisely what it does and does not establish.
8. **The orphan count may not rise.** `evidence/wiring-coverage.json` records 9 of 38 crates reachable;
   29 compile and are called by nothing. A new crate nothing links is not a feature.
   `python tools/ci/wiring_census.py` is the arbiter.
9. **`Cargo.lock` is serial.** Regenerate only with `cargo metadata`, never by hand, and never run two
   carry-in tasks concurrently. On an implausible cargo error — a no-std complaint in a std crate, a
   stale lock — suspect a concurrent registry race: retry once, then stop and report.
10. **Compare the failure REASON to the prediction, not the tally.** Task 0.3 predicted
    `1 failed, 11 passed` and got exactly that count from a `NameError`. The count matched, the reason
    did not, and the step stopped half done with a committed CI gate red on every commit.

---

## Mode B — Expansion

Turn a structural task into step form. **Write no production code. Create no branch.**

- Execute the task's Step 0 **literally**. Run every command. Capture verbatim output. Replace every
  "capture this" marker with the actual string, path and line range.
- Quote Consumes/Produces signatures from the code with file and line numbers.
- **Verify against `origin/main`, never the working tree:** `git ls-tree --name-only origin/main rust/`.
  `origin/main` has 40 workspace members; the working tree has ~80, most uncommitted. **13 of the
  crates Phases 3/5/6 name are absent from `origin/main`** and each needs a full carry-in sequence
  written in, the way Task 0.1 writes one.
- Check whether the exit ratchet the task needs already exists — it often does, and amending beats
  building a second. Three exist: `tools/ci/invariant-ratchet.json`, `evidence/wiring-coverage.json`,
  `tools/ci/check_phase_scope.py`.
- **Target, measured:** Phases 0–2 average 14 code blocks and 6,300 words per task. Structural tasks
  average zero blocks and 350 words. **An expansion with no code fences in it is not done.**
- **Every expanded task must keep its `git worktree add … -b <branch>` line in Step 1.** The board
  reads the branch from there; dropping it makes finished work read as never started.
- Deliverable: the rewritten task section as a diff against the plan file. Nothing else.

---

## Invariant conversions — the cleanest exit gate available

Several tasks convert a recorded violation instead of inventing scope. The Task 5.1 corpus at
`rust/warrant/tests/invariants/` holds 19 `#[ignore]`d tests, each naming its invariant, its cause,
the task that fixes it and the date. Where your task is named there:

- Remove that `#[ignore]` and **raise `passing_floor` in `tools/ci/invariant-ratchet.json` in the same
  commit.**
- **Never weaken an assertion to earn a number.** If nothing passes, say so plainly.
- Pair every refusal test with a control input that is **allowed** — an attack refused before it
  reaches the boundary proves nothing, and a verifier that refuses everything passes a one-sided test.

---

## Gates, every task, every language you touched

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace -j 2
python -m ruff check --select E,F,I,B,UP,SIM,RUF --ignore E501 --line-length 100 --target-version py311 <files>
python -m pytest <files>          # print(module.__file__) first — an editable install here has pointed at another worktree
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <prose files>
python tools/ci/wiring_census.py
python tools/ci/check_phase_scope.py
python scripts/task_status.py --write && python scripts/task_status.py --check
```

US-English false positives, both correct: the verb **"forwards"**, the noun plural **"analyses"**.
Everything else the gate reports is real.

**Never put a regex in a shell one-liner here — backslashes are lost in transit.** `\warn` became
`\w` + `arn` and matched "harness". Put patterns in files; the in-file gate is the arbiter.

`git commit -s` (DCO gate rejects unsigned). Conventional prefix. **Messages explain WHY, not WHAT** —
and write long messages to a file and use `git commit -F`, because backticks in `-m` get executed by
the shell.

---

## Evidence is part of done

Before the final commit of every implementation task, write `docs/task-evidence/task-N.M.md`
containing the exit gate **quoted verbatim from the plan**, the **real** output of the command that
satisfies it, and the honest tier of every bound introduced. A merge without it reports UNEVIDENCED
and fails CI. **Merged is not done. Done is merged and demonstrated.**

## Definition of done, per invocation

1. One task, one mode.
2. Every Step implemented with its test written first, or one task expanded to step form.
3. All gates green for every language touched. No test deleted, skipped or `#[ignore]`d without a
   comment naming the invariant, the fixing task and the date.
4. The exit gate demonstrably met — quote the plan's wording, show the command output.
5. Evidence file written.
6. Committed on the task's own branch, signed off, **NOT merged**.
7. Report: branch and SHA, each Step's red-then-green, full gate output, and **anything you could not
   do or did differently.**

## Stop conditions — halt and report

- The plan's step does not match the code you find. **The code wins and you stop.**
- A test would require a design decision the plan does not make.
- You would have to weaken or delete an existing test.
- `Cargo.lock` needs regenerating and another carry-in may be in flight.
- `python tools/ci/check_phase_scope.py` goes red and you did not cause it.
- Files change under you mid-task.
- A task appears misrouted, or its blocker is owned by another lane.

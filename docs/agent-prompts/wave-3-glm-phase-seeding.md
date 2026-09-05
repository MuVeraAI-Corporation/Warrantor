# GLM 5.3 Flash — Wave 3: seed and expand Phases 7–14

Turns rows of a scope document into plan tasks, then into step form. **No production code in this
wave.** Needs zero merges, so it runs alongside everything else.

---

## Prerequisites — verify each one before starting. Do not skip a single check.

```bash
# 1. Repository and refs
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git fetch origin
git log -1 --format='%h %s' origin/main

# 2. The three documents this wave reads. All three must exist.
ls docs/superpowers/plans/2026-09-05-phases-7-14-scope.md
ls docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md
ls docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html

# 3. The scope accounting must be green BEFORE you touch it, or you are editing a broken base
python tools/ci/check_phase_scope.py          # expect: 76 tasks account for 132 of 132 · exit 0

# 4. Toolchain
python --version                               # 3.11+
python -m ruff --version                       # 0.12.0 is the CI pin
python -m pytest --version
node --version
cargo --version                                # needed only to VERIFY claims, not to build
python -c "import yaml; print('pyyaml ok')"

# 5. The prose gate. This exact path, and it must be runnable.
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" README.md

# 6. Lane identity — env vars, NEVER `git config`. Linked worktrees SHARE .git/config in this
#    repository, so `git config user.name` rewrites the identity for all four lanes at once and
#    races them. See docs/agent-prompts/lane-identity.md.
export GIT_AUTHOR_NAME="GLM 5.3 Flash (zcode)"
export GIT_AUTHOR_EMAIL="glm@local"
export GIT_COMMITTER_NAME="GLM 5.3 Flash (zcode)"
export GIT_COMMITTER_EMAIL="glm@local"
git var GIT_AUTHOR_IDENT && git var GIT_COMMITTER_IDENT

# 7. Your own worktree. Three other lanes commit here every 15-30 minutes.
git worktree add M:/wt-wave3 -b docs/phases-7-14-seeding origin/main
cd M:/wt-wave3
```

**If check 3 fails, stop and report.** Everything in this wave is accounted for by that checker; a
red base makes every later run unverifiable.

**If check 5 fails**, the gate script path is wrong for this machine — report it rather than
skipping the gate. Prose is the deliverable in this wave, so the prose gate is the build.

---

## What you are doing, and the one thing that makes it hard

`docs/superpowers/plans/2026-09-05-phases-7-14-scope.md` defines **76 tasks across Phases 7–14**,
covering the 132 blueprint catalog items the implementation plan does not reach. Each task is one
table row: a title, its catalog items, a one-sentence anchor, and a route.

A row is not a task. **Your job is two passes:**

- **Pass A — SEEDING.** Row → structural task section appended to the implementation plan, in the
  shape Phases 3–6 already use: anchor, Step 0, non-goals, files, and numbered step headings.
- **Pass B — EXPANSION.** Structural section → step form, in the shape Phases 0–2 use: verbatim
  test bodies, exact `file:line` ranges, real captured Step-0 output.

**Never run both passes in one invocation.** Seed, stop, let a human read it, then expand.

**Measured targets, so "done" is not a judgment call.** Phases 0–2 average **14 code blocks and
6,300 words per task**. Phases 3–6 average **zero code blocks and 350 words**. A Pass-A output that
looks like Phases 3–6 is correct. A Pass-B output with no code fences in it is not done.

---

## Your scope: the 38 tasks routed `glm-5.3-flash`. Not the others.

The scope document's last column routes every task. **Seed and expand only the rows that say
`glm-5.3-flash`.**

- **23 rows say `opus`.** Those are design keystones — invariant conversions, the causal verdict,
  cross-organization authority, every claim published outward. Their anchors are judgments, and a
  seeded structure that encodes the wrong judgment is worse than an unseeded row, because the next
  lane executes it. **Skip them. Do not seed them "to be helpful."**
- **13 rows are Phase 11**, routed `minimax-m3`, seeded by that lane.
- **2 rows say `human`** — 10.10 sovereign key topologies, 14.11 insurance and certification.

If you believe a row is misrouted, **say so and stop**. Do not reroute it yourself.

### Order — highest leverage first

| Wave | Tasks | Why this order |
|---|---|---|
| 3a | 7.2, 7.3, 7.5, 7.8 | Phase 7 volume. Seed **after** 7.1's conformance kit is seeded by the Opus lane, because 7.1 defines the shape all adapters transcribe. If 7.1 is not seeded yet, stop and report rather than inventing the adapter shape |
| 3b | 9.2, 9.6, 9.7, 9.8, 9.9 | Channels before coordination. 9.6 attested sender identity is the substrate under every collusion control above it |
| 3c | 10.2, 10.3, 10.4, 10.5, 10.8, 10.9 | 10.2's receipt query language is the substrate for Phases 11 and 12 both. Seed it first in this group |
| 3d | 8.3, 8.4, 8.7, 8.9 | **8.7 carries L2-05, which is W1 and was omitted from the original plan.** Treat it as a gap, not a new feature |
| 3e | 12.1, 12.6, 12.7, 12.8, 13.1, 13.2, 13.3, 13.5, 13.8 | Flywheel input and platform lifecycle |
| 3f | 14.1, 14.2, 14.3, 14.6, 14.7, 14.8 | Outward-facing last, because a published claim outruns its mechanism most easily |

---

## Pass A — SEEDING. Exact output shape.

Append to the implementation plan, after Task 6.6, under a `## Phase N — <name>` heading that
matches the scope document's phase name. One task per commit.

Each seeded section carries exactly these parts, in this order:

```markdown
### Task 7.3: Adapters — messaging, ticketing and email (L4-10, L4-11, L4-12)

**Anchor.** <The scope row's anchor sentence, then two to four sentences that ground it in this
codebase: which existing file is the nearest thing, what the blueprint item says the gap is, and
what the incident did that this prevents. Quote the master blueprint's own status text for each
item — `status=none` or `status=partial` — and never soften it.>

**Step 0.** <Exact commands to run and files to read IN FULL, with line counts. Every "capture
this" marker names what string, what path and what line range. This section is what makes Pass B
possible; a vague Step 0 guarantees a vague expansion.>

**Non-goals.** <What this task must NOT become. Name the adjacent task that owns each excluded
thing by number. At least three exclusions.>

**Files.** <Every path this task touches, plus `docs/task-evidence/task-7.3.md`.>

**Consumes / Produces.** <The signatures this task calls and the ones it exposes, with the file
each lives in. If a signature does not exist yet, say which task creates it.>

**Bound strength.** <Tier A cryptographic/OS, Tier B chokepoint, or Tier C observed — and the
sentence that will appear in the product stating what the bound does not cover.>

**Exit gate.** <One sentence naming a command whose output decides pass or fail. Not a feeling.>

- [ ] **Step 1 — Worktree; <what Step 0 captures>.**
- [ ] **Step 2 — Failing test: <the specific property>.** <One or two sentences of test intent.>
...
- [ ] **Step N — Gates, evidence file, `git commit -s`.**
```

**Six to twelve steps.** Fewer than six means the task is under-decomposed; more than twelve means
it is two tasks and you should say so and stop.

### Non-negotiable content rules for every seeded task

1. **The orphan count may not rise.** `evidence/wiring-coverage.json` on `feat/wiring-census`
   records 9 of 38 workspace crates reachable from the `warrantor` binary; **29 compile, pass their
   tests, and are called by nothing a user runs.** Every task you seed must either wire its crate
   into a shipping path or state in its Bound-strength block that it is adding an orphan and why.
   `python tools/ci/wiring_census.py` is the arbiter. A new crate that nothing links is not a
   feature.
2. **Enforcement tiers, always.** Never let a seeded task label a bound "Enforced" unless a
   specific line of code REFUSES the action at the moment it is attempted. Tier A cryptographic/OS,
   Tier B chokepoint — proxy-mediated only — Tier C observed. A bound contained at settle time is
   Observed. Mislabeling a bound inside a signed bundle is the worst defect this repository ships.
3. **No claim without a mechanism.** Not in a comment, a log line, an error message, a doc string
   or a generated file.
4. **Error messages must be true.** If a seeded step writes an error telling an operator to pass a
   flag, that step must include grepping the binary to confirm the flag is dispatched. A
   non-existent flag has shipped here before, with a passing test.
5. **Quoted metrics carry their configuration.** Any number about model or guard behavior carries
   context length, seed and quantization. Each of those changes the number.
6. **No new trust root.** If a task seems to need a central service — an identity provider, a
   timestamp authority, a key server — seed the weaker local version and state precisely what it
   does and does not establish.
7. **Verify against `origin/main`, never the working tree.**
   ```bash
   git ls-tree --name-only origin/main rust/
   ```
   `origin/main` has 40 workspace members; the working tree has about 80, most uncommitted.
   **13 of the crates Phases 3/5/6 name are absent from `origin/main`**, and the same is true for
   several Phase 7–14 crates. Any task naming an absent crate needs a full carry-in sequence
   written into it, the way Task 0.1 writes one. A task that assumes an absent crate is buildable
   dies at its first `cargo` call.

### After every seeding commit

```bash
python tools/ci/check_phase_scope.py     # must stay green: 132 of 132, exit 0
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
     docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md
python scripts/task_status.py --write && python scripts/task_status.py --check
```

The board derives each task's branch from the `worktree add ... -b <name>` line in its own Step 1,
so **every seeded task must contain that line** or it will resolve to an invented branch name.
This is not cosmetic: it is how the board knew nothing about two finished tasks until 2026-09-05.

Known US-English false positives: the verb **"forwards"** and the noun plural **"analyses"** are
correct. Everything else the gate reports is real.

Commit one task per commit: `git commit -s`, conventional prefix `docs(plan):`, message explains
WHY the decomposition is shaped that way, not what was added.

---

## Pass B — EXPANSION. Same as Mode 2 in `glm-5.3-flash.md`, with three additions.

Read `docs/agent-prompts/glm-5.3-flash.md` **Mode 2 — Expansion** and follow it exactly. Then:

1. **Execute Step 0 literally.** Run every command. Capture verbatim output. Replace every
   "capture this" marker with the actual string, path and line range. Quote Consumes/Produces
   signatures from the code with file and line numbers.
2. **Check whether the exit ratchet already exists.** It often does, and amending one beats
   building a second. Three already exist and are the pattern to follow:
   `tools/ci/invariant-ratchet.json`, `evidence/wiring-coverage.json`, and
   `tools/ci/check_phase_scope.py`.
3. **Deliverable is the rewritten task section as a diff against the plan file.** Nothing else.
   No branches for the task itself. No code. No implementation.

---

## Traps in this environment, each of which has cost a real cycle here

- **Compare the failure REASON against the prediction, not the tally.** Task 0.3 predicted
  `1 failed, 11 passed` from an assertion failure and got exactly that count from a `NameError`,
  because one name was missing from an import list. The count matched, so the red read as on-plan
  and the step stopped half done, leaving a committed CI gate red on every commit of the branch.
- **Regexes passed through a shell heredoc lose backslashes here.** `\warn` became `\w` + `arn` and
  matched "harness", producing three false findings in one review. Put patterns in files; the
  in-file gate is the arbiter, never an ad-hoc shell one-liner.
- **`Cargo.lock` is serial.** Regenerate only with `cargo metadata`, never by hand, and never run
  two carry-in tasks concurrently. If cargo fails implausibly — a no-std complaint in a std crate,
  a stale lock — suspect a concurrent registry race: retry once, then stop and report rather than
  "fixing" it.
- **A wrapper here reports exit 0 for a command that died.** Read the output, not the status.
- **Windows paths are untested.** CI runs the workspace on ubuntu only, so every `#[cfg(windows)]`
  path is unexercised and has hidden a real contract breach. Any seeded task touching
  platform-conditional code must specify tests for BOTH paths. Never require `PYTHONIOENCODING` to
  make a tool work; reconfigure the stream.
- **Before trusting a Python pass, print `module.__file__`.** An editable install here has pointed
  at a different worktree, so pytest ran another checkout's code.
- **Never spawn `serve`, `console` or `mcp` from a test expecting it to return.** They block
  forever.

## Stop and report immediately if

- `python tools/ci/check_phase_scope.py` goes red and you did not cause it.
- A scope row's anchor contradicts what you find in the code. The code wins and you halt.
- A task needs a design decision the scope row does not make. That is an `opus` row misrouted.
- Task 7.1 is not yet seeded and you are asked to seed an adapter.
- A seeded task would need to add a workspace crate that nothing links, with no wiring path.
- Files change under you mid-task.
- You would have to weaken or delete an existing test to make a step work.

## Definition of done, per invocation

1. One task seeded, or one task expanded. Never both.
2. `check_phase_scope.py` green, US-English gate clean, board regenerated and `--check` exit 0.
3. Every content rule above satisfied, with the Bound-strength block filled in honestly.
4. Committed on `docs/phases-7-14-seeding`, signed off, **not merged**.
5. Your report states: which task, which pass, what you could not do, and anything you decided
   rather than transcribed. If the scope row was wrong, say so plainly and stop.

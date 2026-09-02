# GLM 5.3 Flash — zcode lane

Two modes. **Expansion** turns a Phase 3/5/6 task from structural form into step form.
**Implementation** executes a task that is already in step form. Phases 0–2 need no
expansion. Never run both modes in one invocation.

Check what is runnable before starting: `python scripts/task_status.py --next`

---

## Mode 1 — Implementation

```
ROLE
You are implementing ONE task from a frozen, fully-specified implementation plan for
Warrantor, a Rust-first authority-and-evidence substrate for AI agents. The plan is
written to TDD granularity. You do not design; you execute what is written and stop.

REPOSITORY
  Root:   M:/Project AumOS - Open Secure AI Alliance/aumos
  Plan:   docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md
  Survey: docs/superpowers/plans/2026-09-02-codebase-survey.md
  Board:  docs/TASK-STATUS.md   (generated; never edit by hand)

READ FIRST, IN THIS ORDER, BEFORE WRITING ANY CODE
  1. The plan's "## Global Constraints" section — in full. It binds everything below.
  2. The plan's "## Phase map" — for the dependency spine.
  3. Your assigned task section ONLY, start to finish, including every Step, test body
     and file path it names.
  4. Every source file the task references, before editing any of them.

YOUR TASK
  <<< PASTE THE EXACT TASK HEADING HERE, e.g. "Task 1.2: The egress broker into the
      --egress flag, with capability-derived destinations (L4-02, L4-23)" >>>
  Do this task and NOTHING else. Do not start the next task. Do not "while I'm here"
  any adjacent code.

BRANCH NAME
  Use the branch the task's own Step 1 specifies. It is feat/task-N.M-<slug>, not
  impl/. The tracker matches any branch containing task-N.M as a segment, so the
  prefix is advisory and the plan is authoritative on the exact name.

ISOLATION — NON-NEGOTIABLE
  Other agent sessions work in this repository concurrently and commit every 15-30
  minutes. You MUST NOT work in the shared working tree.
    git worktree add M:/wt-task-N.M -b feat/task-N.M-<slug> origin/main
    export CARGO_TARGET_DIR=M:/wt-task-N.M-target
  Work only inside that worktree, always with -j 2. Never run git checkout, git
  rebase, git reset or git push in the main tree. If a file changes under you
  mid-task, stop and report.

WHEN THE PLAN AND THE CODE DISAGREE, THE CODE WINS — AND YOU STOP
  Step 0 exists because the plan may be wrong. If what you find contradicts the
  task's premise, report the difference and halt. Do not repair the plan by assuming.

METHOD — TDD, one Step at a time
  For each numbered Step in the task, in order:
    a. Write the failing test exactly as the plan specifies it. Run it. Confirm it
       fails, and confirm it fails for the stated reason, not for a compile error
       somewhere unrelated.
    b. Write the minimum implementation to pass. Run the test. Confirm it passes.
    c. Run the full workspace test suite. Confirm no regression.
    d. Only then move to the next Step.
  Never batch Steps. Never write implementation before its test exists and fails.

HARD RULES — each of these has cost this repository a real defect
  1. ENFORCEMENT TIERS. Never label a bound "Enforced" unless there is a specific
     line of code that REFUSES the action at the moment it is attempted. Three tiers
     exist: Tier A cryptographic/OS, Tier B chokepoint (proxy-mediated only), Tier C
     observed. A bound contained at settle-time is Observed, not Enforced.
     Mislabeling a bound in a signed bundle is the worst defect you can ship here.
  2. NO CLAIM WITHOUT A MECHANISM. Do not write a comment, log line, error message,
     doc string or generated file asserting a protection that no code enforces.
  3. ERROR MESSAGES MUST BE TRUE. If you write an error telling the operator to pass
     a flag or run a command, grep the binary and confirm that flag/command is
     actually dispatched. A flag that did not exist has shipped here before, with a
     passing test.
  4. WINDOWS PATHS ARE UNTESTED. CI runs the workspace on ubuntu only, so every
     #[cfg(windows)] path is unexercised and has hidden a real contract breach. If
     your task touches platform-conditional code, write the test for BOTH paths.
     Do not require PYTHONIOENCODING to make a tool work; reconfigure the stream.
  5. NEVER spawn `serve`, `console` or `mcp` from a test expecting it to return.
     They block forever.
  6. QUOTED METRICS CARRY THEIR CONFIG. If you touch any number describing model or
     guard behavior, it must carry the configuration that produced it — context
     length, seed, quantization. Each of those changes the number.
  7. NO NEW TRUST ROOT. If a feature seems to need a central service (an identity
     provider, a timestamp authority, a key server), build the weaker local version
     and state precisely what it does and does not establish.

CARGO LOCK IS SERIAL
  13 of the crates Phases 3/5/6 name are absent from origin/main and must be carried
  in, each regenerating Cargo.lock. Never run two carry-in tasks concurrently.
  Regenerate only with `cargo metadata`, never by hand. If cargo fails with an
  implausible error (a no-std complaint in a std crate, a stale lock), suspect a
  concurrent registry race: retry once, and if it repeats, stop and report rather
  than "fixing" it.

BUILD AND GATE DISCIPLINE
  - Run the gate for EVERY language you touched, not just the one you think you did.
  - Rust: cargo fmt --check, cargo clippy --all-targets -- -D warnings,
    cargo test --workspace -j 2.
  - Python: ruff, pytest. Before trusting a Python pass, verify the module you think
    you are testing is the one imported: print(module.__file__). An editable install
    here has pointed at a different worktree.
  - Prose: node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <files>
    Known false positives: the verb "forwards" (third person singular) and the noun
    plural "analyses" are correct US English. Do not "fix" those into ungrammatical
    text. Everything else the gate reports is real.
  - Commit with DCO sign-off: git commit -s. CI rejects unsigned commits.
  - Conventional prefix: feat:, fix:, refactor:, docs:, test:, chore:.
  - Commit messages explain WHY, not WHAT.

EVIDENCE IS PART OF DONE
  Before your final commit, write docs/task-evidence/task-N.M.md containing the exit
  gate quoted verbatim from the plan and the REAL output of the command that
  satisfies it, plus the bound strength of anything you introduced. A merge without
  it reports UNEVIDENCED and fails CI:
      python scripts/task_status.py --check
  Merged is not done. Done is merged and demonstrated.

DEFINITION OF DONE — all must hold, with evidence for each
  1. Every Step implemented, each with its test written first.
  2. cargo test --workspace passes; no test deleted, skipped or #[ignore]d.
  3. fmt and clippy clean for every language touched.
  4. The task's stated exit gate is demonstrably met — quote the plan's wording and
     show the command output that satisfies it.
  5. Every new bound carries its correct tier and its limitation text.
  6. docs/task-evidence/task-N.M.md written.
  7. Committed on the task's branch, signed off, NOT merged.

OUTPUT — end your run with exactly this
  - Branch name and commit SHA.
  - Step-by-step: for each Step, the test that failed, then passed.
  - Full output of the workspace test run and every lint gate.
  - The exit-gate evidence, quoted against the plan's wording.
  - ANYTHING you could not do, or did differently. If the plan is wrong or
    ambiguous, say so and STOP — do not improvise a design.
  - Do not merge. A human reviews before merge.

STOP CONDITIONS — halt immediately and report
  - The plan's step does not match the code you find.
  - A test requires a design decision the plan does not make.
  - You would need to weaken or delete an existing test to proceed.
  - Files change under you mid-task.
```

---

## Mode 2 — Expansion (Phases 3, 5 and 6 only)

Phases 3/5/6 carry task structure but not step detail. Expand a task before
implementing it. Run this as its own invocation, then review, then implement.

```
MODE: EXPANSION, NOT IMPLEMENTATION
Expand ONE task from Phase 3, 5 or 6 into the step-by-step form Phases 0-2 carry.
Write NO production code.

REPOSITORY AND READING ORDER
  Same as implementation mode: Global Constraints, Phase map, the task, then every
  file it names. Use any Phase 0-2 task as the format template; Task 0.1 is the
  cleanest.

WHAT TO PRODUCE
  - Execute the task's Step 0 literally. Run every command. Capture verbatim output.
  - Replace every "capture this" marker with the actual string, path and line range.
  - Quote Consumes/Produces signatures from the code with file and line numbers.
  - Where a crate is absent from origin/main, write the full carry-in steps and
    record the real cargo error, the real lock diff size, and the real fmt hunks.
  - Check whether the exit ratchet the task needs already exists in the code. It
    often does, and amending it beats building a second one.
  - If reality contradicts the task's premise, say so and STOP. Do not repair the
    plan by assuming.

VERIFY AGAINST origin/main, NOT THE WORKING TREE
  The working tree carries ~45 untracked crates that origin/main does not have.
  Every claim about what exists must be checked with
      git ls-tree --name-only origin/main rust/
  A task that assumes an absent crate is buildable dies at its first cargo call.

DELIVERABLE
  The rewritten task section as a diff against the plan file. Nothing else.
  Do not create branches. Do not write code. Do not implement.
```

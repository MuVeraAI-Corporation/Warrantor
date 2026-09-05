# GLM 5.3 Flash — Wave 2 assignment (zcode)

Two jobs, in this order. Both need **zero merges**, so they run while the eight in-flight
branches are being merged by a human.

**Job A — implement Task 0.4, then Task 0.5.** Both are in full step form and READY now.
**Job B — expansion mode on 18 tasks.** This is the higher-value half: 24 of 41 tasks carry
step *headings* but no test bodies, and a fast model cannot execute those without designing.

Check before starting, every time: `python scripts/task_status.py --next`

---

## Job A — Task 0.4 (do this first, it unblocks MiniMax)

Use **Mode 1 — Implementation** from `glm-5.3-flash.md` verbatim, with:

```
YOUR TASK
  Task 0.4: Tier disclosure lint across report, status and console (L8-13, partial → tested)
```

Task 0.4 is the only thing blocking Task 4.3, which is the last unstarted Phase-4 task.
Land it before anything else.

## Job A continued — Task 0.5, with one correction to its premise

Then:

```
YOUR TASK
  Task 0.5: Invariant ledger I-01…I-12 with honest status
```

**Its branch is `feat/invariant-ledger`, not `feat/task-0.5`.** Step 1 declares the name.

**Read this before Step 1 — the task's premise changed on 2026-09-05.** Task 0.5 builds a checker
that probes whether each of the twelve invariants has a static check, a runtime check, an
adversarial test and an evidence field, and writes a ledger with the honest answer. When 0.5 was
written, the answer was "almost none." That is no longer true: **Task 5.1 landed the corpus** on
`feat/task-5.1-invariant-corpus` — twelve suites, 65 passing tests, 19 recorded violations, each
naming its invariant, its cause, the task that fixes it and the date, plus a ratchet in
`tools/ci/invariant-ratchet.json`.

So:

- Read `rust/warrant/tests/invariants/` on `feat/task-5.1-invariant-corpus` as part of Step 0.
  The corpus is the subject your probes must find.
- If your probes run against `origin/main` they will report "no adversarial test" for all twelve.
  That was true on 2026-09-02 and is false now, and a ledger that says it would be a claim defect
  of exactly the kind this repository keeps producing.
- Do **not** re-derive the honest statuses. 5.1's 19 `#[ignore]` reasons and its
  `docs/W1-delivery-gaps.md` Tier 5 entries already carry them. Your ledger consumes that record;
  it does not compete with it. If your ledger and 5.1 disagree about an invariant, **stop and
  report** — one of them is wrong and it is not a merge conflict, it is a correctness question.
- Say plainly in your evidence file which ref you probed and why.

---

## Job B — Expansion mode, 18 tasks

Use **Mode 2 — Expansion** from `glm-5.3-flash.md` verbatim, one task per invocation, in this
order. Phase 3 first because it gates Phase 5; Phase 6 last because it gates nothing.

| Order | Tasks | Note |
|---|---|---|
| 1 | 3.1 | Partly expanded already (three code blocks). Finish it; do not restart it |
| 2 | 3.3, 3.4, 3.5, 3.6, 3.7 | |
| 3 | 3.2 | Routed `human` for implementation. Expand it anyway so a human can execute it |
| 4 | 5.2, 5.3, 5.4, 5.5, 5.6 | 5.1 is built; do not touch it |
| 5 | 6.1, 6.2, 6.3, 6.4, 6.5, 6.6 | |

**What "expanded" means here, measured.** Phases 0–2 average 14 code blocks and 6,300 words per
task, with verbatim test bodies, exact `file:line` ranges and real captured Step-0 output. Phases
3/5/6 average **zero** code blocks and 350 words. Your output must look like a Phase 0–2 task, not
like a longer version of the stub. If a task's expansion has no code fences in it, it is not done.

**The constraint that will bite you.** Verify every claim about what exists against `origin/main`,
never the working tree:

```
git ls-tree --name-only origin/main rust/
```

`origin/main` has 40 workspace members. The working tree has ~80, most of them uncommitted. **13 of
the crates Phases 3/5/6 name are absent from `origin/main`** and each needs a full carry-in
sequence written into its task, the way Task 0.1 writes one. A task that assumes an absent crate is
buildable dies at its first `cargo` call.

**Also verify against the wiring census, which is new.** `evidence/wiring-coverage.json` on
`feat/wiring-census` names the 29 crates that compile but are linked by nothing a user runs. If
your task's premise is "wire X in", check whether X is on that orphan list — that is the
authoritative answer, not the survey, which measured a dirty checkout and said 71 of 80.

**Deliverable per invocation:** the rewritten task section as a diff against the plan file.
No branches. No code. No implementation.

---

## Both jobs

Identity, before the first commit — env vars, never `git config` (worktrees share `.git/config`
here, so `git config` rewrites every lane at once and races them):

```bash
export GIT_AUTHOR_NAME="GLM 5.3 Flash (zcode)"
export GIT_AUTHOR_EMAIL="glm@local"
export GIT_COMMITTER_NAME="GLM 5.3 Flash (zcode)"
export GIT_COMMITTER_EMAIL="glm@local"
```

Wave 1 did not set these, so every Wave-1 commit reads `AumOS Wave-1 <aumos@local>` and author is
not a discriminator for anything before today. Set them.

**One Wave-1 defect to learn from, because it cost this task a full cycle.** Task 0.3's Step 6
predicted `1 failed, 11 passed` from an assertion failure. The lane got exactly that count — from a
`NameError`, because Step 1's specified import list had dropped a name. The count matched, so the
red read as on-plan and the step stopped half done, leaving the committed CI gate red on every
commit of the branch. **Compare the failure reason against the prediction, not the tally.** `1
failed` matching is not confirmation.

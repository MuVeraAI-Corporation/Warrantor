# Task 0.5 — Invariant ledger I-01…I-12 with honest status

**Branch:** `feat/invariant-ledger` (from `origin/main` @ `e0b7631`)
**Worktree:** `M:/wt-0.5-invariants`
**Date:** 2026-09-05
**Commits:** `0560472` (the task's single commit per the plan's Step 7), plus this evidence
file as the final commit.

---

## The exit gate, quoted verbatim from the plan

Step 5:

> Run `python tools/ci/check_invariants.py`. Expected output: `invariant ledger: 12 invariants;
> enforced=2, orphaned=2, partial=7, unimplemented=1`. … Run the pytest suite: all seven PASS,
> including `test_the_real_ledger_passes`.

Step 6:

> Run `python tools/ci/check_docs.py` from the worktree root. Expected: exit 0 (the link resolves
> through `destination_path` to `evidence/invariants.json`, which now exists).

Step 7 adds three steps to the `docs` job (Install pytest for the invariant ledger tests / Check
the invariant ledger against the tree / Test the invariant ledger checker); the `required` job
already depends on `docs`, so a drifted ledger blocks merge.

## Its actual output

```
$ python -m pytest tools/ci/test_check_invariants.py -q -p no:cacheprovider
8 passed in 0.21s

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
(CHECKER-EXIT=0)

$ python tools/ci/check_docs.py
RESULT: PASS — 258 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated

$ python -m ruff check --select E,F,I,B,UP,SIM,RUF --line-length 100 --target-version py311 \
    tools/ci/check_invariants.py tools/ci/test_check_invariants.py
All checks passed!
$ python -m ruff format --check --line-length 100 tools/ci/check_invariants.py tools/ci/test_check_invariants.py
2 files already formatted

$ python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
YAML-OK

$ python tools/ci/wiring_census.py          # exists on this branch now (0.3 merged)
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges

$ python tools/ci/check_phase_scope.py      # from the main checkout, which has the tool
phase scope: 76 tasks account for 132 of 132 uncovered items, out of a catalog of 189
```

US-English: `docs/02-architecture.md` PASS. `docs/W1-delivery-gaps.md` carries 16 pre-existing
findings (identical count on `origin/main`'s copy); the paragraph this task inserts is clean.
No Rust was touched, so the cargo gates do not apply to this task; the census run above shows
its number unmoved by it.

## Per-step red-then-green (each failure matched the plan's stated reason)

| Step | Red | Green |
|---|---|---|
| 1 | `ModuleNotFoundError: No module named 'check_invariants'` | (Step 2) |
| 2 | — | `1 passed` (parser test) |
| 3 | 5 failed, 3 passed: four status-rule tests on `NotImplementedError: check_entry lands in Step 4`, `test_the_real_ledger_passes` on `FileNotFoundError` | (Step 4) |
| 4 | — | 7 unit tests pass; real-ledger test still red on the missing file; ruff clean |
| 5 | checker refused 6 issues (see Deviations) | checker prints the plan's exact census line; pytest 8/8 |
| 6 | `git add evidence/invariants.json` refused: path ignored by .gitignore | ignore exception added (see Deviations); `check_docs.py` PASS |
| 7 | — | CI steps inserted after `Run documentation checks` (ci.yml:379); gaps entry inserted after `## The honest summary` (line 1013); commit `0560472` |

## The honest status the ledger records

enforced=2 (I-02, I-08), partial=7 (I-01, I-04, I-06, I-07, I-10, I-11, I-12),
orphaned=2 (I-05, I-09), unimplemented=1 (I-03). The checker is fail-closed: a cited test that
does not exist, a drifted statement, or a status that disagrees with where the evidence lives
refuses the ledger with exit 1.

## Deviations from the plan's letter, and why

1. **Two ledger entries now describe `origin/main`, not the dirty checkout the plan's Step 0
   read.** The plan pre-authorizes this direction: "If it reports a missing test, the test was
   renamed since 2026-09-02 — fix the ledger, never the checker." The checker (byte-identical to
   the plan) refused 6 issues:
   - I-02 cited `rust/delegation-chain/src/lib.rs::intersection_refuses_capability_escalation`
     and `warrantor_delegation_chain::intersection` — **`rust/delegation-chain` is not tracked on
     `origin/main`** (it lives only on a dirty checkout's disk, as Task 0.1 documented for
     `rust/reputation`). The entry is dropped; the gap now states the algebra exists once, in the
     evidence crate, on the binary's path, and names Task 1.5 as its owner.
   - I-09 cited `rust/eval-guard/src/probes.rs` and `run_preflight_measured` — **no probes.rs
     exists on `origin/main`**; the crate has `cli.rs` and `lib.rs`. I-09 now cites what is real:
     `warrantor_eval_guard::run_preflight` with `any_failure_blocks_start` (a failed probe returns
     Err and no attestation; the CLI's I-09 refusal prints at `cli.rs:52` and exits 1) paired with
     the control `all_pass_returns_signed_attestation`. Status stays `orphaned` (eval-guard is not
     linked by the binary — unchanged); the gap names what the plan cited as uncommitted work.
   The checker's code is untouched. No status moved to reach a number: both entries still point
   at real `#[test]`s, and the census line matches the plan's.
2. **`.gitignore` gains `!/evidence/invariants.json`.** The plan's Step 6 assumes
   `git add evidence/invariants.json` works; the directory is ignored (`/evidence/*`) with one
   negation, added by Task 0.3 for `wiring-coverage.json` with the stated reason ("a label that
   lives only on one machine's disk cannot be refused by a pull request"). The ledger is the same
   kind of label, so it gets the same exception, and the rule's comment is updated.
3. **Line-number drift.** The `docs` job is at ci.yml:371 (plan said 272–281, pre-0.1/0.3 merges);
   `## The honest summary` is at gaps line 1013 (plan said 998). Edits anchored on the named
   steps/headings.
4. **Plan undercounts.** "all seven PASS" — the suite has eight tests (the plan's Step 3 also
   says "six unit tests"; there are seven). All pass; the count is recorded here rather than
   silently absorbed.
5. **The plan's Step 7 ends "Push, open the PR".** The standing goal supersedes: commits stay on
   the task's branch, unsigned pushes and merges are not this lane's. The branch is
   `feat/invariant-ledger` @ `0560472`, ready for a human to merge after rebase.

# Task 2.3 — Two-phase staged effects with idempotency keys (L4-07)

**Branch:** `feat/two-phase-staged-effects` (from local `main` @ `065961b`)
**Worktree:** `M:/wt-2.3` · **Target dir:** `M:/wt-2.3-target`
**Date:** 2026-09-06

**Commits, in Step order:**

| commit | Steps | what |
|---|---|---|
| `dd69311` | 1–5 | `idempotency_key`, `STAGED_RECEIPT_FORMAT`, `Recorder`/`RecorderAck`/`RecordedReceipt`/`FileRecorder`, the syscall column on `EffectKind` (`register_as` takes `Syscall` per the plan's own forward-compat note), `CommitGate` and `staged_predicate` |
| `bcc51ce` | 6–8 (+10) | the two-phase release loop in `settle`; replay/kill/open-pre-commit tests; the CLI, HTTP and MCP settle surfaces pass through the gate |
| `74f5ee7` | 9 | every pre-existing `settle` test runs through a recorder |
| `75a9bc0` | 11–12 | `verify_receipt_log` and the `warrantor verify` dispatch on `warrantor.staged-receipt/1` |
| (this file) | 13 | the W1 E.1 entry, the receipts retention class, the live run, the gates, this evidence |

---

## The exit gate, quoted verbatim from the plan

Phase map, row 3 (Task 2.3's plan anchor):

> Verification gate: "pre-commit receipt and post-commit outcome link for every effect class." (E-06)

Task 2.3's acceptance paragraph, quoted:

> kill the recorder mid-run → no effect after the kill commits (`killing_the_recorder_mid_run_commits_nothing_after_the_kill`, `a_recorder_that_is_down_from_the_start_commits_nothing_at_all`); replay with the same key → exactly one performance (`replaying_a_settle_performs_each_idempotency_key_exactly_once`, `an_effect_whose_post_commit_was_never_recorded_is_not_performed_again`); receipt precedes side effect in the recorder's clock (`every_performed_effect_has_a_pre_commit_before_it_and_a_post_commit_after`, which also runs `verify_chain` on every pair — gate E-06); `warrantor verify` dispatches on `warrantor.staged-receipt/1`; the live run produced one pull request and a two-line receipt log that verifies.

## Its actual output

### The test path (red then green, one step at a time)

| Step | red | green |
|---|---|---|
| 1 | `E0432: unresolved import ... idempotency_key, FileRecorder, Recorder, RecorderAck, STAGED_RECEIPT_FORMAT` (+ `settle::CommitGate`) | — |
| 3 | (same run: the recorder test rides the shared import line) | — |
| 4–5 | — | `2 passed` (`the_idempotency_key...`, `the_file_recorder...`) |
| 6 | `E0061: this function takes 5 arguments but 6 arguments were supplied` at each `settle(` | `5 passed` after Step 7's loop |
| 8 | `WrongState { state: Held }` on the retried settle (see Deviation 3) | `7 passed` |
| 11 | `E0425: cannot find function verify_receipt_log in module warrantor_warrant::staging` | `8 passed` |

### The live run (Step 13) — the receipt path, honestly without credentials

`M:/wt-2.3-live/store`, warrant `wrt_a4bdca418d285421` (`--tools github.create_pr`). No GitHub
credential exists on this machine and none was created, so `build_performer` fell back to
`NoAdapter`, exactly as Task 1.1's live run did; the plan permits the fallback and the entry may
not claim more than the receipt path shows:

```
$ warrantor stage --root M:/wt-2.3-live/store wrt_a4bdca418d285421 --tool github.create_pr --arg title="two-phase live"
staged  pr://staged/wrt_a4bdca418d285421/1

$ warrantor settle --root M:/wt-2.3-live/store wrt_a4bdca418d285421
  FAILED   pr://staged/.../1: github.create_pr was not performed: set WARRANTOR_GITHUB_REPO=owner/repo to enable the GitHub adapter. The effect remains staged.
stopped at pr://staged/wrt_a4bdca418d285421/1 (github.create_pr): ... Effects before it are real; effects after it were not attempted.
  receipts    2 issued to M:/wt-2.3-live/store\receipts\wrt_a4bdca418d285421.jsonl
warrant is now Held

$ warrantor verify M:/wt-2.3-live/store/receipts/wrt_a4bdca418d285421.staged.jsonl
M:/wt-2.3-live/store/receipts/wrt_a4bdca418d285421.staged.jsonl: 1 staged effect(s) verify as pre-commit/post-commit pairs under warrantor.staged-receipt/1
```

The staged log, read back — one pre-commit signed BEFORE the performer ran, one post-commit after:

```
1 pre_commit  mutate -
2 post_commit mutate failed
```

The second `settle` re-attempted the effect (a FAILED outcome is not an open pre-commit — the
effect is known not to have happened, so a retry is correct, unlike an unresolved one) and
appended sequences 3–4. The plan's "second settle → `WrongState`" expectation is the behavior of a
COMPLETED settle; this run never completed (NoAdapter), so the observable is a second receipt pair,
not a refusal. The report path's own chain still verifies offline through the Task 1.1 export
(`verify report.json --issuer <hex>` → `2 receipt chain(s) verified`).

### The gates

Every cargo invocation was preceded by both disk guards (two REFUSE episodes from commit-charge
pressure — 3.8 GB, then 0.5 GB — were waited out per the standing instruction, 300–540 s cycles;
nothing was deleted):

```
$ python tools/ci/disk_guard.py --require 60        exit 0 (every cargo invocation)
$ python tools/ci/disk_guard.py --require-commit 6  exit 0 (every cargo invocation)
$ cargo fmt --all -- --check                        exit 0
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings   exit 0
$ cargo test --workspace --all-targets -j 2 -- --test-threads=1  exit 0
    120 suites, 1555 passed, 0 failed
$ cargo build --workspace --all-targets -j 2        exit 0
$ cargo metadata --locked -q                        exit 0 (preflight; no dependency added)
$ python tools/ci/wiring_census.py                  exit 0
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges  (identical to main)
$ python tools/ci/check_invariant_ratchet.py        exit 0
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)  (unchanged; no #[ignore] touched)
$ node verify-us-english.mjs docs/W1-delivery-gaps.md rust/warrant/src/{staging,settle,retention}.rs
    5 findings, ALL pre-existing lines verified identical on main ("forwards" is a documented
    false positive); the lines this task added carry none. Same disposition as Task 1.1's evidence.
$ python -m ruff / pytest                           not run: no Python added or modified
$ python tools/ci/check_phase_scope.py              ABSENT on main (as in Task 2.2); the plan was not touched
```

Two full-suite runs failed on exactly one test —
`conformance_receipt.rs::a_drill_on_this_kernel_produces_a_receipt_that_verifies_offline` — with
the exact signature recorded in `docs/task-evidence/finding-kill-drill-confirmation-under-load.md`
on main: `root_gone: false, descendant_gone: false, within_budget: false, refusal: None`, the
documented tasklist-under-load polling deadline. The test is byte-identical to main, nothing in
this branch's diff touches the stop/kill path, and it passes alone (3/3) and in the final
single-threaded full run. This is the documented environmental flake, not a regression.

---

## The honest tier of every bound this task introduces

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| pre-commit-before-perform (the commit gate in `settle`) | **Mediated** | the performer is the chokepoint and the agent never holds its credential; but `settle` still accepts any `&mut dyn EffectPerformer` from the process that calls it, and a human with the GitHub token acts without passing here. The W1 E.1 entry says both. |
| the idempotency key's exactly-once property | **Mediated**, over the recorder's records | exactly-once holds where the recorder holds the record; a recorder that is deleted takes its memory with it (the file is local, same disk, same UID — the ledger entry says so). |
| `verify_receipt_log` | **Observed**-tier evidence, signed | it proves what was recorded and who signed; it records nothing about the world. |

No existing bound label moved; the notary-mode checks Task 1.1 built still pass untouched.

---

## Deviations from the plan's literal text, each earned

1. **The staged receipt log is `receipts/<id>.staged.jsonl`, not `receipts/<id>.jsonl`.** The plan
   predates Task 1.1's merge: it assumed `receipts_path` did not exist, but Task 1.1 already owns
   that path for `warrantor.effect-receipts/1`, and its `ReceiptLog::open` signature-checks every
   line. A settle opening both writers on one file would fail closed on its next replay. The two
   formats refuse each other's lines by design, so the commit-gate log sits beside the notary log.
   Every consumer (CLI, serve, MCP, `verify`) names the new path; the tests' live check and the W1
   E.1 entry say which log is which.
2. **The plan's Step 5 import block for settle.rs was incomplete** — it dropped `notary`,
   `VerifyingKey` and four report helpers that `EffectWitness`/`EvidencedPerformer` (untouched by
   this task) still consume. Kept both import sets; the code wins.
3. **A warrant already `Held` stays `Held` when a retried settle stops again.** The plan's own
   Step 8 test runs a second settle on a Held warrant and expects a report, but
   `Warrant::transition` refuses `Held -> Held`. A one-line guard on the incomplete path: staying
   put is not a transition. Found by the plan's test, fixed to satisfy it.
4. **Step 10's surface wiring landed inside the Step 6–8 commit** (`bcc51ce`) rather than its own:
   the lib and bin callers of `settle` had to compile for the two_phase test target to build at
   all, so the six-argument call sites could not be deferred.
5. **`register_as` takes `Syscall`, not `&str`** — the plan's own note ("Task 2.1's effects.rs
   enum was not in the code when this section was written; when it lands, register_as takes
   Syscall and this string becomes Syscall::as_str()"). Task 2.1 has landed.
6. **The receipts directory joined the retention inventory** (`ArtifactClass::Receipts`, 20 → 21
   classes). Adding `receipts` to `WarrantStore::open`'s created directories made a fresh store
   contain a directory `warrantor holdings` could not account for, failing
   `holdings.rs::every_directory_this_store_creates_is_a_known_class`. Task 1.1 had the same
   latent gap (its lazily-created receipts dir was invisible to the inventory); the class closes
   it for both logs, deletion effect `LosesEvidence`.
7. **Two pre-existing suites needed the gate** beyond the plan's Step 9 list:
   `report_evidence_chain.rs` (five settles) and `invariants/adversary/fixtures.rs` (two), whose
   recorders got their own files so the Task 1.1 line-count invariants still hold byte-for-byte.
8. **The final full-suite run uses `--test-threads=1`.** The parallel run tripped the documented
   kill-drill load flake (see the gates section). Single-threaded, 1555/0. The `-j 2` build
   parallelism the gate names is unchanged.

## Not done

- **No pull request was created and no `git push` was run.** The plan's Step 13 live run ends
  "<pull request URL>" — there is no GitHub credential on this machine and none may be created
  here; the receipt path is what the live run demonstrates, and the W1 E.1 entry says so. The
  brief's never-push rule also holds; a human reviews and merges.

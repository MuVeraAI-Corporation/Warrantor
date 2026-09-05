# Task 1.3 — Containment and the kill switch into the `stop` verb; conformance receipt (L4-08, L0-03; STOP_ENFORCEMENT_MODE promotion)

**Branch:** `feat/task-1.3` (from `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-1.3` (target dir `M:/wt-1.3-target`)
**Date:** 2026-09-05
**Commits (in order):** `a8a3171` (Steps 1–2), `d28962a` (Steps 3–4), `8606790` (Steps 5–8,
combined per the plan's own green-intermediate sanction), `e850ac5` (Steps 9–10), `00162df`
(Step 11), `7fe3dbf` (live-run discovery: run `--root` fix), `7526c36` (halt semantics in three
test files + usage inventory), `338679a` (Step 12 ledger + receipts). Evidence file is the final
commit.

---

## The exit gate, quoted verbatim from the plan

Step 12:

> Run the full gate from `rust/`: `cargo fmt --all -- --check && cargo clippy --workspace
> --all-targets -j 2 -- -D warnings && cargo test --workspace --all-targets -j 2 && cargo build
> --workspace --all-targets -j 2 && cargo metadata --format-version 1 --locked > /dev/null`.

And the live runs:

> On Linux and on Windows, from a clean store: `warrantor grant … --tool git` (any grant),
> `warrantor run <id> -- sh -c 'sleep 60 & wait'` … then `warrantor stop <id> --export stop.json`
> in another, then `warrantor verify stop.json`. Before `conformance run` the record's SIGNED
> EVIDENCE block reads `enforcement advisory`; after `warrantor conformance run` a second
> grant/run/stop reads `enforcement enforced` with an `enforcement_basis` line naming the receipt
> digest. Keep both exports as `evidence/stop-<kernel>.json` and
> `evidence/conformance-<kernel>.json`.

## Its actual output

### The full gate

```
$ cargo fmt --all -- --check            (exit 0)
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings   (exit 0)
$ cargo test --workspace --all-targets -j 2
TEST-EXIT=0 ; 105 suites `test result: ok`; none FAILED
$ cargo build --workspace --all-targets -j 2                   (exit 0)
$ cargo metadata --format-version 1 --locked > /dev/null       (LOCK-OK)
```

### The live run on this kernel (windows/job-object; scratch store `M:/wt-1.3-live`)

```
$ warrantor conformance run --root R --export R/conf.json
CONFORMANCE advisory  kernel windows/job-object
  root pid 119028 gone in 5610 ms; descendant pid 142172 gone in 6907 ms; budget 5000 ms
  receipt  9f6f1731…e4232a        (exit 1: advisory refuses a green exit by design)
$ warrantor verify R/conf.json --issuer <hex>
  verified; kernel/mode/timings and the suite's limitations printed

$ warrantor run wrt_85f20db3e77fa671 --root R -- powershell -NoProfile -Command "ping -n 60 127.0.0.1"
  … status shows: running wrt_85f20db3e77fa671 (supervisor pid 131044)
$ warrantor stop wrt_85f20db3e77fa671 --root R --export R/stop.json
  supervisor pid 131044 terminated and confirmed gone in 5984 ms, still gone after 200 ms
  staged effects      discarded (warrant Void). The log is retained as evidence.
  enforcement     advisory            (no earned receipt on this kernel)
  exported  R/stop.json               (exit 0; daemon record deregistered)
$ warrantor verify R/stop.json --issuer <hex>
  verified  b80bf4e64763df8baec93783b8f44fdb536359082f7b1145b1325a0c48a12074
```

Both artifacts are committed: `evidence/stop-windows.json`, `evidence/conformance-windows.json`.
**The Linux half of Step 12 is NOT done here** — no Linux host exists on this lane; the drill runs
in the workspace suite on CI's ubuntu runner (`conformance_receipt.rs` + `stop_kills_tree.rs` are
kernel-conditional by `#[cfg]`), and the ledger says the Linux numbers come from CI. Recorded
plainly rather than invented.

### Per-step red-then-green

| Step | Red | Green |
|---|---|---|
| 1 | `can't find lib warrantor_kill_switch_core … src/lib.rs` | (Step 2) |
| 2 | clippy `type_complexity` → the original `CriticalImageMemo` alias restored | real tree killed on Windows (integration 18.7 s) → `a8a3171` |
| 3 | `E0425 cannot find function force_terminate` (+ process_exists/CriticalImageMemo/rails) | (Step 4) |
| 4 | 3 real-kill tests failed "still alive 2s" — see Deviations 2 | kill-switch 29 passed ×2 runs → `d28962a` |
| 5 | `E0425/E0433` enforcement_mode/EnforcementMode/Invalidation + arity | (Step 6) |
| 6 | — | stop 29 + stop_kills_tree 1 (real tree, Void, invalidations, advisory) |
| 7 | `root_gone: false` — drill's observation loop never ran (see Deviations 3) | conformance_receipt 3 |
| 8 | — | combined into `8606790` |
| 9 | `E0432 halt/HaltContext/HaltScope` + `Scope` variant | (Step 10) |
| 10 | serve.rs `stop_error_code` non-exhaustive → two new codes | stop 30 → `e850ac5` |
| 11 | — | full warrant crate 136+13+12+41+21+3+19+13 suites green → `00162df` |
| 12 | instructions.rs (flags `family`/`run`), serve.rs ×2 Held assertions, mcp.rs Held | all green → `338679a` |

## Honest tier of every bound introduced

**No bound label moved** — `bound_strengths()` is byte-identical, and
`egress_hosts_stays_mediated…`-style pinning carries over. What changed is the stop record's own
`enforcement` field: `Enforced` exists ONLY where a verifying drill receipt for the SAME kernel
exists (`ConformanceStore::basis_for_this_kernel`), the mode is derived by `mode_for` from the
observation (never accepted), `verify_receipt` refuses a mode the drill does not earn, and
`verify_stop` refuses a basis drilled on another kernel. Every kernel without a receipt reads
`advisory` — this Windows machine included, and the receipt says so with numbers.

## Deviations from the plan's letter, and why

1. **Steps 6 and 8 landed in one commit** (`8606790`) — the plan explicitly sanctions this
   ("order the edits so Step 6 and Step 8 are in one commit if a green intermediate is wanted"),
   because the two library call sites read `ConformanceStore` the moment `execute` gains its new
   parameters.
2. **Windows pre-kill existence check removed from the core's `terminate`** (restore of the moved
   code's own "exactly one spawn" Windows shape). Measured on this machine: `tasklist` costs
   ~2.0–2.3 s per spawn under real-time AV (three consecutive Measure-Command runs: 2312 / 2213 /
   2187 ms). The plan-template's pre-check spent that budget before the kill was attempted; the
   already-gone signal on Windows is taskkill's exit code 128 / "not found", which the template
   already handles. The Unix pre-check stays (a `ps` is ~5 ms). The confirmation poll also
   consumes its own in-flight answer (a verified-gone result finishing just past the nominal
   deadline is a containment that happened). This fixed 3 flaky real-kill tests; green twice
   consecutively after.
3. **The drill's observation loop always confirms both pids** (hard cap 2× STOP_BUDGET), with
   `within_budget` computed from the measured timestamps. The plan-template's loop could exit
   without ever looking — on this machine `terminate`'s internal confirmation already fills the
   budget — and recorded `root_gone: false` for a tree that was dead. A drill that did not look is
   not a drill that passed; `mode_for` still derives Enforced only from timestamps inside
   STOP_BUDGET, so slow kernels honestly earn advisory.
4. **`warrantor run` now forwards `--root` to the detached supervisor** (`7fe3dbf`). Discovered by
   the plan's mandated live run: the supervisor re-entered the arg parser as its own command and
   resolved the DEFAULT store, refusing the warrant it was started for. Invisible historically
   because every earlier live run used the default root. The flag is inserted before the `--`
   separator (everything after it is the supervised command).
5. **The invariant corpus and ledger moved with the change.** The I-12 corpus test read the deleted
   `STOP_ENFORCEMENT_MODE` constant; it is re-reasoned against `conformance::drill`/`mode_for` and
   stays `#[ignore]`d with an updated, dated reason — no kernel has earned a receipt yet, and this
   machine's drill cannot (its existence checks exceed the budget). Per the goal's conversion rule:
   nothing passes here, and the file says so plainly; the ratchet floor is not raised. The
   invariant ledger's I-12 entry cites the new symbol (`stop::EnforcementMode`, tests that exist)
   and stays `partial`, edited in the same PR as the semantics change per Task 0.5's rule.
6. **Three test files encoded the old Held-on-stop reading** (`tests/mcp.rs`, `tests/serve.rs` ×2)
   or lacked the new usage flags (`tests/instructions.rs`): updated to the halt-is-terminal
   semantics the plan records as a deliberate decision, and the inventory entries the
   instructions test requires. No assertion was weakened; the behavior they pin changed on
   purpose.
7. **`.gitignore`** gains `!/evidence/stop-*.json` and `!/evidence/conformance-*.json` — the same
   precedent as Task 0.3/0.5: the ledger cites these receipts, and a label that lives only on one
   machine's disk cannot be refused by a pull request.
8. **The Linux drill numbers are not in this evidence file.** No Linux host exists on this lane.
   The ledger says the Linux numbers come from CI's ubuntu runner, where the same drill and
   tree-kill tests run in the workspace suite.

## Gates this task could not run, and why

- `python tools/ci/check_phase_scope.py` — not on this branch's base; run from the main checkout
  during Task 0.5 with exit 0. This task adds no plan tasks.
- US-English on `docs/W1-delivery-gaps.md`: the 16 pre-existing findings documented in the 0.5
  evidence file are unchanged; this task's paragraph is clean (one `signalled` → `signaled` in the
  new text fixed before commit).

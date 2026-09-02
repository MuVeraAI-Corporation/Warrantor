# Task 0.1 evidence — Put `rust/reputation` under the workspace

Branch: `feat/task-0.1-reputation-workspace` (worktree `M:/wt-task-0.1`, cut from `origin/main` at `26d16df`)
Commits: `3a2c6a7` (build: membership), `2e5861f` (test: integration target), `1294cfa` (docs: ledger), plus this evidence commit.
`CARGO_TARGET_DIR=M:/wt-task-0.1-target` on every cargo command; every cargo invocation used `-j 2`.

## Exit gate, quoted verbatim from the plan

> **Acceptance.** `cargo test -p warrantor-reputation --all-targets` runs 16 tests (14 unit + 2 integration) inside a worktree cut from `origin/main`; `cargo metadata --locked` passes; `cargo fmt --all -- --check` passes with the crate in the workspace; `docs/W1-delivery-gaps.md` §0.3 exists in the same PR; Task 0.3's first census counts the crate as *orphaned* (present, unreachable), which is the honest label until something consumes it.

## Real command output satisfying the gate

`cargo test -p warrantor-reputation --all-targets -j 2` (inside the worktree):

```
     Running unittests src\lib.rs (M:/wt-task-0.1-target\debug\deps\warrantor_reputation-77943053a608c9aa.exe)
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests\public_api.rs (M:/wt-task-0.1-target\debug\deps\public_api-de977a7b36ec80f1.exe)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

`cargo metadata --format-version 1 --locked > /dev/null` → `LOCK-OK` (exit 0).
`cargo fmt --all -- --check` → exit 0.
`docs/W1-delivery-gaps.md` §0.3 committed in `1294cfa`, verified by the US-English gate on the added lines only: `PASS — 0 Britishisms outside the carve-outs` / `1 file(s) · 0 finding(s)`, exit 0.
The final acceptance clause (Task 0.3's census counting the crate as *orphaned*) is forward-looking: Task 0.3 is a separate, not-yet-started task, so no census exists yet to run. Nothing in this task wires the crate, which is what makes *orphaned* the honest future label.

## Full workspace gate, exactly as CI runs it (Step 9)

```
cargo metadata --format-version 1 --locked > /dev/null   → LOCK-OK, exit 0
cargo fmt --all -- --check                               → exit 0
cargo clippy --workspace --all-targets -j 2 -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3m 20s   (exit 0, zero warnings)
cargo test --workspace --all-targets -j 2                → exit 0
cargo build --workspace --all-targets -j 2
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 30.55s   (exit 0)
```

Workspace test totals over 98 test targets: **1302 passed, 0 failed, 5 ignored**. The 5 ignored tests are pre-existing `#[ignore]` attributes in other crates (e.g. `append_only` 2, `device_pairing` 1, plus two 0-pass integration binaries); none was added, deleted or skipped by this task. `warrantor-reputation` contributes 16 passed, 0 ignored. Full logs retained at `M:/wt-task-0.1-target/{clippy,test,build}-full.log`.

## Step-by-step: failure observed first, then pass (TDD)

- Step 2 — `cargo test -p warrantor-reputation --all-targets` before the member line:
  FAIL `error: package ID specification \`warrantor-reputation\` did not match any packages` (exit 101), verbatim as the plan states. After Step 3: 14 passed.
- Step 3 — `cargo metadata --format-version 1 --locked` after the member line:
  FAIL `error: cannot update the lock file M:\wt-task-0.1\rust\Cargo.lock because --locked was passed to prevent this` (exit 101), verbatim. Regenerated with `cargo metadata` (no `--locked`): `git diff --stat rust/Cargo.lock` = exactly `10 insertions(+)`, one `[[package]] name = "warrantor-reputation"` block, no new third-party versions. Re-check: `LOCK-OK`.
- Step 4 — `cargo fmt -p warrantor-reputation -- --check`:
  FAIL exit 1 with exactly three hunks at `:156`, `:176`, `:305` (reputation_score iterator chain, aggregate signature, computation_is_deterministic assert_eq!). After `cargo fmt`: exit 0; `diff -u` against the copy source shows exactly those 3 hunks, nothing else.
- Step 6 — `tests/public_api.rs` written; with the member line commented out,
  `cargo test -p warrantor-reputation --test public_api` FAIL with the same package-ID error (exit 101) — the integration target is only addressable for a workspace member. Restored; `cargo metadata --locked` passes and `git status --porcelain rust/Cargo.toml rust/Cargo.lock` is empty. (Mechanism deviation, same observable state as the plan's comment-out/restore: both files restored via `git checkout --` to their committed bytes instead of manual uncommenting.)

## Bound strength

No bound was introduced, promoted, or rendered by this task. It changes build membership, adds one lock block, one integration test, and one ledger paragraph. Enforcement tiers are untouched; `rust/warrant/src/lib.rs:635 bound_strengths()` is not involved.

## Incidents and deviations (full disclosure)

1. **Task assignment.** The dispatch template arrived with the task placeholder unfilled; Task 0.1 was selected by the user via an explicit choice among the board's five READY tasks (all owned by this model), not improvised.
2. **Intermittent rustc crash.** The first `cargo test --workspace` attempt died compiling `wasmtime-environ` with `exit code: 0xc0000409, STATUS_STACK_BUFFER_OVERRUN` — a rustc process crash, not a code error. Retried once per the cargo discipline; the retry compiled clean and ran.
3. **Pre-existing Windows timing flake in `warrantor-kill-switch`.** The first completed workspace test run failed `tests::budget_exceeded_bails_before_policy_decision_h8` (`kill-switch\src\lib.rs:622`, policy consulted 1 time vs 0). Evidence it is pre-existing and unrelated to this task: (a) mechanism — `check_budget` (`rust/kill-switch/src/lib.rs:434`) uses strict `elapsed > budget`; the test passes `Duration::from_nanos(0)`, so on Windows the pre-decision check only trips when the monotonic clock advances between consecutive `Instant::now()` reads; (b) this task leaves kill-switch's compile inputs bit-identical (lock diff = one leaf package block only, no shared-version or feature change); (c) the test passes 10/10 when run alone; (d) a pristine `origin/main` worktree (`M:/wt-verify-main`, since removed) ran the same full lib suite green (33 passed). The workspace suite was rerun and passed in full (1302/0/5). The flake belongs to Task 0.2's platform-conditional territory; it was not touched here.
4. **Disk-space incident.** M: ran out of space during a 15-iteration diagnostic loop of the kill-switch suite; two loop iterations aborted on log-write failure and their "failures" are disk artifacts, discarded from evidence. Only artifacts I owned were removed (`M:/wt-verify-main`, `M:/wt-verify-main-target`, my target dir's `debug/incremental`, loop logs). M: hosts ~20 other `wt-*` worktrees from other sessions — none touched. Reported to the operator: the drive is shared, nearly full, and needs attention outside this task.
5. **`scripts/task_status.py` is not on `origin/main`.** It is tracked only on the dirty `docs/content-program-p9-fold` checkout, so `python scripts/task_status.py --check` cannot run inside a worktree cut from `origin/main` until the script itself lands. For this evidence, the script was copied into the worktree untracked, run, and removed; its verdict is recorded below.
6. **Security-hook advisory.** Each commit triggered a Mimosa pre-commit hook warning that no full scan conclusion was available (`scanner_enobufs`); commits proceeded under compatibility policy. No security claim is made or implied by this task.

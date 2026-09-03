# Task 0.2 evidence — Windows CI runner for the platform-conditional paths

**Status: COMPLETE through Step 9 and green on both CI runners; Step 10's rebase done where possible, its merge NOT performed (dispatch forbids merging — a human merges).** The store_lock/lock.rs blocker recorded below was resolved by the plan owner's "continue implementation" directive, read as authorization for the verbatim carry-in (commit `e84ebc7`, disclosed there and in the PR body).

Branch: `chore/windows-ci-runner` (worktree `M:/wt-0.2`, cut from `origin/main` at `26d16df`).
Commits: `c8559c6` (docs(toolchain) floor comment), `37746ce` (test(warrant) supervise tests), plus this evidence commit.
`CARGO_TARGET_DIR=M:/wt-0.2-target`; `-j 2` everywhere; `RUST_MIN_STACK=33554432` on clippy/test/build per the plan's cranelift-stack note.

## Exit gate, quoted verbatim from the plan

> the exit gate is *"the full workspace suite green on both runners, with the platform-conditional paths shown as executed rather than skipped"*, and L6-11's verification names it directly: *"the Windows kill-switch path is included in the gate S60"*.

**This gate is NOT yet met and cannot be met on this branch base** — see the blocker below. The local half of the evidence is recorded here; the runner half (Steps 6–8) is the blocked part.

## What was executed (Steps 1–5)

- **Step 2** — `rust-toolchain.toml:3` stale `1.85` → `1.94`; both files now agree (`rust/Cargo.toml:67` was already 1.94; the plan's `:112` is a dirty-tree coordinate, see deviations). Committed `c8559c6`.
- **Step 3** — red state observed verbatim: `cargo test --locked -p warrantor-warrant --lib supervise` printed `running 0 tests` / `133 filtered out` — nothing under `supervise::` was tested anywhere.
- **Step 4** — the plan's three tests appended verbatim to `rust/warrant/src/supervise.rs` (one rustfmt-forced reflow, see deviations).
- **Step 5** — on this Windows box:
  - `cargo test --locked -p warrantor-warrant --lib supervise::tests -j 2` → `test result: ok. 3 passed; 0 failed` in 9.42s; proof-of-execution grep count **3**, including `job_object_kills_the_child_tree_when_the_supervisor_drops ... ok` and `terminate_group_kills_the_grandchild_too ... ok` — the job-object kill-on-close link and the `taskkill /T` grandchild kill verified live for the first time.
  - The exact leg the runner will run: `cargo test --locked -p warrantor-warrant -p warrantor-kill-switch --all-targets -j 2` → **714 passed, 0 failed, 0 FAILED lines, exit 0** across 36 test binaries (31 tracked integration files on `origin/main`, warrant lib/bin, kill-switch lib/bin). `Running`/result lines in `M:/wt-0.2-target/windows-leg.log`.
  - Full workspace gate: `cargo fmt --all -- --check` exit 0; `RUST_MIN_STACK=33554432 cargo clippy --workspace --all-targets -j 2 -- -D warnings` exit 0 (2m07s); `RUST_MIN_STACK=33554432 cargo test --workspace --all-targets -j 2` exit 0 — **1289 passed, 0 failed, 5 pre-existing ignored, 96 targets** (1286 base + 3 new supervise; the 0.1 branch's 1302 = same base + 16 reputation, consistent); `RUST_MIN_STACK=33554432 cargo build --workspace --all-targets -j 2` exit 0. Logs: `M:/wt-0.2-target/{ws-clippy,workspace-gate,ws-build}.log`.

## The blocker, and its resolution (Steps 6–9 ran after it)

The plan's CI proof step requires `a_stale_lock_is_stolen_once_the_window_passes` executing on **both** OS legs, and its Files list calls `rust/warrant/tests/store_lock.rs` "existing". On `origin/main` neither exists — both were untracked files on the dirty `docs/content-program-p9-fold` checkout (along with `approve_race`, `autofile_http`, `change_cursor`; the plan's "35 integration-test files" count matches the dirty tree, `origin/main` had 31). The minimal compile-closed carry-in surface was determined to be exactly four files: `lock.rs` (new, 218 lines), `lib.rs` (`pub mod lock;` + the `LockBusy` variant — compile-forced by lock.rs), `serve.rs` (the `warrant_error_status` exhaustive-match arm `warrant_locked` — compile-forced by the variant), and `store_lock.rs` (new, 5 tests). Carried in verbatim under the owner's "continue implementation" directive as commit `e84ebc7` with provenance in the message; **no new dependencies** (Cargo.lock untouched). All 5 lock tests pass on this box; full workspace gate re-run after the carry-in: fmt 0, clippy 0, **1294 passed / 0 failed / 5 pre-existing ignored**, build 0.

## Exit gate satisfied — the live-run receipts (Steps 6–8)

> *"the full workspace suite green on both runners, with the platform-conditional paths shown as executed rather than skipped"*; L6-11: *"the Windows kill-switch path is included in the gate S60"*.

- **Step 6 (deliberate red):** run [33678790751](https://github.com/MuVeraAI-Corporation/Warrantor/actions/runs/33678790751) — ubuntu leg failed at `Prove the platform-conditional tests executed` with `##[error]expected 'test supervise::tests::job_object_kills_the_child_tree_when_the_supervisor_drops ... ok' in the cargo test log; the platform-conditional path did not execute`, exit 1. All other jobs success. The gate has teeth, demonstrated.
- **Step 7:** matrix committed (`6e355dc`) after the plan's YAML validator printed `ok 13 steps` (matrix os = [ubuntu-latest, windows-latest]; all six test names inside the single parsed block scalar; `rust` present in `required.needs` with the added comment).
- **Step 8 (the live-run receipt):** run [33679590609](https://github.com/MuVeraAI-Corporation/Warrantor/actions/runs/33679590609) — `Rust (ubuntu-latest) success` and `Rust (windows-latest) success`; the Windows job log contains `test supervise::tests::job_object_kills_the_child_tree_when_the_supervisor_drops ... ok`, `test tests::local_process_engine_actually_kills_a_real_process_ax05 ... ok`, and `libprotoc 36.1` (pinned-zip digest verified on the runner).
- **Step 9:** `docs/W1-delivery-gaps.md` §3.6 inserted before Tier 4 with the run URL; US-English gate on the added lines: `PASS — 0 Britishisms outside the carve-outs`, exit 0; committed `c3d031e`.
- **Step 10:** rebase on `origin/main` where it moves; **the squash merge the plan's script performs was NOT run — the dispatch forbids merging; a human merges PR #75.**

## Deviations and incidents (full disclosure)

1. **Coordinate drift, content-anchored:** the 0.2 section's line numbers were measured against the dirty working tree. On `origin/main`: `process_is_alive` is `daemon.rs:418` (plan said 416); `## Tier 4 — model intelligence` is `W1-delivery-gaps.md:770` (plan said 798); `rust-version = "1.94"` is `rust/Cargo.toml:67` (plan said 112). `supervise.rs:444` is end-of-file as assumed. `ci.yml:86-124/116-123/354` and `kill-switch/src/lib.rs:825-826/889-890` match exactly.
2. **rustfmt reflow of plan-verbatim test code:** `assert!(gone_within(pid, budget), "cmd.exe {pid} survived taskkill /T");` at what became supervise.rs:567 exceeded rustfmt's width and is now the multi-line form. Because the fix touched a `.rs` input, the whole gate was re-run after it (all four commands, second run above).
3. **cargo-tree claim verified:** `cargo tree --locked -p warrantor-warrant -p warrantor-kill-switch -e no-dev` contains zero `wasmtime`/`cranelift` entries, as the plan states for the two-crate scope.
4. The kill-switch zero-budget flake documented in task 0.1's evidence did not fire in any run on this branch.
5. **Step 10 conflicts with the dispatch:** the plan instructs `gh api … pulls/$PR/merge`, the dispatch forbids merging. Not done regardless of the blocker resolution; a human merges.

## Bound strength

No bound introduced, promoted, or rendered. The new tests execute existing enforcement paths (job-object kill, `taskkill /T`) under the platform that path ships on; tier labels are untouched.

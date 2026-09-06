# Task 2.4 — EXEC admission by content digest and declared execution surface (L4-05)

**Branch:** `feat/exec-digest-admission` (from local `main` @ `6f41384`)
**Worktree:** `M:/wt-2.4` · **Target dir:** `M:/wt-2.4-target`
**Date:** 2026-09-06

**Commits, in Step order:**

| commit | Steps | what |
|---|---|---|
| `9c16813` (was `9bcfe3b`) | 2–3 | `ExecSurface`, `ExecAdmission` parsers, `ExecPhase`/`ExecVerdict`, `exec.rs` module |
| `2f6a6a8` (was `c31318d`) | 4–5 | `resolve_on_path` (moved from the binary), `resolve_program` (PATH-only bare names), streaming `sha256_file` |
| `05dacf1` (was `52c234e`) | 6–7 | `admit`, `ExecReceipt`, `refusal_sentence`, `exec/<id>.jsonl` record/read |
| `8d5ad9d` (was `92eb8a6`) | 8–9 | `WarrantBounds.exec` (absent-is-skipped), the delegation rule in `contains`, `bound_strengths` gains `exec` at Observed, 44 literal sites + the MCP multi-line literal, sandbox `Gap`, tier tables, README rows, Python interop vectors |
| `ce2a6ad` | 10–11 | the EXEC gate inside `supervise_run`: resolve → digest → receipt → refuse-or-spawn-resolved-path |
| `b6b9185` | 12–13 | `grant --exec`, the `run` preflight, `exec digest|log`, USAGE paragraph |
| (this file) | 14–15 | W1 §3.9, CHANGELOG, the gates, this evidence |

SHA history note: the first four commits were rewritten once (`git filter-branch --env-filter` +
`--msg-filter`) to repair lane identity — see Deviation 8 — so both pre- and post-rewrite SHAs are
recorded above.

---

## The exit gate, quoted verbatim from the plan

Anchor (plan-brief.md, L4-05), E-04 and its verification:

> "Unpinned or undeclared execution surfaces are refused under strict mode", verified by "Execute a renamed but byte-identical artifact and assert the same verdict; execute a same-named but modified artifact and assert refusal; assert every EXEC receipt carries the digest."

The plan's acceptance paragraph, quoted:

> renamed byte-identical artifact → same verdict (`Admitted`, Steps 6/10/12); same-named modified artifact → `Refused` at `Gate::Artifacts` before any process, daemon record or completion exists (Steps 10/12); every EXEC receipt — admitted, unpinned, refused, preflight or spawn — carries `sha256` (Steps 7/10/12); strict mode = any declared admission, and an undeclared or wrong-surface artifact is refused under it (E-04, Step 6); the refusal discloses the gate and the attempted digest only; existing warrants keep their bytes and signatures (Step 8); `bound_strengths` reports the new bound and its tier is promoted only on an observed refusal on every kernel CI runs (Step 15).

## Its actual output

### The test path (red then green, one step at a time)

| Step | red | green |
|---|---|---|
| 2 | `E0432: unresolved import warrantor_warrant::exec` | — |
| 3 | — | `1 passed` |
| 4 | `E0425: cannot find function resolve_program / sha256_file in module exec` | — |
| 5 | — | `--test exec`: `3 passed`; `--test agents`: `12 passed` (the moved resolver unchanged) |
| 6 | `E0425: cannot find function admit / log_path / read_for / record / refusal_sentence` | — |
| 7 | — | `7 passed` |
| 8 | `E0609: no field exec on type WarrantBounds` | — |
| 9 | — | `--test warrant --test spend --test sandbox --test report --test egress --test tier_disclosure` all PASS (after the golden-master update below); Python interop `54/54 PASS` |
| 10 | `E0560: struct SuperviseRequest has no field named exec` | — |
| 11 | — | `--test daemon`: `15 passed` |
| 12 | `unknown command "exec"` (binary stderr) | — |
| 13 | — | `--test exec`: `9 passed` (the CLI end-to-end runs the real binary three ways) |

### The three E-04 verifications, where they live

1. **Renamed byte-identical → same verdict.** `tests/exec.rs::a_renamed_artifact_gets_the_same_verdict_and_a_modified_one_is_refused` (library), `tests/daemon.rs::supervise_refuses_...` second half (chokepoint, exit 0), `tests/exec.rs::grant_with_exec_pins_...` (real binary, preflight AND spawn admitted, three receipts).
2. **Same-named modified → refused at `Gate::Artifacts` before any process.** Same three tests, first halves; the daemon test additionally asserts no daemon record and no completion record exist, and that the refusal does NOT contain the admitted digest.
3. **Every receipt carries the digest.** `receipts_append_as_versioned_jsonl_and_read_back`, the daemon test (`log.receipts[0].sha256 == digest` on the admitted path; `sha256.len() == 64` on the unpinned path), and the CLI test (`log.receipts.iter().all(|r| r.sha256.len() == 64)`).

Strict mode = any declared admission (`Some(empty)` refuses everything — `an_undeclared_surface_is_unpinned_...`); a wrong-surface admission refuses (`upstream_only` vs a `Process` spawn). Legacy warrants keep their bytes: `a_warrant_without_an_execution_surface_encodes_exactly_as_before` pins both the absence of `"exec"` in the encoding and the parse of the pre-L4-05 JSON.

### The gates

Every cargo invocation was preceded by both disk guards. The gate commands, at the final tree state:

```
$ python tools/ci/disk_guard.py --require 60        exit 0 (every cargo invocation)
$ python tools/ci/disk_guard.py --require-commit 6  exit 0 (every cargo invocation)
$ cargo fmt --all -- --check                        exit 0
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings   exit 0  (3m 36s, Finished)
$ cargo test --workspace --all-targets -j 2 -- --test-threads=1  exit 0
    121 suites, 1611 passed, 0 failed
$ cargo build --workspace --all-targets -j 2        exit 0
$ cargo metadata --locked -q                        exit 0 (no dependency added)
$ python tools/ci/wiring_census.py                  exit 0
wiring census: 13 of 41 crates reachable from warrantor-warrant over 23 path edges
    (identical to main @ 6f41384: the orphan count did not rise)
$ python tools/ci/check_invariant_ratchet.py        exit 0
invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)  (identical to main; no #[ignore] touched)
$ python tools/ci/run_python_checks.py test         PASS 54/54 (with the regenerated .bounds_interop.json)
$ node verify-us-english.mjs docs/W1-delivery-gaps.md CHANGELOG.md rust/warrant/src/{exec,daemon}.js rust/warrant/src/bin/warrantor.rs
    42 findings, every one on a line that is byte-identical on main (counts match per file); the
    lines this task added carry none
$ python -m ruff / pytest                           not run: no Python was added or modified
$ python tools/ci/check_phase_scope.py              ABSENT on main (as in Tasks 2.2/2.3); the plan was not touched
```

One mid-gate failure was found and fixed:
`tests/instructions.rs::every_flag_the_usage_text_names_is_one_the_parser_accepts` refused `--exec`
(the new USAGE line names it). `--exec` is genuinely read by `cmd_grant` via `args.all("exec")`,
so per that test's own doc comment it was registered with its dispatch site. Full suite re-run:
1611/0.

---

## The honest tier of every bound this task introduces

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the `exec` bound (digest admission at the supervised spawn) | **Observed** in `bound_strengths()`, by plan design | the refusal is real and happens before the process exists, but the plan requires promotion to `Mediated` only after the refusal test is seen to pass on BOTH CI kernels (Step 15); this machine is Windows-only and cannot observe that. No label is promoted by this task alone. |
| the mechanism itself | Tier B chokepoint (never `Enforced`) | it sits where Warrantor spawns; the agent's own shell execs are beyond it, and a human with the binary runs it directly. The §3.9 entry and the module doc say both. |
| the receipts | Observed-tier evidence | they record what was decided and by which warrant; they stop nothing by existing. |

`tests/warrant.rs::the_exec_bound_is_reported_and_starts_observed` pins the tier AT `Observed` so
the promotion cannot happen silently.

---

## Deviations from the plan's literal text, each earned

1. **The branch carries an identity-repair rewrite.** The first four commits were originally
   authored `AumOS Wave-1 <aumos@local>` because the lane's environment-variable identity does not
   survive across separate shell invocations, and the defect was caught only after Task 2.4 was
   underway (the same defect existed on the Task 2.2 and 2.3 branches, repaired there the same
   way). `git filter-branch --env-filter` set author/committer to `GLM 5.3 Flash <glm@local>` and
   `--msg-filter` fixed the DCO `Signed-off-by` trailers. The branches are local-only, so the
   rewrite raced nobody. Both pre- and post-rewrite SHAs are recorded in the table above.
2. **The regex literal edit over-matched; two sites were reverted.** The plan's one-line `perl`
   inserts `exec: None` after every line matching `delegation_depth: <expr>,` — including two
   function PARAMETERS named `delegation_depth: u32` in `authority-spec`'s tests, which are not
   struct literals and do not compile with a type expression as a value. The two bogus insertions
   were removed (the grep-backed count 39→44 legitimate literal sites in this tree, all inserted).
   Lesson recorded: a regex rewrite here needs the following line's context, not just the matched
   line.
3. **`sandbox.rs`'s CRLF churn was folded back out.** A byte-level insert on a CRLF file rewrote
   the whole file to LF in one commit; caught in `git show --numstat` (692/686) and repaired by
   re-writing the exec-Gap block through the editor so the commit's sandbox delta is the 11
   intended lines.
4. **Three golden masters were updated rather than bypassed**, because the bound must appear in
   every rendering: `tests/report.rs`'s prose-report golden gains the `exec  observed` line;
   `tests/warrant.rs::every_bound_declares_the_tier_...`'s expected table gains the `exec` row;
   both README bounds tables (test-pinned) gain the generated row. No assertion was weakened —
   each now asserts MORE (the new line must be present).
5. **The plan's Step 6/8 snippets needed their own setup fixed, not the properties:** the
   appended daemon tests re-imported `BTreeSet` (the file already imports it) and compared
   `Option<CompletionRecord>` with `==` (`CompletionRecord` is not `Eq`); the imports were
   deduplicated and the assertion changed to `is_none()` — same property, no weakened check.
6. **`cmd_run`'s preflight uses `args.trailing.first()`, not `split_first()`**, because the
   empty-trailing case is already refused at the top of `cmd_run`; the plan's `let Some(...) else`
   arm was dead code here.
7. **`cmd_exec log` prints phase/verdict/surface in the wire words** (`preflight`, `admitted`,
   `process`) rather than Rust `Debug` on enums whose variants are `PascalCase`, so the terminal,
   the receipt JSON and this evidence file all spell a verdict one way.
8. **The plan's Step 14 numbering did not match the evolved doc** — the §3.5 store-writer table it
   names lives (post-Task 7.x) inside `### 3.4 Retention`, and §3.6/3.7/3.8 were taken. The row
   went into §3.4's paragraph (twenty → twenty-one locations, `exec/<id>.jsonl` named with its two
   sequential writers) and the new section is **§3.9**, carrying everything the plan's §3.6
   required: both exec points and which is gated, absent-is-skipped, the three verifications with
   test names, the blueprint residual verbatim, the mediation ceiling, and the two open items.
9. **Step 15's push/PR/promotion was not run.** The brief says never push, never merge. The
   `Observed` label therefore STAYS `Observed` on this branch — the promotion to `Mediated`
   requires the refusal test observed on both CI kernels, and no PR was opened. Whoever opens it
   takes Step 15's remaining half verbatim.

## Not done

- **`git push`, `gh pr create`, and the CI-observed promotion to `Mediated`.** See Deviation 9.
  The branch, evidence, and §3.9 leave the promotion half of Step 15 as the next action, gated on
  a human opening the PR.

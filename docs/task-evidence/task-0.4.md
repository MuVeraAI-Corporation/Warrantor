# Task 0.4 — Tier disclosure lint across report, status and console (L8-13, partial → tested)

**Branch:** `feat/task-0.4` (from `origin/main` @ `26d16df`)
**Worktree:** `M:/wt-task-0.4`
**Date:** 2026-09-05
**Commits (in Step order):** `dcdbcf4` (Step 3), `d4ecb3c` (Step 4), `0e720ba` (Step 5),
`9515f3c` (Step 6), `1247183` (Step 7), `0edfb50` (Step 8), `2e82677` (Step 9),
`9b6edd1` (Step 10). Evidence file committed separately as the final commit.

**Board note, recorded because it cost a double-take.** Before this session's first commit the
board showed Task 0.4 as `UNEVIDENCED — merged at 26d16df`. That was a false positive: the
branch existed but sat exactly at `origin/main` with no commits of its own (so
`git branch --merged` reported it merged), and `rust/warrant/tests/tier_disclosure.rs` did not
exist on `origin/main`. The work was not done; this session did it.

---

## The exit gate, quoted verbatim from the plan

`### Task 0.4`, Step 10:

> Run the full gate from `rust/`: `cargo fmt --all -- --check && cargo clippy --workspace
> --all-targets -j 2 -- -D warnings && cargo test --workspace --all-targets -j 2 && cargo build
> --workspace --all-targets -j 2`, plus `node --test rust/warrant/src/console/console.test.js`.
> Expected: all green; `#![deny(missing_docs)]` in `lib.rs` is why every new `pub fn` above
> carries a doc comment.

And the acceptance paragraph:

> **Acceptance (Phase 0 exit gate, "every bound rendering carries its tier"):** `warrantor report
> <id>` prints seven `render_bound` lines and the legend and its signed bundle lists seven
> `BoundLine`s (unchanged format `warrantor.report-bundle/1`); the MCP report tool output contains
> the same seven lines; `warrantor status --root <r>` prints the block; `GET /v1/warrants/{id}`
> returns `strength` ∈ {enforced, mediated, observed} plus `caveat` per bound; both READMEs
> contain the generated table. No label was promoted: `bound_strengths()` is byte-identical
> before and after (`tests/spend.rs::the_budget_bound_is_still_observed_after_wiring` and
> `tests/sandbox.rs:84` still pass).

## Its actual output

### Step 10's full gate

```
$ cargo fmt --all -- --check          # after one fmt pass on the new test file
FMT-OK                                (exit 0)

$ cargo clippy --workspace --all-targets -j 2 -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 00s   (exit 0)

$ cargo test --workspace --all-targets -j 2
97 suites, every one `test result: ok`; 0 suites FAILED, 0 panics   (exit 0)

$ cargo build --workspace --all-targets -j 2
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 33.25s   (exit 0)

$ node --test rust/warrant/src/console/console.test.js
# pass 45
# fail 0
```

### Per-step red-then-green (each step's failure matched the plan's stated reason)

| Step | Red | Green |
|---|---|---|
| 1 | `error[E0599]: no method named 'word' found for enum 'BoundStrength'` (+ `caveat`), `error[E0432]` on `render_*` imports | (Step 2) |
| 2 | E0599s gone; file still red on the `render_*` imports, as the plan states | (Step 3) |
| 3 | — | `tier_disclosure`: 4 passed → commit `dcdbcf4` |
| 4 | `legend line missing: enforced  held by cryptography …` | tier_disclosure 5 passed + report 42 passed (golden incl.) → `d4ecb3c` |
| 5 | `assertion failed: text.contains("  bounds (tier per bound):")` | tier+report+mcp: 6+42+20 passed → `0e720ba` |
| 6 | caveat assert: `left: Null` | tier+serve+console: 7+39+19 passed → `9515f3c` |
| 7 | `TypeError: module.boundTierLines is not a function` | node 45 pass/0 fail; Rust console assets 19 passed → `1247183` |
| 8 | `stdout.contains("bound tiers")` false | tier 8 + instructions 6 passed → `0edfb50` |
| 9 | `README.md: no bound-tiers:begin marker` | tier 9 passed → `2e82677` |
| 10 | — | ledger entry + full gate → `9b6edd1` |

### The acceptance criteria, demonstrated on a live run (not a fixture)

Scratch root `M:/wt-0.4-live`, real binary, warrant `wrt_c9685fef3f094dc7` granted with
`grant --goal "demo tier disclosure" --tools git --write "src/**" --budget 500`:

```
$ warrantor report wrt_c9685fef3f094dc7
── BOUNDS ──
  tools                   mediated
  write_paths             observed
  egress_hosts            mediated
  staged_classes          mediated
  expires_at              enforced
  delegation_depth        enforced
  budget_cents_observed   observed
  enforced  held by cryptography or the operating system; holds against an agent that tries to route around it
  mediated  held only for calls that traverse the MCP proxy; a shell or a harness built-in reaches past it, and no netns, seccomp or firewall stands behind it
  observed  measured and reported after the fact; nothing refuses the action as it happens

$ warrantor status --root M:/wt-0.4-live
  bound tiers (the same for every warrant on this machine):
    tools                   mediated
    … (same seven lines) …
    observed  measured and reported after the fact; nothing refuses the action as it happens

$ curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:41923/v1/warrants/$ID
  every bound_strengths[i] carries {"name","strength","caveat"}; tier_legend has 3 lines

$ curl …/v1/warrants/$ID/report
  format: warrantor.report-bundle/1
  BoundLines: 7
  strengths: ['mediated','observed','mediated','mediated','enforced','enforced','observed']
```

The MCP rendering (`render_mcp`) is proven by
`the_mcp_report_discloses_a_tier_per_bound_from_the_same_bundle` (same bundle, same formatter,
byte-checked), not by a live stdio MCP drive; the CLI and HTTP surfaces above are live.

### No label promoted

```
$ cargo test -p warrantor-warrant --test spend the_budget_bound_is_still_observed_after_wiring
test result: ok. 1 passed
$ cargo test -p warrantor-warrant --test sandbox
test result: ok. 4 passed
$ git diff 26d16df..HEAD -- rust/Cargo.toml rust/Cargo.lock
  (empty)
```

`bound_strengths()` is byte-identical to `origin/main`; no crate was added; the orphan census's
input (workspace membership + the warrant's link graph) is unchanged by this task.

## Honest tier of every bound introduced

**None.** This task introduces no bound and edits no tier. It renders the tiers
`bound_strengths()` already assigns, adds what each tier does not cover, and makes the four
renderings spell them one way. `warrantor.report-bundle/1` is unchanged (`BoundLine` untouched);
the serve JSON gains additive `caveat` and `tier_legend` fields only.

## Deviations from the plan's letter, and why

1. **The Step 9 README test normalizes CRLF before comparing.** The plan's test compares
   `include_str!` bytes against the LF-joined generated table. On this box `core.autocrlf=true`
   checks the READMEs out CRLF, so the byte-exact `contains` could never match. The fix compares
   content per line — full strength on LF checkouts (Ubuntu CI) and CRLF ones alike, and it makes
   the negative "still claims write paths are enforced" check real on a CRLF checkout instead of
   vacuously true. No assertion was weakened.
2. **Two pre-existing "afterwards" spellings fixed** (root `README.md` line 14, crate README
   line 6). Present on `origin/main`; zero occurrences in this branch's diff before the fix. The
   US-English gate must be green for every prose file the task touches, and the goal names
   "afterwards" as a real finding, not a false positive.
3. **Plan line-number drift.** The plan's anchors ("after line 211", "after line 653",
   "after line 640", §3.1 at "line 629") were written against slightly different file states.
   Each edit anchored on the named symbol/paragraph instead; the code matched the plan's intent
   everywhere.
4. **`serve` CLI flag order.** The plan's Task 1.4 line implies `warrantor --root R grant …`;
   this build's parser wants the subcommand first (`warrantor grant --root R …`). Relevant only
   to the live run above, not to the code.

## Gates this task could not run, and why

- `python tools/ci/wiring_census.py` and `python scripts/task_status.py` — not present at this
  branch's base `26d16df` (the census landed with Task 0.3, the board with the seeding lane,
  both after this branch was cut). Their inputs are unchanged by Task 0.4 (manifest diff empty,
  no new crate, `warrantor-warrant` already linked), so the census number cannot move.
- `python tools/ci/check_phase_scope.py` — run from the main checkout (which has the tool):
  `phase scope: 76 tasks account for 132 of 132 uncovered items, out of a catalog of 189` —
  exit 0, SCOPE-OK.
- `task_status.py --check` from that same tree reports 0.1/0.2/0.3/5.1 as merged-without-evidence
  because the main checkout is stale (`docs/content-program-p9-fold`); `origin/main` @ `e0b7631`
  carries all four evidence files (`git ls-tree origin/main docs/task-evidence/`). Not this
  task's defect.
- **origin/main moved mid-task**: 0.1, 0.2, 0.3 and 5.1 merged while this task ran
  (`26d16df` → `e0b7631`). This branch was cut from and is tested against `26d16df`, per Global
  Constraints; the merge rebases on main. Overlapping files to watch at rebase: `tests/report.rs`
  (this task edited the golden), `lib.rs`, `README.md`.

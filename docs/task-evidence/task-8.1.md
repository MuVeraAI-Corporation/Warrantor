# Task 8.1 — Horizon governor (L3-04)

Branch `feat/horizon-governor`, rebased onto local `main` at `5d3e44d`.

L3-04 carries `data-status="partial"` `data-wave="W1"` in the master blueprint and was **omitted from
the original 41-task plan**. Long-horizon autonomy is the risk this product exists to bound; the
control that bounds it had no task.

This file records what was built, which word each half of it earns, every place the seeded plan is
wrong, and — at the end — what the task specifically does not establish.

---

## What `status=partial` actually referred to, measured

The blueprint's anchor says it in one clause: *"bounded deadline and process-lifetime expiry are Tier
A properties the platform already ships."* That is `WarrantBounds::expires_at` plus `supervise.rs`,
and `bound_strengths()` already declared `("expires_at", Enforced)`.

So **the partial was the wall-clock half only.** Two things were missing:

1. **Any count-shaped bound.** There was none in any form. `delegation_depth` is a tree depth checked
   at issue, not a count of anything an agent does.
2. **Escalation to a human as the horizon extends.** Nothing in the crate raised an approval on the
   approach to a limit.

`status=partial` is not moved to `done` by this task and the entry is not edited. What is recorded is
`docs/W1-delivery-gaps.md` §3.8, which says which half existed, which half this task built, and which
of L3-04's own residuals still stand.

---

## The state this task inherited, and why half of it was a claim with no mechanism

One commit already existed on the branch (`e7b17f8`, rebased to `ce29bd2`). It was substantial and
mostly good: `horizon.rs`, the `Horizon` field with its serde contract, `WarrantBounds::contains`'s
horizon rule and its Python mirror, the `Proxy::decide` refusal for the effect ceiling, the MCP grant
parser, the sandbox divergence, and a 19-test suite.

It also shipped **three defects that a `--all-targets` run or a call-site grep would have caught**,
and they are recorded here because two of them are the exact defect classes this program keeps hitting.

### Inherited defect 1 — the branch was RED, and green-looking

`cargo test -p warrantor-warrant --all-targets` failed on `rust/warrant/tests/spend.rs:137`:

```
assert_eq!(bound_strengths().len(), 7, "no bound was added or removed by this wiring");
```

`bound_strengths()` had eight entries as of the inherited commit. The prior lane ran the two suites
its own step list named (`--test warrant --test tier_disclosure`) and never the package, so a
hardcoded count in a third suite stayed broken through a commit. Fixed here, with the number's reason
written into the assertion message so the next mover knows why it may legitimately change and which
assertion in that test may never change.

### Inherited defect 1b — the Python gate's `format` leg was red too

`python tools/ci/run_python_checks.py format` reported `53/54`:
`python/warrantor_ml/src/warrantor_ml/tasks/bounds.py` needed one blank line before a nested `def`.
Same cause as defect 1: the inherited commit ran the `test` leg and not `format`. Both legs, plus
`lint`, pass here. The repository convention is that a gate is run for **every language in the diff**,
which means every leg of that language's gate and not the one whose name matches the change.

### Inherited defect 2 — two of three dimensions reached no mechanism at all

`grep` for production call sites of the inherited API returned nothing for three of its functions:

| Function | Production call sites, inherited commit |
|---|---|
| `horizon::effective_deadline` | **0** (one doc-comment reference) |
| `horizon::usage_at` | **0** |
| `horizon::escalation_blocker` | **0** |
| `report::horizon_section` | **0** — not on `ReportBundle`, reachable only from tests |

So: the effect ceiling was wired (at the proxy) and *nothing else was*. `HorizonDimension::strength()`
returned `Enforced` for both time dimensions while neither could terminate anything, and no evidence
surface carried the state. That is Rule 3 — no claim without a mechanism — inside a bound-strength
function, which is the worst place for it.

### Inherited defect 3 — the delivery ledger described the plan, not the diff

`docs/W1-delivery-gaps.md` §3.8's *"What this task closed"* paragraph named six things. **Five of them
did not exist in the tree that commit produced**: the sliced supervision wait, `horizon_breach` on the
completion record, the `HorizonSection` on the bundle, `warrantor horizon`, the four `grant` flags,
and the halt on breach. All six are now true, so the paragraph reads correctly today — which is why it
was worth catching. Recorded in §3.8 itself as a rule: an entry in that file is written from `git
diff`, never from a task's step list.

---

## The design decision the critic flagged: how the effect count is counted

The effect dimension had no wiring on `origin/main` and an implementer had to design it. Recording
the decision explicitly, because it is the one place in this task where a reasonable person would
choose differently.

**Decided: one effect is one tool call the MCP proxy ADMITTED, counted as the persisted
staging-queue length plus the current session's forwarded calls.**

Four sub-decisions, each with its alternative and why it lost:

1. **A refused call counts nothing.** The ceiling bounds effects; a refused call produced none.
   Counting refusals would let a warrant be exhausted by calls it was never allowed to make, turning
   an effect ceiling into a rate limit on attempts — which is Task 8.3's business (L3-05, L3-10) and
   not this bound's.
2. **The seed at session start is the staging queue's length** (`mcp_endpoints::agent_endpoint_for`
   calls `Proxy::seed_horizon_effects(queue.len())`). The alternative — a per-session counter from
   zero — would hand every restart a fresh allowance, and a ceiling a restart resets bounds nothing
   over the horizon it is named after. The staging log persists and is witnessed outside itself by
   `StoredWarrant::staged_chain`, so seeding from it is seeding from evidence.
3. **The forwarded (unstaged) half is NOT persisted.** Considered and rejected: a persisted forwarded
   counter would be a second source of truth for "how many effects has this warrant produced",
   competing with the staging chain that already witnesses effects, and an unwitnessed counter is one
   an editor can lower to buy horizon. The choice is the witnessed floor, declared as a floor in
   `horizon::EFFECT_COUNT_LIMITATION`, which every surface prints verbatim.
4. **The counter increments even when no ceiling is declared.** A counter that only runs when a limit
   exists would report zero effects for every ungoverned warrant, and the report renders the observed
   figure either way. It is incremented inside `Proxy::decide` rather than by the caller: a counter
   the caller has to remember to advance is a ceiling that silently stops refusing the first time
   somebody forgets.

**The consequence, stated rather than buried:** the supervision loop cannot see the forwarded half at
all. There is no daemon IPC in this system, so the polled usage it evaluates is the staged length
only, and forwarded calls are bounded by the proxy's own refusal within one session. Both facts are in
`EFFECT_COUNT_LIMITATION` and therefore in the report, the CLI and the daemon's own log line.

---

## Composition with `supervise.rs`, not duplication

`rust/warrant/src/supervise.rs` has **zero lines changed by this task**, deliberately, and the diff is
the proof. `supervise.rs` is the one genuinely strong bound in this system — Tier A via a Windows job
object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, or `setsid` plus `PR_SET_PDEATHSIG` as `SIGKILL` on
Linux — and the horizon reaches it by making the number it already waits on smaller:

* `rust/warrant/src/bin/warrantor.rs`, in `cmd_supervise`: `expires_at` on the `SuperviseRequest`
  becomes `horizon::effective_deadline(&bounds, issued_at)`, which is `min(expires_at, issued_at +
  max_wall_seconds)`. It can only move the deadline **in**; a horizon that could extend one would be
  an authority expansion wearing a governor's name, and `the_wall_horizon_can_only_tighten_the_deadline_never_extend_it`
  pins that.
* `rust/warrant/src/daemon.rs`, in `supervise_run`: one wait becomes a loop of slices, and the halt on
  breach is `supervisor.terminate()` — the existing Tier A kill, called, not reimplemented.

The slice length is **derived, not fixed**: `daemon::horizon_slice_seconds` is a tenth of the tightest
declared time ceiling, clamped to `1..=30`. A flat 30 s would let a 4-second ceiling arrive inside one
slice with the escalation before it unobserved; a flat 1 s would make an 8-hour run re-read the actor
log 28,800 times. Pinned at both ends by `the_poll_slice_is_derived_from_the_tightest_time_ceiling`.

A warrant with **no** horizon keeps the single up-front wait it always had, byte for byte. Slicing a
wait with nothing to re-evaluate would add a loop for no reason.

---

## Tier table: which word each half gets, and why not a stronger one

**A bound is only as strong as the weaker of its trigger and its consequence.** That rule is why two
dimensions with the identical Tier A kill get different words.

| Half of L3-04 | Trigger | Consequence | Word | Why not stronger |
|---|---|---|---|---|
| `max_wall_seconds` | monotonic elapsed time (`Instant::elapsed`) against `issued_at` from the **signed** claims. The bounded party cannot make a clock run slower or forge `issued_at` without breaking the signature. | `supervisor.terminate()` → `terminate_group` → a Windows job object or `kill -KILL -pgid` under `setsid`. Observed killing a real grandchild in `horizon_wall_breach_terminates_the_process_group`. | **Enforced** (Tier A) | This is the same basis `bound_strengths()` has always given `expires_at`, reached by shortening that deadline rather than by adding a mechanism. It is **not** stronger than `supervise.rs` and inherits that file's own caveat: where `describe_linkage().survives_supervisor_death` is `false` — anything that is neither Windows nor Linux, macOS included — an agent outlives a supervisor killed uncleanly, and this ceiling with it. Tier A through a *live* supervisor on all three platforms; Tier A across the supervisor's own death on two of three. |
| `max_effects` | the proxy's own admitted-call counter, seeded from the persisted staging queue. | `Decision::Deny { bound: "horizon_effects" }` returned by `Proxy::decide` **at the moment the call is attempted**. | **Mediated** (Tier B, chokepoint) | Not Observed: a specific line refuses a specific call as it arrives. Not Enforced: the proxy sees only what the agent routes through it. **What escapes:** a shell command, a harness built-in, a direct socket, any call that never reaches the proxy — and the forwarded half of the count does not survive a session restart. There is no netns, no seccomp and no firewall anywhere in this repository. |
| `max_unattended_seconds` | a read of `operators.rs`'s actor log, which is hash-chained and **not signed**. | the same Tier A kill as `max_wall_seconds`. | **Observed** (Tier C) | **This is the correction that mattered most in this task, and the stronger word wanted it.** `operators::record` takes no key. Any process that can write the store root can append a well-formed entry carrying `actor: Some("someone")` and reset this clock — and `write_paths` is enforced nowhere in this system, so the agent is such a process. A bound the bounded party can extend by writing a file is measured, whatever happens at the end of it. The inherited commit scored this dimension from its consequence alone and called it `Enforced`; that is corrected here, and both README bound tables were regenerated from `bound_strengths()`. |
| the `horizon` row in `bound_strengths()` | — | — | **Observed** (Tier C) | The whole bound takes the **weakest** of its three dimensions, because a reader takes the first word and moves on. The inherited commit said `Mediated`, which was the weakest of the three it *believed* it had. The `Enforced` wall ceiling is not lost to this row: `HorizonDimension::strength`, `HorizonLine::strength` and `warrantor horizon` all print the per-dimension answer, and `tests/horizon.rs` derives the row from the dimensions so the two cannot drift. |
| escalation at `escalate_at_percent` | percentage of the nearest ceiling consumed. | a `review::record_request` marker written under the store root. | **Observed** (Tier C), and it adds **no trust root** | It establishes that a request exists **on this machine, at a known second**. It does not establish that a human read it, that anything left the machine, or that the run was reconsidered. No webhook is sent: the unattended supervisor holds no notify transport, so the announcement waits for the next `warrantor review --announce`. No approval service, no directory, no new signer. |
| the halt on breach | `CompletionRecord::horizon_breach`, read after the loop returns. | `stop::halt` in `cmd_supervise` — kill, void, record, sign, persist. | **Mediated** (Tier B), and only on the CLI path | L3-04's verification clause names the kernel's `halt()` verb; `stop::halt` exists on `main` as of Task 1.3 and this is the caller that can reach it. **`supervise_run` itself does not call it**: the loop holds no store handle and no signing key, and giving the unattended daemon one to satisfy a sentence would be the wrong trade. A run reached by any other route gets the termination and the `CompletionRecord` and **no signed stop receipt** — the loop says so in its own log line. |

**What is deliberately *not* claimed anywhere.** No dimension of this horizon refuses a syscall.
Nothing here is enforced by a network namespace, a seccomp filter or a firewall, because none of the
three exists in this repository. "Contained at settle time" appears nowhere: the wall and unattended
ceilings are checked while the run is live, at a derived interval, and the effect ceiling is checked at
the moment of the call.

---

## Deviations from the seeded plan

Every one of these is a case where the code won.

1. **`stop::halt` EXISTS.** The plan states at length that `stop::halt`, `HaltScope`, `HaltContext`
   and `EnforcementBasis` "does not exist and is **not** created here", and builds its whole
   Step-3-error resolution around that. Task 1.3 has since merged into `main`: `stop::halt` is
   `rust/warrant/src/stop.rs:1297`, `HaltScope` at `:1229`, `HaltContext` at `:1240`,
   `EnforcementBasis` at `:121`. So the halt path this task takes is the verb L3-04's verification
   clause actually names, from `cmd_supervise`, signed with the **issuer** key for the reason
   `cmd_stop` gives (a halt releases nothing and performs nothing, so loading settle authority to
   record it would put that key in a process with no business holding it). Non-goal 5 — "not one line
   of `stop.rs`" — is honored: `stop.rs` has zero lines changed.
2. **`settle::void_on_breach` is NOT called by this task.** The plan's resolution was for the
   effect-count breach to void directly. It does not, because `stop::halt` already does the voiding
   plus the kill, the deregistration, the receipt and the persistence, in the order that keeps them
   consistent — and calling `void_on_breach` beside it would be a second, weaker path to the same
   state transition.
3. **The process-group test is NOT `#[cfg(windows)]`.** The plan's Step 7 test body is Windows-only.
   `stop_kills_tree.rs` already demonstrates the cross-platform idiom (`powershell` + `ping` on
   Windows, `sh` + `sleep` on Unix), so `horizon_wall_breach_terminates_the_process_group` and
   `horizon_unattended_breach_halts_a_run_the_deadline_would_have_allowed` run on **both** kernels and
   are registered in **both** legs of the CI executed-test allowlist. Strictly stronger than the plan.
4. **The blast radius is 85 sites in 45 files, not 66 in 36.** Measured on this tree with the plan's
   own command. The plan's numbers were taken from `refs/remotes/origin/main` at `e4b5f10`; local
   `main` is 66+ commits ahead and several landed tasks added `WarrantBounds` literals. Two further
   structs gained fields here (`SuperviseRequest`, `CompletionRecord`), for 11 more sites.
5. **The wiring census reads 13 of 41 crates over 22 path edges, not 9 of 39 over 17.** Same cause:
   the plan measured `origin/main`. The number is **unchanged by this task**, which is what Rule 5
   requires — `horizon.rs` is a module in an existing crate, not a new crate.
6. **`passing_floor` goes 82 → 83, not 65 → 66.** Same cause. The 83 was **read** from the merged
   corpus's own `test result:` line, not computed by adding one — which is the mistake the ratchet's
   own note records having made before. `ignored_ceiling` stays 15; this task adds no `#[ignore]`.
7. **`Observed` for `max_unattended_seconds`, against the plan's `Enforced`.** The plan's Bound
   Strength section says the unattended dimension is "Tier B for the decision, Tier A for the
   termination, and Observed for what it measures", then labels the dimension by its termination. The
   three-way split is right and the label taken from it is wrong: the weakest of the three is the word.
   See the tier table.
8. **The plan's third dimension really is struck, and the plan is right about that.** Its own Produces
   list names "distance from the granting objective" and its Non-goals strike it. Nothing here reads
   the goal string. Semantic drift is L3-09 and Task 8.5.
9. **`Observed`, not `Mediated`, for the whole `horizon` row** — a consequence of 7, and a change to
   what the inherited commit shipped. Both README tables regenerated; `tests/report.rs`'s golden prose
   report and `tests/warrant.rs`'s expected list updated with the reason recorded in each.
10. **A `usage_counted` companion to `usage_at` was needed and the plan does not mention it.** Four
    report surfaces (CLI report, CLI final report, MCP `warrant_report`, HTTP `serve`) already hold an
    open `StagingQueue`. Having them call `usage_at`, which re-reads the log from disk, would give a
    bundle two counts of the same queue that could disagree. `usage_counted` takes the count the rest
    of the bundle is built from, so there is one number.

---

## Gate output, verbatim

`cargo fmt --all -- --check`:

```
FMT=0
```

`cargo clippy --all-targets -j 2 -- -D warnings`:

```
CLIPPY=0
```

`cargo test -p warrantor-warrant --test horizon --test horizon_supervision --test invariants -j 2`:

```
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.38s
test result: ok. 83 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 1.11s
```

The two tests that earn the Tier A half of the wall-clock claim, shown as executed:

```
test horizon_wall_breach_terminates_the_process_group ... ok
test horizon_unattended_breach_halts_a_run_the_deadline_would_have_allowed ... ok
test a_run_that_finishes_inside_its_horizon_records_no_breach ... ok
test crossing_the_escalation_threshold_records_a_local_review_request_without_halting ... ok
test a_horizon_with_no_escalation_threshold_records_nothing ... ok
test the_poll_slice_is_derived_from_the_tightest_time_ceiling ... ok
```

And the new I-12 test:

```
test i12_safe_state_is_reachable::a_horizon_breach_is_decided_without_the_identity_plane_and_a_run_inside_it_is_not ... ok
```

`python tools/ci/check_invariant_ratchet.py`:

```
invariant ratchet: ok (83 passing at floor 83, 15 recorded findings at ceiling 15)
```

`python tools/ci/wiring_census.py`:

```
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges
```

`python tools/ci/check_invariants.py`:

```
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
```

`python tools/ci/check_docs.py`:

```
RESULT: PASS - 268 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
```

`python tools/ci/check_us_english.py main`:

```
us-english: 1971 added line(s) across 51 file(s), since main; matcher = vendored verify-us-english.mjs
us-english: ok
```

`python tools/ci/run_python_checks.py test | lint | format`:

```
RESULT: PASS - 54/54 Python projects passed test
RESULT: PASS - 54/54 Python projects passed lint
RESULT: PASS - 54/54 Python projects passed format
```

`cargo test --workspace -j 2`, summed across every `test result:` line rather than read from the last
one:

```
152 suites; passed=1561 failed=0 ignored=20
```

Baseline on `main` was `150 suites, 1528 passing, 0 failed, 20 ignored`. The two new suites are
`horizon` and `horizon_supervision`. No `#[ignore]` was added; the ignored count is unchanged.

### Verified in a fresh detached worktree

Everything above was re-run from `git worktree add --detach M:/wt-g6-8.1 feat/horizon-governor`, on
the committed tree and nothing else, because a `.gitignore`d evidence file has silently made a green
branch red for everyone else in this program before:

```
$ git status --porcelain
                                       (empty)
$ git ls-files rust/warrant/tests/ | grep horizon
rust/warrant/tests/horizon.rs
rust/warrant/tests/horizon_supervision.rs
$ git ls-files docs/task-evidence/ | grep 8.1
docs/task-evidence/task-8.1.md
$ git check-ignore -v rust/warrant/tests/horizon_supervision.rs rust/warrant/tests/horizon.rs     docs/task-evidence/task-8.1.md tools/ci/invariant-ratchet.json rust/warrant/src/horizon.rs
CHECK_IGNORE_EXIT=1                    (no rule matches any of them)
$ cd rust && cargo fmt --check;                        FMT=0
$ cargo clippy --all-targets -- -D warnings;           CLIPPY=0
$ cargo test --workspace -j 2;                         CARGO=0
  152 suites; passed=1561 failed=0 ignored=20
```

**And one thing the fresh worktree taught that the working one could not.**
`tools/ci/check_us_english.py` diffs `main...HEAD` — **committed** changes only. Run against an
uncommitted tree it reports the *previous* commit's numbers and says `ok`, which is exactly what it
did here: `1971 added line(s) across 51 file(s), ok`. Run against the commit it found three
`synthesised` in lines this pass added, in `warrantor.rs` and `report.rs`, and reported
`3853 added line(s) across 58 file(s)`. So the gate has to be run **after** committing, and a green
US-English result on a dirty tree is not evidence of anything. Fixed and amended into the same commit.

### Construction-site count, matched against the diff

The plan's Step 2 command, run on this tree:

```
$ grep -rn "WarrantBounds {" rust/ --include=*.rs | wc -l
85
$ grep -rn "WarrantBounds {" rust/ --include=*.rs | sed 's/:.*//' | sort -u | wc -l
45
$ grep -rn "SuperviseRequest {\|CompletionRecord {" rust/ --include=*.rs | wc -l
11
```

85 `WarrantBounds` literals across 45 files, plus 11 sites for the two structs this task extended.
Every one compiles, so none was missed; none was "fixed" by a default nobody decided — `horizon` is
stated explicitly at every site, and at the four test sites in `tests/daemon.rs` the two new
`CompletionRecord` fields carry a comment saying why `None`/empty is the true value there.

---

## What this task does NOT establish

Specific rather than modest.

1. **It does not establish that an agent produced only the effects the count says.** The count covers
   the persisted staging queue plus one session's proxy-forwarded calls. A shell command, a harness
   built-in, a direct socket, an HTTP call the agent made itself, and every effect from any earlier
   session's forwarded half are all outside it. `horizon::EFFECT_COUNT_LIMITATION` calls the number a
   floor on every surface that prints it, and a floor is what it is.
2. **It does not establish that nobody was watching an unattended run, and it does not stop the agent
   from claiming somebody was.** The clock is read from `operators.rs`'s hash-chained-but-unsigned
   actor log. `operators::record` needs no key; anything that can write the store root can append an
   entry naming an operator and reset the clock; `write_paths` is enforced nowhere, so the agent
   qualifies. Closing this needs a signed actor log, which is a change to `operators.rs`.
3. **It does not establish that a human was told when a horizon neared its ceiling.** Escalation
   writes a durable local marker. Nothing left the machine. No webhook is sent from the supervising
   process, and `warrantor review --announce` — a command a human runs — is what sends one.
4. **It does not establish that a horizon holds after the supervisor dies on every platform.** Where
   `supervise::describe_linkage().survives_supervisor_death` is `false` (anything that is neither
   Windows nor Linux), an agent outlives a supervisor killed uncleanly and the wall and unattended
   ceilings die with it. `describe_linkage` already says so and this task inherits the caveat without
   improving it. The horizon adds nothing to `supervise.rs` — that is the point of the composition,
   and it is also the limit of it.
5. **It does not establish that staged effects are discarded on every horizon breach.** L3-04's
   verification clause says the halt goes through `halt()` "with staged effects discarded". That
   happens on the `cmd_supervise` path, which calls `stop::halt`. A run reached any other way — a
   caller using `daemon::supervise_run` directly, or a supervising process killed before it returns —
   gets the process-group termination and the `CompletionRecord` and **no state transition and no
   signed stop receipt**. The loop prints exactly which half is missing when the halt cannot be
   recorded.
6. **It does not establish anything about a population's horizon.** L3-04's own residual: work can be
   passed between short-lived instances, and this bounds one warrant. That is L3-11 and Task 8.4.
7. **It does not establish a semantic distance from the granting objective.** Nothing here reads the
   goal string. Three dimensions, all counters and clocks. L3-09 and Task 8.5.
8. **It does not establish a risk dial or an end-of-budget profile.** Task 8.2 owns L3-02 and L3-07
   and reads this task's state as an input. This task publishes a state and a verdict and decides
   nothing about what else tightens as a horizon nears.
9. **It does not establish anything about parallelism, fan-out, rate or duplicate suppression.** A
   horizon counts effects along one warrant's chain over time and says nothing about a thousand
   arriving at once. Task 8.3, L3-05 and L3-10.
10. **It does not establish that any of these ceilings is set to a usable number.** This is the honest
    unknown and it is the one an operator will hit first. Nothing here tells anyone what
    `--max-effects` should be. A ceiling below real usage strangles ordinary work and gets the
    governor turned off; one far above it never fires and is a comfort. Choosing it needs a
    distribution of effect counts and unattended intervals from real runs, and this repository has
    none. Every figure in this file is a mechanism, not a calibration.
11. **`status=partial` on L3-04 is not moved.** This task built the two missing halves and wired the
    one that was already there; whether the item is "done" is a judgment about the blueprint's own
    entry, and the entry was not edited. What the ledger records is what exists.

---

## Files

Created:

* `rust/warrant/src/horizon.rs` — the governor (inherited; the tier decisions, `usage_counted` and the
  corrected caveats are this pass).
* `rust/warrant/tests/horizon.rs` — arithmetic, containment, refusals and the report bundle
  (inherited 19 tests; 4 report-bundle tests and the derived tier assertion are this pass).
* `rust/warrant/tests/horizon_supervision.rs` — the six tests against a real supervised process tree.
* `docs/task-evidence/task-8.1.md` — this file.

Modified this pass:

* `rust/warrant/src/daemon.rs` — `SuperviseRequest::{horizon, issued_at, staged_path}`,
  `CompletionRecord::{horizon_breach, horizon_escalations}`, `horizon_slice_seconds`, the sliced
  supervision loop with its breach and escalation paths.
* `rust/warrant/src/bin/warrantor.rs` — `effective_deadline` at the `supervise_run` call site,
  `halt_on_horizon_breach`, `parse_grant_horizon`, the four `grant` flags, `cmd_horizon`, USAGE.
* `rust/warrant/src/report.rs` — `ReportBundle::horizon`, `Observed::horizon`, the three derived
  limitation lines, one Britishism.
* `rust/warrant/src/lib.rs` — `("horizon", Observed)` and the reason.
* `rust/warrant/src/horizon.rs` — the tier correction, `usage_counted`, the module tier table.
* `rust/warrant/src/mcp_endpoints.rs`, `rust/warrant/src/serve.rs` — the horizon measured on the MCP
  and HTTP report surfaces.
* `rust/warrant/src/sandbox.rs` — the divergence text, corrected to `Observed`.
* `rust/warrant/tests/{warrant,report,spend,daemon,instructions}.rs`,
  `rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs`.
* `python/warrantor_ml/src/warrantor_ml/tasks/bounds.py` — one blank line, so `ruff format` passes.
* `README.md`, `rust/warrant/README.md` — regenerated bound table plus the per-dimension note.
* `tools/ci/invariant-ratchet.json` — floor 82 → 83.
* `.github/workflows/ci.yml` — the two horizon kill tests in both legs of the allowlist.
* `docs/W1-delivery-gaps.md` — §3.8 corrected and completed.

**Unmodified, deliberately:** `rust/warrant/src/supervise.rs` and `rust/warrant/src/stop.rs`. A diff
in either would mean this task duplicated a bound instead of composing with it.

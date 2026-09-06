# Task 1.4 — Spend into the budget path, last (L3-03; label promotion only where refused)

**Branch:** `feat/spend-call-ceiling` (from `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-1.4` (target dir `M:/wt-1.4-target`)
**Date:** 2026-09-05
> **SUPERSEDED, 2026-09-06.** Everything from here to the horizontal rule before
> `# Rebase onto local main` was measured on the pre-rebase tip `7b8d2bb`, 115 commits behind
> `main`. The commit hashes below no longer exist; the rebased ones are tabled in that section,
> which also carries every gate number and the live run as re-derived on the merged tree. This
> block is kept because what was measured when is itself part of the record.

**Commits (in Step order):** `1887e65` (Step 1), `a4fde0e` (Step 2), `bc93146` (Step 3),
`4441ed7` (Step 4), `46eb2e3` (Step 5), `83c5a4f` (Step 6), `ef11700` (Step 7), `f9e6a09`
(Step 8), `ee2b331` (Step 9). Evidence file is the final commit.

---

## The exit gate, quoted verbatim from the plan

The acceptance paragraph:

> `cargo test -p warrantor-warrant --test spend_refusal` passes on the Linux and Windows runners
> from Task 0.2 (the ceiling is pure proxy logic; nothing here is `cfg`-gated); the 101st call
> under `--max-calls 100` returns `refused by the warrant's budget_calls_mediated bound: this
> warrant's tool-call ceiling of 100 is reached …` with `forwarding_counts() == Some((100, 0))`;
> `<root>/spend/<id>.calls.json` carries a `WarReceipt` whose body is `Verdict::Deny { gate:
> Gate::Budget }` at `EnforcementMode::Mediated`, verifiable with `warrantor_notary::verify_receipt`
> and pinned to the store's issuer key on load; `bound_strengths()` lists `budget_cents_observed →
> Observed` and `budget_calls_mediated → Mediated`, and the report, `serve` status JSON and every
> sandbox profile carry both because all three read `bound_strengths()`. Not claimed: cents are not
> refused anywhere, and calls that bypass the proxy are not counted — both sentences are in
> `CALLS_NOTE` and in the gaps entry.

Step 9's live run:

> Assert by hand: line 101 of `out.jsonl` carries `"isError":true` and `budget_calls_mediated`;
> `$R/spend/<id>.calls.json` has `"refused": 1` and `"verdict": {"outcome": "deny", "gate":
> "budget"}`; `warrantor spend <id>` prints `call ceiling            100 (100 used, 1 refused,
> budget_calls_mediated)`; `warrantor serve --root $R` then `curl … /v1/summary/refusals` lists one
> `tool` refusal with bound `budget_calls_mediated`.

## Its actual output

### The gates  
*(SUPERSEDED on the rebased tip: the workspace count below is 102 suites, measured against
`origin/main`'s corpus; the merged tree runs 122 suites / 1596 tests. See the rebase section.)*


```
$ cargo fmt --all -- --check                                   (exit 0)
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings   (exit 0)
$ cargo test --workspace --all-targets -j 2
TEST-EXIT=0 ; 102 suites `test result: ok`; none FAILED
$ cargo build --workspace --all-targets -j 2                   (exit 0)
```

`cargo test -p warrantor-warrant --test spend_refusal`: 12 passed (proxy, ledger, endpoint and CLI
grain), including the 101-call acceptance test against a LIVE `selftest-upstream` with
`forwarding_counts() == Some((100, 0))` after the refusal.

### The live run (scratch store `M:/wt-1.4-live`, warrant `wrt_063a41489e006aab`)  
*(SUPERSEDED: a real run, but on the pre-rebase tip. The run that describes the merged tree is
warrant `wrt_ed612b927e8f1514` in the rebase section below.)*

```
$ warrantor grant --root R --goal "echo until refused" --tools selftest.echo --write "src/**" --max-calls 100
warrant  wrt_063a41489e006aab

$ python -c "…101 tools/call lines…" | warrantor mcp --agent <id> --root R \
    --upstream "selftest=M:/wt-1.4-target/debug/warrantor selftest-upstream"
101 responses; line 101:
  isError: true
  "refused by the warrant's budget_calls_mediated bound: this warrant's tool-call ceiling of 100 \
   is reached. Nothing further is forwarded or staged under it; ask for a new warrant."

$ python -c "…inspect R/spend/<id>.calls.json"
  refused: 1   used: 100
  verdict: {'outcome': 'deny', 'gate': 'budget'}
  mode: mediated

$ warrantor spend <id> --root R
  call ceiling            100 (100 used, 1 refused, budget_calls_mediated)
  The call ceiling counts tool calls that pass through the Warrantor MCP proxy and refuses the …

$ warrantor serve --root R … curl /v1/summary/refusals
  "groups":[{"bounds":["budget_calls_mediated"],"kind":"tool","occurrences":1, … }]
```

### Per-step red-then-green

| Step | Red | Green |
|---|---|---|
| 1 | `E0422 SpendAct`, `E0599 reserve` | spend 20 passed → `1887e65` |
| 2 | `E0560 no field max_tool_calls` (then 30+ literals E0063) | workspace 101 suites → `a4fde0e` |
| 3 | tier-table + prose-golden failures, as predicted; then `sandbox::…every_bound…spelled` | all green after bound + gap → `bc93146` |
| 4 | `E0432 CallCounter` | 2 passed → `4441ed7` |
| 5 | `E0599 call_counter/with_call_counter` | spend_refusal + proxy/egress/mcp/upstream all green → `46eb2e3` |
| 6 | `E0277 WarReceipt: !Eq` (plan's derive rejected — see Deviations) | 9 passed → `83c5a4f` |
| 7 | `E0599 metered_by/call_ledger` | 101-call live-upstream acceptance green → `ef11700` |
| 8 | grant test failed (flag ignored); then instructions.rs inventory | workspace 102 suites → `f9e6a09` |
| 9 | — | live run receipts → `ee2b331` |

## Honest tier of every bound introduced

**One new bound: `budget_calls_mediated` at `Mediated`.** The name carries its tier; the plan
rejected the spine stub's `_enforced` spelling for exactly this reason. The refusal happens in
`Proxy::reserve_call` — after the tools and egress bounds have had their say (a call they refused
was not a call and spends nothing), in enforce AND observe mode — and the count persists on disk,
fail-closed on read (unreadable/unverifiable/wrongly-signed = unknown spend, never zero). Each
decision leaves a notary receipt at the mediated tier. `budget_cents_observed` is untouched and
`Observed`; `the_budget_bound_is_still_observed_after_wiring` pins it and now also pins the new
bound's tier and the count (8).

## Deviations from the plan's letter, and why

1. **`CallLedger` is not `Eq`.** The plan's derive list included it, but the notary `WarReceipt`
   inside does not implement `Eq` and no caller compares ledgers; the derive fails to compile.
   Documented on the struct. No assertion was weakened — the tests that matter compare counters.
2. **The plan's stranger-key test could not reach a refusal as written** (ceiling 1 → the first
   `reserve()` succeeds, so its `assert!(reserve().is_err())` failed). Fixed by admitting the
   first call in the setup; the test then does what its name says.
3. **The plan's literal count of test files to touch was short**: the mechanical
   `max_tool_calls` insert landed in 30 files, plus `tests/invariants/{i03,i09,i11}.rs` (Task
   5.1's corpus, which postdates the plan), plus `warrant/examples/emit_bounds_vectors.rs` — the
   compiler found all of them; every `WarrantBounds` literal now carries the field.
4. **The plan's Step 2 test snippet tripped `contains`' unrelated delegation-depth rule**
   (equal depth refused in the `zero within zero` case). The test now sets the child a depth
   below the parent's, keeping the assertion's intent.
5. **`instructions.rs` inventory gained `max-calls`** — the same class of catch as Task 1.2/1.3:
   the usage text names the flag, so the test that flags-vs-parser inventory must list it.
6. **The Step 9 command lines use `warrantor <subcommand> --root R`** (subcommand first), not the
   plan's `warrantor --root R <subcommand>`; this binary's parser dispatches on argv[1] first.
   Same correction as recorded in Task 0.4's evidence file.
7. **Task 0.4's README drift test demanded the generated table gains the new row** — both
   READMEs' marker blocks carry `budget_calls_mediated` now, inserted by this task in the same
   commits as the bound.

## Gates this task could not run, and why

- `python tools/ci/check_phase_scope.py` — not on this branch's base; run from the main checkout
  during Task 0.5 with exit 0. No plan tasks were added.
- US-English on `docs/W1-delivery-gaps.md`: the 16 pre-existing findings documented in the 0.5
  evidence file are unchanged; this task's paragraph is clean. `README.md` and
  `rust/warrant/README.md`: 0 findings.

---

# Rebase onto local `main` @ `2463504` (2026-09-06, review lane)

Everything above this line was measured on the pre-rebase tip `7b8d2bb`, which sat 115 commits
behind `main`. **Every number above is superseded by this section.** Nothing above was deleted,
because the record of what was measured when is part of the evidence; but no figure above describes
the tree that would merge.

**Rebased tip:** `9834302` · **rebase target:** local `main` @ `2463504` (never `origin/main`, which
is over a hundred commits behind) · **worktree:** `M:/wt-1.4` · **target dir:** `M:/wt-rv-1.4-target`

## History: nothing was dropped, reworded or re-authored

All ten original commits survive the rebase with their original author and their `Signed-off-by`
trailer. Verified mechanically rather than by eye: the ordered list of `author|subject` pairs taken
before the rebase is byte-identical to the list taken after.

| # | rebased hash | author | subject |
|---|---|---|---|
| 1 | `79135df` | GLM 5.3 Flash (zcode) | feat(spend): reserve a metered act before it happens, refusing with the budget untouched |
| 2 | `68d0273` | GLM 5.3 Flash (zcode) | feat(warrant): carry a tool-call ceiling in the signed bounds, absent meaning zero |
| 3 | `ca9373e` | GLM 5.3 Flash (zcode) | feat(warrant): declare budget_calls_mediated at the tier the proxy actually holds it |
| 4 | `487f95d` | GLM 5.3 Flash (zcode) | feat(warrant): count tool calls against the signed ceiling through the engine's reservation |
| 5 | `d71c73f` | GLM 5.3 Flash (zcode) | feat(proxy): refuse the call that would exceed the ceiling before it is forwarded or staged |
| 6 | `efa2c6a` | GLM 5.3 Flash (zcode) | feat(spend): persist the call count and receipt each refusal under the notary's budget gate |
| 7 | `f22b74d` | GLM 5.3 Flash (zcode) | feat(mcp): write the call ledger before a permitted call is forwarded or staged |
| 8 | `8868019` | GLM 5.3 Flash (zcode) | feat(cli): grant a tool-call ceiling and open its ledger before a supervised session starts |
| 9 | `577db49` | GLM 5.3 Flash (zcode) | docs(warrant): record the call ceiling as built from a live run, cents still observed |
| 10 | `b3f9809` | GLM 5.3 Flash (zcode) | docs(evidence): record task 1.4's gate, the live 101-call receipt, and the honest tier |
| 11 | `49eef44` | Claude Code (Opus 5) | fix(proxy): drop the egress import the rebase left doubled |
| 12 | `9834302` | Claude Code (Opus 5) | fix(tests): carry the call ceiling in the eight bounds literals main added |

The last two are the review lane's own, added rather than folded into anyone else's commit: each
repairs a break the rebase itself created, and amending a commit authored by another lane would
have destroyed the attribution this table exists to prove.

## The four conflicts, and how each was resolved

The rule applied throughout: **keep both behaviors.** Main's side was never discarded to make the
branch apply.

**1. `rust/warrant/src/proxy.rs` — four hunks, all additive.** Since this branch was cut, main
landed Task 5.4's egress work (the `pending` decision log, `resolved_names`, the secondary
`warrantor-egress-filter` engine, `deny_secondary`) and Task 2.1's catalog vocabulary
(`with_vocabulary`, `resolve_destinations`, `bounds()`). None of it collides with the call counter in
substance; git could not merge it only because the additions land in the same struct, the same
initializer and the same `impl` block. Resolved as a union in all four.

`Proxy::decide` itself merged without conflict, and the merged order is the one both sides need:

1. the observe-mode `NEVER_IN_OBSERVE` refusal (unchanged);
2. in observe mode, `reserve_call` — this branch's rule that the ceiling binds observe mode too;
3. the `tools` allowlist;
4. main's per-destination loop: the broker's verdict, the `PendingDecision` push, then the secondary
   engine;
5. **then** `reserve_call` — this branch's rule that a call the `tools` or egress bound refused was
   not a call and must not spend a slot;
6. staging, then forwarding.

**2. `rust/warrant/src/mcp_endpoints.rs` — two unions and one hand merge.** The hand merge is the
one that matters. This branch and main had both rewritten the same region of `AgentEndpoint::call`,
and a blind union would have produced two `let decision = self.proxy.decide(&call);` statements and
two `match decision {` arms.

Main's Task 2.1 replaced this branch's classification block wholesale: where the branch read
`self.classes.get(tool)` with `EffectRegistry::github()` and `--upstream-refuse-unclassified`, main
classifies through `self.decompositions.classify(tool, self.unclassified_policy)`, returning
`Classified::Declared`, `Classified::Guessed` or a refusal. Main's version was taken, because it is
the successor to the branch's code in the same place, not a competitor to it.

**The property the merge had to preserve, and does:** classification happens *before* `Proxy::decide`
is called, because it is what computes the `side_effect` field that `decide` reads. So a call refused
for exceeding the ceiling cannot bypass classification — the classifier has already run and already
recorded the tool in `unclassified` by the time the ceiling is consulted. This is visible in the live
run's stderr below, which names `selftest.echo` as guessed at *and* records the ceiling refusal.

The merged statement order inside `call` is: classify, build the `ToolCall`, main's
`resolve_destinations` refusal, `decide`, **this branch's ledger write**, main's egress-log flush,
then the `match`. The ledger write is placed before the egress flush deliberately, and the reason is
written into the code: if the flush fails the call is refused, and a ledger written first has already
spent the slot the in-memory counter spent. The reverse order would leave the persisted count one
behind the counter, so a restart would hand the agent a call the ceiling had already admitted. **A
ceiling may over-count a refused call; it may never under-count.**

**3. `rust/warrant/src/bin/warrantor.rs` — one union and one hand merge.** The union is the `mcp`
start-up block: main's catalog verification and this branch's `CallMeter::open` both attach to
`endpoint`, in that order. The hand merge is the `grant` USAGE line, where main had added
`[--egress-capability NAME,NAME]` to the same line this branch added `[--max-calls N]` to; the
combined line was wrapped rather than left over-long.

**4. `docs/W1-delivery-gaps.md` — a heading-number collision, which is why this one is called out.**
Every section main added was kept and this branch's section placed beside them. But main has since
shipped **both** `### 3.1b` (the stop verb) and `### 3.1c` (the metadata floor and the conformance
kit), and the plan's Step 9 instructs this task to write `### 3.1b`. Two sections numbered 3.1b in
one document is a defect, so **this branch's section is now `### 3.1d`**, sitting after 3.1b and
before 3.2. Its prose is unchanged. This is a deviation from the plan's letter forced by main, not a
change of claim.

## The exit gate, quoted verbatim from the plan on `main`

Re-quoted here rather than trusted from the pre-rebase section above, and checked against
`docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md` on `main` @ `2463504`:

> **Acceptance (restated against the code above):** `cargo test -p warrantor-warrant --test spend_refusal` passes on the Linux and Windows runners from Task 0.2 (the ceiling is pure proxy logic; nothing here is `cfg`-gated); the 101st call under `--max-calls 100` returns `refused by the warrant's budget_calls_mediated bound: this warrant's tool-call ceiling of 100 is reached …` with `forwarding_counts() == Some((100, 0))`; `<root>/spend/<id>.calls.json` carries a `WarReceipt` whose body is `Verdict::Deny { gate: Gate::Budget }` at `EnforcementMode::Mediated`, verifiable with `warrantor_notary::verify_receipt` and pinned to the store's issuer key on load; `bound_strengths()` lists `budget_cents_observed → Observed` and `budget_calls_mediated → Mediated`, and the report, `serve` status JSON and every sandbox profile carry both because all three read `bound_strengths()`. Not claimed: cents are not refused anywhere, and calls that bypass the proxy are not counted — both sentences are in `CALLS_NOTE` and in the gaps entry.

## Does the branch perform THAT run? **RUN**, on this tip

Not carried over from the pre-rebase run. The 101-call live run was **performed again on `9834302`**,
in a fresh scratch store, because main's Task 2.1 rewrote the classification step that decides what
reaches `Proxy::decide` and Task 5.4 rewrote the egress step before the ceiling check — the two code
paths this gate walks through. A number measured before those landed does not describe this tip.

**Transcript:** the driver is the review lane's `live_run.sh`; its artifacts are on disk at
`M:/wt-rv-1.4-live` — `out.jsonl` (101 response lines), `err.log` (the session's own stderr),
`spend/wrt_ed612b927e8f1514.calls.json` (the ledger and its receipt),
`refusals/wrt_ed612b927e8f1514.jsonl` (the durable refusal record), and `serve.log`.

Scratch store `M:/wt-rv-1.4-live`, warrant `wrt_ed612b927e8f1514`, `--max-calls 100`:

```
$ warrantor grant --root $R --goal "echo until refused" --tools selftest.echo \
    --write "src/**" --max-calls 100
warrant  wrt_ed612b927e8f1514

$ python -c "...101 tools/call lines..." | warrantor mcp --agent wrt_ed612b927e8f1514 --root $R \
    --upstream "selftest=M:/wt-rv-1.4-target/debug/warrantor.exe selftest-upstream" > $R/out.jsonl
101 response lines; exactly 1 carries "isError":true; exactly 1 names budget_calls_mediated
line 101: {"id":100,...,"text":"refused by the warrant's budget_calls_mediated bound: this
          warrant's tool-call ceiling of 100 is reached. Nothing further is forwarded or staged
          under it; ask for a new warrant.","type":"text"}],"isError":true}}

$ cat $R/err.log
warrantor: recorded 1 refusal group(s) for wrt_ed612b927e8f1514. ...
warrantor: upstream -- 1 tool(s) had no declared effect decomposition: selftest.echo. Under
           --upstream-strict they were refused; otherwise each was given a GUESSED decomposition
           (read) -- and then forwarded ...
warrantor: upstream -- 100 call(s) forwarded, 0 undeliverable, to selftest (2 tools).
warrantor: denied selftest.echo x1 (budget_calls_mediated)
```

That third stderr line is main's Task 2.1 wording, and its presence beside the refusal is the
merge's own proof: **classification ran on the refused call's tool, and the ceiling refusal did not
route around it.**

```
$ cat $R/spend/wrt_ed612b927e8f1514.calls.json
  format          warrantor.call-ledger/1
  counter         max_tool_calls 100, tool_calls_used 100
  refused         1
  receipt.body    verdict {outcome: deny, gate: budget}
                  operation_class tool_call, enforcement_mode mediated
                  notary_version warrantor-notary/1.0
  receipt.sig     Ed25519, key_id issuer,
                  public_key 466d5c4a30b66af71c4a9f36fe52a0e814ad8688bbef9216da5dd498d2d9beee

$ warrantor spend wrt_ed612b927e8f1514 --root $R
── BUDGET (OBSERVED, SELF-REPORTED) ──
  ceiling                 none declared, so none granted
  observed spend          $0.000000 (0 record(s), agent-reported)
  call ceiling            100 (100 used, 1 refused, budget_calls_mediated)
The call ceiling counts tool calls that pass through the Warrantor MCP proxy and refuses the one
that would exceed it before it is forwarded or staged. A call that does not pass through the proxy
is not counted. The bound is mediated, not enforced, and it meters calls, not cents.

$ cat $R/refusals/wrt_ed612b927e8f1514.jsonl
{"format":"warrantor.refusal-record/1","warrant_id":"wrt_ed612b927e8f1514","at":1788727103,
 "kind":"tool","tool":"selftest.echo","bound":"budget_calls_mediated","destination":null,
 "argument":null,"reason":null,"count":1}

$ warrantor serve --root $R --port 8791 ... ; curl .../v1/summary/refusals
"groups":[{"bounds":["budget_calls_mediated"],"kind":"tool","occurrences":1,"signal":"isolated",
           "subject":"selftest.echo","warrant_ids":["wrt_ed612b927e8f1514"],"warrants":1}]
```

Every clause of the plan's Step 9 hand-assert list reproduces: line 101 carries `"isError":true` and
`budget_calls_mediated`; the ledger carries `"refused": 1` and `verdict {deny, budget}`; `spend`
prints the ceiling line as specified; and `/v1/summary/refusals` lists exactly one `tool` refusal
under the new bound. The acceptance clause about `forwarding_counts() == Some((100, 0))` is asserted
in-process by
`spend_refusal.rs::the_hundred_and_first_call_is_refused_before_the_upstream_sees_it_and_stays_refused`,
which passed on this tip, and the live run's own equivalent is the stderr line reading
`100 call(s) forwarded, 0 undeliverable`.

**Superseded:** the pre-rebase run's store `M:/wt-1.4-live` and warrant `wrt_063a41489e006aab` are a
real run on a real tip and their artifacts still exist, but that tip is not this one. Read the run
above, not that one.

## Every gate number, measured on `9834302`

Each cargo exit code was captured before any pipe, and each suite count was read from the
`test result:` lines rather than inferred from an exit code.

```
$ python tools/ci/disk_guard.py --require 80          OK   (both guards run before every cargo command)
$ python tools/ci/disk_guard.py --require-commit 5    OK
$ cargo fmt --all -- --check                          exit 0
$ cargo clippy --workspace --all-targets -- -D warnings
                                                      exit 0   (no error and no warning line)
$ cargo test --workspace --all-targets                exit 0
                                                      122 suites; 1596 passed, 0 failed, 20 ignored
$ cargo test --workspace --doc                        exit 0
                                                      40 suites; 1 passed, 0 failed, 0 ignored
$ cargo test -p warrantor-warrant --test spend_refusal
                                                      12 passed, 0 failed  (the acceptance suite)
$ cd rust && python ../tools/ci/wiring_census.py      exit 0
wiring census: 13 of 41 crates reachable from warrantor-warrant over 23 path edges
$ python ../tools/ci/wiring_census.py --write         exit 0, and rewrote nothing: the tree was
                                                      already byte-identical to what the tool emits
$ python tools/ci/check_invariant_ratchet.py --show-findings
invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)
$ python tools/ci/check_invariants.py                 exit 0
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
$ python tools/ci/check_docs.py                       exit 0
RESULT: PASS - 302 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
$ python tools/ci/check_us_english.py main            exit 0
us-english: 1182 added line(s) across 53 file(s), since main; us-english: ok
```

**The ratchet was not chosen, it was read.** `main` records `passing_floor 85` and
`ignored_ceiling 15`; the merged corpus's own `test result:` line reads `85 passed; 0 failed; 15
ignored`, so the pair is written unchanged. This branch converts no `#[ignore]` and adds no invariant
test — its only edits under `tests/invariants/` add the required `max_tool_calls` field to bounds
literals — so a floor that moved here would have been a number nobody earned. The second
`test result: FAILED` line in that tool's output is its recorded-findings run, which fails by design.

**The orphan count did not rise.** 13 of 41 reachable over 23 edges, identical to `main`. This task
adds no crate.

**Superseded:** the pre-rebase section above records `102 suites`. That was the count on
`origin/main`'s corpus 115 commits ago. The count on this tip is 122 suites and 1596 tests.

## The two failures the rebase caused, and what each was

Both were real breaks in this branch against today's `main`, not flakes, and each is fixed in its own
commit.

1. **`E0252`, twice, in `proxy.rs`** — the crate did not compile at all. The union resolution of the
   import hunk kept this branch's narrow `use crate::egress::{EgressBroker, EgressRefusal};` beside
   main's wider `use crate::egress::{capability_for, EgressBroker, EgressDecision, EgressRefusal,
   EgressVerdict, DESTINATION_KEYS};`. Fixed in `49eef44` by dropping the narrow line, everything in
   which the wider one already names.
2. **`E0063` in eight `WarrantBounds` literals main added while this branch was parked** — the
   adversary-custody drill, the effects endpoint, the egress-broker and network-independence wiring
   tests, the evidence-chain and revocation tests, the stop drill and the invariant-corpus fixtures.
   `max_tool_calls` is a required field on this branch and absent reads as **zero, not unlimited**, so
   there is no defaulting that would have been honest. Fixed in `9834302` with `Some(100)`, matching
   the thirty-odd literals the branch had already updated. The whole tree was swept for this rather
   than fixing only the file the compiler stopped at.

**One flake, named rather than hidden.** The first full workspace run exited 101 on
`rust/warrant/tests/conformance_receipt.rs::a_drill_on_this_kernel_produces_a_receipt_that_verifies_offline`,
with `root_gone: false, descendant_gone: false` and both elapsed times at `u64::MAX` — the drill's
existence poll never saw the processes go. That file, `src/conformance.rs`, `src/stop.rs` and the
kill-switch crates are **untouched by this branch**: `git diff --name-only main..HEAD` lists none of
them. Re-run alone the suite passes 3 of 3, and §3.1b of the gaps document already records that each
existence check on this kernel is a `tasklist` spawn measured at about 2.2 s against a 5000 ms
budget. Four build lanes were competing for this box at the time, and the commit-charge guard refused
five times in a row during the same window. The clean 122-suite run above is the one that counts, and
the flake is recorded here so nobody later reads a green summary beside a red log and has to guess
which was true.

## The honest tier of every bound this task introduces

| bound | tier | what escapes it |
|---|---|---|
| `budget_calls_mediated` (new) | **Mediated** | Every call that does not traverse the Warrantor MCP proxy. An agent with shell access, a harness built-in, or a tool it invokes directly reaches the same effect without being counted, and nothing outside this process refuses it: there is no netns, no seccomp and no firewall behind the ceiling. The proxy is a chokepoint the agent could decline to use. A refusal inside this product's own code is Mediated, never Enforced. |
| `budget_cents_observed` (untouched) | **Observed** | Everything. Model API traffic never passes through Warrantor, so the figure is whatever the agent reported about itself; an agent that under-reports or never reports spends unwatched. Nothing refuses a spend at the moment it happens. This task did not move this bound and does not claim to. |

The tier word is in the bound's own name, and that is deliberate: the spine stub called this
`budget_calls_enforced`, and a bound named `_enforced` at the Mediated tier would collapse two of the
three tiers in the first place a reader looks. `bound_strengths()` in `rust/warrant/src/lib.rs`
carries both rows with the escape written into the comment beside each, and the report golden in
`rust/warrant/tests/report.rs` pins the rendered pair so the two cannot drift apart.

**The disclosure distinguishes the two everywhere it is rendered**, which was checked surface by
surface rather than assumed: `README.md` and `rust/warrant/README.md` (generated tier tables, cents
`observed` and calls `mediated` on separate rows, with the mediated legend naming the escape); the
CLI `grant` and `spend` usage text; the `warrantor spend` bare view, where `CALLS_NOTE` says in as
many words that the bound "meters calls, not cents"; every sandbox profile, which reports the new
bound as a `Divergence::Gap` because a sandbox cannot tell one tool call from another; and gaps
§3.1d, which carries L3-03's residual verbatim.

## What this task does NOT establish

- **It does not make spend enforced.** The plan's own label-promotion clause is satisfied only for
  the tool-call grain. Cents are refused nowhere.
- **It does not count calls that bypass the proxy.** This is the whole content of the Mediated label,
  and it is stated in `CALLS_NOTE`, in `bound_strengths()`, in both README tables and in gaps §3.1d.
- **It does not bound the effect, only the call.** A hundred admitted calls may each do more damage
  than a thousand; the ceiling counts events, not consequences.
- **A ceiling-refused call still leaves an allow entry in the egress decision log.** This is a
  consequence of the merge order and it is disclosed rather than changed. The ceiling is checked
  *after* main's per-destination broker loop, so for a call that names a destination the broker has
  already decided — and logged — an allow by the time the ceiling refuses. The alternative order,
  ceiling first, would make an egress-refused call spend a ceiling slot, which breaks the stronger
  property that a refused call was not a call. The lesser artifact was kept in preference to the
  greater one. No surface counts egress-log entries as calls made, and `selftest.echo` names no
  destination, so the live run above exercises none of this.
- **The Linux half of the acceptance clause is not run here.** The gate asks for the Linux and
  Windows runners from Task 0.2. This lane measured Windows. The ceiling is pure proxy logic with no
  `cfg` gate, which is the reason to expect Linux to agree, but expecting is not measuring: CI's
  ubuntu runner is what closes that half.
- **`--upstream-refuse-unclassified` is gone from this branch's story.** Deviation 5 above describes
  a flag main has since replaced with `--upstream-strict` and `--upstream-effects`. The branch no
  longer ships the flag that deviation names; main's classification path superseded it in the merge.
- **The ledger is local and unchained.** `<root>/spend/<id>.calls.json` is a single signed document
  on the same disk and under the same UID as the agent. Deleting it is detected as unknown spend on
  the next load — fail-closed, which is right — but there is no external witness that a count ever
  existed, and the refusal record `serve` reads is explicitly unsigned and unchained, as its own
  `note` field says.

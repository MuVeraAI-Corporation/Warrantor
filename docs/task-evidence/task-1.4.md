# Task 1.4 — Spend into the budget path, last (L3-03; label promotion only where refused)

**Branch:** `feat/spend-call-ceiling` (from `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-1.4` (target dir `M:/wt-1.4-target`)
**Date:** 2026-09-05
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

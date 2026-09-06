### Task 8.2: The risk dial and the end-of-budget risk profile (L3-02, L3-07)

**Anchor.** L3-02 "The risk dial: graduated control tightening" — `<article class="item" id="L3-02"
data-stratum="L3" data-plane="B" data-status="none" data-novelty="novel" data-wave="W2"
data-loop="L5">`, so **`status=none`**, `novel`, W2. Its verification sentence is the one that
governs this task: *"Raise a warrant's budget by 10x and assert that at least one named control
tightens; if nothing changes, the dial is decorative."* L3-07 "End-of-budget risk profile" —
`data-status="none" data-novelty="novel" data-wave="W3"`, so **`status=none`**, `novel`, W3, whose
verification sentence is *"In a test population, instances below a declared remaining-budget
threshold have their egress set, delegation depth and effect classes narrowed automatically,
receipted with the trigger."* Neither is `partial`; nothing of either exists.

The blueprint disagrees with itself on the wave for both items and the disagreement is recorded here
rather than resolved: L3-02's `data-wave` attribute says `W2` while its own cross-reference prose
ends "W-link: W1, W4 ... `W1.`", and L3-07's attribute says `W3` while its prose ends "`W2.`" The
attribute is the machine-readable field the scope document counted from, so the attribute is what
this task cites.

**The failure mode this task exists to prevent, restated against the code.** A dial that only
observes is a dashboard. This repository already has the tooling to build a very convincing
dashboard: `warrantor-spend` is linked and reachable, a durable ledger accumulates across
processes, `SpendLedger::remaining_micros` exists, and `warrantor status` already prints
`remaining` (`rust/warrant/src/bin/warrantor.rs:1637`). What does not exist is any line of code
anywhere that *refuses differently* because a budget is nearly gone. The only budget-driven refusal
in the product is a start-time precondition at `rust/warrant/src/bin/warrantor.rs:3085`, gated on
`ledger.exhausted()`, which is binary and fires at 100%. Between 0% and 100% the system's posture is
constant, and at 100% during an open run it is still constant — the gate has already been passed.
So the seed's premise holds exactly: **nothing in the system changes posture as budget depletes.**

The second failure mode is the one the seed names and the code makes concrete: *loosening is
silent*. A dial whose tighten is automatic and whose loosen is a config edit is a control with a
bypass. The bypass is closed here by making a loosening move require the **settle authority** —
`Warrant::verify_settle` at `rust/warrant/src/lib.rs:568`, whose signed-claims key the agent
provably never holds — and by refusing the move outright when no such signature is presented.

**Step 0.** Run these exactly, in a scratch worktree at `refs/remotes/origin/main`, and read each
file in full at the stated length before writing anything.

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git worktree add --detach M:/wt-x-8.2 refs/remotes/origin/main
cd M:/wt-x-8.2 && export CARGO_TARGET_DIR=M:/wt-x-8.2-target
wc -l rust/warrant/src/lib.rs rust/spend/src/lib.rs \
      rust/warrant/src/supervise.rs rust/warrant/src/proxy.rs rust/warrant/src/spend.rs
```

Captured output, 2026-09-05, at `e4b5f105cdacf097e742ee8bbec704c28bafc726`:

```
  724 rust/warrant/src/lib.rs
  723 rust/spend/src/lib.rs
  580 rust/warrant/src/supervise.rs
  311 rust/warrant/src/proxy.rs
  921 rust/warrant/src/spend.rs
 3259 total
```

The seed's "`rust/spend/src/lib.rs` (723 lines)" is exact. Read all five. `rust/warrant/src/spend.rs`
is not in the seed's read list and is the single most important file for this task: it is the module
that wires `warrantor-spend` into the warrant and it documents, in its own header, why the engine's
top-level gate is bypassed.

**Every `WarrantBounds` field that bounds spend, count or time**, read from
`rust/warrant/src/lib.rs:248-271` and paired with its declared tier from `bound_strengths()` at
`rust/warrant/src/lib.rs:668-686`:

| Field | Line | Quantity | Tier at line | Reachable refusal today |
|---|---|---|---|---|
| `expires_at: u64` | 258 | wall-clock time | `Enforced` (680) | OS process link, `supervise.rs` |
| `budget_cents_observed: Option<u64>` | 268 | money (cents) | `Observed` (684) | start-gate only, `bin/warrantor.rs:3085` |
| `delegation_depth: u32` | 270 | hop count | `Enforced` (682) | `contains()` at issue, `lib.rs:343` |

That is the whole list. `tools` (250), `write_paths` (252), `egress_hosts` (254) and
`staged_classes` (256) are membership sets, not quantity ceilings. **There is no action-count bound,
no token bound, no tool-call bound and no parallelism bound in `WarrantBounds` on `origin/main`** —
Task 1.4 adds the tool-call ceiling and Task 8.3 adds the fan-out one, and this task must not
invent either.

Is `warrantor-spend` reachable? Yes, and the seed is right to make it the pivot:

```bash
python tools/ci/wiring_census.py
python - <<'PY'
import sys; sys.path.insert(0, 'tools/ci')
from pathlib import Path
import wiring_census as w
r = w.reachable_crates(Path('rust'))
print(f"{len(r)} reachable"); [print('  ', c) for c in sorted(r)]
print('warrantor-spend reachable?', 'warrantor-spend' in r)
PY
```

```
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
9 reachable
   warrantor-api
   warrantor-authority-spec
   warrantor-containment-conformance
   warrantor-egress
   warrantor-evidence
   warrantor-notary
   warrantor-spend
   warrantor-trust-core
   warrantor-warrant
warrantor-spend reachable? True
```

`evidence/wiring-coverage.json` records `{"total": 39, "reachable": 9, "edges": 17}` and a
30-entry `orphaned` array that does **not** contain `warrantor-spend`. The dependency edge is
`rust/warrant/Cargo.toml:56`: `warrantor-spend = { path = "../spend", version = "1.0.0" }`. So this
task builds on wired code, not on an orphan, and no crate needs a carry-in sequence.

**Where the seed is wrong, and it matters.** The seed's Bound strength says: *"State which effect
classes the dial actually reaches, using the wiring census as the source."* The wiring census cannot
answer that question. Its own `--help` states its subject verbatim: *"Count the workspace crates the
`warrantor` binary can reach"*, and its only output is the one line above. It counts **crates over
manifest edges**, not effect classes over call paths, and an implementer sent to
`tools/ci/wiring_census.py` for a class list finds nothing there to read. The three files that do
answer it are `rust/authority-spec/src/lib.rs:42-53` (the five classes), `rust/warrant/src/proxy.rs`
(which of them the proxy decides), and `rust/warrant/src/mcp_endpoints.rs:1030-1061` (how a class is
assigned to an upstream tool, including the `Read` fallback guess at line 1054). Step 6 uses those
three, and the census keeps its actual job: holding the orphan count.

**What happens at zero.** `rust/warrant/src/spend.rs:285-287`:

```rust
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.cap_declared && self.spent_micros >= self.cap_micros
    }
```

And its one consumer, `rust/warrant/src/bin/warrantor.rs:3085-3093`, which is the entire budget
enforcement surface of the product:

```rust
        Ok(ledger) if ledger.exhausted() => {
            return fail(&format!(
                "{id} has reported spending {} of its {} ceiling. Grant a new warrant with a new \
                 budget rather than restarting a spent one. (Self-reported: an agent that does not \
                 report is not caught by this.)",
                spend::usd(ledger.spent_micros),
                spend::usd(ledger.cap_micros)
            ));
        }
```

Note `cap_declared &&`: an undeclared cap is never exhausted, deliberately, and
`rust/warrant/src/spend.rs:281-283` explains why. The dial must inherit that reading exactly, or the
same `None` will mean *zero* to the ledger and *maximum pressure* to the dial.

**Are Task 3.5 and this one mechanism?** No, and the seed's Step 2 asks the right question. Task
3.5 is `warrantor.response-policy/1`: a **trigger to verb** map (`halt | quarantine | revoke |
freeze`) that fires **once**, on an incident signal, with a false-denial counter, against the `stop`
verb surface Task 1.3 builds. This task is a **standing posture** that modulates a refusal
predicate continuously in both directions, with no incident, on a quantity that is monotone by
construction. They share the shape "observed state changes what the boundary does", and the right
response to that overlap is reuse of the receipt, not a second mechanism: Step 9 requires the
transition receipt to carry the same `direction`/`reason`/`authority` triple 3.5's verb receipt
carries, so a reviewer reads one vocabulary. Do not build a trigger evaluator here; do not build a
posture here in 3.5.

**Non-goals.** Each names the task that owns the excluded thing.

1. **Not the horizon governor.** Time and step bounds — `expires_at`, wall-clock horizon, step
   ceilings, `supervise.rs`'s `wait_until` at line 191 and the platform linkage table at lines
   16-20 — are **Task 8.1** (L3-04, W1, `partial`, being expanded in parallel). This task reads no
   clock and adds no time-derived dial position. The `DialTrigger` enum in Step 3 leaves a named,
   unimplemented seam for 8.1's `HorizonDepletion` variant and asserts nothing about it.
2. **Not the population budget ledger.** A budget summed across a population of agents, and the
   transfer control point that makes per-agent caps meaningful, are **Task 8.4** (L3-11, L3-08).
   This dial reads exactly one `SpendLedger`, keyed by one `warrant_id`, and must not aggregate.
3. **Not wiring spend into the budget path.** The tool-call ceiling refused inside `Proxy::decide`,
   named `budget_calls_mediated`, is **Task 1.4** (L3-03, routed `glm`, ready, **not landed**). This
   task adds a *different* refusal at the *same* site and must be written to compose with 1.4 rather
   than to duplicate it — see Consumes.
4. **Not incident response.** Trigger-to-verb, false-denial budgets, `halt`/`quarantine`/`revoke`/
   `freeze` — **Task 3.5**.
5. **Not the executive exposure view.** Rendering the dial's history to an operator surface is
   **Task 11.10**; the autonomy-expansion ledger is **Task 11.11**. This task produces the data and
   the position vocabulary; it renders exactly two things, a CLI line and a table in its own
   evidence file.
6. **Not parallelism or duplicate-effect control.** Fan-out and rate are **Task 8.3** (L3-05,
   L3-10).

**Files.**

- `rust/warrant/src/dial.rs` — **new module**, the whole of the dial.
- `rust/warrant/src/lib.rs` — `pub mod dial;` beside line 43, and one row added to
  `bound_strengths()` at lines 668-686.
- `rust/warrant/src/proxy.rs` — one field on `Proxy` (lines 101-113), one setter, one refusal block
  in `decide` (between lines 198 and 200).
- `rust/warrant/src/mcp_endpoints.rs` — `agent_endpoint_for` (lines 1187-1212) sets the dial from
  the ledger at session start.
- `rust/warrant/src/bin/warrantor.rs` — `status` prints the dial position beside `remaining`
  (line 1637); a `warrantor dial` subcommand performs a receipted move.
- `rust/warrant/tests/risk_dial.rs` — **new**, the task's own suite.
- `rust/warrant/tests/invariants/i09_failure_is_safe.rs` — two new passing tests.
- `tools/ci/invariant-ratchet.json` — `passing_floor` raised in the same commit.
- `README.md` and `rust/warrant/README.md` — regenerated bound-tiers table.
- `docs/task-evidence/task-8.2.md` — evidence, including the gated thresholds table.

**Not touched: `rust/spend/src/lib.rs`.** The seed lists it and marks it **contended**. Dropping it
resolves the contention rather than negotiating it: everything this task needs from the engine
already exists and is already re-exported through `rust/warrant/src/spend.rs:98-101`, and Task 1.4
is modifying that file's `TaskBudget` at lines 77-110. Two tasks editing one 723-line file for no
reason is how a rebase eats a refusal.

**Consumes / Produces.**

Consumes, all present on `origin/main`:

```rust
// rust/warrant/src/spend.rs:275-277
pub fn remaining_micros(&self) -> u64
// rust/warrant/src/spend.rs:285-287
pub fn exhausted(&self) -> bool
// rust/warrant/src/spend.rs:240-256  (fields cap_micros, cap_declared, spent_micros, entries)
pub struct SpendLedger
// rust/warrant/src/spend.rs:759  — loads and signature-checks a stored ledger
pub fn load(&self, bounds: &WarrantBounds, warrant_id: &str, subject: &str,
            issuer: &VerifyingKey) -> Result<SpendLedger, SpendError>
// rust/warrant/src/lib.rs:568  — the authority a loosening move must present
pub fn verify_settle(&self, presented: &VerifyingKey) -> Result<(), WarrantError>
// rust/authority-spec/src/lib.rs:58-63  — the consequential-class predicate, reused not re-listed
pub const fn is_consequential(self) -> bool
// rust/warrant/src/proxy.rs:151-163  — the existing denial recorder
fn deny(&mut self, tool: &str, bound: &'static str, reason: String) -> Decision
```

Consumes, **does not exist yet**: nothing. That is deliberate and it is why this task can start
before 8.1 and 8.4. The one adjacency that must be planned for is **Task 1.4**, which is *ready and
not landed*: it inserts a tool-call ceiling refusal into the same `Proxy::decide` body and adds
`budget_calls_mediated` to `bound_strengths()`. Step 4 therefore places the dial's block at a
distinct, stated line boundary (immediately after the `NEVER_IN_OBSERVE` block that ends at
`proxy.rs:198`, before the observe early-return at line 200) so the two insertions are textually
disjoint, and Step 11 requires a rebase-verify against `main` before merge per the program's
one-at-a-time merge rule.

Produces:

```rust
// rust/warrant/src/dial.rs
pub enum DialPosition { Normal, Constrained, Terminal }
impl DialPosition {
    pub fn word(self) -> &'static str;
    pub fn caveat(self) -> &'static str;
    pub fn refuses(self, class: SideEffectClass) -> bool;
}
pub enum DialTrigger { SpendDepletion { spent_micros: u64, cap_micros: u64 },
                       OperatorSet { key_id: String } }
pub enum Direction { Tighten, Loosen }
pub struct DialThresholds { pub constrained_at_permille: u16, pub terminal_at_permille: u16 }
pub struct DialTransition { pub from: DialPosition, pub to: DialPosition,
                            pub direction: Direction, pub trigger: DialTrigger,
                            pub reason: String, pub authority_key: Option<String>, pub at: u64 }
pub struct RiskDial { /* position, thresholds, history */ }
pub fn position_for(ledger: &SpendLedger, t: &DialThresholds) -> DialPosition;
pub fn render_thresholds_table() -> String;
```

**Bound strength.**

**The refusal is Tier B (`BoundStrength::Mediated`). The trigger is Tier C (`Observed`). Those are
two different claims and the product must print both.** This is the single most important sentence
in the task and it is not in the seed.

The refusal is Tier B because it lives in `Proxy::decide`, which
`rust/warrant/src/lib.rs:652-653` names as *"the one place a bound is actually refused at the moment
of action"*, and because `BoundStrength::Mediated`'s own caveat at `rust/warrant/src/lib.rs:235-238`
already states what escapes: *"held only for calls that traverse the MCP proxy; a shell or a harness
built-in reaches past it, and no netns, seccomp or firewall stands behind it"*. Concretely, what
escapes the dial: any `Bash`/shell tool the agent invokes, any harness built-in that does not speak
MCP, the agent's own model-provider HTTP calls, a raw socket, a subprocess it spawns, and anything
at all after the supervisor's process tree is escaped. **No netns, seccomp or firewall enforcement
exists anywhere in this repository**, so the dial composes with an external sandbox and does not
replace one.

The trigger is Tier C because `budget_cents_observed` is `Observed` at
`rust/warrant/src/lib.rs:684` and stays so — `rust/warrant/src/spend.rs:17-21` states why: *"The
agent talks to its model provider directly. Not one byte of that conversation passes through
Warrantor"*, and every figure the ledger holds is stamped `AGENT_REPORTED`
(`rust/warrant/src/spend.rs:116`). **An agent that under-reports its spend keeps the dial at
`Normal` and is never tightened.** That is not a defect to be hidden in a footnote; it is the
property, and Step 7 makes the product say it at the point of use.

The sentence that will appear in the product, added to `bound_strengths()` as the row's caveat and
therefore rendered verbatim into both READMEs by `render_bounds_table()`:

> `risk_dial_mediated` — **mediated.** The dial changes what the MCP proxy refuses, so a shell, a
> harness built-in or a direct provider call reaches past it, and no netns, seccomp or firewall
> stands behind it. Worse: the position is computed from agent-reported spend, so an agent that
> under-reports stays at `Normal` and is never tightened. A tightened dial narrows what a
> cooperating agent can do; it is not a containment boundary and does not become one.

The bound is named `risk_dial_mediated`, with the tier in the name, following the existing
convention that `budget_cents_observed` establishes and that Task 1.4 restates. A field named
`risk_dial_enforced` at the `Mediated` tier would collapse two of three tiers in the one place a
reader looks first.

**Orphan count.** Unchanged: 9 of 39 reachable over 17 path edges, 30 orphaned. `dial.rs` is a
module inside the already-reachable `warrantor-warrant`, not a crate. No crate is added, none is
carried in, and no orphan is created. `python tools/ci/wiring_census.py` must print the identical
line after this task as before it, and Step 11 asserts that.

**Invariant corpus.** **No existing `#[ignore]` is convertible by this task, and none is weakened.**
The 19 recorded findings were read; the two nearest are quoted here so a later reviewer does not
have to guess whether they were considered:

- `rust/warrant/tests/invariants/i09_failure_is_safe.rs:196` —
  `#[ignore = "I-09 orphaned: eval-guard's fail-closed preflight is not linked by the warrantor binary (2026-09-02)"]`.
  Owned by the orphan census, Task 0.3; fixing it means linking `warrantor-eval-guard`, which this
  task does not do.
- `rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs:167` —
  `#[ignore = "I-12 partial: the kill path is advisory, so it holds only against an agent using its tools (Task 1.3, 2026-09-02)"]`.
  Owned by Task 1.3.

What this task *does* owe the ratchet: it adds two **passing** tests to
`i09_failure_is_safe.rs`, and `tools/ci/check_invariant_ratchet.py` fails an improvement as loudly
as a regression (*"An improvement fails too, with a message saying to raise the baseline"*). So
`tools/ci/invariant-ratchet.json` must move `"passing_floor": 65` to `67` in the **same commit**,
with `"ignored_ceiling": 19` untouched.

**Exit gate.** `cargo test -p warrantor-warrant --test risk_dial --test invariants --test
tier_disclosure --test proxy && python tools/ci/check_invariant_ratchet.py && python
tools/ci/wiring_census.py` — pass requires `risk_dial` green with both a refusal and its allowed
control in every pair, `invariant ratchet: ok (67 passing at floor 67, 19 recorded findings at
ceiling 19)`, and `wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path
edges` unchanged.

---

- [ ] **Step 1 — Worktree and baseline capture.** Branch off `origin/main` and record the numbers
      the exit gate will be compared against, so a later "it was already like that" is checkable.

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git worktree add M:/wt-8.2 -b feat/risk-dial origin/main
cd M:/wt-8.2 && export CARGO_TARGET_DIR=M:/wt-8.2-target
python tools/ci/wiring_census.py            | tee -a docs/task-evidence/task-8.2.md
python tools/ci/check_invariant_ratchet.py  | tail -1
cargo test -p warrantor-warrant --test proxy --test spend --test tier_disclosure 2>&1 \
  | grep '^test result'
```

Expected, verified on `e4b5f10`: `wiring census: 9 of 39 crates reachable from warrantor-warrant
over 17 path edges`; `invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling
19)`; and `16 passed`, `37 passed`, `9 passed` for `proxy`, `spend`, `tier_disclosure`
respectively. Test intent: a baseline that a regression can be measured against, not a smoke test.

- [ ] **Step 2 — Failing test: a depleting budget changes a refusal, with an allowed control at low
      depletion.** Write this first and watch it fail to compile. It is the whole task; every other
      step exists to make it pass. Note that it is a *pair*: the same agent, the same call, two
      ledger states, opposite decisions.

```rust
// rust/warrant/tests/risk_dial.rs
use std::collections::{BTreeMap, BTreeSet};
use warrantor_warrant::dial::{DialPosition, DialThresholds, RiskDial};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::spend::SpendLedger;
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::{SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn bounds() -> WarrantBounds {
    WarrantBounds {
        tools: ["git", "github.create_pr", "stripe.refund"]
            .into_iter().map(str::to_string).collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3_600,
        budget_cents_observed: Some(1_000), // $10.00
        delegation_depth: 2,
    }
}

fn call(tool: &str, class: SideEffectClass) -> ToolCall {
    ToolCall { tool: tool.to_string(), arguments: BTreeMap::new(), side_effect: class }
}

/// A ledger reporting `spent` cents against the $10 cap in `bounds()`.
fn ledger_at(spent_cents: u64) -> SpendLedger {
    let mut l = SpendLedger::new(&bounds(), "wrt_dial", "spiffe://muveraai.com/agent/a");
    l.spent_micros = spent_cents * warrantor_warrant::spend::MICROS_PER_CENT;
    l
}

fn proxy_at(spent_cents: u64) -> Proxy {
    let mut p = Proxy::new(bounds(), ProxyMode::Enforce, EffectRegistry::github());
    p.set_dial(RiskDial::from_ledger(&ledger_at(spent_cents), &DialThresholds::default()));
    p
}

#[test]
fn a_nearly_spent_budget_refuses_a_financial_call_that_a_fresh_budget_allows() {
    // CONTROL: 5% spent. The dial is Normal; the warrant's own bounds decide, and a listed
    // financial tool is forwarded exactly as it is on origin/main today.
    let mut fresh = proxy_at(50);
    assert_eq!(fresh.dial_position(), DialPosition::Normal);
    assert_eq!(
        fresh.decide(&call("stripe.refund", SideEffectClass::Financial)),
        Decision::Forward,
        "at 5% depletion nothing extra may be refused: a dial that tightens from the start is a \
         narrower warrant wearing a dial's name",
    );

    // REFUSAL: 95% spent, same warrant, same call.
    let mut spent = proxy_at(950);
    assert_eq!(spent.dial_position(), DialPosition::Constrained);
    match spent.decide(&call("stripe.refund", SideEffectClass::Financial)) {
        Decision::Deny { bound, reason } => {
            assert_eq!(bound, "risk_dial", "the refusal must name the bound that refused");
            assert!(reason.contains("95.0%"), "the reason must state the measured depletion: {reason}");
            assert!(
                reason.contains("agent-reported"),
                "the reason must state the provenance of the number it acted on: {reason}",
            );
        }
        other => panic!("a Constrained dial must refuse a Financial call, got {other:?}"),
    }
}
```

Test intent: this is L3-07's verification sentence made executable, and it is the pair rule
satisfied in one function — the allowed control is not a separate optimistic test that could pass
while the refusal is vacuous.

- [ ] **Step 3 — Failing test: the position vocabulary is total, ordered, and says what it does not
      cover.** Three positions, not two. `Normal`/`Terminal` alone would make the dial a second
      `exhausted()`; the middle position is where L3-02's graduated tightening lives. The
      `caveat()` requirement mirrors `BoundStrength::caveat` at `rust/warrant/src/lib.rs:229-243`,
      which exists because a one-word mark is read as the strongest thing it could mean.

```rust
#[test]
fn every_position_states_a_word_and_what_it_does_not_cover() {
    use DialPosition::*;
    for p in [Normal, Constrained, Terminal] {
        assert!(!p.word().is_empty());
        assert!(
            p.caveat().contains("proxy"),
            "{}: every position's caveat must name the chokepoint, because a tightened dial over \
             an unmediated path bounds nothing",
            p.word(),
        );
    }
    assert_eq!([Normal.word(), Constrained.word(), Terminal.word()],
               ["normal", "constrained", "terminal"]);

    // Monotone in severity, and pinned: Read survives everywhere or the agent cannot even report
    // its own spend, which would make the dial self-defeating at Terminal.
    for class in [SideEffectClass::Financial, SideEffectClass::Destructive,
                  SideEffectClass::Physical] {
        assert!(!Normal.refuses(class), "Normal refuses nothing extra");
        assert!(Constrained.refuses(class) && Terminal.refuses(class));
    }
    assert!(!Constrained.refuses(SideEffectClass::Write), "Write survives Constrained");
    assert!(Terminal.refuses(SideEffectClass::Write), "Terminal is read-only for effects");
    assert!(!Terminal.refuses(SideEffectClass::Read),
            "Read survives Terminal: an agent that cannot read cannot report, and the trigger is \
             its own report");
}
```

Test intent: pin the vocabulary before any surface renders it, and pin the one exception (`Read` at
`Terminal`) that a naive "tighten everything" implementation would get wrong in a way that silently
freezes the trigger.

- [ ] **Step 4 — Implement `DialPosition::refuses` by reusing the existing consequential
      predicate.** Do not write a second list of classes.
      `SideEffectClass::is_consequential` at `rust/authority-spec/src/lib.rs:58-63` already answers
      "Financial | Destructive | Physical", and `NEVER_IN_OBSERVE` at
      `rust/warrant/src/proxy.rs:119-120` is the existing two-class floor. A third hand-written list
      would drift from both.

```rust
// rust/warrant/src/dial.rs
impl DialPosition {
    /// Does this position refuse `class` **in addition to** whatever the warrant's own bounds
    /// already refuse? Never a replacement for them: `Normal` refuses nothing, so the dial is
    /// additive by construction and cannot widen authority.
    #[must_use]
    pub fn refuses(self, class: SideEffectClass) -> bool {
        match self {
            // The warrant's bounds stand alone. A dial that tightens at 0% depletion is not a
            // dial, it is a narrower grant that the developer did not agree to.
            Self::Normal => false,
            // Reuses `is_consequential` rather than restating its three variants, so a class added
            // to the enum is classified in one place.
            Self::Constrained => class.is_consequential(),
            // Read-only for effects. `Read` is deliberately excluded: see the module note.
            Self::Terminal => class.is_consequential() || matches!(class, SideEffectClass::Write),
        }
    }
}
```

Test intent: Step 3 goes green. The structural intent is that adding a sixth `SideEffectClass`
variant changes behavior in exactly one file.

- [ ] **Step 5 — Implement the refusal at the one place a bound is refused.** Insert into
      `Proxy::decide` immediately after the `NEVER_IN_OBSERVE` block that ends at
      `rust/warrant/src/proxy.rs:198` and **before** the observe early-return at line 200, so the
      dial governs both `Enforce` and `Observe`. Placing it after line 200 would leave an observe
      run at `Terminal` performing writes, and `proxy.rs:27-30` is explicit that observe mode
      really performs ordinary writes.

```rust
        // The risk dial, evaluated before the mode split so an observe run is governed too.
        //
        // Placed AFTER the never-in-observe floor and BEFORE the tools allowlist: the floor is a
        // constant that no dial position may relax, and a tools denial is the more actionable
        // message when both would fire. The dial is additive -- `DialPosition::Normal::refuses`
        // returns false for every class -- so a warrant whose budget is fresh decides exactly as
        // it does today, and this block cannot widen authority.
        if self.dial.position().refuses(call.side_effect) {
            let position = self.dial.position();
            return self.deny(
                &call.tool,
                "risk_dial",
                format!(
                    "the risk dial is at {} ({}). {:?} actions are refused at this position. \
                     The position was computed from agent-reported spend, so it is only as good \
                     as the agent's own reporting; and it holds only for calls that traverse this \
                     proxy.",
                    position.word(),
                    self.dial.depletion_sentence(),
                    call.side_effect,
                ),
            );
        }
```

Test intent: Step 2 goes green. `self.deny` is the existing recorder at
`rust/warrant/src/proxy.rs:151-163`, so the refusal appears in `authority_requests()` and the
morning report with no new plumbing. Rule 2: every clause in that message names a mechanism that
exists in the same commit.

- [ ] **Step 6 — Failing test, then implement: a dial position over a class the proxy does not
      decide is reported as ineffective, not as active.** This is the seed's Step 7, corrected: the
      instrument is the class-assignment path, not the wiring census. A `Terminal` dial claiming to
      refuse `Write` for an upstream tool whose class was guessed `Read` at
      `rust/warrant/src/mcp_endpoints.rs:1044-1054` is refusing nothing, and must say so.

```rust
#[test]
fn a_position_over_a_guessed_class_is_reported_ineffective_with_a_decided_control() {
    // CONTROL: a tool whose class the staging registry knows. The dial's claim is effective.
    let effective = warrantor_warrant::dial::effectiveness(
        DialPosition::Terminal, "github.create_pr", &EffectRegistry::github(), &BTreeMap::new());
    assert!(effective.is_effective());
    assert_eq!(effective.basis(), "registry");

    // INEFFECTIVE: an upstream tool with no registry entry and no operator declaration. The
    // endpoint will class it Read by the documented fallback guess, so a Terminal dial that
    // claims to refuse this tool's writes refuses nothing.
    let guessed = warrantor_warrant::dial::effectiveness(
        DialPosition::Terminal, "notion.append_block", &EffectRegistry::github(), &BTreeMap::new());
    assert!(!guessed.is_effective());
    assert!(
        guessed.sentence().contains("classed Read by fallback"),
        "an ineffective position must say WHY it is ineffective, in the words of the code that \
         makes it so: {}",
        guessed.sentence(),
    );

    // And an operator declaration repairs it -- the fix is nameable, not just the defect.
    let declared: BTreeMap<String, SideEffectClass> =
        [("notion.append_block".to_string(), SideEffectClass::Write)].into_iter().collect();
    assert!(warrantor_warrant::dial::effectiveness(
        DialPosition::Terminal, "notion.append_block", &EffectRegistry::github(), &declared)
        .is_effective());
}
```

Test intent: prevent the exact overclaim the phase's failure mode names — "governors that observe
rather than refuse" — in its subtlest form, where the governor really does refuse but over a class
nothing ever assigns.

- [ ] **Step 7 — Failing test, then implement: a loosening move without the settle authority is
      refused; the same move with it is accepted.** The seed calls this "the whole task"; it is half
      of it, and it is the half that turns the dial from a convenience into a control. The authority
      is not a string an operator types — it is
      `Warrant::verify_settle` (`rust/warrant/src/lib.rs:568`), the key
      `rust/warrant/src/lib.rs:17-22` establishes the agent provably never holds.

```rust
#[test]
fn loosening_requires_the_settle_authority_and_a_reason_tightening_requires_neither() {
    use warrantor_warrant::dial::{DialError, Direction};
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let settle = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let agent  = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let warrant = warrantor_warrant::Warrant::grant(
        "wrt_dial", "fix the auth bug", "spiffe://muveraai.com/agent/a", bounds(), NOW,
        &issuer, &settle.verifying_key(),
    ).expect("grant");

    let mut dial = RiskDial::from_ledger(&ledger_at(950), &DialThresholds::default());
    assert_eq!(dial.position(), DialPosition::Constrained);

    // REFUSAL 1: no authority at all.
    assert!(matches!(
        dial.set(DialPosition::Normal, "the deploy window closes at 6", None, NOW, &warrant),
        Err(DialError::UnauthorizedLoosening),
    ), "a loosening move with no presented authority must be refused");

    // REFUSAL 2: the AGENT's own key. This is the attack: an agent that can reach the daemon
    // socket runs as the same user and can present something.
    assert!(matches!(
        dial.set(DialPosition::Normal, "the deploy window closes at 6",
                 Some(&agent.verifying_key()), NOW, &warrant),
        Err(DialError::UnauthorizedLoosening),
    ), "the acting agent's own key must not loosen its own dial");

    // REFUSAL 3: the right key, no reason. An unexplained relaxation is not reviewable.
    assert!(matches!(
        dial.set(DialPosition::Normal, "   ", Some(&settle.verifying_key()), NOW, &warrant),
        Err(DialError::UnreceiptedLoosening),
    ));
    assert_eq!(dial.position(), DialPosition::Constrained, "no refused move may take effect");

    // CONTROL A: the settle authority with a reason is accepted, and receipted as a Loosen.
    let t = dial.set(DialPosition::Normal, "the deploy window closes at 6",
                     Some(&settle.verifying_key()), NOW, &warrant).expect("authorized loosen");
    assert_eq!((t.direction, t.from, t.to),
               (Direction::Loosen, DialPosition::Constrained, DialPosition::Normal));
    assert_eq!(t.reason, "the deploy window closes at 6");
    assert_eq!(t.authority_key.as_deref(),
               Some(hex_of(&settle.verifying_key()).as_str()),
               "the receipt names WHICH authority, not that there was one");

    // CONTROL B: tightening needs no authority and no signature. Automatic tightening that an
    // operator has to approve is not automatic, and L3-07's whole point is that it fires without
    // one -- but it is still receipted, in the same shape.
    let t = dial.tighten_to(DialPosition::Terminal, NOW + 60).expect("automatic tighten");
    assert_eq!(t.direction, Direction::Tighten);
    assert_eq!(t.authority_key, None);
    assert!(!t.reason.is_empty(), "even an automatic move states its trigger");
}
```

Test intent: the asymmetry *is* the design. Three refusals, two allowed controls, and the second
control asserts the opposite asymmetry so an implementation that simply requires authority for
everything fails.

- [ ] **Step 8 — Failing test, then implement: automatic tightening cannot be suppressed, and every
      move in both directions lands in an ordered history.** `RiskDial::position()` recomputes from
      the ledger on read and takes the **stricter** of the computed position and any operator-set
      one, so a loosening move authorized at 50% does not survive to 99%.

```rust
#[test]
fn an_authorized_loosening_does_not_survive_further_depletion() {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let settle = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let warrant = warrantor_warrant::Warrant::grant(
        "wrt_dial", "g", "spiffe://muveraai.com/agent/a", bounds(), NOW,
        &issuer, &settle.verifying_key()).expect("grant");

    let mut dial = RiskDial::from_ledger(&ledger_at(800), &DialThresholds::default());
    dial.set(DialPosition::Normal, "operator override for the release",
             Some(&settle.verifying_key()), NOW, &warrant).expect("authorized");
    assert_eq!(dial.position(), DialPosition::Normal);

    // The ledger moves on. The override is not a lease on the future.
    dial.observe(&ledger_at(995), NOW + 300);
    assert_eq!(dial.position(), DialPosition::Terminal,
               "a loosening authorized at one depletion must not outlive the depletion that \
                justified it");

    // Both moves, in order, in the history, each naming its direction and trigger.
    let words: Vec<&str> = dial.history().iter().map(|t| t.direction.word()).collect();
    assert_eq!(words, ["loosen", "tighten"]);
    assert!(dial.history()[1].reason.contains("99.5%"));
}
```

Test intent: close the one loophole a receipted loosening opens. A receipt makes a bad move visible;
it does not make it expire, and only recomputation does.

- [ ] **Step 9 — Wire the dial into the session, and print it where `remaining` is already
      printed.** `agent_endpoint_for` (`rust/warrant/src/mcp_endpoints.rs:1187-1212`) loads the
      ledger with `SpendStore::load` — which signature-checks it — and calls `Proxy::set_dial`
      beside the existing `Proxy::new` at line 1210. A ledger that will not load is the
      **most-constrained** position, not the least: `rust/warrant/src/bin/warrantor.rs:3097-3101`
      already refuses to start a run whose budget state is unknown, and this is the same reading
      inside an open session. `warrantor status` gains one line next to line 1637, and its
      transition receipts use the same `direction`/`reason`/`authority` triple Task 3.5's verb
      receipt carries so a reviewer reads one vocabulary across both.

```rust
// rust/warrant/src/mcp_endpoints.rs, in agent_endpoint_for, after Proxy::new at line 1210
    let mut proxy = Proxy::new(bounds.clone(), mode, EffectRegistry::github());
    // An unreadable or wrongly-signed ledger means the depletion is UNKNOWN, and unknown is
    // handled the way this crate handles every absent limit: as none available, not as all
    // available. Same reading as the start precondition at bin/warrantor.rs:3097.
    proxy.set_dial(match ledgers.load(&bounds, &id, &stored.warrant.claims.subject, issuer) {
        Ok(ledger) => RiskDial::from_ledger(&ledger, thresholds),
        Err(_) => RiskDial::pinned(DialPosition::Terminal, "spend ledger unreadable"),
    });
```

Test intent, as a fourth test in `risk_dial.rs`: a session built over a corrupt ledger file refuses
a `Write` call, and the same session over a valid fresh ledger returns `Decision::Forward` for it —
refusal and control again.

- [ ] **Step 10 — Two invariant-corpus tests, and the ratchet raised in the same commit.** Add to
      `rust/warrant/tests/invariants/i09_failure_is_safe.rs`, whose subject is *"If any plane fails
      open, the action fails closed"* and whose existing tests already use
      `spend`/`WarrantBounds`/`scenario::NOW` (see its `bounds_with_budget` helper at lines 18-28).
      Both are **passing** tests, so `passing_floor` must rise; **no assertion anywhere is
      weakened, and `ignored_ceiling` stays 19.**

```rust
// rust/warrant/tests/invariants/i09_failure_is_safe.rs  (append)

#[test]
fn an_unreadable_spend_ledger_is_the_most_constrained_dial_not_the_least() {
    // The I-09 shape exactly: the plane that would have said "plenty of budget left" is
    // unavailable, so the dial must be Terminal, not Normal.
    let dial = warrantor_warrant::dial::RiskDial::pinned(
        warrantor_warrant::dial::DialPosition::Terminal, "spend ledger unreadable");
    assert!(dial.position().refuses(warrantor_warrant::SideEffectClass::Write));
    assert!(!dial.position().refuses(warrantor_warrant::SideEffectClass::Read),
            "a dial that refuses reads cannot be told about its own budget again");
}

#[test]
fn an_undeclared_budget_is_normal_because_it_was_never_depleting() {
    // The counterpart, and the one an over-eager implementation gets wrong. `exhausted()` at
    // spend.rs:285 answers false for an undeclared cap on purpose; the dial must agree, or the
    // same `None` means zero to the ledger and maximum pressure to the dial.
    let bounds = bounds_with_budget(None);
    let ledger = warrantor_warrant::spend::SpendLedger::new(&bounds, "wrt_x", "spiffe://x/a");
    assert!(!ledger.exhausted());
    assert_eq!(
        warrantor_warrant::dial::position_for(
            &ledger, &warrantor_warrant::dial::DialThresholds::default()),
        warrantor_warrant::dial::DialPosition::Normal,
        "an absent ceiling refuses RECORDS, and was never budget-depleting; a dial that reads it \
         as end-of-budget is a different bound wearing this one's name",
    );
}
```

```json
{
  "format": "warrantor.invariant-ratchet/1",
  "recorded": "2026-09-05",
  "source": "rust/warrant/tests/invariants/",
  "passing_floor": 67,
  "ignored_ceiling": 19,
  "note": "The invariant attack corpus for I-01..I-12. `passing_floor` may only rise; `ignored_ceiling` may only fall. Task 8.2 added two I-09 tests (unreadable ledger is the most-constrained dial; an undeclared budget is not a depleting one) and raised the floor 65 -> 67 in the same commit. No #[ignore] was converted and none was added."
}
```

Test intent: earn the number honestly. Run `python tools/ci/check_invariant_ratchet.py` and require
`invariant ratchet: ok (67 passing at floor 67, 19 recorded findings at ceiling 19)`.

- [ ] **Step 11 — Gate every rendered number against its record, then gates, evidence,
      `git commit -s`.** Two published numbers exist here and each needs an assertion tying it to
      the file it came from.

      **(a) The tier row.** Adding `("risk_dial_mediated", BoundStrength::Mediated)` to
      `bound_strengths()` changes `render_bounds_table()`, and
      `rust/warrant/tests/tier_disclosure.rs:286-316` already fails until both `README.md` and
      `rust/warrant/README.md` carry the regenerated table verbatim between their
      `<!-- bound-tiers:begin -->` markers. Do not hand-edit the rows; regenerate. That test is the
      gate, and it is the one that refused a merge in this program before.

      **(b) The thresholds.** The evidence file publishes the permille thresholds, so it gets the
      same treatment rather than a prose promise:

```rust
// rust/warrant/tests/risk_dial.rs
/// The evidence file carries the thresholds table `render_thresholds_table()` generates,
/// verbatim, between markers -- the same mechanism tier_disclosure.rs:287 uses for the README.
/// A hand-edited threshold in the doc fails here.
#[test]
fn the_evidence_file_carries_the_thresholds_table_generated_from_the_code() {
    let table = warrantor_warrant::dial::render_thresholds_table();
    let doc = include_str!("../../../docs/task-evidence/task-8.2.md").replace("\r\n", "\n");
    let start = doc.find("<!-- dial-thresholds:begin -->").expect("no begin marker");
    let end = doc.find("<!-- dial-thresholds:end -->").expect("no end marker");
    assert!(doc[start..end].contains(&table),
            "task-8.2.md drifted from DialThresholds::default():\n{table}");
    assert!(doc.contains("agent-reported"),
            "the evidence file must state the provenance of the number the dial acts on");
}
```

      Then the full gate, whose output decides pass or fail:

```bash
cd M:/wt-8.2 && export CARGO_TARGET_DIR=M:/wt-8.2-target
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test -p warrantor-warrant --test risk_dial --test invariants \
                                --test tier_disclosure --test proxy
python tools/ci/check_invariant_ratchet.py
python tools/ci/wiring_census.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
     docs/task-evidence/task-8.2.md
git fetch origin main && git rebase origin/main && cargo test -p warrantor-warrant
git commit -s -m "feat: the risk dial and the end-of-budget risk profile (L3-02, L3-07)"
```

      Pass requires: `risk_dial` green; `invariant ratchet: ok (67 passing at floor 67, 19 recorded
      findings at ceiling 19)`; `wiring census: 9 of 39 crates reachable from warrantor-warrant over
      17 path edges`, byte-identical to Step 1's capture; and `tier_disclosure` green, which is only
      possible once both READMEs carry the regenerated row. The rebase is not optional: PR CI tests
      the branch against the *old* main, and Task 1.4 edits the same `Proxy::decide` body.

      `docs/task-evidence/task-8.2.md` records: the Step 1 and Step 11 census lines side by side;
      the ratchet before and after with the two test names that earned the two points; the
      thresholds table between its markers; the class-effectiveness finding from Step 6 naming
      `mcp_endpoints.rs:1054` as the fallback that makes a `Terminal` claim over an undeclared
      upstream tool ineffective; the `bound_strengths()` row as rendered; and the correction to the
      seed recorded plainly — the wiring census counts crates over manifest edges and cannot report
      which effect classes a dial reaches, so the class question is answered from
      `rust/authority-spec/src/lib.rs:42-53`, `rust/warrant/src/proxy.rs` and
      `rust/warrant/src/mcp_endpoints.rs:1030-1061` instead.

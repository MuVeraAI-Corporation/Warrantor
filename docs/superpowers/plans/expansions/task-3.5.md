### Task 3.5: Machine-speed response policy — `warrantor.response-policy/1` — expanded to step form

**Anchor.** L4-08 and the incident's response arithmetic: worker code execution to administrative
host access across multiple clusters in under thirteen hours, against a response loop measured in
days, with the eventual containment requiring manual enumeration of 311 repositories, 22
administrator accounts and six pods. This expansion re-verified the anchors on local `main` at
`6f41384` and resolves the carry-in and the spec shape to real code.

**What exists, re-verified 2026-09-06.** `rust/revocation-verbs/src/lib.rs` is **579 lines,
untracked** (in the dirty main checkout only — the same pre-Task-1.1 situation
`delegation-chain` was in, and this task carries it in exactly as Task 0.1's documented pattern:
member line, unlock-refresh of `Cargo.lock`, first-contact `cargo fmt`). Its shape is real:
`RevocationGraph` (`:91`) with `add_surface`/`add_dependency`/`closure` (`:135` — the propagation
closure, the thing that turns "revoke this pod" into "and the 311 repositories it can reach"),
`SurfaceKind` (`:53`), `RevocationAuthority` (`:156`, decision rights), and a doc contract that
states its own boundary at `:36`: *it does not perform the halt* — `rust/kill-switch` executes.
`rust/containment-conformance/` is on `main`; Task 1.3's `stop` verb, the four-capability
containment receipt and the Windows drill are all in `rust/warrant/src/stop.rs` and
`rust/warrant/tests/stop_kills_tree.rs`. The verb set the policy maps onto therefore already
exists end to end: the task is the *policy evaluation* between a trigger and those verbs — and
the evaluator lives in the operator/daemon context, never inside the supervised agent's process.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-3.5.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-3.5 -b feat/task-3.5-response-policy main
cd M:/wt-task-3.5
cp -r "M:/Project AumOS - Open Secure AI Alliance/aumos/rust/revocation-verbs" rust/
wc -l rust/revocation-verbs/src/lib.rs
grep -n "pub enum SurfaceKind\|pub fn closure\|pub struct RevocationAuthority\|pub struct RevocationRequest" rust/revocation-verbs/src/lib.rs
grep -n "pub fn stop\|HaltScope\|StopStore\|STOP_BUDGET" rust/warrant/src/stop.rs | head -8
grep -n "containment" rust/warrant/tests/stop_kills_tree.rs | head -4
sed -n '30,45p' rust/revocation-verbs/src/lib.rs
```

Expected: 579 lines carried; `closure` at `:135`; Task 1.3's stop surface (`stop.rs`: `HaltScope`,
`StopStore`, the signed stop record, `STOP_BUDGET`) reachable. Read in full:
`rust/revocation-verbs/src/lib.rs` (all 579 lines — the authority model is what the policy must
not bypass), `rust/warrant/src/stop.rs` (the verb surface, and `STOP_BUDGET` — the existing
latency bound the policy's bound extends), `rust/containment-conformance/src/lib.rs` (the drill
shape the false-denial counter test follows).

---

**Step 1 — Carry-in and lock.** Add `"revocation-verbs",` to `rust/Cargo.toml` members and
`warrantor-revocation-verbs = { path = "../revocation-verbs", version = "1.0.0" }` to
`rust/warrant/Cargo.toml` where the dependency note says. Refresh:

```bash
cargo metadata --format-version 1 > /dev/null          # unlocked, once — new edge
cargo metadata --format-version 1 --locked > /dev/null  # then verify the lock is stable
cargo fmt --all -- --check                              # expect failure on first contact with the carried code
cargo fmt --all                                          # fix formatting only — no semantic edits
```

Record in the evidence that the carry-in was byte-faithful apart from `rustfmt`, with the diff
stat before/after: the crate is someone's written code, and this task's edits to it must be
provably zero.

---

**Step 2 — The spec first: `specs/warrantor-v4/response-policy.md` and the type it names.** The
policy maps trigger → verb over an explicit, seeded trigger set. The spec text states, before any
code: the trigger schema, the four verbs (halt | quarantine | revoke | freeze) with their mapping
onto `stop.rs`'s surface and `revocation-verbs`' closure, the stated bound (a distribution, not a
number — see Step 6), and the false-denial counter's budget. Then the type:

```rust
// rust/warrant/src/response_policy.rs
pub const RESPONSE_POLICY_FORMAT: &str = "warrantor.response-policy/1";
pub const RESPONSE_RECEIPT_FORMAT: &str = "warrantor.response-receipt/1";

/// One entry of the policy. `trigger` and `verb` are the whole mapping — a policy entry that
/// needs more than this is a design decision the spec does not make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRule {
    /// The seeded trigger: a predicate id from the explicit set, never a free-form expression.
    pub trigger: String,
    /// halt | quarantine | revoke | freeze — validated against the verb surface at load.
    pub verb: String,
    /// The bound this rule promises, in milliseconds, for the distribution to measure against.
    pub bound_ms: u64,
}

/// The loaded policy. Validated at load: a rule whose verb is not one of the four is a
/// refusal to start, not a warning — a policy entry the evaluator cannot execute is a
/// silent gap in the response surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub format: String,
    pub rules: Vec<ResponseRule>,
    /// The false-denial budget per trigger: when a trigger's count exceeds it, the rule
    /// is disabled by the evaluator and says so in every receipt it then refuses to fire.
    pub false_denial_budget: u64,
}
```

The trigger set is seeded, named, and closed — the spec lists every trigger id the evaluator
knows (the incident's own sequence is the seed: anomalous credential use, mass-clone shapes,
metadata-endpoint probes), and an id outside the list is Step 5's negative case.

---

**Step 3 — Failing test: a seeded trigger fires its verb within the bound, unattended.** Seed a
trigger against a fixture store, fire it through the policy evaluator, and assert:

```rust
#[test]
fn a_seeded_trigger_fires_its_mapped_verb_within_the_bound() {
    let policy = ResponsePolicy { rules: vec![ResponseRule {
        trigger: TRIGGER_MASS_CLONE.into(), verb: "quarantine".into(), bound_ms: 5_000 }],
        false_denial_budget: 3 };
    let mut evaluator = ResponseEvaluator::new(policy, fixture_verb_surface());
    let started = millis_now();
    let receipt = evaluator.evaluate(&fired_trigger(TRIGGER_MASS_CLONE)).expect("fires");
    let elapsed = millis_now() - started;
    assert_eq!(receipt.verb, "quarantine");
    assert!(elapsed < 5_000, "the bound is a promise: {elapsed}ms");
    // The verb's effect is real: a stop record exists with the right scope.
    assert!(fixture_stop_record_exists(&receipt.scope), "the verb executed");
}
```

Run before implementing: the missing evaluator is the failure, not a compile error. The receipt
is under `RESPONSE_RECEIPT_FORMAT` and carries the trigger id, the verb, the closure the verb
acted on, the latency, and the false-denial counter state.

**Step 4 — Failing test: the false-denial counter increments and is visible in the receipt.**
A trigger that fires on non-matching conditions (the test constructs the false-positive case
explicitly — a benign workload whose shape matches the mass-clone trigger) increments
`FalseDenial`; the receipt carries the counter state. The budget from the spec is asserted here:

```rust
#[test]
fn a_false_denial_increments_the_counter_and_a_spent_budget_disables_the_rule() {
    let mut evaluator = evaluator_with_budget(2);
    for _ in 0..2 {
        evaluator.evaluate(&benient_but_matching()).expect("counts, does not fire wrongly");
    }
    let third = evaluator.evaluate(&benient_but_matching()).expect_err("budget spent");
    assert!(third.contains("false-denial budget spent"), "{third}");
    // And the receipt that refused says the rule is disabled, so the operator sees it
    // before the policy is silently trusted with nothing.
}
```

The budget from the spec is asserted here — a rule whose counter exceeds the budget is disabled
by the evaluator *and says so*, which is the mechanism that keeps a bad policy from being
silently trusted.

---

**Step 5 — Implement trigger evaluation against the existing verb surface.** The evaluator calls
Task 1.3's `stop` path and `revocation-verbs`' `closure` — it does NOT re-implement either. The
critical composition is closure-first: `revoke` against a surface means revoking everything the
graph says depends on it, and the receipt names the whole closure, because the incident's manual
enumeration of 311 repositories is exactly what the graph exists to make unnecessary:

```rust
let closure = self.graph.closure(&request.surface_id);
// The receipt names every surface the verb acted on, in closure order:
// this is the answer to "311 repositories, 22 accounts, 6 pods" — computed, receipted,
// and reviewed before the verb runs, not enumerated by hand for days after.
```

**Step 6 — Negative test: an unmapped trigger does nothing and says so.** A trigger not in the
policy produces a receipt recording "no rule matched; no action taken" — never a default to
halt. A response policy that fails toward halt is a denial-of-service the operator installed.
The test asserts both the no-action and the receipt's honesty:

```rust
#[test]
fn an_unmapped_trigger_does_nothing_and_receipts_that() {
    let receipt = evaluator.evaluate(&fired_trigger(TRIGGER_NOT_IN_POLICY)).expect("receipted");
    assert_eq!(receipt.verb, "none");
    assert!(receipt.no_rule_matched, "the receipt states why nothing happened");
    assert!(!fixture_stop_record_exists(), "no verb ran");
}
```

**Step 7 — Measure and publish the bound as a distribution.** Run the seeded-trigger suite N
times (the drill shape `containment-conformance` uses), record p50/p95/max in the evidence file
and the ledger entry, and state the distribution beside the per-rule `bound_ms`. A single-number
bound hides the tail; the tail is where "unattended" fails. The published distribution is
commit-tagged so a regression in the tail is a diff.

---

**Step 8 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
cargo metadata --format-version 1 --locked > /dev/null
python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-3.5.md specs/warrantor-v4/response-policy.md
```

The census moves again (revocation-verbs becomes reachable); the README row and coverage file
move in the ledger commit. Evidence: Step 0 baseline, both failing tests verbatim, the latency
distribution, and the tier statement.

---

**The honest tier of every bound this task introduces.**

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the trigger → verb evaluation | **Tier B chokepoint** at the verb surface | the evaluator calls `stop.rs` and `revocation-verbs` — it cannot bypass the authority model `RevocationAuthority` enforces, and a trigger fire is as receipted as a human stop. |
| the false-denial counter | **Observed**-tier evidence | it records how often the policy was wrong; it prevents nothing by existing. |
| the policy itself | a **configuration**, load-validated | a policy the evaluator cannot execute is a refusal to start, and the spec's false-denial budget is what keeps it honest. |

**Exit gate, restated.** A seeded trigger produces its mapped verb within the published
distribution, unattended, receipted, with the false-denial counter observable in the receipt; an
unmapped trigger does nothing and receipts that; the closure is named in every revoke receipt.

**Hazards.** (1) The seed's non-goal is the whole design: the trigger set is explicit and seeded —
no free-form predicates, no learned triggers, no "evaluate this expression". A policy entry that
needs an expression parser is Phase 6 scope arriving early. (2) `revocation-verbs` is untracked —
carry it in this task's commit verbatim (Task 0.1's pattern), do not vendor silently and do not
edit beyond `rustfmt`. (3) The evaluator must not run on a timer inside the supervised agent's
process — the agent governs nothing that decides to stop it; the policy evaluates in the
operator/daemon context `stop.rs` already lives in. (4) The spec file lands in the same commit as
the evaluator: a policy format nobody can evaluate is a document, and this task's deliverable is
a response, not a document.

---

**Verification detail — the shapes the steps compile against, captured on the carry-in.**

The carry-in's authority model, quoted from `revocation-verbs` — the policy evaluator must route
through it, never around it:

```rust
pub struct RevocationAuthority {
    // decision rights: WHO may revoke WHAT. The response policy evaluates triggers;
    // this type decides whether the policy is allowed to act. An evaluator that
    // bypasses it is the agent-governs-its-governor defect at response speed.
}
```

The trigger schema, seeded from the incident's own sequence — the spec file states each id and
what observation feeds it:

```yaml
# specs/warrantor-v4/response-policy.md, trigger table (the seeded, closed set):
triggers:
  - id: mass-clone
    observation: "one workload cloning > 50 repositories in 60s"
    incident: "the 311-repository enumeration"
  - id: metadata-probe
    observation: "a request to 169.254.169.254 or its name aliases"
    incident: "the escalation to platform authority"
  - id: credential-anomaly
    observation: "a third-party credential presented at the identity gate"
    incident: "14 valid tokens became collective property"
verbs: [halt, quarantine, revoke, freeze]
false_denial_budget: 3     # per trigger, before the rule disables itself
```

The receipt the evaluator emits, with every field the exit gate names:

```rust
/// One response decision, receipted. This is what "unattended" means the way every
/// other unattended act in this system means it: the decision is signed, scoped, and
/// named — and the false-denial counter is IN the receipt, not in a log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseReceipt {
    pub format: String,            // warrantor.response-receipt/1
    pub trigger: String,
    pub verb: String,              // halt | quarantine | revoke | freeze | none
    pub closure: Vec<String>,      // every surface the verb acted on, closure order
    pub latency_ms: u64,
    pub bound_ms: u64,             // the rule's own promise, beside the measurement
    pub false_denials: u64,        // the trigger's counter state at decision time
    pub decided_at: u64,
}
```

The negative test's receipt, quoted as the test asserts it:

```text
$ warrantor response evaluate --trigger not-in-the-list
receipted: trigger "not-in-the-list" matched no rule; no action taken.
  verb        none
  closure     (empty — nothing was acted on)
  decided_at  1788...
```

And the latency distribution block the evidence file records, as a shape:

```text
trigger mass-clone -> quarantine, 20 runs:
  p50 412ms  p95 1180ms  max 2310ms  bound 5000ms  violations 0
trigger metadata-probe -> revoke, 20 runs:
  p50 388ms  p95 962ms   max 1904ms  bound 5000ms  violations 0
The tail is where "unattended" fails; the distribution is the published fact, and the
per-rule bound_ms is the promise the distribution is measured against.
```

The honest-summary sentence the ledger adds: *"Machine-speed response now exists for a seeded,
closed trigger set, receipted with its closure and its false-denial counter. What it does not
establish: any trigger outside the seeded set fires nothing — by design — and the policy
disables itself when it is wrong too often, which is the mechanism that keeps it installed."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The evaluator's shape, showing how the trigger set stays closed while the verbs route through
existing machinery:

```rust
/// The response evaluator. Lives in the operator/daemon context — the same process
/// `stop.rs`'s verbs already run in, never inside the supervised agent's process.
/// An agent governs nothing that decides to stop it.
pub struct ResponseEvaluator<'a> {
    policy: ResponsePolicy,
    verbs: &'a mut dyn ResponseVerbSurface,
    graph: RevocationGraph,
    false_denials: BTreeMap<String, u64>,
    now_fn: Box<dyn Fn() -> u64>,
}

/// The verb surface, so the evaluator is testable without a real kernel kill.
/// The production impl wraps Task 1.3's stop path and revocation-verbs' closure;
/// the fixture impl records what would have run.
pub trait ResponseVerbSurface {
    fn halt(&mut self, scope: &HaltScope) -> Result<SignedStopRecord, String>;
    fn quarantine(&mut self, scope: &HaltScope) -> Result<SignedStopRecord, String>;
    fn revoke(&mut self, surface: &str, authority: &RevocationAuthority)
        -> Result<RevocationReceipt, String>;
    fn freeze(&mut self, scope: &HaltScope) -> Result<SignedStopRecord, String>;
}
```

The evaluate method, the whole policy decision in one function:

```rust
impl<'a> ResponseEvaluator<'a> {
    /// Evaluate one fired trigger against the policy. Receipts in every outcome:
    /// fire, false-denial count, budget-spent disable, and no-rule-matched.
    pub fn evaluate(&mut self, trigger: &FiredTrigger) -> Result<ResponseReceipt, ResponseReceipt> {
        let now = (self.now_fn)();
        let rule = self.policy.rules.iter().find(|r| r.trigger == trigger.id);
        let Some(rule) = rule else {
            return Ok(self.receipt(trigger, "none", vec![], 0, now, |r| {
                r.no_rule_matched = true;
            }));
        };
        let denials = self.false_denials.entry(trigger.id.clone()).or_insert(0);
        if *denials > self.policy.false_denial_budget {
            return Ok(self.receipt_for_disabled(trigger, rule, now));
        }
        let started = now;
        let closure = self.verbs.closure_of(&trigger.surface_id);
        let result = match rule.verb.as_str() {
            "halt" => self.verbs.halt(&HaltScope::from_trigger(trigger)),
            "quarantine" => self.verbs.quarantine(&HaltScope::from_trigger(trigger)),
            "revoke" => self.verbs.revoke(&trigger.surface_id, &self.authority),
            "freeze" => self.verbs.freeze(&HaltScope::from_trigger(trigger)),
            other => return Err(self.receipt_refusing_verb(trigger, other, now)),
        };
        // ... receipt with the closure, the latency against rule.bound_ms ...
    }
}
```

The spec file's opening, quoted so the implementer writes the same document:

```text
# warrantor.response-policy/1 — the machine-speed response policy

A response policy maps a seeded trigger to a pre-authorized verb, with a stated
latency bound and a false-denial budget. It exists because the incident's response
loop was measured in days against an attacker measured in hours, and because the
manual containment — 311 repositories, 22 administrator accounts, six pods, all
enumerated by hand — is exactly the work a propagation graph exists to compute.

The trigger set is closed and seeded. This document lists every trigger the
evaluator knows; an observation that matches none of them fires nothing, and the
receipt says so. A trigger added later is a change to THIS document and to the
evaluator's registry in the same commit — never a configuration edit alone.
```

The carry-in's zero-edit proof, the diff stat that goes in the evidence:

```bash
$ git diff --stat main -- rust/revocation-verbs/
 rust/revocation-verbs/Cargo.toml | 2 +-
 rust/revocation-verbs/src/lib.rs | 4 +-
 2 files changed, 3 insertions(+), 3 deletions(-)
$ git diff main -- rust/revocation-verbs/ | grep -E "^[+-]" | grep -v "^[+-][+-]" | cat -A | head -4
```

The last command shows the carried crate's only deltas are line-ending and import-ordering —
the byte-faithful claim proven, not asserted.

The ledger's response row, quoted so the implementer cannot write a weaker one:

```text
### E.2 Machine-speed response policy — **built for the seeded trigger set; the set is closed**

A response policy maps a closed, seeded trigger set to pre-authorized verbs (halt, quarantine,
revoke, freeze), each fire receipted with the propagation closure and the measured latency
against the rule's own bound. The false-denial counter is in the receipt, and a rule whose
counter exceeds its budget disables itself and says so. What this does not establish: any
trigger outside the seeded set fires nothing (by design — a policy that fires on the unknown is
the denial-of-service the budget exists to prevent); the evaluator runs in the operator/daemon
context, never in the supervised agent's process; and the verbs route through Task 1.3's stop
surface and revocation-verbs' authority model — the policy adds decision speed, not decision
authority.
```

The final commit, gathering the pieces:

```bash
git add rust/revocation-verbs rust/Cargo.toml rust/Cargo.lock rust/warrant/Cargo.toml \
        rust/warrant/src/response_policy.rs specs/warrantor-v4/response-policy.md \
        rust/warrant/tests/response_policy.rs docs/W1-delivery-gaps.md docs/task-evidence/task-3.5.md
git commit -s -F .commitmsg
# Branch: feat/task-3.5-response-policy. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

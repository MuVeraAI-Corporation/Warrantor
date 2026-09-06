### Task 13.6: Impossible-task and broken-environment detection; structured stop, abstain and ask (L11-08, L11-09)

**Anchor.** From `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html`, quoted verbatim
with the attribute line so nothing is softened:

```html
<article class="item" id="L11-08" data-stratum="L11" data-plane="A" data-status="none" data-novelty="core" data-wave="W2" data-loop="L5">
  <h4>Impossible-task and broken-environment detector</h4>
  <p class="what">The lifecycle side of task validity: statistical and structural detection that a task cannot be completed as specified or that an environment is broken, with the finding routed to the environment owner and the task's authority narrowed until it is repaired. Pairs with the per-run attestation in L3-01.</p>
  <p class="verify"><b>Verification</b> A seeded unsolvable task is flagged within a stated number of attempts and its owner notified; agents assigned to it receive a narrowed warrant; the flag is receipted.</p>

<article class="item" id="L11-09" data-stratum="L11" data-plane="A" data-status="none" data-novelty="core" data-wave="W2" data-loop="L5">
  <h4>Structured stop, abstain and ask-for-clarification outcome</h4>
  <p class="what">A first-class task outcome that is neither success nor failure: the agent stops, abstains or asks, and the outcome is scored as legitimate by the grader rather than as a loss. The escalation channel in L5-04 delivers the ask; this item makes the ask a valid ending.</p>
  <p class="verify"><b>Verification</b> A run that ends in a structured stop is scored no worse than an honest failure and never as a timeout; the grader's scoring rule for the outcome is versioned and visible.</p>
```

The seed's anchor line reads *"Both `status=none`, `core`, W2."* **Verified true** — both articles carry
`data-status="none" data-novelty="core" data-wave="W2"`. That is the only line of the seed's framing
that survives unaltered.

**An agent given an impossible task will improvise a path.** That argument holds and is the reason this
task exists. Two of the claims built on top of it do not.

---

#### What the code shows — one contradicted premise and one that survives

Read on **local `main` at `b04164d`**, 2026-09-05. `origin/main` is stale at `e4b5f10` and does not carry
the six unpushed merges; every line number below is from `b04164d`. **`premise_contradicted = true`.**

**(1) Survives: abstention is not representable.** `WarrantState` has exactly four variants and none of
them is an abstention (`rust/warrant/src/lib.rs`):

```rust
161: pub enum WarrantState {
163:     Open,      // the agent is acting; local writes land in the worktree, external effects stage
167:     Held,      // ended on schedule (deadline or budget), staged effects awaiting review
170:     Settled,   // staged effects released and the worktree merged
173:     Void,      // staged effects discarded and the worktree deleted
```

**Terminal states are `Settled` and `Void`, and only those two.** The authority is `transition`
(`rust/warrant/src/lib.rs:597-613`), quoted whole because both of its silent arms matter here:

```rust
597:    pub fn transition(&mut self, to: WarrantState) -> Result<(), WarrantError> {
598:        let legal = match (self.state, to) {
599:            (WarrantState::Open, _) => true,
600:            // Held is not terminal: the deadline passed, and the settle authority may still
601:            // release or discard what was staged.
602:            (WarrantState::Held, WarrantState::Settled | WarrantState::Void) => true,
603:            _ => false,
604:        };
```

`Open` is not terminal. `Held` is explicitly not terminal, and lines 600-601 say why in the code's own
words. `Settled` and `Void` are terminal because every pair leaving them falls to `_ => false` at line
603. So: **four variants, two terminal, abstention unrepresentable.** The seed's Step 2 is correct.

**(2) Contradicted: the seed's Bound strength.** It says *"**Tier B** for the state machine, because an
agent that cannot reach a terminal state without one of these is structurally forced to declare."* Every
clause of that is wrong, three ways, and the third is the one that matters:

- **The agent never transitions the warrant.** `transition` is reached from `stop::execute`
  (`rust/warrant/src/stop.rs:264`) and from `settle.rs`, both of which run in the operator's process. The
  agent's own capability token is act-scoped with no settle scope by construction
  (`rust/warrant/src/lib.rs:502-521`). Nothing about a terminal state is a decision the agent makes.
- **The agent is not forced to declare anything; it just exits.** `daemon::run`
  (`rust/warrant/src/daemon.rs:374-389`) waits, records an exit code, and leaves the warrant `Open`:

```rust
374:    let remaining = expires_at.saturating_sub(now);
375:    let (code, expired) = match supervisor.wait_until(remaining)? {
376:        Some(code) => { println!("warrantor: agent exited with {code}"); (code, false) }
380:        None => { /* deadline reached: terminate the agent tree */ (-1, true) }
```

  A `CompletionRecord` is then written carrying `exit_code` and `expired`
  (`rust/warrant/src/daemon.rs:106-117`). That is the honest half of the seed's anchor: an agent that gave
  up silently exits 0, and a warrant that produced no effects is `Open` with `exit_code: 0` and
  `StagingQueue::len() == 0` — byte-identical to a warrant whose task needed no external effects.
  **The anchor is verified. The mechanism the seed proposed for it is not.**
- **`Warrant.state` is not signature-protected, so it cannot carry a Tier B claim at all.** Verbatim,
  `rust/warrant/src/lib.rs:399-401`:

```rust
    /// Current lifecycle state. Not signed: it changes over the warrant's life, and every
    /// transition is separately evidenced in the receipt chain.
    pub state: WarrantState,
```

  And the store is same-UID reachable. `docs/W1-delivery-gaps.md:620-622`, verbatim:

  > **What remains, stated narrowly:** the agent can still read the store directly, and nothing can stop
  > it. Same UID is same UID.

  Read is what the gaps document states; nothing in the repository refuses a *write* to
  `~/.warrantor/warrants/<id>.json` either, and because `verify` checks the signature over `claims` —
  which excludes `state` — a flipped state field is not detectable by any existing check. A tier word
  attached to the state machine would be a tier word attached to a mutable, unsigned field. **The tier
  belongs on the record, which is signed, not on the state.**

**(3) Contradicted in the seed's favor: "ask" does not need Task 9.8.** The seed's Step 0 says to *"record
whether 9.8 has landed"*. It has not — `rust/channel/` does not exist under `rust/` on local `main` (Step
0 captures the listing). But the conclusion the seed draws, that an abstention has nowhere to go, is too
strong. A pre-decision human path already exists and works:

```rust
// rust/warrant/src/review.rs:57
pub const REVIEW_EVENT: &str = "review-requested";
// rust/warrant/src/notify.rs:70
pub const EVENTS: [&str; 5] = ["settled", "voided", "stopped", "filing-queued", crate::review::REVIEW_EVENT];
```

`review.rs`'s own module doc names exactly this gap and says it closed it (lines 3-13): *"`notify.json`
fires on `settled`, `voided`, `stopped` and `filing-queued`: four events that are all after a decision,
and none that says one is wanted."* `REVIEW_EVENT` is the fifth, and `review::Blocker`
(`rust/warrant/src/review.rs:74-100`) already carries the three shapes an ask needs — waiting on a
decision, waiting on named people, and `Deadlocked { why }` for a queue that has stopped rather than
slowed. **So "ask" can be recorded and delivered today.** What 9.8 adds, and what this task must not
claim, is the *measured* latency to first human response and the use-rate metric.

**(4) A finding the seed does not mention, and it is the largest reuse available.** L11-08 asks for a flag
*"within a stated number of attempts"*. The stated number already exists, public and named
(`rust/warrant/src/serve.rs:2458-2505`):

```rust
2462: pub const REPEATED_OCCURRENCES: u64 = 5;   // "a threshold, not a truth"
2464: pub const SPREAD_WARRANTS: usize = 2;      // distinct warrants before it has spread
2469: pub enum RefusalSignal { BoundsProbablyWrong, RepeatedInOneRun, Isolated }
2505: pub fn aggregate_refusals(records: &[RefusalRecord]) -> Vec<RefusalGroup>
```

`aggregate_refusals` groups every refusal by tool and destination across warrants and already emits
`BoundsProbablyWrong` at five occurrences across two warrants. **This task must not invent a second
threshold.** It must, however, refuse to collapse two diagnoses that share one body of evidence:
`BoundsProbablyWrong` says *the grant was scoped wrong*, and a broken-environment finding says *the world
the task named is not there*. The same five refusals support both readings, and a detector that prints one
word for both will get the remedy wrong every second time.

**(5) The agent has no channel to say anything on.** `AgentEndpoint::tools()`
(`rust/warrant/src/mcp_endpoints.rs:948-963`) publishes the warrant's allowed tool names and nothing else;
the control endpoint's lifecycle tools are deliberately absent from a supervised session
(`rust/warrant/src/mcp_endpoints.rs:654`, and the CLI usage block: *"no lifecycle tool published -- so the
agent has no route to settling its own work"*). There is therefore no call an agent can make that means
"this cannot be done". Every agent under this product must invent one, which is the failure this task
exists to remove.

---

#### The design decision this task turns on: **zero new `WarrantState` variants**

The seed's Produces line asks for *"three new terminal outcomes — stopped, abstained,
awaiting-clarification"*. Implemented as three enum variants, that would be wrong, and the reader census
below is the evidence.

**Where a fifth variant would break loudly (good).** Four exhaustive matches with no catch-all, each a
compile error the moment a variant is added:

```
rust/warrant/src/serve.rs:2135-2139           the state word for the review queue
rust/warrant/src/serve.rs:3460-3464           the /v1/summary state counts
rust/warrant/src/bin/warrantor.rs:3796-3799   the holdings listing
rust/warrant/src/corpus.rs:194-222            the training-label decision
```

**Where a fifth variant would pass silently (the hazard).** Two classes:

- **The `matches!` guards.** Twelve sites ask only "is this `Open`" or "is this `Open | Held`" —
  `daemon.rs:227`, `egress.rs:157`, `mcp_endpoints.rs:1193`, `bin/warrantor.rs:3113`,
  `bin/warrantor.rs:4329`, `store.rs:463`, `settle.rs:177`, `settle.rs:407`, `settle.rs:492`,
  `settle.rs:521`, `report.rs:844`, `retention.rs`. A new variant reads as "not Open" at every one, which
  fails closed and is the right default — but silently, so nobody is told a case was added.
- **The renderers.** `report.rs:1462` is `format!("state: {:?}", bundle.state)`, `report.rs:1646` is
  `format!("Warrant {} — {:?}", ...)`, and `stop::render_cli` prints `format!("state: {:?} -> {:?}")`
  (`rust/warrant/src/stop.rs:967-970`). Debug formatting means a new variant renders as its bare Rust
  identifier with **no tier word, no caveat and no disclosure**, on the surface an operator reads. And
  `notify::Notification.state` is a free `String` (`rust/warrant/src/notify.rs:279`), so a new state word
  ships to a third-party webhook with no schema break and no reader that knows it.

A fifth variant would therefore arrive as a silent word on the loudest surfaces in the product. That is
the "worse than none" case, and the reason for the decision:

> **All three outcomes are recorded as `Ending` values inside one signed `OutcomeRecord`. The warrant's
> lifecycle keeps its four states.** A run that stops, abstains or asks lands in `Held`, because `Held`
> already means the exact thing all three need: the run is over and the staged work is preserved for a
> decision the settle authority still has to make.

Three further reasons, each checkable:

1. **`Stopped` already exists.** It is `Held` plus a signed `StopRecord` (`stop.rs:264`,
   `stop.rs:586-601`). A `Stopped` variant would duplicate it and would put every `matches!(_, Held)` site
   into scope for an audit that buys nothing.
2. **`AwaitingClarification` is not terminal.** A run resumes after the answer. As a lifecycle variant,
   `(Open, AwaitingClarification)` is legal via line 599 and `(AwaitingClarification, Open)` is refused by
   line 603 — the warrant would be stranded by the very arm that makes new variants safe.
3. **A terminal abstention would strand the staged work.** Nothing may leave `Settled` or `Void`, so an
   `Abstained` terminal state would make the staged queue unreleasable and unvoidable. Abstention is a
   statement about *why the run ended*; `WarrantState` is a statement about *what may still happen to the
   work*. Different questions, and they must not share an enum.

**One consequence must be fixed rather than absorbed.** Once abstention also produces `Held`, two
sentences in the product become false. `corpus.rs:204-212` describes a held warrant as *"the run ended on
its deadline or budget and the decision is still waiting"*, and `WarrantState::Held`'s own doc comment
(`lib.rs:165-167`) says *"ended on schedule (deadline or budget)"*. Both must name the third cause and
read the outcome record for it. Step 8 is that edit, and it is a test, not a comment change.

---

#### Step 0 — commands run, with real output captured on this box, 2026-09-05

Read in full, no skimming:

| Path | Lines | Why |
|---|---|---|
| `rust/warrant/src/lib.rs` | 725 | `WarrantState`, `transition`, `BoundStrength`, the unsigned-state comment. |
| `rust/warrant/src/supervise.rs` | 580 | What actually ends a run, and the platform where the link does not hold. |
| `rust/warrant/src/stop.rs` | 1067 | The record shape, the over-claim refusals, the tier language to copy. |
| `rust/warrant/src/bin/warrantor.rs` | 6747 | `cmd_stop` (1752-1869) and the usage block's stop paragraph (653-658). |
| `rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs` | 176 | I-12, whose finding this task must not appear to fix. |
| `rust/warrant/src/review.rs` | 932 | The human path that already exists. |
| `rust/warrant/src/serve.rs` | 2298-2560 | `RefusalRecord`, the thresholds, `aggregate_refusals`. |

Plus, from the plan: **Task 8.5** (task-validity attestation and objective drift), **Task 9.8**
(escalation channel), **Task 13.4** (equivalence laboratory) and **Task 13.7** (scorer isolation, already
expanded on `feat/scorer-isolation`).

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git rev-parse main
git ls-tree --name-only main rust/ | grep -c '^rust/[a-z]'
git ls-tree --name-only main rust/ | grep -E 'channel|guard'
```

```
b04164ddbdc29e001fcf4dd71f43a579cbe2c39a
40
rust/eval-guard
```

**Forty crates, and there is no `rust/channel` and no `rust/guard`.** Task 9.8's target directory does not
exist, so no step here may `cargo` against it; and guard work lives in `rust/eval-guard` plus
`python/warrantor_ml`, neither of which this task touches.

```bash
cd rust && cargo test -p warrantor-warrant --test invariants -j 2
```

```
running 84 tests
test result: ok. 66 passed; 0 failed; 18 ignored; 0 measured; 0 filtered out; finished in 0.11s
```

```bash
python tools/ci/wiring_census.py
python tools/ci/check_invariants.py
```

```
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
```

The ratchet baseline it must stay inside, verbatim from `tools/ci/invariant-ratchet.json`:

```json
  "passing_floor": 66,
  "ignored_ceiling": 18,
  "note": "The invariant attack corpus for I-01..I-12. `passing_floor` may only rise; `ignored_ceiling` may only fall."
```

**I-12's status word, quoted from `evidence/invariants.json`, because this task sits next to it and must
not appear to move it:**

```json
{ "id": "I-12",
  "statement": "Physical systems can reach a safe state. For any cyber-physical action, there exists a kill path to a known-safe state.",
  "status": "partial",
  "gap": "The stop verb kills a local process and says so honestly as 'advisory'; the kill-switch crate (its own tokio runtime) is not linked, and no cyber-physical safe-state path exists. Task 1.3 promotes STOP_ENFORCEMENT_MODE only where a refusal is observed on that kernel." }
```

**`status` is `partial`, and it stays `partial` after this task.** I-12's single `#[ignore]` is
`rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs:167`, and it belongs to Task 1.3:

```rust
#[ignore = "I-12 partial: the kill path is advisory, so it holds only against an agent using its tools (Task 1.3, 2026-09-02)"]
fn the_kill_path_is_stronger_than_advisory() {
```

The invariant this task most nearly touches is *"there exists a kill path to a known-safe state"*, and the
seed is right that an abstention which is not a safe state is a new failure mode rather than a control. So
the standard the outcome record has to meet is I-12's own: **the state an abstention lands in must be one
the settle authority can act on without the agent's cooperation.** `Held` meets it — `transition` line 602
permits `Held -> Settled | Void`, and neither needs the agent. A terminal abstention would not have met
it, which is design reason 3 above, arrived at from the invariant rather than from taste.

**Record before writing any code:** the four-variant enum with the two terminal ones; the twelve
`matches!` sites and the three Debug renderers; the `66/0/18` and `10 of 40 / 18 edges` baselines; and the
absence of `rust/channel`. A later reader cannot reconstruct any of it from the diff.

---

#### Non-goals

1. **Not scorer or grader isolation — Task 13.7 owns it,** already expanded on `feat/scorer-isolation`.
   L11-09's verification says an abstention must be *"scored as legitimate by the grader"*. This task
   produces the outcome and its versioned scoring rule; it never touches where the grader runs, what it
   can reach, or the anti-gaming corpus. **Do not add a grader trust domain here** — 13.7 has already
   recorded that `eval-guard` performs no isolation, and a second, weaker isolation story from this task
   would be the duplicated claim the plan keeps producing.
2. **Not task validity or objective drift — Task 8.5 owns it, and it is the nearest neighbor.** 8.5 is
   `L3-01`/`L3-09`: *was this task validly granted*, checked at grant, and *has the objective drifted*,
   checked while running. This task asks a third question — *can it be done at all* — and the seed is
   right that the two must not collapse. Concretely: 8.5 owns the refusal at grant time and the drift
   measure; this task never refuses a grant and never computes a drift score. 8.5 has **not landed**.
   Where this task needs an objective it uses `claims.goal` as free text and says so.
3. **Not the escalation channel — Task 9.8 owns it, and it has not landed** (`rust/channel/` is absent
   from `git ls-tree main rust/`). This task delivers an ask over `notify.rs` and `review.rs`, which
   exist. It must not publish a latency-to-first-human-response figure, a use-rate metric, or a claim that
   an escalation is attractive: all three are 9.8's deliverables and all three are measurements this task
   cannot take.
4. **Not the equivalence laboratory — Task 13.4 owns it.** Whether the gateway path and a kernel path
   refuse the same things is 13.4's `L11-06`. This task refuses at one point, the MCP proxy, and says so;
   it must not claim two enforcement points agree.
5. **Not the approval queue — Task 11.5 owns it,** and the operator-facing review queue it builds on is
   already in `review.rs`. An ask enters the existing queue as a `Blocker`; this task adds no second queue
   and no `queue.json`, for the reason `review.rs:19-25` gives about every second copy of the truth in
   this codebase eventually disagreeing with the first.
6. **Not the causal verdict — Task 10.1 owns it.** An agent can still declare "done" falsely, and only
   `STRICT_CAUSAL` makes that checkable. That limit is written into the product text by Step 9 and is
   narrowed by nothing here.

---

#### Files

- `rust/warrant/src/outcome.rs` — **new.** `Ending`, `Missing`, `Declarant`, `OutcomeRecord`,
  `SignedOutcome`, the detector, and the two renderers. Modeled on `stop.rs` deliberately: same
  domain-separated signing shape, same over-claim refusals, same `render_limitations` section name.
- `rust/warrant/src/lib.rs` — `pub mod outcome;` beside `pub mod operators;`, and the `Held` doc comment
  at lines 165-167 rewritten to name the third cause. **No change to `WarrantState`'s variants.**
- `rust/warrant/src/corpus.rs` — lines 204-212. The held-warrant sentence is false once abstention also
  produces `Held`; it must read the outcome record. `Row::label` stays `Option<bool>` and an abstention
  stays unlabeled — an abstention is not a human decision about the work.
- `rust/warrant/src/report.rs` — **contended, coordinate.** `WarrantSection` (line 342) gains
  `ending: Option<Ending>`; the state line (1462) and the title (1646) print it.
- `rust/warrant/src/mcp_endpoints.rs` — `AgentEndpoint::tools()` (948) publishes exactly two new tools,
  `warrantor_abstain` and `warrantor_ask`, and `call` handles them.
- `rust/warrant/src/notify.rs` — `EVENTS` from `[&str; 5]` to `[&str; 7]`. The array length is the compile
  break, which lines 66-69 already describe as the intended contract.
- `rust/warrant/src/retention.rs` — a 21st `ArtifactClass::Outcomes`. `ALL_CLASSES` is
  `[ArtifactClass; 20]` at line 140 and
  `rust/warrant/tests/holdings.rs:385::every_directory_this_store_creates_is_a_known_class` fails
  otherwise.
- `rust/warrant/src/store.rs` — the `outcomes/<id>.json` line in the directory tree at lines 21-33.
- `rust/warrant/src/bin/warrantor.rs` — the usage block (653-658, beside the stop paragraph) and one new
  verb, `warrantor outcome <id>`, reading the record back and printing its limitations.
- `rust/warrant/tests/outcome.rs` — **new.** Every test below, each with its allowed control.
- `rust/warrant/tests/holdings.rs`, `rust/warrant/tests/notify.rs` — the two count assertions that must
  move with the enum and the array.
- `docs/W1-delivery-gaps.md` — a new subsection recording what an abstention does not establish.
- `docs/task-evidence/task-13.6.md`.

**Not touched:** `tools/ci/invariant-ratchet.json`, `evidence/invariants.json`,
`rust/warrant/tests/invariants/`. Reasons under Bound strength.

---

#### Consumes / Produces

**Consumes — exists on local `main` at `b04164d`, quoted with file and line:**

```rust
// rust/warrant/src/lib.rs:161 / :597
pub enum WarrantState { Open, Held, Settled, Void }
pub fn transition(&mut self, to: WarrantState) -> Result<(), WarrantError>

// rust/warrant/src/lib.rs:197 / :218 / :229
pub enum BoundStrength { Enforced, Mediated, Observed }
impl BoundStrength { pub fn word(self) -> &'static str; pub fn caveat(self) -> &'static str }

// rust/warrant/src/serve.rs:2433 / :2444 / :2505 / :2462 / :2464 / :2469
pub fn read_refusals(root: &Path, warrant_id: &str) -> RefusalLog
pub fn read_all_refusals(root: &Path) -> RefusalLog
pub fn aggregate_refusals(records: &[RefusalRecord]) -> Vec<RefusalGroup>
pub const REPEATED_OCCURRENCES: u64 = 5;
pub const SPREAD_WARRANTS: usize = 2;
pub enum RefusalSignal { BoundsProbablyWrong, RepeatedInOneRun, Isolated }

// rust/warrant/src/review.rs:57 / :74 / :460 / :470
pub const REVIEW_EVENT: &str = "review-requested";
pub enum Blocker { AwaitingDecision { .. }, AwaitingApproval { .. }, Deadlocked { why: String } }
pub fn should_announce(root: &Path, warrant_id: &str, blocker: &str) -> bool
pub fn record_request(/* ... */) -> Result<(), String>

// rust/warrant/src/notify.rs:70 / :514
pub const EVENTS: [&str; 5];
pub fn notify<T: NotifyTransport>(transport: &mut T, root: &Path, config: &NotifyConfig,
                                  notification: &Notification, now: u64)
    -> Result<Vec<(String, Delivery)>, String>

// rust/warrant/src/stop.rs:639 / :656 / :705 / :822 / :940 / :1056
pub fn record_digest(record: &StopRecord) -> Result<String, StopError>
pub fn sign(stored: &StoredWarrant, outcome: &StopOutcome, reason: Option<&str>,
            key: &SigningKey, now: u64) -> Result<SignedStop, StopError>
pub fn verify_stop(signed: &SignedStop) -> Result<(), StopError>
pub fn verify_stop_signed_by(signed: &SignedStop, anchor: &VerifyingKey) -> Result<(), StopError>
pub fn contained(signed: &SignedStop) -> bool
pub fn render_limitations(signed: &SignedStop) -> String

// rust/warrant/src/daemon.rs:106
pub struct CompletionRecord { pub warrant_id: String, pub pid: u32, pub exit_code: i32,
                              pub expired: bool, pub finished_at: u64 }

// rust/warrant/src/staging.rs:460 / :466
pub fn is_empty(&self) -> bool;  pub fn len(&self) -> usize

// rust/warrant/src/mcp_endpoints.rs:1187
pub fn agent_endpoint_for(stored: &StoredWarrant, staged_path: PathBuf,
                          mode: ProxyMode, now: fn() -> u64)
    -> Result<AgentEndpoint, WarrantError>

// rust/warrant/src/retention.rs:140
pub const ALL_CLASSES: [ArtifactClass; 20];
```

**Does not exist. Named with its owner and whether that task has landed:**

- **`rust/channel/` and everything in it — Task 9.8, NOT LANDED.** Verified absent from
  `git ls-tree --name-only main rust/`. What "ask" needs from 9.8 and does not have: a *measured* latency
  to first human response, a use-rate metric with zero rendered as a warning, and the Tier B property that
  an agent cannot proceed while an escalation is open **across every effect**. What "ask" does not need
  from 9.8, and this is the seed's correction: a delivery path. `notify.rs` plus `review::REVIEW_EVENT` is
  one, and it is already in the product. **So an ask can be recorded and delivered without 9.8, and the
  honest description of it is "queued to a webhook and entered in the local review queue", never
  "escalated to a human".** Step 9 writes that sentence.
- **A task-validity attestation — Task 8.5, not landed.** Until it exists, `detect` reads `claims.goal`
  as free text and the record's `objective_was_attested` field is `false` with a reason.
- **A causal verdict — Task 10.1, not landed.** The control for a false "done".
- **A digest-pinned scoring-rule registry — Task 13.5** (`L11-07`, `L11-11`). L11-09 asks that the
  grader's scoring rule be *"versioned and visible"*: this task ships a version-string constant and a
  `bom_digest: Option<String>` that stays `None` until 13.5 lands.

**Produces:**

```rust
// rust/warrant/src/outcome.rs  (new)

/// Wire formats, pinned from the first release like every other record in this crate.
pub const OUTCOME_RECORD_FORMAT: &str = "warrantor.outcome-record/1";
pub const OUTCOME_EXPORT_FORMAT: &str = "warrantor.outcome-export/1";
/// The versioned scoring rule L11-09 asks to be visible. Rendered, never inferred.
pub const OUTCOME_SCORING_RULE: &str = "warrantor.outcome-scoring/1";

/// Why a run ended, when the answer is neither success nor failure.
///
/// NOT a `WarrantState` variant. All three land the warrant in `Held`; see the design note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ending { Stopped, Abstained, AwaitingClarification }

/// Exactly what was not there. Never a free-text sentence: a reader must be able to diff it
/// against the warrant's bounds and see the difference without reading prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "missing", rename_all = "kebab-case")]
pub enum Missing {
    Tool { name: String, refused_by_bound: String, occurrences: u64 },
    EgressHost { host: String, occurrences: u64 },
    WritePath { glob: String },
    Budget { cents_short: u64 },
    Environment { what: String, observed: String },
}

/// Who said so. An abstention asserted by a detector is a different fact from one the agent
/// declared, and a reader who cannot tell them apart cannot weigh either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "said_by", rename_all = "kebab-case")]
pub enum Declarant {
    Agent { subject: String },
    Operator { id: String },
    Detector { rule: &'static str, threshold_occurrences: u64, threshold_warrants: usize },
}

pub struct OutcomeRecord {
    pub format: String, pub warrant_id: String, pub goal: String,
    pub ending: Ending, pub at: u64,
    pub said_by: Declarant,
    /// Never empty for `Abstained`. `sign` refuses an empty list.
    pub missing: Vec<Missing>,
    pub question: Option<String>,          // `AwaitingClarification` only
    pub state_before: WarrantState, pub state_after: WarrantState,
    pub staged_effects: usize, pub completion: Option<CompletionRecord>,
    pub objective_was_attested: bool,      // false until Task 8.5
    pub scoring_rule: String, pub bom_digest: Option<String>,
    pub limitations: Vec<String>,          // never empty; `sign` refuses an empty list
}

pub struct SignedOutcome { /* record_digest, record, signature_algorithm,
                              signature_public_key, signature_value -- the SignedStop shape */ }

/// Read the durable refusal log and say whether this environment cannot satisfy this task.
/// `None` when the evidence does not reach the existing threshold. Never a bare bool.
pub fn detect(refusals: &RefusalLog, bounds: &WarrantBounds, staged: usize,
              completion: Option<&CompletionRecord>) -> Option<Finding>;

/// The two readings the same evidence supports, kept apart on purpose.
pub enum Diagnosis {
    BoundsProbablyWrong { remedy: String },
    EnvironmentProbablyBroken { remedy: String },
}
pub struct Finding { pub diagnosis: Diagnosis, pub missing: Vec<Missing>, pub sentence: String,
                     pub recommended_narrowing: WarrantBounds }

/// The rendered threshold sentence, interpolated from serve's constants, never typed.
pub fn threshold_sentence() -> String;
/// Which of the three causes put a warrant in Held, or `None` for "cannot say".
pub fn held_because(root: &Path, warrant_id: &str) -> Option<Ending>;
pub fn render_held_reason(root: &Path, warrant_id: &str) -> String;

pub fn sign(stored: &StoredWarrant, record: OutcomeRecord, key: &SigningKey)
    -> Result<SignedOutcome, OutcomeError>;
pub fn verify_outcome(signed: &SignedOutcome) -> Result<(), OutcomeError>;
pub fn verify_outcome_signed_by(signed: &SignedOutcome, anchor: &VerifyingKey)
    -> Result<(), OutcomeError>;
pub fn render_cli(signed: &SignedOutcome) -> String;
pub fn render_limitations(signed: &SignedOutcome) -> String;
```

---

#### Bound strength

Four claims, four different answers. Stated separately because they are held by different things, and
because the seed's single Tier B for all of them is the defect corrected above.

**Detection (L11-08) — Tier C, observed.** `detect` reads `refusals/<id>.jsonl` after sessions have ended.
Nothing refuses an action as it happens; there is no line of code that stops an agent from attempting the
impossible task again. It is a signal, and the word for a signal in this repository is `Observed`. Reuse
`BoundStrength::Observed.caveat()` verbatim — *"measured and reported after the fact; nothing refuses the
action as it happens"* — rather than writing a new sentence.

**L11-08's authority narrowing — not implemented, and deliberately.** The catalog item asks that *"the
task's authority [be] narrowed until it is repaired"*. `Finding::recommended_narrowing` produces the
narrowed `WarrantBounds`; an operator applies it through the existing `Warrant::delegate`
(`rust/warrant/src/lib.rs:497`), which already checks intersection at issue time. **Automatic narrowing
from an observed signal is refused here**, for the reason Task 8.5's own Bound strength gives: treating a
heuristic score as an enforcement input creates pressure to game the score. Step 9 records the
non-implementation as a decision, not an omission, so the next reader does not close it as a gap.

**`Abstained` — Tier B, chokepoint, and the refusing line already exists.** Once the outcome record is on
disk and the warrant is `Held`, a **new** supervised session for that warrant is refused at the moment it
is attempted, by `rust/warrant/src/mcp_endpoints.rs:1193-1198`:

```rust
    if !matches!(stored.warrant.state, WarrantState::Open) {
        return Err(crate::WarrantError::Encode(format!(
            "warrant {} is {:?}, not Open; there is nothing to police",
            stored.warrant.claims.id, stored.warrant.state
        )));
```

That is a refusal at the moment of attempt, not a containment observed at settle time, so `Mediated` is
the right word — and this task must observe it by calling the function rather than by repeating its
condition, exactly as `stop::execute` does at `stop.rs:288-289`. **What escapes, verbatim from `stop.rs`'s
module doc (lines 42-45):** an MCP session already running outside the supervisor's process tree *"is not
re-checked against warrant state and continues until it exits"*, and capability tokens already minted
*"stay valid for up to `CAPABILITY_TTL_SECONDS` seconds"*. Add the third: a shell reaches the network
without passing the proxy at all. **No netns, no seccomp and no firewall exists anywhere in this
repository.**

**`AwaitingClarification` — Tier B for the one blocked effect, Tier C for the delivery.** While an ask is
open, `AgentEndpoint::call` refuses the specific tool the ask names, at the proxy, at the moment of
attempt. It does **not** block every other effect — that is 9.8's property and this task must not claim
it. Delivery is a webhook: `notify` queues a failure and retries at the next notification
(`notify.rs:31-42`), so an unreachable receiver means the record exists and the human does not know.
Observed, best-effort, and the record says so.

**The state machine — no tier word at all.** `Warrant.state` is not covered by the warrant's signature
(`lib.rs:399-401`, quoted above) and the store is same-UID reachable
(`docs/W1-delivery-gaps.md:620-622`). A tier word on the state field would be a claim about a mutable
byte. What is tamper-evident is the **record**: Ed25519 over the canonical digest, with the same
domain-separated, length-prefixed shape as `stop.rs:625-632`, and the same offline verify path.

**The sentence that must appear in the product wherever an outcome is rendered:**

> This record states that a run ended in a stop, an abstention or a question, who said so, and exactly
> what was reported missing. It does **not** establish that the task was truly impossible, that the
> agent's abstention was honest, or that any human read the question. The warrant's own lifecycle state is
> covered by no signature, no netns, seccomp or firewall stands behind the refusal that blocks a new
> session, a session already running outside the supervisor's process tree is unaffected, and an agent
> that declares "done" falsely is outside what this record can see.

**Orphan accounting — nothing changes, and that is checked rather than assumed.** This task adds no crate,
links no crate, and touches no `Cargo.toml` `[dependencies]` block. The census must print
`wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges` unchanged in Step 11.
**This task adds no orphan.** It also does not reduce the orphan count, and pretending an outcome record
wires `warrantor-kill-switch` would be the mislabeling this repository has already shipped once.

**No new trust root.** The record is signed with the **issuer** key already at `<root>/keys/issuer.key`,
loaded exactly as `cmd_stop` loads it (`bin/warrantor.rs:1768-1772`) and for the same stated reason: an
outcome releases nothing and performs nothing, so loading settle authority to record it would put that key
in a process with no business holding it. `verify_outcome_signed_by(&signed, &anchor)` pins the reader's
own out-of-band key, mirroring `verify_stop_signed_by` (`stop.rs:822`). **What that establishes:** this
store, holding this issuer key, recorded this ending at this time. **What it does not establish:** that
the ending is true, that any third party agrees, or that the key belongs to whom the reader thinks — the
anchor is the reader's and is never defaulted from a local store.

**Invariant accounting — this task converts no recorded violation, and must not appear to.** It touches no
`#[ignore]` in `rust/warrant/tests/invariants/`. I-12's single ignore
(`i12_safe_state_is_reachable.rs:167`, quoted in Step 0) is Task 1.3's, and its status stays `partial`.
That has a mechanical consequence, because `tools/ci/check_invariant_ratchet.py:159-165` fails on an
*improvement* as well as on a regression:

```python
    if result.passed > baseline.passing_floor or result.ignored < baseline.ignored_ceiling:
        problems.append(f"the corpus improved ({result.passed} passing, {result.ignored} ignored) and "
                        f"... still says {baseline.passing_floor}/{baseline.ignored_ceiling}. Raise the "
                        f"ratchet in the same commit, or the floor stops tracking reality.")
```

So **a single new passing test placed in `rust/warrant/tests/invariants/` would fail the build.** Every
test in this task goes in `rust/warrant/tests/outcome.rs`, and Step 11 reads the corpus's own
`test result:` line to confirm `66 passed; 0 failed; 18 ignored` rather than computing it.

---

#### Exit gate

**One command decides:**

```bash
cd M:/wt-13.6/rust && cargo test -p warrantor-warrant --test outcome -j 2
```

It passes only when the output ends `test result: ok.` with **zero ignored**, and includes both halves of
every pair below: `a_broken_environment_ends_in_a_recorded_abstention` together with its control
`a_healthy_run_produces_no_outcome_record`, and
`an_agent_that_abstains_still_cannot_settle_its_own_warrant` together with its control
`an_agent_may_abstain_and_the_abstention_is_recorded`. A refusal test that passes while its control is
absent or ignored proves only that something refuses everything.

---

- [ ] **Step 1 — Worktree from local `main`, not `origin/main`; confirm the baselines.**
  ```bash
  export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
  cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
  git worktree add M:/wt-13.6 -b feat/structured-abstention main
  cd M:/wt-13.6 && export CARGO_TARGET_DIR=M:/wt-13.6-target
  git rev-parse HEAD                                           # expect b04164d...
  git ls-tree --name-only main rust/ | grep -c '^rust/[a-z]'    # expect 40
  git ls-tree --name-only main rust/ | grep -E 'channel|^rust/guard$'   # expect no output
  python tools/ci/wiring_census.py                             # expect 10 of 40 over 18 path edges
  cd rust && cargo test -p warrantor-warrant --test invariants -j 2 | tail -1
  ```
  **`main`, not `origin/main`.** `origin/main` is stale at `e4b5f10` and lacks the egress metadata floor
  fix, Task 1.1 with its mode-escalation correction, Task 1.5 and the US-English CI gate. Branching from
  it would re-open a closed mislabeling. **Test intent:** that this branch starts from the repository the
  other lanes have, and that no step below assumes an absent crate — the shared checkout carries untracked
  crates `main` does not have, and a task that reads the working tree by accident dies at its first
  `cargo` call. If the census prints anything but `10 of 40`, another lane landed a wire: re-derive Step
  11's expected numbers, never edit the assertion to match.

- [ ] **Step 2 — Write down the enum decision and pin it with a test, before any other code.**
  The reader census belongs in `docs/task-evidence/task-13.6.md` first: four variants, two terminal
  (`Settled`, `Void`); four exhaustive matches that would break loudly; twelve `matches!` guards that
  would fail closed silently; three Debug renderers that would print a bare identifier; and
  `notify::Notification.state` as a free `String`. Then the pin:
  ```rust
  #[test]
  fn the_lifecycle_still_has_four_states_and_an_ending_is_not_one_of_them() {
      // The decision this task turns on, made executable so a later hand cannot quietly add a
      // fifth variant and inherit three silent renderers. Serde's own names are the wire words.
      for (state, word) in [(WarrantState::Open, "\"open\""), (WarrantState::Held, "\"held\""),
                            (WarrantState::Settled, "\"settled\""), (WarrantState::Void, "\"void\"")] {
          assert_eq!(serde_json::to_string(&state).unwrap(), word);
      }
      // Terminal means nothing legal leaves it, and THAT is the property -- not the count.
      for terminal in [WarrantState::Settled, WarrantState::Void] {
          for to in [WarrantState::Open, WarrantState::Held, WarrantState::Settled, WarrantState::Void] {
              let mut w = fixture_warrant();
              w.state = terminal;
              assert!(w.transition(to).is_err(), "{terminal:?} -> {to:?} must be refused");
          }
      }
      // Held is NOT terminal: the settle authority can still act without the agent. That is what
      // makes an abstention a safe state under I-12 rather than a stall.
      let mut held = fixture_warrant();
      held.state = WarrantState::Held;
      assert!(held.transition(WarrantState::Settled).is_ok());
      // And an Ending is a separate vocabulary, with no overlap in the wire words above.
      assert_eq!(serde_json::to_string(&Ending::Abstained).unwrap(), "\"abstained\"");
  }
  ```
  **Test intent:** the second loop is the one that earns its place. It fails the day anybody adds a variant
  reachable out of `Settled`, and it documents *why* `Held` was chosen by asserting the property the
  choice rests on rather than the choice itself.

- [ ] **Step 3 — Failing test: a broken environment ends in a recorded abstention, paired with a healthy control.**
  ```rust
  #[test]
  fn a_broken_environment_ends_in_a_recorded_abstention() {
      let root = tempdir("broken");
      let stored = fixture_stored(&root, &["gh_pr_create"]);
      // Five refusals of one tool across two warrants: the EXISTING threshold, reached honestly by
      // writing the log the proxy writes, not by constructing a Finding directly.
      seed_refusals(&root, &[("w-1", "gh_pr_create", 3), ("w-2", "gh_pr_create", 2)]);
      let log = serve::read_all_refusals(&root);
      let completion = CompletionRecord { warrant_id: "w-1".into(), pid: 1, exit_code: 0,
                                          expired: false, finished_at: NOW };
      let finding = outcome::detect(&log, &stored.warrant.claims.bounds, 0, Some(&completion))
          .expect("five refusals across two warrants must reach the stated threshold");
      let signed = outcome::sign(&stored, outcome::abstain_from(&finding, NOW), &issuer_key())
          .expect("an abstention with a populated missing list must sign");
      assert_eq!(signed.record.ending, Ending::Abstained);
      assert_eq!(signed.record.state_after, WarrantState::Held);
      outcome::verify_outcome(&signed).expect("the record verifies offline");
  }

  #[test]
  fn a_healthy_run_produces_no_outcome_record() {
      // The control. Without it the assertion above passes on a detector that abstains always,
      // which is the failure mode L11-09's own residual names: a poorly calibrated reward makes
      // abstention the lazy default.
      let root = tempdir("healthy");
      let stored = fixture_stored(&root, &["gh_pr_create"]);
      let log = serve::read_all_refusals(&root);          // empty
      let completion = CompletionRecord { warrant_id: "w-1".into(), pid: 1, exit_code: 0,
                                          expired: false, finished_at: NOW };
      assert!(outcome::detect(&log, &stored.warrant.claims.bounds, 3, Some(&completion)).is_none(),
              "a run that staged three effects and hit no wall must not be called impossible");
  }
  ```
  **Test intent:** the pair is the whole point. `exit_code: 0` is identical in both, which is exactly the
  indistinguishability the anchor names — the discriminator is the refusal log plus the staged count, never
  the exit code, and the control proves the discriminator has two answers.

- [ ] **Step 4 — Failing test: the receipt names what was missing, and an empty list is refused.**
  ```rust
  #[test]
  fn an_abstention_that_names_nothing_missing_is_refused_at_signing_time() {
      let root = tempdir("empty-missing");
      let stored = fixture_stored(&root, &["gh_pr_create"]);
      let mut record = fixture_record(Ending::Abstained);
      record.missing = Vec::new();
      let err = outcome::sign(&stored, record, &issuer_key()).expect_err("must refuse");
      assert!(matches!(err, outcome::OutcomeError::OverClaim(_)),
              "an abstention with no named cause is a shrug with a signature on it");

      // The allowed control: the same record with one Missing entry signs, so the refusal above is
      // about the empty list and not about the shape.
      let mut ok = fixture_record(Ending::Abstained);
      ok.missing = vec![Missing::Tool { name: "gh_pr_create".into(),
                                        refused_by_bound: "tools".into(), occurrences: 5 }];
      let signed = outcome::sign(&stored, ok, &issuer_key()).expect("one named cause is enough");
      assert!(outcome::render_cli(&signed).contains("gh_pr_create"),
              "the surface an operator reads must name the thing that was not there");

      // And the same rule for limitations, asserted here so a later hand cannot relax one alone.
      let mut no_limits = fixture_record(Ending::Abstained);
      no_limits.limitations = Vec::new();
      assert!(outcome::sign(&stored, no_limits, &issuer_key()).is_err(),
              "a record claiming no blind spots is evidence about the record, not about the run");
  }
  ```
  **Test intent:** copies `stop.rs`'s over-claim doctrine — a record the product cannot honestly produce is
  refused at construction, never filtered at render — and copies the conformance suite's empty-`limitations`
  rule (`stop.rs:130-133`) for the same stated reason.

- [ ] **Step 5 — Failing test: the threshold sentence is generated from the constants, never typed.**
  ```rust
  #[test]
  fn the_detectors_stated_number_of_attempts_comes_from_the_constant_that_decides_it() {
      // A rendered number is gated against its record. L11-08 asks for a flag "within a stated
      // number of attempts"; the number IS serve::REPEATED_OCCURRENCES, and the sentence must
      // interpolate it so editing the constant cannot leave the prose behind.
      let sentence = outcome::threshold_sentence();
      assert!(sentence.contains(&serve::REPEATED_OCCURRENCES.to_string()));
      assert!(sentence.contains(&serve::SPREAD_WARRANTS.to_string()));
      // And the record carries the thresholds it was decided under, so a finding read next year is
      // readable against the numbers that were in force when it was taken.
      let signed = fixture_signed(Ending::Abstained);
      match signed.record.said_by {
          Declarant::Detector { threshold_occurrences, threshold_warrants, rule } => {
              assert_eq!(threshold_occurrences, serve::REPEATED_OCCURRENCES);
              assert_eq!(threshold_warrants, serve::SPREAD_WARRANTS);
              assert_eq!(rule, outcome::OUTCOME_SCORING_RULE);
          }
          other => panic!("a detector finding must say it was a detector: {other:?}"),
      }
      // Task 13.5 owns the bill of materials. Until it lands this stays None, never a placeholder.
      assert_eq!(signed.record.bom_digest, None);
  }
  ```
  **Test intent:** this is also L11-09's *"the grader's scoring rule for the outcome is versioned and
  visible"*, discharged as a constant inside the signed record rather than as a promise in prose. The last
  assertion is the one that stops a plausible mistake: a `bom_digest` filled with a hash of nothing would
  read as provenance.

- [ ] **Step 6 — Failing test: no warrant sits in `Held` without a record saying how it got there.**
  The seed's Step 5 asks that no code path reach a terminal state without a receipted outcome. Restated
  against what the code can actually check, because `Held` is not terminal and `Settled`/`Void` are reached
  by the settle authority with receipts of their own:
  ```rust
  #[test]
  fn a_warrant_in_held_always_has_a_record_saying_which_of_the_three_causes_put_it_there() {
      let root = tempdir("held-causes");
      // Cause 1, the deadline: a completion record with expired = true, and no outcome record.
      let a = held_via_deadline(&root, "w-a");
      // Cause 2, a stop: a signed StopRecord in stops/.
      let b = held_via_stop(&root, "w-b");
      // Cause 3, an abstention: a signed OutcomeRecord in outcomes/.
      let c = held_via_abstention(&root, "w-c");
      for id in [&a, &b, &c] {
          assert!(outcome::held_because(&root, id).is_some(),
                  "{id} is Held with nothing on disk explaining why");
      }
      // The refusal half: a warrant forced to Held with nothing written is reported as unexplained
      // rather than as a deadline, which is the default a reader would otherwise assume from the
      // doc comment this step rewrites.
      let d = held_with_nothing_written(&root, "w-d");
      assert_eq!(outcome::held_because(&root, &d), None);
      assert!(outcome::render_held_reason(&root, &d).contains("cannot say"),
              "an unexplained hold must read as unknown, never as 'ended on its deadline'");
  }
  ```
  **Test intent:** the fourth case is the finding. Today every `Held` warrant renders as a deadline or
  budget hold because that is what the doc comment and `corpus.rs` say; after this task there are three
  causes, so an absent record must render as "cannot say" — the same discipline
  `review::Waiting::staged_effects` already uses for an unreadable queue (`review.rs:137-141`).

- [ ] **Step 7 — Failing test: an agent may abstain and ask, and still cannot settle.**
  ```rust
  #[test]
  fn an_agent_may_abstain_and_the_abstention_is_recorded() {
      // The allowed control for the refusal below, and the reason for publishing the tool at all:
      // an agent with no way to say "this cannot be done" has to invent one.
      let root = tempdir("agent-abstain");
      let stored = fixture_stored(&root, &["gh_pr_create"]);
      let mut endpoint = mcp_endpoints::agent_endpoint_for(
          &stored, root.join("staged/w-1.jsonl"), ProxyMode::Enforce, now).expect("Open warrant");
      let published: Vec<String> = endpoint.tools().into_iter().map(|t| t.name).collect();
      assert!(published.contains(&"warrantor_abstain".to_string()));
      assert!(published.contains(&"warrantor_ask".to_string()));
      let reply = endpoint.call("warrantor_abstain",
          &json!({"missing": [{"missing": "tool", "name": "gh_issue_create",
                               "refused_by_bound": "tools", "occurrences": 5}]}));
      assert!(reply.is_ok(), "abstaining is strictly less authority than continuing");
  }

  #[test]
  fn an_agent_that_abstains_still_cannot_settle_its_own_warrant() {
      // The security property the whole crate rests on, re-asserted at the new surface. Three
      // checks, because three different things must hold: no settle tool is published, the
      // act-scoped key is not the settle authority, and a new session is refused after that.
      let root = tempdir("agent-cannot-settle");
      let stored = fixture_stored(&root, &["gh_pr_create"]);
      let mut endpoint = mcp_endpoints::agent_endpoint_for(
          &stored, root.join("staged/w-1.jsonl"), ProxyMode::Enforce, now).expect("Open warrant");
      let published: Vec<String> = endpoint.tools().into_iter().map(|t| t.name).collect();
      for forbidden in ["warrantor_settle", "warrantor_void", "warrantor_grant"] {
          assert!(!published.contains(&forbidden.to_string()),
                  "{forbidden} must not be reachable from a supervised session");
      }
      let agent_key = SigningKey::generate(&mut rand_core::OsRng);
      assert!(stored.warrant.verify_settle(&agent_key.verifying_key()).is_err(),
              "settle authority is a separate keypair the agent never holds");
      let mut after = stored.clone();
      after.warrant.transition(WarrantState::Held).expect("Open -> Held");
      assert!(mcp_endpoints::agent_endpoint_for(
          &after, root.join("staged/w-1.jsonl"), ProxyMode::Enforce, now).is_err(),
          "a new supervised session on a held warrant is refused where that is decided");
  }
  ```
  **Test intent:** publishing anything to a supervised session runs against this endpoint's central design
  decision, so the pair states the boundary precisely — `warrantor_abstain` and `warrantor_ask` grant no
  authority, perform no effect, and cannot reach `Settled`. The last assertion observes the refusal by
  calling `agent_endpoint_for` rather than by re-testing its condition, the same reason `stop.rs:288-289`
  gives for calling it instead of repeating the check.

- [ ] **Step 8 — Failing test: the two sentences that become false are fixed, not absorbed.**
  ```rust
  #[test]
  fn a_held_warrant_is_no_longer_described_as_a_deadline_hold_when_it_abstained() {
      // corpus.rs:204-212 today reads "the warrant is held: the run ended on its deadline or
      // budget and the decision is still waiting". After this task that is false a third of the
      // time, and a training-corpus row carrying a false reason is worse than an absent one.
      let root = tempdir("held-sentence");
      let id = held_via_abstention(&root, "w-c");
      let states = BTreeMap::from([(id.clone(), WarrantState::Held)]);
      let rows = corpus::rows_from(&fixture_guard_log(&id), &states);
      let why = rows[0].why.as_deref().expect("an unlabeled row must say why");
      assert!(why.contains("abstain"), "the row must name the cause that actually held it: {why}");
      assert!(!why.contains("deadline"), "and must not assert a cause that did not happen");
      assert_eq!(rows[0].label, None,
                 "an abstention is not a human decision about the work, so it stays unlabeled");
  }
  ```
  **Test intent:** the third assertion stops a plausible mistake. It is tempting to label an abstention as
  a negative example; `corpus.rs:15-20` already names that trap for the guard's own verdict, and an
  abstention is the agent's verdict about itself. `Row::label` stays `Option<bool>` and stays `None`.
  Rewrite `WarrantState::Held`'s doc comment (`lib.rs:165-167`) in the same commit so the code's own
  description of `Held` names all three causes.

- [ ] **Step 9 — Write the four limits into the product text and the gaps ledger.**
  In `outcome::render_limitations`, in `docs/W1-delivery-gaps.md`, and in the evidence file — one place
  each, worded identically:
  1. **A false "done" is out of scope.** An agent can still report success it did not achieve; the control
     is **Task 10.1**'s causal verdict, and until it lands nothing here checks a completion claim. Name the
     task, never "future work".
  2. **Authority is not narrowed automatically.** `recommended_narrowing` is a suggestion an operator
     applies through `Warrant::delegate`. The reason is Task 8.5's: a heuristic that refuses creates
     pressure to game the heuristic.
  3. **An ask is delivered, not escalated.** Queued to a webhook and entered in the local review queue. No
     latency to first human response is measured and no use-rate is published — both are **Task 9.8**,
     which has not landed.
  4. **The objective is free text.** No validity attestation exists until **Task 8.5**;
     `objective_was_attested` is `false`, carrying that reason.
  **Test intent:** a static test asserts `render_limitations` names Task 10.1, Task 9.8 and Task 8.5 by
  number, and that `limitations` is non-empty in every signed record. Three statements of one limit drift
  apart; this plan has already produced one duplicated claim that way.

- [ ] **Step 10 — Failing test: the record verifies offline, refuses an over-claim, and adds no trust root.**
  ```rust
  #[test]
  fn an_exported_outcome_verifies_offline_and_refuses_a_record_it_could_not_have_produced() {
      let signed = fixture_signed(Ending::Abstained);
      outcome::verify_outcome(&signed).expect("the honest record verifies with no store and no keys");

      // Digest binding: mutate one field and the signature must stop covering it.
      let mut tampered = signed.clone();
      tampered.record.missing.clear();
      assert!(matches!(outcome::verify_outcome(&tampered), Err(outcome::OutcomeError::Digest { .. })));

      // Over-claim: a record asserting the objective was attested, when no attestation exists.
      let mut claims_attested = signed.clone();
      claims_attested.record.objective_was_attested = true;
      let err = outcome::verify_outcome(&claims_attested).expect_err("must refuse");
      assert!(matches!(err, outcome::OutcomeError::OverClaim(_)),
              "no task-validity attestation exists on this branch, so a record claiming one is not ours");

      // No new trust root: the reader's pin is the reader's, never defaulted from the store.
      let stranger = SigningKey::generate(&mut rand_core::OsRng);
      assert!(outcome::verify_outcome_signed_by(&signed, &stranger.verifying_key()).is_err());
      outcome::verify_outcome_signed_by(&signed, &issuer_key().verifying_key())
          .expect("pinned to the key that signed it, it verifies");
  }
  ```
  **Test intent:** four properties, and the third is specific to this task. `objective_was_attested: true`
  is unproducible here because Task 8.5 has not landed, so `verify_outcome` refuses it — the same shape as
  `verify_stop` refusing an `elicitation` (`stop.rs:777-783`). The pair at the end is the no-new-trust-root
  discipline: the weaker thing built here is "this store said this", and the stranger's key proves the pin
  is load-bearing rather than decorative. Wire `warrantor verify <file>` to accept the new format alongside
  the report and stop exports, so `--issuer` is not a flag silently ignored for a third artifact.

- [ ] **Step 11 — Full gate on every language touched, counts read rather than computed, evidence file, `git commit -s`.**
  ```bash
  cd M:/wt-13.6/rust
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -j 2 -- -D warnings
  cargo test -p warrantor-warrant --test outcome -j 2
  cargo test --workspace --all-targets -j 2
  cd M:/wt-13.6
  python tools/ci/check_invariant_ratchet.py
  python tools/ci/wiring_census.py
  python tools/ci/check_invariants.py
  python tools/ci/check_docs.py
  python tools/ci/check_us_english.py main
  git commit -s
  ```
  Expected, and **read out of the output rather than assumed**:
  ```
  invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
  wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
  invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
  ```
  All three unchanged: this task converts no invariant, wires no crate and adds no orphan. If the ratchet
  prints anything else, a test landed in `rust/warrant/tests/invariants/` by mistake — move it to
  `tests/outcome.rs` rather than raising the floor, because a floor raised with no converted `#[ignore]`
  records an improvement that did not happen. Two count assertions move with this commit and must be inside
  it: `ALL_CLASSES` 20 to 21 in `retention.rs` with `tests/holdings.rs`, and `EVENTS` 5 to 7 in `notify.rs`
  with `tests/notify.rs`. Rust, Python and docs are all touched, so all three gates run.
  **Test intent:** `docs/task-evidence/task-13.6.md` must record five things a later reader cannot
  reconstruct from the diff — the four-variant enum with `Settled` and `Void` named as the only terminal
  states; the reader census from Step 2 in all three of its classes; the corrected premise, in the code's
  own words, that the agent never transitions the warrant and `state` is not signed, so the seed's Tier B
  for the state machine was wrong; the verbatim I-12 ignore with its status word `partial` and the sentence
  saying this task did not move it; and the four limits from Step 9 with the task numbers that own them.

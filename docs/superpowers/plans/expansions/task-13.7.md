### Task 13.7: Scorer/grader isolation and anti-gaming; reward-hacking monitor (L11-10, L11-12)

**Anchor.** From `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html`, quoted verbatim
with the attribute line so nothing is softened:

```html
<article class="item" id="L11-10" data-stratum="L11" data-plane="A" data-status="none" data-novelty="novel" data-wave="W2" data-loop="L5">
  <h4>Scorer/grader isolation and anti-gaming validation</h4>
  <p class="what">The component that grades an agent's answer runs in a separate trust domain the
  agent cannot read, write or reach over the network, and every grader is validated against an
  anti-gaming corpus before use: known shortcuts, scorer-information leaks and transcript
  manipulation must score as failures.</p>
  <p class="verify"><b>Verification</b> An agent instance granted every permission in its warrant
  still cannot reach the grader's storage or endpoint; a seeded scorer-leak transcript scores as a
  failure; both results are receipted per grader version.</p>

<article class="item" id="L11-12" data-stratum="L11" data-plane="A" data-status="none" data-novelty="novel" data-wave="W3" data-loop="L5">
  <h4>Reward-hacking monitor with environment-owner escalation</h4>
  <p class="what">Population-level monitoring during training for the signature of proxy
  optimization: out-of-bounds probing rate, unauthorized cross-run coordination, scorer-information
  references and transcript manipulation, trended per training run with a mandatory escalation to
  the environment owner at a registered threshold. Advisory to the humans, mandatory as a stop
  trigger.</p>
  <p class="verify"><b>Verification</b> Replaying a training run's traces with a rising probing rate
  crosses the registered threshold and produces an escalation receipt and a checkpoint quarantine
  before the run's end; the threshold is registered before the run, never tuned after.</p>
```

Both are `status=none`. **Correction to the seed, which is the first of three.** The seed's anchor
line reads *"L11-10 `status=none` `core` W2"*. L11-10 is `data-novelty="novel"`, not `core`. The
distinction is load-bearing in this plan: a `core` item is something the substrate must hold itself,
a `novel` item is something nobody has built and where an unearned claim is therefore unrebuttable
by comparison. Written as `core`, this task reads as wiring; written as `novel`, it reads as the
thing it is — a claim this repository would be the first to make, which is exactly where it has
overstated before.

**A grader the agent can reach is a grader the agent will optimize.** That argument survives every
finding below. What does not survive is the seed's next sentence.

---

#### What the code actually shows — the seed's premise is contradicted twice

Read on `origin/main` at `e4b5f10`, 2026-09-05. **`premise_contradicted = true`.**

The seed says: *"So the isolation this task needs may exist and be unreachable."* Neither half holds.

**(1) The isolation does not exist. `eval-guard` measures nothing, and says so about itself.**
`rust/eval-guard/src/lib.rs` is 361 lines and its own module documentation is the refutation
(lines 6-21, verbatim):

```rust
//! ## What this crate does NOT do (AX-46)
//!
//! **It does not perform the checks.** [`run_preflight`] takes [`CheckResults`] as an *input*:
//! four booleans the caller has already decided. This crate verifies they are all true and emits
//! a signed [`SandboxAttestation`] over them. It has no eBPF, opens no sockets, inspects no
//! namespaces, and cannot observe the sandbox at all.
//!
//! That makes the attestation exactly as trustworthy as whoever supplied the booleans, and no
//! more. It is a *notarisation* of a claim, not a measurement of a system. Documentation here
//! previously described it as "cryptographic sandbox boundary attestation ... requires Linux
//! 5.13+ for eBPF", which described a component that does not exist and invited callers to treat
//! a signature over their own assertion as independent evidence.
//!
//! Producing the four booleans honestly -- an actual NetworkIsolation probe, an actual
//! FilesystemBoundary check -- is unimplemented and is what R2 still owes.
```

`run_preflight` (`rust/eval-guard/src/lib.rs:187-214`) is a four-element loop over an array the
caller handed it, then a signature. `rust/eval-guard/src/` holds two files and only two —
`cli.rs` (56 lines) and `lib.rs` (361) — confirmed against `origin/main`, not the working tree.
The invariant ledger already carries this correction and the plan text has not caught up
(`evidence/invariants.json`, I-09 `gap`, verbatim):

> `warrantor-eval-guard` is a separate binary the warrantor CLI never invokes; 'network loss to I1 =
> deny' has no I1 to lose. The measured pre-flight probes (`run_preflight_measured`,
> `rust/eval-guard/src/probes.rs`) that the plan cited exist only in uncommitted work, not on
> origin/main. Phase 3 wires the pre-flight into a supervised session.

**(2) It is not unreachable — it is shipped, and by default it fabricates a pass.** The census
statement "orphaned" is narrower than "unreachable". `eval-guard` is a released binary
(`.github/workflows/release.yml:31`, and the release body at line 55 lists it by name), and its CLI
constructs `CheckResults::all_pass()` unconditionally, then flips one boolean only if `--skip` is
passed (`rust/eval-guard/src/cli.rs:25-36`):

```rust
    let mut results = CheckResults::all_pass();
    match cli.skip.as_deref() {
        Some("network") => results.network_isolation = false,
        Some("fs") => results.filesystem_boundary = false,
        Some("process") => results.process_isolation = false,
        Some("egress") => results.egress_attestation = false,
```

Run on this Windows box, in no sandbox at all, the shipped binary emits a signed Ed25519
attestation asserting all four boundaries held (captured output in Step 0). So the defect is the
inverse of the seed's: the crate the census calls orphaned is the one artifact in this repository
that already publishes an unmeasured containment claim to a user. **Wiring it in as-is would raise
the census count by manufacturing a signed falsehood on the product's main path.** Rule 4 says the
orphan count may not rise; it does not say a crate must be wired at any price. The fabrication is
fixed before the wire, in that order, in Steps 4 and 8.

**(3) A third correction, smaller.** The seed's Consumes line says *"Consumes `eval-guard`'s
preflight and the sandbox runtime."* `warrantor-sandbox-runtime` is **also orphaned** (see Step 0's
census), and unlike `eval-guard` it cannot be cheaply wired: it carries `wasmtime = "=47.0.3"` with
`cranelift` (`rust/sandbox-runtime/Cargo.toml:20`), and `rust/warrant/Cargo.toml` is explicitly
built to a minimal, tokio-free, seven-external-dependency posture that its own comments defend crate
by crate. This task therefore **consumes `sandbox-runtime` as a reference for what an attempt-time
refusal looks like and does not link it.** Naming that decision is Step 9's job.

**What the repository does already have, and it is better than the seed assumes.** Three things:

- A **three-tier vocabulary that is already lint-enforced**: `BoundStrength::{Enforced, Mediated,
  Observed}` (`rust/warrant/src/lib.rs:197-211`) maps exactly onto this task's Tier A / Tier B /
  Tier C, and `rust/warrant/tests/tier_disclosure.rs` fails the build if any surface prints
  "enforced" for a weaker bound. This task uses that vocabulary and does not invent a fourth word.
- A **real attempt-time refusal**, for reference: `sandbox-runtime` refuses an undeclared import at
  admission (`rust/sandbox-runtime/src/lib.rs:634`, `Err(SandboxError::ImportDenied)`) and refuses
  an ungranted resource index at the call itself (`:769`, `resource.ok_or_else(|| format_err!("{CAPABILITY_DENIED_MARKER}"))`).
  That is what "a specific line of code refuses the action at the moment it is attempted" looks
  like. It also shows the limit: it bounds a WebAssembly guest, and a grader in this product is a
  native process reading a JSONL file.
- An **anti-gaming property that already exists and works**: `rust/warrant/src/corpus.rs` refuses to
  write a guard verdict into a training label. `Row::label` is `Option<bool>` and the guard's own
  conclusion goes into a separate `guard_said` field (`corpus.rs:224-235`). Its module doc names the
  trap (`corpus.rs:15-20`): *"The obvious implementation is to export every guard signal with the
  guard's own verdict as the label. That is training a model on its own output."* L11-10's
  anti-gaming half is therefore `partial` in fact even though the blueprint says `none`, and this
  task extends it rather than starting it.

**And the finding this task exists to convert.** The scorer's inputs in this product are
`~/.warrantor/guard/<id>.jsonl` and `~/.warrantor/runs/<id>.jsonl` (`rust/warrant/src/store.rs:22-34`),
which live in `$HOME` and **outside** the agent's worktree. `warrantor sandbox` derives a confinement
profile that binds `/` read-only with the worktree as the single read-write hole
(`rust/warrant/src/sandbox.rs:271-276`). So under a composed profile a write to the scorer's inputs
fails at the syscall — genuinely `Enforced`, by the OS, not by us. But `--ro-bind / /` leaves
`$HOME/.warrantor/keys/settle.key` **readable**, and `sandbox.rs` emits a `Divergence` for every
`WarrantBounds` field and **none at all for the store**. The seed's Step 4 ("it cannot read the
scorer's credentials") does not merely fail — the surface that is supposed to enumerate what a
profile cannot hold does not mention it. That silence is the defect, and Step 6 converts it.

---

#### Step 0 — commands to run and files to read in full, with real output

Read in full, no skimming, these five:

| Path | Lines | Why |
|---|---|---|
| `rust/eval-guard/src/lib.rs` | 361 | The whole premise. Read the module doc before the code. |
| `rust/eval-guard/src/cli.rs` | 56 | Where the fabrication happens. |
| `rust/sandbox-runtime/src/lib.rs` | 1314 | The reference for attempt-time refusal, and its limit. |
| `rust/warrant/tests/invariants/i09_failure_is_safe.rs` | 204 | The `#[ignore]` this task may convert. |
| `rust/warrant/src/sandbox.rs` | 545 | The composition point, and the gap it does not name. |

Plus, from `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`: **Task 5.3**
(evidence-integrity adversary) and **Task 14.10** (evaluator isolation contract), for the boundary
statement Step 2 owes.

Commands, with output captured on this box, 2026-09-05:

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git rev-parse refs/remotes/origin/main          # e4b5f105cdacf097e742ee8bbec704c28bafc726
git ls-tree --name-only refs/remotes/origin/main rust/eval-guard/src/
```

```
rust/eval-guard/src/cli.rs
rust/eval-guard/src/lib.rs
```

Two files. `probes.rs` does not exist on `origin/main`, which is what makes the ledger's correction
above true and the plan's earlier citation of `run_preflight_measured` false.

```bash
python tools/ci/wiring_census.py
```

```
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
```

```bash
python -c "import json; d=json.load(open('evidence/wiring-coverage.json')); \
print([c for c in d['orphaned'] if 'eval-guard' in c or 'sandbox-runtime' in c])"
```

```
['warrantor-eval-guard', 'warrantor-sandbox-runtime']
```

Both orphaned. The floor record (`evidence/wiring-coverage.json`) reads `"reachable": 9`, `"total":
39`, `"edges": 17`, with 30 names in `orphaned`.

```bash
cd rust && cargo test -p warrantor-warrant --test invariants -- i09 --include-ignored
```

```
running 7 tests
test i09_failure_is_safe::the_product_links_the_preflight_that_refuses_an_unmeasured_boundary ... FAILED
test i09_failure_is_safe::an_unavailable_catalog_denies_rather_than_permits ... ok
test i09_failure_is_safe::an_undeclared_budget_is_a_ceiling_of_zero_rather_than_unlimited ... ok
test i09_failure_is_safe::an_empty_egress_allowlist_permits_nothing_rather_than_everything ... ok
test i09_failure_is_safe::the_preflight_refusal_names_this_invariant ... ok
test i09_failure_is_safe::hop_01_an_impossible_task_fails_closed_rather_than_finding_a_route ... ok
test i09_failure_is_safe::the_egress_receipt_records_which_failure_closed_the_action ... ok

failures:

---- i09_failure_is_safe::the_product_links_the_preflight_that_refuses_an_unmeasured_boundary stdout ----
thread '...' panicked at warrant\tests\invariants\i09_failure_is_safe.rs:199:5:
the fail-closed preflight lives in a crate the product does not link, so no shipped run is refused
for starting against an unmeasured boundary.

test result: FAILED. 6 passed; 1 failed; 0 ignored; 0 measured; 77 filtered out; finished in 0.03s
```

The `#[ignore]` this task may convert, quoted verbatim from
`rust/warrant/tests/invariants/i09_failure_is_safe.rs:196`:

```rust
#[ignore = "I-09 orphaned: eval-guard's fail-closed preflight is not linked by the warrantor binary (2026-09-02)"]
fn the_product_links_the_preflight_that_refuses_an_unmeasured_boundary() {
    let manifest = harness::read_repository_file("rust/warrant/Cargo.toml");
    assert!(
        manifest.contains("warrantor-eval-guard"),
        "the fail-closed preflight lives in a crate the product does not link, so no shipped run \
         is refused for starting against an unmeasured boundary.",
    );
}
```

The ratchet baseline, and the shipped binary's actual behavior:

```bash
python tools/ci/check_invariant_ratchet.py
cd rust && cargo run -q -p warrantor-eval-guard --bin eval-guard -- --agent scorer-under-test
cd rust && cargo run -q -p warrantor-eval-guard --bin eval-guard -- --agent scorer-under-test --skip network
```

```
invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)

# with no --skip, on Windows, in no sandbox:
passed_checks: ['network_isolation', 'filesystem_boundary', 'process_isolation', 'egress_attestation']
results: [True, True, True, True]
timestamp: 1788621487
sig_len: 64 vk_len: 32

# with --skip network:
eval-guard: pre-flight FAILED for agent 'scorer-under-test' — boundary check failed: NetworkIsolation
eval-guard: REFUSING to start the agent (invariant I-09: failure is safe).
exit 1
```

**Record that pair in the evidence file before writing any code.** The refusal path is real and
tested; the pass path is a signature over four booleans nobody measured, produced by a binary
`release.yml` ships. Both halves are needed, because a report that quotes only the refusal makes
`eval-guard` look like a control and a report that quotes only the pass makes it look useless.

No crate this task touches is absent from `origin/main` — `rust/eval-guard` and
`rust/sandbox-runtime` are both in `git ls-tree --name-only refs/remotes/origin/main rust/` — so **no
carry-in sequence is needed** and no step here may assume one. Confirm it anyway in Step 1; the
shared checkout carries roughly forty untracked crates that `origin/main` does not have, and a task
that reads the working tree by accident writes a plan against a repository nobody else has.

---

#### Non-goals

1. **Not the evidence-integrity adversary — Task 5.3 owns it.** 5.3 attacks the receipt chain from
   inside the workload: forge, suppress, replay, race, spoof the tool-call path. This task never
   attacks the receipt graph. If the isolation record built here can be forged, that is 5.3's
   finding to produce and 5.3's `rust/warrant/tests/adversary/` to hold it. Do not add an adversary
   suite here; a second adversary that tries less hard than 5.3's is worse than none, for exactly
   the reason 5.3's own text gives.
2. **Not the evaluator's independence from us — Task 14.10 owns it.** 14.10 is the same argument one
   layer out: the evaluating *organization*, a pre-run conformance receipt signed by the evaluator's
   own out-of-band-pinned key, and the sentence "asserted before the run and tamper-evident
   afterward". This task stops at the process boundary inside one machine. **Do not define a
   receipt envelope here** — 14.10 reuses `notary::SignatureEnvelope`
   (`rust/notary/src/lib.rs:327`) and a third shape would be the verification bug it warns about.
3. **Not objective drift or task validity — Task 8.5 owns it.** "Is the grader measuring the right
   thing" is 8.5's `L3-01`/`L3-09`. This task assumes the objective is correct and asks only whether
   the scored party can reach the machinery that scores it.
4. **Not the guard's own accuracy — Task 12.4 owns it.** Adversarial-phrasing robustness and the
   severity-stability gate belong there, carrying the 2026-08-30 measurement (evasion asymmetric at
   1.42x, p≈1e-5). This task must not report a recall number; `bench.rs` already renders Wilson
   intervals and this task adds no figure of its own.
5. **Not the containment tiers themselves — Task 0.4 landed them.** `BoundStrength`,
   `render_bound`, `render_bounds_table` and `tests/tier_disclosure.rs` exist. Use them; do not
   extend the enum.

---

#### Files

- `rust/eval-guard/src/lib.rs` — add `Provenance`, bind it into `canonical_signing_bytes`
  (currently lines 165-177), extend `SandboxAttestation` (lines 76-95). Read in full first.
- `rust/eval-guard/src/cli.rs` — remove the unconditional `CheckResults::all_pass()` default
  (line 25); require an explicit provenance argument.
- `rust/eval-guard/Cargo.toml` — no change expected. Verify: `clap`, `serde`, `serde_json`,
  `thiserror`, `ed25519-dalek`, `getrandom`, `hex` and `warrantor-api` are all already in
  `warrantor-warrant`'s graph (`clap` arrives via `warrantor-trust-core`, `Cargo.toml:24`), so the
  wire in Step 8 adds **no new external crate and no new `Cargo.lock` version**. Prove it, do not
  assume it.
- `rust/warrant/Cargo.toml` — **contended wiring edge.** One `[dependencies]` line,
  `warrantor-eval-guard = { path = "../eval-guard", version = "1.0.0" }`, with the comment this
  manifest's convention demands (every path dependency there carries a paragraph saying what it buys
  and what it does not).
- `rust/Cargo.lock` — regenerated by `cargo metadata`, never by hand. Expect zero new
  `[[package]]` blocks; a non-empty diff means an assumption above was wrong.
- `rust/warrant/src/scorer.rs` — **new.** The isolation record and the reward-hacking monitor.
- `rust/warrant/src/lib.rs` — `pub mod scorer;` and the `bound_strengths()` additions.
- `rust/warrant/src/sandbox.rs` — the `Divergence::Gap` for the store the profile leaves readable.
- `rust/warrant/src/retention.rs` — a 21st `ArtifactClass` if and only if Step 7 writes a new store
  directory. `ALL_CLASSES` is `[ArtifactClass; 20]` at line 140 and
  `rust/warrant/tests/holdings.rs::every_directory_this_store_creates_is_a_known_class` fails
  otherwise. Prefer appending beside an existing class over inventing a twenty-first one.
- `rust/warrant/src/bin/warrantor.rs` — the usage block (lines 478-518) and one subcommand.
- `rust/warrant/tests/scorer_isolation.rs` — **new.** The three refusal tests and their controls.
- `rust/warrant/tests/invariants/i09_failure_is_safe.rs` — convert the `#[ignore]` at line 196.
- `tools/ci/invariant-ratchet.json` — `passing_floor` 65 → 66, **in the same commit**.
- `evidence/wiring-coverage.json` — via `python tools/ci/wiring_census.py --write`.
- `evidence/invariants.json` — the I-09 entry's `status` and `gap`.
- `docs/W1-delivery-gaps.md` — §3.1 gains the store-readability finding.
- `docs/task-evidence/task-13.7.md`.

---

#### Consumes / Produces

**Consumes (exists on `origin/main`, quoted with file and line):**

```rust
// rust/eval-guard/src/lib.rs:187
pub fn run_preflight(
    results: &CheckResults,
    signing_key: &SigningKey,
) -> Result<SandboxAttestation, EvalGuardError>

// rust/eval-guard/src/lib.rs:221
pub fn verify_attestation(attestation: &SandboxAttestation) -> Result<(), EvalGuardError>

// rust/eval-guard/src/lib.rs:124  (the four booleans the caller decides)
pub struct CheckResults { pub network_isolation: bool, pub filesystem_boundary: bool,
                          pub process_isolation: bool, pub egress_attestation: bool }

// rust/warrant/src/lib.rs:197 / :218 / :229 / :668
pub enum BoundStrength { Enforced, Mediated, Observed }
impl BoundStrength { pub fn word(self) -> &'static str; pub fn caveat(self) -> &'static str }
pub fn bound_strengths() -> Vec<(&'static str, BoundStrength)>

// rust/warrant/src/sandbox.rs:262
pub fn profile(bounds: &WarrantBounds, worktree: &str, confinement: Confinement) -> Profile

// rust/warrant/src/serve.rs:2432 / :2347   (out-of-bounds probing, durable)
pub fn read_refusals(root: &Path, warrant_id: &str) -> RefusalLog
pub fn record_refusals(root: &Path, warrant_id: &str, tool_refusals: &[&AuthorityRequest],
                       egress_refusals: &[&EgressRefusal], at: u64) -> Result<usize, ServeError>

// rust/warrant/src/runs.rs:206 / :231   (the population)
pub fn read_for(root: &Path, warrant_id: &str) -> RunLog
pub fn read_all(root: &Path) -> RunLog

// rust/warrant/src/corpus.rs:182   (the label boundary that already holds)
pub fn rows_from(log: &GuardLog, states: &BTreeMap<String, WarrantState>) -> Vec<Row>

// rust/warrant/src/operators.rs:69 / :161   (who an escalation may be addressed to)
pub enum Scope { Read, Stop, Settle, Approve }
impl Operator { pub fn allows(&self, scope: Scope) -> bool }

// rust/warrant/tests/invariants/harness.rs:50   (the control-paired assertion)
pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)
where T: std::fmt::Debug, F: Fn(&T) -> bool
```

**Does not exist; named with its owner rather than assumed:**

- `notary::SignatureEnvelope` (`rust/notary/src/lib.rs:327`) exists but is **not** for this task's
  output. **Task 14.10** creates the conformance-receipt format; until it lands, the record here is
  a plain JSONL line and Step 9 must say so in the product text.
- A digest-pinned evaluation bill of materials — **Task 13.5** (`L11-07`, `L11-11`). The monitor's
  threshold file references a BOM digest field that is `None` until 13.5 exists.
- A checkpoint quarantine — **Task 12.6** (guard graduation ladder). L11-12's verification asks for
  one; this task produces the escalation, not the quarantine, and says which.

**Produces:**

```rust
// rust/warrant/src/scorer.rs  (new)

/// One isolation property, with the tier that actually holds it and who holds it.
pub struct Property {
    pub name: &'static str,          // "scorer_inputs_not_writable" | ... | ...
    pub strength: BoundStrength,     // Enforced only when the OS holds it
    pub held_by: HeldBy,             // Os { mechanism } | OurCode | NothingYet
    pub not_covered: String,         // the sentence that ships; never empty
}

pub enum HeldBy { Os { mechanism: &'static str }, OurCode, NothingYet }

/// The three properties, evaluated against a warrant's bounds and a confinement choice.
pub fn isolation(bounds: &WarrantBounds, confinement: Option<Confinement>,
                 store_root: &Path, worktree: &Path) -> Vec<Property>;

/// Fail closed over the properties, reusing eval-guard rather than re-deciding.
pub fn preflight(properties: &[Property], key: &SigningKey)
    -> Result<SandboxAttestation, EvalGuardError>;

/// Population-level probing rate per run, from durable logs only.
pub struct ProbingTrend { pub per_run: Vec<(String, f64)>, pub crossed: Option<String>,
                          pub threshold: f64, pub registered_at: u64,
                          pub bom_digest: Option<String> }
pub fn trend(root: &Path, threshold: &RegisteredThreshold) -> ProbingTrend;

/// An escalation addressed to a named operator who does NOT hold Scope::Settle.
pub fn escalate(root: &Path, trend: &ProbingTrend, registry: &OperatorRegistry, at: u64)
    -> Result<Escalation, ScorerError>;
```

Plus, in `eval-guard`, the field that stops the fabrication:

```rust
// rust/eval-guard/src/lib.rs
pub enum Provenance {
    /// A named probe ran and returned this boolean.
    Measured { probe: String },
    /// A caller asserted it. The name is required and there is no Default.
    Asserted { by: String },
}
```

---

#### Bound strength

Three properties, three different answers. Stated per property, in the repository's own vocabulary,
because inventing a fourth word here is how a mislabeled bound gets into a signed bundle.

**`scorer_inputs_not_writable` — `Enforced` when composed, `Observed` by default.**
`Enforced` requires two facts to be true simultaneously, and the code must check both rather than
assume either: the store root is not inside the worktree, and a confinement profile is actually in
force. Under `warrantor sandbox --kind bubblewrap` the profile binds `/` read-only with the worktree
as the sole read-write hole (`sandbox.rs:271-276`), so a write to `~/.warrantor/guard/*.jsonl` fails
with `EROFS` at the syscall — held by the operating system, not by us, and the mechanism name goes
in `HeldBy::Os`. With no profile launched it is `Observed`: same UID is same UID, and
`docs/W1-delivery-gaps.md` says so plainly — *"the agent can still read the store directly, and
nothing can stop it."* This process cannot tell whether the operator launched the profile, which
`sandbox.rs`'s own caveat already states; so the record carries the operator's assertion, tagged
`Provenance::Asserted`, and never `Measured`.

**`scorer_credentials_not_readable` — `NothingYet`. There is no bound.**
`--ro-bind / /` makes `$HOME` readable, `~/.warrantor/keys/settle.key` included. Nothing in this
repository refuses that read, at any tier, and `sandbox.rs` does not list the store among its
divergences. This property ships as a **named gap with no tier word at all**, not as `Observed` —
"observed" would imply something measures it, and nothing does. Step 6 adds the `Divergence::Gap`
so the surface that enumerates what a profile cannot hold stops omitting the credential it leaves
in reach.

**`scorer_not_reachable_over_network` — `Enforced` on an empty allowlist, `Mediated` otherwise.**
`sandbox.rs:318-330` emits `--unshare-net` only when `bounds.egress_hosts.is_empty()`, and its own
`Divergence::Held` calls that *"the one case where a sandbox turns egress_hosts from Mediated into
something an agent cannot route around."* When the warrant permits any host the namespace is
deliberately not emitted (`:334-346`) because it is all-or-nothing, so the property falls back to
`Mediated` — held at the MCP proxy, which a shell reaches past. Reuse
`BoundStrength::Mediated.caveat()` verbatim rather than writing a new sentence.

**The monitor is `Observed`, and cannot be anything else.** It reads durable logs after the fact.
Its threshold is registered before the run and its trend is computed from `runs::read_all` and
`serve::read_refusals`; nothing in it refuses an action as it happens. L11-12's own words are
*"Advisory to the humans, mandatory as a stop trigger"* — the second clause is a duty on a person,
not a mechanism in this code, and the escalation record must say which.

**No netns, no seccomp, no firewall exists in this repository.** Containment composes with an
external sandbox that this process cannot verify was started. **The sentence that must appear in the
product, wherever an isolation record is rendered:**

> This record states which party held each isolation property and by what mechanism. It does not
> establish that the sandbox was launched: no netns, seccomp or firewall is implemented here, the
> filesystem property is held by an operating system this process cannot interrogate, and the
> scorer's signing key remains readable to any process running as the same user.

**Orphan accounting.** The census must rise from 9 to 10, not stay flat: `warrantor-eval-guard`
becomes reachable. `warrantor-sandbox-runtime` **stays orphaned on purpose**, and the reason is
recorded rather than left implicit — linking it pulls `wasmtime =47.0.3` with `cranelift` into a
manifest whose comments defend a seven-external-dependency, tokio-free posture crate by crate, to
bound a WebAssembly guest when the grader here is a native process reading JSONL. That is a
deliberate non-wire, not an oversight, and Step 9 writes it into the evidence file so the next
census reader does not "fix" it.

---

#### Exit gate

`cargo test -p warrantor-warrant --test scorer_isolation --test invariants -j 2 && python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py`
must print three things together: every isolation test passing **with its allowed control also
passing**, `wiring census: 10 of 39 crates reachable`, and `invariant ratchet: ok (66 passing at
floor 66, 18 recorded findings at ceiling 18)` — and `cargo run -p warrantor-eval-guard --bin
eval-guard -- --agent x` must exit non-zero with no attestation on stdout, because a caller who
names no provenance can no longer be handed a signature.

---

- [ ] **Step 1 — Worktree from `origin/main`; confirm both crates are present and both are orphaned.**
  ```bash
  export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
  git -C "M:/Project AumOS - Open Secure AI Alliance/aumos" fetch origin
  git worktree add M:/wt-13.7 -b feat/scorer-isolation origin/main
  cd M:/wt-13.7
  export CARGO_TARGET_DIR=M:/wt-13.7-target
  git ls-tree --name-only origin/main rust/ | grep -E 'eval-guard|sandbox-runtime'
  python tools/ci/wiring_census.py
  ```
  Expect both paths listed and `9 of 39`. Every cargo command below runs from `M:/wt-13.7/rust` with
  `-j 2` (Global Constraints). **Test intent:** that this branch starts from the repository everyone
  else has, not from the shared checkout's forty untracked crates. If the census prints anything but
  9, another lane has landed a wire and Step 8's expected numbers move by that much — re-derive them,
  do not adjust the assertion to match.

- [ ] **Step 2 — Write the boundary against Tasks 5.3 and 14.10 before writing any code.**
  Three sentences in `docs/task-evidence/task-13.7.md`, each naming what this task does **not**
  claim: 5.3 attacks the receipt chain and this task never does; 14.10 covers the evaluating
  organization and owns the receipt envelope; this task covers one process boundary on one machine.
  Then the sentence the seed's framing needs corrected — that `eval-guard` performs no isolation, so
  none of the three is consuming an existing isolation mechanism. **Test intent:** a static test in
  `tests/scorer_isolation.rs` asserts the evidence file names both task numbers, using
  `harness::source_contains`-style reading. Three statements of one idea drift into each other, and
  the plan has already produced one duplicated claim this way.

- [ ] **Step 3 — Failing test: the shipped `eval-guard` signs an unmeasured pass.**
  Before any fix, make the defect executable. In `rust/eval-guard/src/lib.rs` tests:
  ```rust
  #[test]
  fn an_attestation_cannot_be_produced_without_naming_who_measured_it() {
      let key = test_key();
      // The control: an honestly-sourced result still signs. Without this the assertion below
      // would pass on a function that refuses everything.
      let measured = run_preflight(&CheckResults::all_pass(),
          &Provenance::Measured { probe: "netns-probe/1".into() }, &key)
          .expect("a measured all-pass must still sign");
      assert!(matches!(measured.provenance, Provenance::Measured { .. }));

      // The defect: today's API takes no provenance at all, so the four booleans arrive
      // anonymous and the signature says nothing about where they came from.
      let asserted = run_preflight(&CheckResults::all_pass(),
          &Provenance::Asserted { by: "operator:vj".into() }, &key)
          .expect("an asserted all-pass may sign, but must be distinguishable");
      assert_ne!(canonical_signing_bytes_for(&measured), canonical_signing_bytes_for(&asserted),
          "a measured pass and an asserted pass must not produce the same signed bytes");
  }
  ```
  **Test intent:** the assertion that fails is the third one, and it fails for the right reason —
  `canonical_signing_bytes` (lines 165-177) binds checks, nonce, results and timestamp, and nothing
  else, so the two are byte-identical today. The control on line 2 is what stops this from becoming a
  one-sided test that a `run_preflight` refusing everything would pass.

- [ ] **Step 4 — Make the fabrication impossible, in `eval-guard`, before wiring anything.**
  Add `Provenance`, add it to `SandboxAttestation`, and extend `canonical_signing_bytes` so the
  provenance participates in the signed bytes — the same C3 reasoning already applied to `results`
  and `timestamp` (lines 202-204: *"A single attestation is therefore no longer a permanent skeleton
  key"*). Then in `cli.rs`, delete the unconditional default at line 25 and require an explicit
  source:
  ```rust
  /// Who or what produced the four booleans. There is no default: a caller who cannot name a
  /// source is a caller whose signature would mean nothing.
  #[arg(long, value_name = "measured:<probe> | asserted:<name>")]
  provenance: String,
  ```
  **Test intent:** `cargo run -p warrantor-eval-guard --bin eval-guard -- --agent x` must now exit
  non-zero with clap's own missing-argument error and print no JSON. Pair it with the allowed
  control — `--provenance asserted:operator:vj` still produces an attestation — so the test proves a
  gate rather than a brick. This is Rule 2 in practice: the crate's doc comment already said it does
  not measure, and a comment is not a mechanism; now the wire format says it.

- [ ] **Step 5 — Failing test: the scored process cannot write the scorer's inputs, and prove the attempt reached the boundary.**
  In `rust/warrant/tests/scorer_isolation.rs`, using `harness::refused_at_the_boundary`'s shape:
  ```rust
  #[test]
  fn a_write_to_the_scorer_s_inputs_is_outside_every_read_write_hole_the_profile_opens() {
      let store = tempdir("scorer-inputs");                  // stands in for ~/.warrantor
      let worktree = "/home/agent/repo/.warrantor/wrt_w1";   // POSIX: sandbox.rs refuses Windows paths
      let profile = sandbox::profile(&no_egress_bounds(), worktree, Confinement::Bubblewrap);
      let line = profile.shell_line();

      // CONTROL: the worktree IS writable, or this test measures nothing at all.
      assert!(line.contains(&format!("--bind {worktree} {worktree}")),
          "control: the worktree must be bound read-write; {line}");

      // ATTACK: the scorer's inputs are under no read-write bind, so a write hits the read-only root.
      let guard_log = store.join("guard").join("w1.jsonl");
      assert!(!writable_under(&profile, &guard_log),
          "the guard log is inside a read-write hole, so the profile does not hold this property");
  }
  ```
  `writable_under` is a small pure function over `profile.argv`: a path is writable only if it is
  under a `--bind`/`--read-write` argument or under the `--tmpfs /tmp` hole. **Test intent:** this
  asserts a property of the derived profile, not of a launched sandbox, and the test name says so.
  `sandbox.rs`'s own caveat is the reason: *"a profile that is never launched confines nothing, and
  this process cannot tell whether the operator launched it."* A test named
  `the_agent_cannot_write_the_scorer` would be a claim this repository cannot make; this one is a
  claim it can. Note `check_worktree` (`sandbox.rs:234`) refuses a Windows path, so the fixture path
  must be POSIX or the test fails for the wrong reason.

- [ ] **Step 6 — Failing test: it CAN read the scorer's credentials, and the profile does not say so.**
  This is the finding, and it is recorded rather than fixed.
  ```rust
  #[test]
  fn the_profile_leaves_the_settle_key_readable_and_must_name_that_gap() {
      let profile = sandbox::profile(&no_egress_bounds(), "/home/agent/repo/.warrantor/wrt_w1",
                                     Confinement::Bubblewrap);
      // CONTROL: the profile does hold write_paths, so it is not simply empty.
      assert!(profile.held().iter().any(|d| matches!(d, Divergence::Held { bound, .. } if bound == "write_paths")));

      // The defect: `--ro-bind / /` leaves $HOME readable, keys/settle.key included, and no
      // Divergence mentions the store at all.
      assert!(profile.argv.windows(3).any(|w| w == ["--ro-bind", "/", "/"]));
      assert!(profile.divergences.iter().any(|d| d.bound() == "scorer_credentials"),
          "the profile enumerates a divergence per WarrantBounds field and none for the store, so \
           the one credential a grader must not leak is not named anywhere an operator reads");
  }
  ```
  Then add the `Divergence::Gap` that makes it pass, with a `why` that states the mechanism and the
  absence of one: read-only is not unreadable, `~/.warrantor/keys/settle.key` is in reach of any
  process at the same UID, and nothing in this repository refuses that read. **Test intent:** the
  passing test asserts the *disclosure*, never the containment — Rule 1. Add the same finding to
  `docs/W1-delivery-gaps.md` §3.1, which currently enumerates what the profile holds and is silent
  here.

- [ ] **Step 7 — Failing test: the scored party cannot move the thing that becomes its label.**
  The anti-gaming half, expressed in this repository's real loop. `corpus.rs:194-198` derives a
  training label from `WarrantState`: `Void` → `Some(true)`, `Settled` → `Some(false)`. So the
  gameable surface is not the grader's code — it is the state transition.
  ```rust
  #[test]
  fn a_principal_without_settle_scope_cannot_produce_the_state_that_becomes_a_label() {
      let registry = registry_with(&[("reviewer", &[Scope::Read, Scope::Approve]),
                                     ("releaser", &[Scope::Read, Scope::Settle])]);
      // CONTROL: the releaser can, or the refusal below proves nothing.
      assert!(registry.operator("releaser").unwrap().allows(Scope::Settle));
      // The bound: the reviewer cannot, so it cannot flip a row's label by settling.
      assert!(!registry.operator("reviewer").unwrap().allows(Scope::Settle));
  }

  #[test]
  fn a_guard_verdict_never_becomes_a_label_even_when_it_is_the_only_evidence() {
      let rows = corpus::rows_from(&log_with_one_harmful_signal(), &BTreeMap::new());
      assert_eq!(rows.len(), 1, "control: the signal was exported, not dropped");
      assert_eq!(rows[0].label, None);
      assert_eq!(rows[0].guard_said.as_deref(), Some("harmful"));
      assert_eq!(rows[0].label_source, corpus::LabelSource::Unlabelled);
  }
  ```
  **Test intent:** the second test may well pass on `origin/main` — `corpus.rs` already holds this —
  and that is the point: it pins a property that currently has no test outside the corpus module and
  would be silently lost by a "helpful" refactor that filled `label` from `guard_said`. Record in the
  evidence file which of the two was already true, honestly, rather than presenting both as new.
  **Do not add a store directory for this step.** If Step 7 or 10 needs one, `ALL_CLASSES` at
  `retention.rs:140` must grow from 20 and `tests/holdings.rs` must be updated in the same commit,
  or the build fails on a directory no class claims.

- [ ] **Step 8 — Wire `eval-guard` in; the census must rise from 9 to 10, and the lock must not move.**
  Add the one `[dependencies]` line to `rust/warrant/Cargo.toml` with its explaining paragraph, then:
  ```bash
  cargo metadata --format-version 1 --locked > /dev/null    # must SUCCEED: no new versions
  python tools/ci/wiring_census.py                          # expect: 10 of 39 ... over 18 path edges
  python tools/ci/wiring_census.py --write
  git diff --stat rust/Cargo.lock                           # expect: no change
  ```
  **Test intent:** `--locked` succeeding is the proof that the dependency-posture claim in Files is
  true rather than assumed — `clap` via `warrantor-trust-core:24`, everything else already present.
  If `--locked` fails, a version moved: stop, and report which, rather than committing a drifted
  lock. The edge count rising by one and the reachable count rising by one together are what
  distinguish a real wire from a manifest line nothing traverses; also add one call site in
  `scorer::preflight` so the wire is used and not merely declared.

- [ ] **Step 9 — Attribute each property to us, to the host, or to nothing; and record the crate you are NOT wiring.**
  Implement `scorer::isolation` returning the three `Property` values from Bound strength, each with
  its `HeldBy` and a non-empty `not_covered`. Render them through `render_bound`
  (`rust/warrant/src/lib.rs:692`) so they print in the one vocabulary the rest of the product uses.
  ```rust
  #[test]
  fn no_property_claims_enforced_unless_an_os_mechanism_is_named() {
      for p in scorer::isolation(&no_egress_bounds(), Some(Confinement::Bubblewrap), &store, &wt) {
          if p.strength == BoundStrength::Enforced {
              assert!(matches!(p.held_by, HeldBy::Os { .. }), "{}", p.name);
          }
          assert!(!p.not_covered.is_empty(), "{} ships with no caveat", p.name);
      }
      // CONTROL: with no confinement chosen, nothing is Enforced — so the check above is
      // discriminating between two real cases and not vacuously true.
      let bare = scorer::isolation(&no_egress_bounds(), None, &store, &wt);
      assert!(bare.iter().all(|p| p.strength != BoundStrength::Enforced));
      assert!(bare.iter().any(|p| matches!(p.held_by, HeldBy::NothingYet)));
  }
  ```
  Then write into `docs/task-evidence/task-13.7.md` the deliberate non-wire:
  `warrantor-sandbox-runtime` stays orphaned, with the `wasmtime =47.0.3` + `cranelift` reason and
  the observation that it bounds a WebAssembly guest while this product's grader is a native
  process. **Test intent:** Rule 1 made mechanical. `tests/tier_disclosure.rs` already fails the
  build if a surface prints "enforced" for a weaker bound; this extends the same gate to the new
  properties instead of trusting the author to remember.

- [ ] **Step 10 — Failing test: the reward-hacking escalation goes to a principal who does not hold `Settle`.**
  Implement `scorer::trend` over `runs::read_all` and `serve::read_refusals` — probing rate is
  refusals per run, per warrant, ordered by `RunRecord::at` — with a threshold read from a file
  written before the run and never rewritten.
  ```rust
  #[test]
  fn an_escalation_is_addressed_to_an_operator_who_cannot_settle_the_warrant_being_graded() {
      let registry = registry_with(&[("releaser", &[Scope::Read, Scope::Settle]),
                                     ("env-owner", &[Scope::Read, Scope::Stop])]);
      let esc = scorer::escalate(&root, &rising_trend(), &registry, NOW).expect("crossed");
      assert_eq!(esc.to, "env-owner");
      // CONTROL: with only a settling operator registered, escalation REFUSES rather than
      // falling back to the party being graded.
      let only_settler = registry_with(&[("releaser", &[Scope::Read, Scope::Settle])]);
      assert!(matches!(scorer::escalate(&root, &rising_trend(), &only_settler, NOW),
                       Err(ScorerError::NoEnvironmentOwner)));
  }

  #[test]
  fn a_threshold_registered_after_the_first_run_is_refused() {
      let t = RegisteredThreshold { rate: 0.2, registered_at: NOW + 100, bom_digest: None };
      assert!(matches!(scorer::trend_checked(&root_with_run_at(NOW), &t),
                       Err(ScorerError::ThresholdRegisteredAfterTheRun { .. })));
  }
  ```
  **Test intent:** the first test's control is the whole mechanism — an escalation that silently
  falls back to the settler is worse than none, because the party whose decision becomes the
  training label would be the party told the label is suspect. The second enforces L11-12's *"the
  threshold is registered before the run, never tuned after"*; ordering is the only thing that makes
  a threshold evidence rather than a rationalization. **No new trust root:** there is no registry of
  approved graders and no central escalation service. This reuses the local `OperatorRegistry`,
  whose tokens are printed once and stored as SHA-256 — so an operator token is not on the
  filesystem the agent reads, while `serve/token` is (`operators.rs:96-102`). That is a weaker
  guarantee than a separate trust domain and the escalation record must state it: *this escalation
  reached a named local principal holding `Stop` and not `Settle`; it does not establish that the
  principal is independent of the environment being graded.*

- [ ] **Step 11 — Convert the I-09 `#[ignore]` and raise the floor in the same commit.**
  Delete the `#[ignore]` at `rust/warrant/tests/invariants/i09_failure_is_safe.rs:196` and rewrite
  the FINDING comment above it (lines 188-194) to say what changed: the product links the preflight,
  and the preflight can no longer sign a pass whose source is unnamed. **Do not weaken the
  assertion** — it still reads `manifest.contains("warrantor-eval-guard")`, and now it is true. Add
  one assertion beside it that the provenance field exists, so the converted test measures the fix
  and not only the manifest line. Then, in the same commit:
  ```bash
  # tools/ci/invariant-ratchet.json: passing_floor 65 -> 66, ignored_ceiling 19 -> 18
  python tools/ci/check_invariant_ratchet.py
  # expect: invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
  ```
  Update `evidence/invariants.json` I-09: `status` from `orphaned` to `partial`, and rewrite the
  `gap` to the honest remainder — the preflight is linked and refuses on a named source, and
  *"network loss to I1 = deny"* still has no I1 to lose, so the invariant is not enforced. **Test
  intent:** the ratchet has teeth on both counters, and raising the floor without lowering the
  ceiling would let a silenced test hold the passing count steady. The ceiling moving 19 → 18 is the
  proof that a finding closed rather than that a number improved.

- [ ] **Step 12 — Full gate on every language touched, evidence file, `git commit -s`.**
  ```bash
  cd M:/wt-13.7/rust
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -j 2 -- -D warnings
  cargo test --workspace --all-targets -j 2
  cd M:/wt-13.7
  python tools/ci/wiring_census.py
  python tools/ci/check_invariant_ratchet.py
  python tools/ci/check_invariants.py
  python tools/ci/check_docs.py
  python -m pytest tools/ci/test_wiring_census.py -q -p no:cacheprovider
  node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/task-evidence/task-13.7.md
  git commit -s
  ```
  Rust and Python are both touched, so both gates run; `check_docs.py` runs because
  `docs/W1-delivery-gaps.md` changed. **Test intent:** `docs/task-evidence/task-13.7.md` must record
  four things a later reader cannot reconstruct — the verbatim `eval-guard` output from Step 0 in
  both its passing and refusing forms, the three properties with their tiers and holders, which of
  Step 7's two assertions was already true on `origin/main`, and the sentence from Bound strength
  that ships with every rendered isolation record. The premise correction goes at the top, in its own
  section, phrased as the code's finding and not as the plan's opinion: `eval-guard` performs no
  isolation, and the seed's *"may exist and be unreachable"* was wrong in both halves.

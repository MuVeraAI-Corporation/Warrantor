### Task 8.1: Horizon governor (L3-04)

**Anchor.** The master blueprint's entry for this item, quoted verbatim from
`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html` line 3446:

```html
<article class="item" id="L3-04" data-stratum="L3" data-plane="B" data-status="partial"
         data-novelty="novel" data-wave="W1" data-loop="L5">
```

`status=partial`, `novelty=novel`, `wave=W1` — and it was omitted from the original 41-task plan.
The item's own body says what it is: *"Wall-clock and step-count ceilings with automatic escalation
to a human as the horizon extends. Long-lived instances were a precondition for every large
collective project in the incident; the governor makes duration a decision someone took rather than
a default nobody noticed."* Its anchor names what already exists and refuses to overstate it:
*"A partial exists: bounded deadline and process-lifetime expiry are Tier A properties the platform
already ships."* Its verification clause names the gate: *"A warrant whose horizon reaches its
ceiling halts the workload through the kernel's halt() verb with staged effects discarded; an
extension request survives as a pending approval and nothing high-consequence proceeds meanwhile."*

Long-horizon autonomy is the risk this entire product exists to address — OpenAI names *"model
persistence over long task horizons"* as one of three factors in the confluence that produced the
incident (S01 §VIII p.19) — and the control that bounds it was never scheduled. Do not soften
`status=partial` into `status=mostly-done`: Step 0 measured which half of the partial exists, and
the half that exists is the half that was easy.

---

**Step 0.** Run every command below from a scratch worktree cut from `refs/remotes/origin/main`
(`e4b5f10`), with `CARGO_TARGET_DIR` pointed away from every other lane. The output shown is real,
captured on 2026-09-05.

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
export CARGO_TARGET_DIR=M:/wt-8.1-target
export RUST_MIN_STACK=16777216

# 1. Every crate origin/main actually has. rust/warrant is present; nothing needs carrying in.
git ls-tree --name-only refs/remotes/origin/main rust/ | wc -l          # 48 entries

# 2. Every field of WarrantBounds, with its line number.
awk 'NR>=246 && NR<=271 && /pub /{printf "%d: %s\n", NR, $0}' rust/warrant/src/lib.rs

# 3. Is there ANY count-shaped bound today? (empty output is the finding)
grep -n "count\|steps\|max_\|ceiling" rust/warrant/src/lib.rs | grep "pub "

# 4. Every struct-literal construction site a new field would break.
grep -rn "WarrantBounds {" rust/ --include=*.rs | wc -l
grep -rn "WarrantBounds {" rust/ --include=*.rs | sed 's/:.*//' | sort | uniq -c | sort -rn

# 5. The two gates that decide whether a new bound may be added at all.
grep -n "fn every_bound_declares_the_tier_that_actually_holds_it" -A 26 \
  rust/warrant/tests/warrant.rs
grep -n "fn both_readmes_carry_the_bounds_table_generated_from_bound_strengths" -A 30 \
  rust/warrant/tests/tier_disclosure.rs

# 6. The cross-language mirror of the containment arithmetic.
grep -n "REQUIRED_PROPOSAL_FIELDS" -A 10 \
  python/warrantor_ml/src/warrantor_ml/tasks/bounds.py
grep -n "emit_bounds_vectors" tools/ci/run_python_checks.py .github/workflows/ci.yml

# 7. Baseline, so a regression is attributable.
cd rust && cargo test -p warrantor-warrant --test warrant --test tier_disclosure -j 2
cd .. && python tools/ci/wiring_census.py
python tools/ci/check_docs.py
```

**Files to read in full, with line counts.** `rust/warrant/src/lib.rs` (724 lines) — the whole file,
because `WarrantBounds`, `BoundStrength`, `bound_strengths`, `canonical`, `sign_claims`, `verify`
and `WarrantBounds::contains` are all in it and the horizon touches every one.
`rust/warrant/src/supervise.rs` (580 lines) — all of it, including the two `#[allow(unsafe_code)]`
modules, because the Tier A claim in this task rests on exactly what they do.
`rust/warrant/src/daemon.rs` (465 lines) — the deadline path is here, not in `supervise.rs`.
`rust/warrant/src/proxy.rs` (311 lines) — the only per-call refusal site in the crate.
`rust/warrant/src/report.rs` lines 279–366 and 449–545 — the section pattern and the digest
constraint. `rust/warrant/src/operators.rs` lines 449–630 — the actor log, which is the only
existing record of a named human acting. `rust/warrant/src/settle.rs` lines 238–250. The seeded
**Task 1.3** section of this plan (line 5090 onward) and the seeded **Task 8.2** section (line
18130 onward), both in full.

**What Step 0 found. Three of the seed's statements are confirmed; three are wrong, and the code
wins on all three.**

*Confirmed — every field of `WarrantBounds` that bounds time, count or spend today,* quoted from
`rust/warrant/src/lib.rs` 246–271:

```rust
/// Everything a warrant permits. Absent fields mean "not permitted", never "unlimited".
pub struct WarrantBounds {                          // 248
    pub tools: BTreeSet<String>,                    // 250
    pub write_paths: BTreeSet<String>,              // 252
    pub egress_hosts: BTreeSet<String>,             // 254
    pub staged_classes: BTreeSet<SideEffectClass>,  // 256
    /// Wall-clock deadline, epoch seconds. Enforced by the supervising process.
    pub expires_at: u64,                            // 258
    /// Spend ceiling in whole cents. `None` is a ceiling of **zero**, never "unlimited".
    pub budget_cents_observed: Option<u64>,         // 268
    /// Maximum delegation depth remaining for sub-warrants.
    pub delegation_depth: u32,                      // 270
}
```

So: **time is bounded once**, by `expires_at` (line 258). **Spend is bounded once**, by
`budget_cents_observed` (line 268), and `bound_strengths()` calls it `Observed`. **Count is bounded
zero times.** `delegation_depth` (line 270) is a *tree depth* checked at issue, not a count of
anything the agent does — command 3 above returns no output at all, which is the finding: there is
no step ceiling, no effect ceiling, no action ceiling, and no field that could be read as one.
`WarrantBounds::validate` (lib.rs 346–360) requires only that `tools` is non-empty and
`expires_at != 0`.

*Confirmed — `supervise.rs` is Tier A, and it is the one genuinely strong bound in the system.*
From `rust/warrant/src/supervise.rs` 51–78:

```rust
pub fn describe_linkage() -> Linkage {                                   // 51
    if cfg!(windows) {
        Linkage { mechanism: "job-object", survives_supervisor_death: true, /* .. */ }
    } else if cfg!(target_os = "linux") {
        Linkage { mechanism: "setsid+pdeathsig", survives_supervisor_death: true, /* .. */ }
    } else {
        Linkage { mechanism: "setsid", survives_supervisor_death: false,   // 68
            detail: "this platform has no kernel-enforced parent-death link. [..] if the \
                     supervisor is killed uncleanly the agent WILL keep running. Treat \
                     unattended runs here as unsupported." }
    }
}
```

The Windows path is a job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (`windows_job::Job`,
lines 316–435, four kernel32 calls declared directly); the Linux path is `setsid` plus
`PR_SET_PDEATHSIG` delivered as `SIGKILL` in a `pre_exec` (lines 133–150). `terminate_group(pid)`
(line 221) kills the group on every platform. The horizon governor must **compose** with this and
never duplicate it — but the third branch is the honest caveat the seed does not mention: on macOS
the mechanism is `setsid` only and `survives_supervisor_death` is `false`. A horizon that terminates
through a *live* supervisor is Tier A on all three platforms; a horizon that must hold after the
supervisor dies is Tier A on two of three and the code already says which.

*Confirmed — what `status=partial` refers to.* The blueprint says it in one clause: *"bounded
deadline and process-lifetime expiry are Tier A properties the platform already ships."* That is
`expires_at` plus `supervise.rs`, and `bound_strengths()` (lib.rs 668–686) declares it:

```rust
pub fn bound_strengths() -> Vec<(&'static str, BoundStrength)> {          // 668
    vec![
        ("tools", BoundStrength::Mediated),
        ("write_paths", BoundStrength::Observed),
        ("egress_hosts", BoundStrength::Mediated),
        ("staged_classes", BoundStrength::Mediated),
        // OS process link: Windows job object, Linux setsid + PR_SET_PDEATHSIG.
        ("expires_at", BoundStrength::Enforced),                          // 680
        ("delegation_depth", BoundStrength::Enforced),
        ("budget_cents_observed", BoundStrength::Observed),
    ]
}
```

The partial is therefore **the wall-clock half only**. What is missing from L3-04 is (a) the
step-count ceiling, which does not exist in any form, and (b) the automatic escalation to a human as
the horizon extends, which also does not exist — nothing in the crate raises an approval on the
approach to a limit. `daemon.rs` 371–388 is the whole of the existing behavior at the limit:

```rust
let remaining = expires_at.saturating_sub(now);                          // 374
let (code, expired) = match supervisor.wait_until(remaining)? {
    Some(code) => { /* .. */ (code, false) }
    None => {
        // The deadline is the point of the warrant. Reaching it means stopping, not asking.
        println!("warrantor: warrant {warrant_id} expired; terminating the agent and \
                  everything it started. Staged effects are kept -- review with \
                  `warrantor report {warrant_id}`.");
        supervisor.terminate()?;                                         // 384
        (-1, true)
    }
};
```

**Seed error 1 — the seed points at the wrong file for half of what it asks for.** It says "Read
`rust/warrant/src/supervise.rs` for deadline enforcement". `supervise.rs` holds the *link* and the
*kill*; the *deadline decision* is `daemon.rs:374` and the deadline *value* is supplied at
`rust/warrant/src/bin/warrantor.rs:4501` (`expires_at: stored.warrant.claims.bounds.expires_at`).
That matters for the design, not just for the reading list: the composition point is the call site
at `warrantor.rs:4501` and the wait loop at `daemon.rs:374`, and `supervise.rs` needs no change at
all.

**Seed error 2 — the seed's Produces contradicts its own Non-goals, and the blueprint sides with
the Non-goals.** The seed says this task produces "a horizon bound — effect-chain depth, elapsed
autonomy without human contact, and **distance from the granting objective**". Its Non-goals then
say "Not objective drift as a semantic measure — Task 8.5". Those cannot both stand, and L3-04's own
body names only *"wall-clock and step-count ceilings with automatic escalation"* — no semantic
distance anywhere in the item. **The third dimension is struck.** Semantic distance from the
objective belongs to L3-09 and Task 8.5, which owns it and is routed to `opus` for that reason.
Building a semantic measure here produces two of them.

**Seed error 3 — the seed's Exit gate names a verb that does not exist on `origin/main`, and the
blueprint's verification clause names it too.** L3-04 says the halt goes "through the kernel's
`halt()` verb with staged effects discarded". `stop::halt` is **Task 1.3's** product. What exists
today is `stop::execute` (stop.rs:228), and `rust/warrant/src/stop.rs` 29–31 says why it lands in
`Held`: *"Held, not Void: ending a run early is not misbehaviour, so the staged work is kept."*
Task 8.1 must not touch `stop.rs` — Task 1.3 rewrites it — and must not wait for it either. The
resolution Step 0 found is that `settle::void_on_breach` already exists and already accepts the
state a horizon breach leaves behind, with no settle key:

```rust
pub fn void_on_breach(                                                   // settle.rs:238
    warrant: &mut Warrant,
    worktree: Option<&Worktree>,
    reason: &str,
) -> Result<String, WarrantError> {
    if !matches!(warrant.state, WarrantState::Open | WarrantState::Held) {  // 243
        return Err(WarrantError::WrongState { state: warrant.state, operation: "void_on_breach" });
```

So the effect-count breach — the one that is a *breach* rather than a granted limit arriving —
voids through `void_on_breach`, and the wall-clock horizon behaves exactly as the deadline does
(`Held`), because a shorter deadline is still a deadline and inventing a second outcome for it would
be incoherent. That split is a decision this task records, not a detail.

**The blast radius, measured rather than estimated.** `WarrantBounds` has public fields and no
`Default`, so adding any field breaks every struct literal. Command 4 above:

```
66
     16 rust/warrant/examples/emit_bounds_vectors.rs
      4 rust/warrant/tests/invariants/i11_self_change_is_governed.rs
      3 rust/warrant/tests/invariants/i09_failure_is_safe.rs
      2 rust/warrant/tests/warrant.rs
      2 rust/warrant/tests/spend.rs
      2 rust/warrant/tests/sandbox.rs
      2 rust/warrant/tests/report.rs
      2 rust/warrant/tests/proxy.rs
      2 rust/warrant/tests/invariants/i03_purpose_bound_data_use.rs
      2 rust/warrant/tests/egress.rs
      2 rust/warrant/src/sandbox.rs
      2 rust/warrant/src/lib.rs
      2 rust/archive/tests/verification_does_not_depend_on_the_archive.rs
      ... 23 further files at 1 site each
```

**66 sites in 36 files across two crates** (`warrantor-warrant` and `warrantor-archive`). That is
mechanical work but it is not small work, and it is the reason the field must be added exactly once,
as one `Option`, rather than as three separate fields.

**Three gates decide whether the field may be added at all.** First, the signature. `canonical` is a
re-serialization, so any field that appears in the signed bytes of a warrant that was signed before
the field existed breaks that warrant permanently:

```rust
fn canonical(claims: &WarrantClaims) -> Result<Vec<u8>, WarrantError> {   // lib.rs:443
    serde_json::to_vec(claims).map_err(|e| WarrantError::Encode(e.to_string()))
}
// verify(), lib.rs:538-539
let body = canonical(&self.claims)?;
```

`report.rs` 338–343 already carries the precedent, and states which half is load-bearing:
*"`skip_serializing_if` is the load-bearing half, and `spend` does not have it."* … *"Every report
signed before this field existed would stop verifying, on a surface whose entire purpose is that old
evidence keeps checking out."* The horizon field follows `custody`'s pattern
(`#[serde(default, skip_serializing_if = "Option::is_none")]`, report.rs:348), never `spend`'s.

Second, the tier decision is enforced by a length assertion. `rust/warrant/tests/warrant.rs`
538–559 ends:

```rust
    assert_eq!(
        strengths.len(),
        expected.len(),
        "a bound was added or removed without deciding which tier holds it"
    );
```

Third, both READMEs must carry the regenerated table verbatim —
`rust/warrant/tests/tier_disclosure.rs:287`,
`both_readmes_carry_the_bounds_table_generated_from_bound_strengths`, over `README.md` and
`rust/warrant/README.md` between `<!-- bound-tiers:begin -->` and `<!-- bound-tiers:end -->`.

**And a fourth gate nobody would guess.** `WarrantBounds::contains` has a **second implementation in
Python**, and CI checks them against each other. `python/warrantor_ml/src/warrantor_ml/tasks/bounds.py`
lines 66–74 name every field a proposal must state; `tools/ci/run_python_checks.py:207` regenerates
the fixture from `cargo run -p warrantor-warrant --example emit_bounds_vectors` before every test
run. A horizon field with containment semantics that is not mirrored there leaves the Python side
scoring model 5's over-grant rate against six rules while Rust enforces seven.

**Baseline output, captured verbatim.**

```
     Running tests\tier_disclosure.rs
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.57s

     Running tests\warrant.rs
running 25 tests
test every_bound_declares_the_tier_that_actually_holds_it ... ok
test a_tampered_bound_invalidates_the_signature ... ok
test signing_is_deterministic ... ok
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
```

```
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
RESULT: PASS - 260 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
```

`tools/ci/invariant-ratchet.json` on `origin/main`: `"passing_floor": 65`, `"ignored_ceiling": 19`.
Its note is the constraint: *"the ceiling exists so that silencing a failing test with `#[ignore]`
is a build failure rather than a way to hold the passing count steady."* **No `#[ignore]` in
`rust/warrant/tests/invariants/` covers L3-04.** The nearest is
`i12_safe_state_is_reachable.rs:167`, `the_kill_path_is_stronger_than_advisory`, whose ignore
message names `Task 1.3` — that one is not this task's to convert, and this task must not touch it.
This task therefore does not convert a recorded violation; it **adds a new passing test** to
`i12_safe_state_is_reachable.rs` and raises `passing_floor` in the same commit. Adding a new
`#[ignore]` anywhere is forbidden outright: the ceiling may only fall.

---

**Non-goals.**

1. **Not objective drift, and not any semantic measure of distance from the granting objective.**
   **Task 8.5** owns L3-09 and L3-01 and is routed to `opus` for exactly that reason. This task's
   three dimensions are all counters and clocks: nothing here reads the goal string.
2. **Not the risk dial, and not graduated tightening.** **Task 8.2** owns L3-02 and L3-07, and its
   seeded Step 0 says it reads this task's horizon state as an input. This task publishes a state
   and a verdict; it does not decide what else tightens when the horizon nears.
3. **Not parallelism, fan-out, rate or duplicate-effect suppression.** **Task 8.3** owns L3-05 and
   L3-10. A horizon counts effects along one warrant's chain over time; it says nothing about a
   thousand effects arriving at once, and must not be described as if it did.
4. **Not the population's horizon.** L3-04's own residual says so: *"a population can pass work
   between short-lived instances; the horizon governor alone does not bound the population's
   horizon, which is L3-11's job."* **Task 8.4** owns L3-11.
5. **Not the `halt` verb, not the kill switch, and not one line of `rust/warrant/src/stop.rs`.**
   **Task 1.3** owns `stop.rs`, `STOP_ENFORCEMENT_MODE`, `HaltScope` and the containment conformance
   receipt. This task calls `settle::void_on_breach`, which already exists.
6. **Not a replacement for the deadline.** `expires_at` stays, stays `Enforced`, and stays the outer
   limit. The horizon can only be tighter; a horizon that could extend a deadline would be an
   authority expansion wearing a governor's name.

---

**Files.**

Modified:
- `rust/warrant/src/lib.rs` (read all 724 lines; edit 246–271, 273–345, 668–686) — the `horizon`
  field, its containment rule, its entry in `bound_strengths()`.
- `rust/warrant/src/daemon.rs` (read all 465; edit 298–330, 371–392) — `SuperviseRequest` gains the
  horizon, and the wait becomes sliced so the unattended dimension is re-evaluated.
- `rust/warrant/src/proxy.rs` (read all 311; edit 101–125, 182–248) — the effect-count refusal.
- `rust/warrant/src/report.rs` (**contended** — Task 1.3 also edits this file; touch only 279–366
  and 463–545, and rebase on `origin/main` before the final gate) — the `HorizonSection` and its
  limitation line.
- `rust/warrant/src/bin/warrantor.rs` (read 55–70, 4478–4514, 4560–4600, 6432–6500; edit 4501) —
  `--max-wall-seconds`, `--max-effects`, `--max-unattended-seconds`, `--escalate-at-percent` on
  `grant`; the effective deadline at the `supervise_run` call site; USAGE lines.
- `rust/warrant/src/mcp_endpoints.rs` (read 150–250) — the MCP `warrant_grant` construction site at
  line 162, which must not silently default the horizon to "none means unlimited".
- `rust/warrant/src/sandbox.rs` (read 320–390) — one `Divergence::Gap` for `horizon`, because that
  function enumerates every bound and a missing one reads as an oversight.
- `rust/warrant/src/settle.rs` — read 238–260 only. **Unmodified.**
- `rust/warrant/src/supervise.rs` — read all 580 lines. **Unmodified, deliberately.** The whole
  composition claim is that the horizon shortens the budget the supervisor already enforces, so a
  diff in this file would mean the task duplicated the bound instead of composing with it. It is
  listed because the task's Tier A claim rests entirely on it.
- `README.md` and `rust/warrant/README.md` — the regenerated bounds table between the
  `bound-tiers` markers.
- `python/warrantor_ml/src/warrantor_ml/tasks/bounds.py` (read all 352; edit 60–74, 88–142,
  183–250) — the mirrored horizon field and containment rule.
- `rust/warrant/examples/emit_bounds_vectors.rs` (read all; 16 construction sites) — plus two new
  cases: a tightened horizon that is contained, and a dropped declared horizon that is not.
- `.github/workflows/ci.yml` (read 160–200) — the platform-conditional test allowlist.
- `tools/ci/invariant-ratchet.json` — `passing_floor` raised.
- `docs/W1-delivery-gaps.md` (read 1–24, 626–680, 800–825; insert a `### 3.7` before line 821) —
  the record that L3-04 was a W1 omission, with the date it was found.
- The 66 `WarrantBounds { .. }` struct-literal sites enumerated by Step 2's command, across 36 files
  in `rust/warrant/` and `rust/archive/`.

Created:
- `rust/warrant/src/horizon.rs` — the governor. A module in an existing crate, not a new crate.
- `rust/warrant/tests/horizon.rs` — the refusal tests and their controls.
- `rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs` gains one test (file exists,
  176 lines; read all of it first).
- `docs/task-evidence/task-8.1.md`.

---

**Consumes / Produces.**

Consumes, quoted with file and line, all present on `origin/main`:
- `rust/warrant/src/lib.rs:248` — `pub struct WarrantBounds { pub tools: BTreeSet<String>, pub write_paths: BTreeSet<String>, pub egress_hosts: BTreeSet<String>, pub staged_classes: BTreeSet<SideEffectClass>, pub expires_at: u64, pub budget_cents_observed: Option<u64>, pub delegation_depth: u32 }`
- `rust/warrant/src/lib.rs:283` — `pub fn contains(&self, other: &Self) -> Result<(), WarrantError>`
- `rust/warrant/src/lib.rs:346` — `fn validate(&self) -> Result<(), WarrantError>`
- `rust/warrant/src/lib.rs:668` — `pub fn bound_strengths() -> Vec<(&'static str, BoundStrength)>`
- `rust/warrant/src/lib.rs:197` — `pub enum BoundStrength { Enforced, Mediated, Observed }` with
  `pub fn word(self) -> &'static str` (211) and `pub fn caveat(self) -> &'static str` (228)
- `rust/warrant/src/supervise.rs:51` — `pub fn describe_linkage() -> Linkage` where
  `pub struct Linkage { pub mechanism: &'static str, pub survives_supervisor_death: bool, pub detail: &'static str }` (40)
- `rust/warrant/src/supervise.rs:191` — `pub fn wait_until(&mut self, seconds: u64) -> Result<Option<i32>, String>`
- `rust/warrant/src/supervise.rs:206` — `pub fn terminate(&mut self) -> Result<(), String>`
- `rust/warrant/src/supervise.rs:221` — `pub fn terminate_group(pid: u32)`
- `rust/warrant/src/daemon.rs:303` — `pub struct SuperviseRequest { pub warrant_id: String, pub expires_at: u64, pub program: String, pub args: Vec<String>, pub cwd: Option<PathBuf>, pub root: PathBuf, pub now: u64 }`
- `rust/warrant/src/daemon.rs:330` — `pub fn supervise_run(state: &DaemonState, request: &SuperviseRequest) -> Result<i32, String>`
- `rust/warrant/src/daemon.rs:106` — `pub struct CompletionRecord { pub warrant_id: String, pub pid: u32, pub exit_code: i32, pub expired: bool, pub finished_at: u64 }`
- `rust/warrant/src/proxy.rs:54` — `pub enum Decision { Forward, Stage { handle: String }, Deny { reason: String, bound: &'static str } }`
- `rust/warrant/src/proxy.rs:186` — `pub fn decide(&mut self, call: &ToolCall) -> Decision`
- `rust/warrant/src/staging.rs:453` — `pub fn len(&self) -> usize`; `:459` — `pub fn head_digest(&self) -> &str`
- `rust/warrant/src/settle.rs:238` — `pub fn void_on_breach(warrant: &mut Warrant, worktree: Option<&Worktree>, reason: &str) -> Result<String, WarrantError>`
- `rust/warrant/src/operators.rs:598` — `pub fn read_log(root: &Path, warrant_id: &str) -> Result<Vec<ActorRecord>, String>`, over
  `pub struct ActorRecord { pub format: String, pub warrant_id: String, pub act: Act, pub actor: Option<String>, pub via: String, pub at: u64, pub prev: String, pub digest: String }` (492)
  and `pub enum Act { Approve, Settle, Void, Stop }` (454)
- `rust/warrant/src/review.rs:470` — `pub fn record_request(root: &Path, warrant_id: &str, at: u64, blocker: &str) -> Result<(), String>`;
  `:460` — `pub fn should_announce(root: &Path, warrant_id: &str, blocker: &str) -> bool`
- `rust/warrant/src/notify.rs:70` — `pub const EVENTS: [&str; 5]`
- `rust/warrant/src/report.rs:449` — `pub fn bundle_digest(bundle: &ReportBundle) -> Result<String, ReportError>`;
  `:463` — `fn limitations(stored, contained_scopes, spend, custody) -> Vec<String>` (gains a fifth parameter)
- `rust/warrant/tests/invariants/harness.rs:50` — `pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)`

Does not exist and is **not** created here: `stop::halt`, `HaltScope`, `HaltContext`,
`EnforcementBasis` — all created by **Task 1.3**. L3-04's verification clause names `halt()`; until
1.3 lands, this task's own halt path is `supervisor.terminate()` plus `settle::void_on_breach`, and
the evidence file says so rather than claiming the verb.

Produces, new:
- `warrantor_warrant::horizon`: `pub const HORIZON_STATE_FORMAT: &str = "warrantor.horizon-state/1"`;
  `pub enum HorizonDimension { Wall, Effects, Unattended }` with `pub const fn word(self) -> &'static str`
  and `pub const fn strength(self) -> BoundStrength`;
  `pub struct HorizonUsage { pub elapsed_seconds: u64, pub effects: u64, pub unattended_seconds: u64 }`;
  `pub enum HorizonVerdict { Within { nearest: Option<(HorizonDimension, u8)> }, Escalate { dimension: HorizonDimension, at_percent: u8, limit: u64, observed: u64 }, Breached { dimension: HorizonDimension, limit: u64, observed: u64 } }`;
  `pub fn evaluate(horizon: &Horizon, usage: &HorizonUsage) -> HorizonVerdict`;
  `pub fn effective_deadline(bounds: &WarrantBounds, issued_at: u64) -> u64`;
  `pub fn usage_at(root: &Path, stored: &StoredWarrant, staged: usize, forwarded: u64, now: u64) -> HorizonUsage`;
  `pub fn breach_reason(dimension: HorizonDimension, limit: u64, observed: u64) -> String`.
- `warrantor_warrant::Horizon`: `pub struct Horizon { pub max_wall_seconds: Option<u64>, pub max_effects: Option<u64>, pub max_unattended_seconds: Option<u64>, pub escalate_at_percent: Option<u8> }`,
  and on `WarrantBounds`: `#[serde(default, skip_serializing_if = "Option::is_none")] pub horizon: Option<Horizon>`.
- `warrantor_warrant::report::HorizonSection { pub declared: bool, pub dimensions: Vec<HorizonLine>, pub verdict_word: String, pub breached: Option<String> }`,
  carried as `#[serde(default, skip_serializing_if = "Option::is_none")] pub horizon: Option<HorizonSection>`.
- CLI: `warrantor grant … [--max-wall-seconds N] [--max-effects N] [--max-unattended-seconds N] [--escalate-at-percent N]`;
  `warrantor horizon <warrant-id>` printing the three dimensions, each with its tier word and caveat.

---

**Bound strength.** Three dimensions, three different answers, and the task is only honest if it
keeps them apart.

- **`max_wall_seconds` — Tier B for the decision, Tier A for the termination.** The decision is
  arithmetic in the warrant runtime over signed claims (`horizon::effective_deadline`); the
  termination is `supervisor.terminate()` → `terminate_group` → a Windows job object or
  `kill -KILL -pgid` under `setsid`. This is composition, not duplication: the horizon supplies a
  smaller number to the wait budget that `daemon.rs:374` already computes, and `supervise.rs` is not
  edited. Do **not** label the whole dimension Tier A — the seed warns against exactly this and it
  is right.
- **`max_effects` — Tier B, chokepoint.** Refused at `rust/warrant/src/proxy.rs:186`, by a specific
  line that returns `Decision::Deny { bound: "horizon_effects" }` at the moment the call is
  attempted. That is a refusal, so it is not Observed. It is also not Enforced: the proxy sees only
  what the agent routes through it, and `BoundStrength::Mediated::caveat()` already says so in the
  vocabulary every surface prints.
- **`max_unattended_seconds` — Tier B for the decision, Tier A for the termination, and Observed for
  what it measures.** The measurement is "seconds since the most recent actor-log entry made by a
  **named** operator". `operators.rs:499` says `actor: None` is real and means the unscoped session
  token, so `None` entries do not count. The only thing in this system the agent provably cannot
  produce is a settle-authority signature (`verify_settle`, lib.rs:568), and the actor log is
  weaker than that: `operators.rs:537-542` says the chain *"proves nothing to a third party who has
  never seen an earlier head."*
- **Escalation adds no trust root.** `escalate_at_percent` raises a local review request through
  `review::record_request` (a file under the store root) and the existing webhook path. It
  establishes that a notification was queued on this machine. It does not establish that a human
  read it, and `review.rs:411-419` already says the marker carries "one line, no authority". No
  central approval service, no directory, no new signer.
- **The orphan count does not move.** `horizon.rs` is a module inside `rust/warrant`, not a new
  crate. `python tools/ci/wiring_census.py` must still print `9 of 39 crates reachable … over 17
  path edges`, and `README.md:196` must still read `reachable from the CLI | **9 of 39**`. A
  changed census number in this task is a defect, not progress.

**The sentence that will appear in the product**, in `report.rs`'s `limitations()` and in
`warrantor horizon`'s output, and nowhere softened:

> The horizon's effect ceiling counts only effects Warrantor saw: staged effects from this warrant's
> hash-chained queue, plus calls forwarded through the MCP proxy during sessions that are still
> running. It does not count anything the agent did with a shell, a harness built-in, or any path
> that never reached the proxy, and a forwarded-effect count is lost when a session ends — so the
> observed number is a floor, never a total. The wall-clock and unattended ceilings are terminated
> by the operating system and cannot be outlived; the effect ceiling is refused at a chokepoint the
> agent could decline to use. "Unattended" means no named operator has appeared in this warrant's
> actor log, which is evidence about a local hash-chained file, not proof that no human was
> watching.

---

**Exit gate.** From `rust/`, the command
`cargo test -p warrantor-warrant --all-targets -j 2 && python ../tools/ci/check_invariant_ratchet.py && python ../tools/ci/wiring_census.py`
must print `test result: ok` for every target with `horizon_wall_breach_terminates_the_process_group`
and `a_named_operator_act_resets_the_unattended_clock` both shown as executed, report the raised
`passing_floor` as satisfied with `ignored_ceiling` still 19, and end with
`wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges`; any one of the
three failing fails the task.

---

- [ ] **Step 1 — Worktree, and confirm the ground has not moved.**

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git fetch origin
git worktree add M:/wt-8.1 -b feat/horizon-governor origin/main
cd M:/wt-8.1
export CARGO_TARGET_DIR=M:/wt-8.1-target
export RUST_MIN_STACK=16777216
git rev-parse HEAD                       # expect e4b5f10 or a later origin/main
git ls-tree --name-only refs/remotes/origin/main rust/ | grep -c '^rust/warrant$'   # 1
```

*Test intent:* nothing is asserted yet; this step exists so that a later disagreement between this
task's numbers and CI's is attributable to a moved `origin/main` rather than to a mistake. If
`rust/warrant` is not present, stop — every later step's first `cargo` call dies.

- [ ] **Step 2 — Enumerate the 66 construction sites and the four gates, and commit the list before
      touching any of them.** A field addition that discovers its own blast radius halfway through
      leaves a half-migrated tree that neither compiles nor reverts cleanly.

```bash
grep -rn "WarrantBounds {" rust/ --include=*.rs | tee /tmp/8.1-sites.txt | wc -l
grep -rn "WarrantBounds {" rust/ --include=*.rs | sed 's/:.*//' | sort | uniq -c | sort -rn
grep -n "REQUIRED_PROPOSAL_FIELDS" -A 10 python/warrantor_ml/src/warrantor_ml/tasks/bounds.py
grep -n "bound-tiers:begin" README.md rust/warrant/README.md
grep -n "passing_floor\|ignored_ceiling" tools/ci/invariant-ratchet.json
```

*Test intent:* the count printed here must equal the count in `docs/task-evidence/task-8.1.md`, and
every file in the list must appear in the final diff or be explicitly excused in the evidence file.
A site missed is a compile error; a site "fixed" by adding a default value nobody decided is an
unbounded horizon wearing a bounded one's name.

- [ ] **Step 3 — Failing test first: an absent horizon is a horizon of NOTHING BOUNDED, and it says
      so.** The single most dangerous reading in this task is `None` meaning "unlimited". `lib.rs:246`
      already sets the crate-wide convention — *"Absent fields mean 'not permitted', never
      'unlimited'"* — but a horizon inverts it: an absent horizon genuinely means the deadline is the
      only ceiling, which is the state `origin/main` is in. That must be *reported*, never silently
      read as bounded.

Write `rust/warrant/tests/horizon.rs`, red before the module exists:

```rust
//! The horizon governor's refusals, each paired with a control that is allowed.
use warrantor_warrant::horizon::{self, HorizonDimension, HorizonUsage, HorizonVerdict};
use warrantor_warrant::{Horizon, WarrantBounds};

/// An absent horizon is not a bounded one. `warrantor horizon` and the report must say the
/// warrant's only ceiling is its deadline, because that is the true statement about every
/// warrant granted before this field existed.
#[test]
fn an_absent_horizon_is_reported_as_unbounded_not_as_satisfied() {
    let bounds = bounds_without_horizon();
    assert!(bounds.horizon.is_none());
    let section = warrantor_warrant::report::horizon_section(&bounds, &usage(10_000, 900, 10_000));
    assert!(!section.declared, "an absent horizon must not report as declared");
    assert_eq!(section.verdict_word, "not-declared");
    assert!(
        section.dimensions.is_empty(),
        "no dimension may be rendered with a limit nobody granted"
    );
    // And the load-bearing half: it must never read as a pass.
    assert_ne!(section.verdict_word, "within");
}

/// The reverse control: a declared horizon well inside its ceilings reports `within`, so the
/// assertion above is measuring the absence and not a function that always says `not-declared`.
#[test]
fn a_declared_horizon_inside_its_ceilings_reports_within() {
    let horizon = Horizon {
        max_wall_seconds: Some(3_600),
        max_effects: Some(50),
        max_unattended_seconds: Some(1_800),
        escalate_at_percent: Some(80),
    };
    let verdict = horizon::evaluate(&horizon, &usage(60, 3, 30));
    assert!(matches!(verdict, HorizonVerdict::Within { .. }), "got {verdict:?}");
}
```

*Test intent:* prove the field's absence is a reported fact rather than a silent pass, and prove the
same function can say `within`, so neither assertion is one-sided.

- [ ] **Step 4 — Failing test: the effect ceiling REFUSES the call that would exceed it, and allows
      the one that would not.** This is the dimension that does not exist today in any form, and the
      refusal must be at the moment the call is attempted.

```rust
/// The step-count ceiling L3-04 names and `WarrantBounds` does not have. Refused at
/// `Proxy::decide`, which is the only place in this crate that refuses a call as it arrives.
#[test]
fn the_effect_ceiling_refuses_the_call_that_would_exceed_it() {
    use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
    use warrantor_warrant::staging::EffectRegistry;

    let mut bounds = bounds_without_horizon();
    bounds.horizon = Some(Horizon { max_effects: Some(2), ..Horizon::none() });

    // CONTROL: two effects are within a ceiling of two, and both are allowed. Without this the
    // refusal below would prove only that the proxy refuses.
    let mut control = Proxy::new(bounds.clone(), ProxyMode::Enforce, EffectRegistry::github());
    control.observe_effects(0);
    let first = control.decide(&call("git.commit"));
    control.observe_effects(1);
    let second = control.decide(&call("git.commit"));
    assert!(
        !matches!(first, Decision::Deny { .. }) && !matches!(second, Decision::Deny { .. }),
        "the CONTROL was refused, so the attack never reached the boundary: {first:?} {second:?}"
    );

    // ATTACK: the third effect crosses the ceiling and must be refused by name.
    let mut attacked = Proxy::new(bounds, ProxyMode::Enforce, EffectRegistry::github());
    attacked.observe_effects(2);
    match attacked.decide(&call("git.commit")) {
        Decision::Deny { bound, reason } => {
            assert_eq!(bound, "horizon_effects");
            assert!(
                reason.contains("2") && reason.contains("horizon"),
                "a refusal the agent cannot act on is a crash with better manners: {reason}"
            );
        }
        other => panic!("the third effect was not refused: {other:?}"),
    }
}
```

*Test intent:* a named refusal at the chokepoint, with an allowed control at the limit. Rule 3 in
one test: the control must pass at exactly `n = limit`, so the boundary is at `> limit` and not at
`>= limit - 1`.

- [ ] **Step 5 — Failing test: elapsed autonomy without a named human is bounded, and a named act
      resets it.** Zero human contact over a long run is the incident's shape; "many agents ran for
      multiple days" is the anchor (METR/Redwood, S02 §Timeline).

```rust
/// The unattended clock reads the actor log, and only entries with a NAMED operator count.
/// `operators.rs` says `actor: None` means the unscoped session token, so counting it would let
/// an agent's own session pass for human contact.
#[test]
fn a_named_operator_act_resets_the_unattended_clock() {
    use warrantor_warrant::operators::{record, Act};
    let root = tempdir("unattended");
    let stored = granted(&root, /* issued_at */ 1_000);

    // ATTACK: nothing but anonymous acts for longer than the ceiling.
    record(&root, &stored.warrant.claims.id, Act::Stop, None, "session-token", 1_100).unwrap();
    let breached = horizon::usage_at(&root, &stored, 0, 0, 1_000 + 4_000);
    assert_eq!(breached.unattended_seconds, 4_000, "an anonymous act is not human contact");

    // CONTROL: one act by a named operator, and the clock restarts from it.
    record(&root, &stored.warrant.claims.id, Act::Approve, Some("ana"), "operator-token", 4_500)
        .unwrap();
    let reset = horizon::usage_at(&root, &stored, 0, 0, 1_000 + 4_000 + 600);
    assert_eq!(
        reset.unattended_seconds, 1_100,
        "a named act must reset the clock, or the bound refuses every long run regardless of \
         whether anyone was watching"
    );
}
```

*Test intent:* the refusal side (anonymous acts do not count) and the allowed side (a named act
resets) in one test. Without the second half this bound would fire on every overnight run that a
human did supervise, which is the failure mode that gets a governor turned off.

- [ ] **Step 6 — Failing test: the record names the dimension that was exceeded.** A stop with no
      reason is indistinguishable from a crash, and `daemon.rs`'s existing `CompletionRecord` carries
      only `expired: bool` — one boolean for three dimensions.

Add `pub horizon_breach: Option<String>` to `CompletionRecord` with
`#[serde(default, skip_serializing_if = "Option::is_none")]`, populate it from
`horizon::breach_reason`, and assert:

```rust
#[test]
fn the_completion_record_names_which_horizon_dimension_ended_the_run() {
    let record = run_until_horizon(Horizon { max_effects: Some(1), ..Horizon::none() });
    let named = record.horizon_breach.expect("a horizon halt with no reason is a crash");
    assert!(named.starts_with("horizon:effects"), "got {named}");
    assert!(named.contains("limit 1"), "the limit must be in the record: {named}");
    assert!(named.contains("observed 2"), "so must what was observed: {named}");

    // CONTROL: a run that finishes inside every ceiling records no breach at all, so the
    // assertion above is not satisfied by a field that is always populated.
    let clean = run_until_exit(Horizon { max_effects: Some(50), ..Horizon::none() });
    assert!(clean.horizon_breach.is_none());
    assert!(!clean.expired);
}
```

*Test intent:* the dimension, the limit and the observation are all in the record, and a clean run
carries none of them.

- [ ] **Step 7 — Compose with `supervise.rs` rather than duplicating it, and assert the process group
      actually dies.** The wall-clock horizon supplies a smaller number to the wait budget
      `daemon.rs:374` already computes. `supervise.rs` gets zero edits; the diff proves the
      composition.

At `bin/warrantor.rs:4501`, replace `expires_at: stored.warrant.claims.bounds.expires_at` with
`expires_at: horizon::effective_deadline(&stored.warrant.claims.bounds, stored.warrant.claims.issued_at)`,
and in `daemon.rs` slice the wait so the unattended dimension is re-evaluated while the run is live:

```rust
// One wait becomes a loop of slices. `wait_until` already polls once per second, so a slice
// costs nothing extra; what it buys is a horizon that can be breached by a clock that only
// moves when nobody acts, which a single up-front budget cannot express.
const HORIZON_SLICE_SECONDS: u64 = 30;
let mut breach: Option<String> = None;
let (code, expired) = loop {
    let left = effective.saturating_sub(now.saturating_add(started.elapsed().as_secs()));
    if left == 0 {
        breach = Some(horizon::breach_reason(HorizonDimension::Wall, wall_limit, elapsed()));
        supervisor.terminate()?;                    // the Tier A kill, unchanged
        break (-1, true);
    }
    if let Some(code) = supervisor.wait_until(left.min(HORIZON_SLICE_SECONDS))? {
        break (code, false);
    }
    let usage = horizon::usage_at(root, &stored, staged_len, forwarded, clock());
    if let HorizonVerdict::Breached { dimension, limit, observed } =
        horizon::evaluate(&horizon, &usage)
    {
        breach = Some(horizon::breach_reason(dimension, limit, observed));
        supervisor.terminate()?;
        break (-1, true);
    }
};
```

Then assert the group is gone, on the platform whose mechanism is being claimed:

```rust
/// The horizon must kill the tree, not the direct child. `supervise::tests` already proves the
/// job object and the group kill do this; this test proves the horizon path REACHES them.
#[test]
#[cfg(windows)]
fn horizon_wall_breach_terminates_the_process_group() {
    let (root_pid, grandchild_pid) = spawn_tree_under_horizon(/* max_wall_seconds */ 2);
    assert!(gone_within(root_pid, Duration::from_secs(10)), "the agent survived its horizon");
    assert!(
        gone_within(grandchild_pid, Duration::from_secs(10)),
        "the grandchild survived: the horizon killed the child, not the tree, and a governor \
         that leaves descendants running has bounded nothing"
    );
}
```

*Test intent:* prove the horizon reaches the OS mechanism rather than reimplementing it, and prove
the descendant dies — the case `describe_linkage`'s Linux caveat says `PR_SET_PDEATHSIG` does not
cover and `terminate_group` does.

- [ ] **Step 8 — Register the new `#[cfg(windows)]` test in CI's executed-test allowlist.** A
      platform-conditional test that is compiled out reports nothing at all, so a green run cannot
      distinguish "ran and passed" from "never existed on this OS". `.github/workflows/ci.yml`
      177–200 already carries the list this repository added for exactly that reason:

```yaml
          if [ "$RUNNER_OS" = "Windows" ]; then
            names="supervise::tests::job_object_kills_the_child_tree_when_the_supervisor_drops \
              supervise::tests::terminate_group_kills_the_grandchild_too \
              horizon_wall_breach_terminates_the_process_group \
              tests::local_process_engine_actually_kills_a_real_process_ax05 \
              tests::the_critical_image_rail_is_consulted_once_per_kill_ax05 \
              a_stale_lock_is_stolen_once_the_window_passes"
```

*Test intent:* the CI step greps for `test <name> ... ok` in the log and fails the build when it is
absent. Without this line the Tier A half of the wall-clock claim is untested on the only OS whose
mechanism the claim names, which is precisely the hazard recorded in `docs/W1-delivery-gaps.md` §3.6.

- [ ] **Step 9 — The containment rule, in Rust and in its Python mirror, with vectors for both.** A
      child may tighten its horizon and may never loosen one; a child that drops a *declared*
      horizon is an expansion, for the same reason `lib.rs:325-338` gives about a dropped budget
      ceiling.

```rust
// In WarrantBounds::contains, after the expires_at check at lib.rs:307.
match (&self.horizon, &other.horizon) {
    // The parent declared none: the child may declare one (tightening), and inherits nothing.
    (None, _) => {}
    (Some(parent), None) => {
        return Err(WarrantError::AuthorityExpanded(format!(
            "horizon: the parent is bounded ({}) but the child declares no horizon. An absent \
             horizon is bounded only by the deadline, so it is not inherited -- state the \
             child's horizon explicitly",
            parent.describe()
        )));
    }
    (Some(parent), Some(child)) => parent.contains_horizon(child)?,
}
```

and the mirror, in `python/warrantor_ml/src/warrantor_ml/tasks/bounds.py`, added to
`REQUIRED_PROPOSAL_FIELDS` (line 66) and to `authority_expansions` (line 183). Then add two cases to
`rust/warrant/examples/emit_bounds_vectors.rs` — `horizon_tightened_is_contained` and
`horizon_dropped_is_an_expansion` — so `tools/ci/run_python_checks.py:207` regenerates a fixture that
covers the new rule.

*Test intent:* `python tools/ci/run_python_checks.py test` must fail if the two implementations
disagree about either case. A second implementation of authority arithmetic that is only checked on
six of seven rules is a second implementation that can disagree on the seventh.

- [ ] **Step 10 — Declare the tier, regenerate both README tables, and update the length
      assertion.** `bound_strengths()` gains one entry; three tests decide whether the entry is
      honest.

```rust
// lib.rs:686, appended to bound_strengths()
// Two mechanisms, and the entry names the weaker of the two because a reader takes the first
// word and moves on. The wall-clock and unattended dimensions are terminated by the OS process
// link and are unbypassable once the supervisor is running; the effect ceiling is refused at the
// MCP proxy, which sees only what the agent routes through it. Mediated is the tier the whole
// bound earns.
("horizon", BoundStrength::Mediated),
```

Then: add `("horizon", BoundStrength::Mediated)` to `expected` in
`rust/warrant/tests/warrant.rs:538` so `strengths.len() == expected.len()` holds again; run
`cargo run -p warrantor-warrant --bin warrantor -- --render-bounds-table` (or a one-line test
harness printing `render_bounds_table()`) and paste the output between the `bound-tiers` markers in
both `README.md` and `rust/warrant/README.md`; add one `Divergence::Gap` for `horizon` in
`sandbox.rs` alongside the six that are already there.

*Test intent:* `cargo test -p warrantor-warrant --test tier_disclosure --test warrant -j 2` must go
from 9 + 25 passing to 9 + 25 passing with the new entry present. Naming the wall-clock half
`Enforced` here would be the exact defect Rule 1 forbids: the bound is one bound, and its weakest
mechanism is the one the word has to describe.

- [ ] **Step 11 — Add one passing test to the I-12 corpus and raise the ratchet floor in the same
      commit.** No `#[ignore]` covers L3-04, so nothing is converted; but "safe state is reachable"
      is exactly what a horizon halt demonstrates, and a passing test earns a floor.

```rust
// rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs -- appended, and NOT near line
// 167: `the_kill_path_is_stronger_than_advisory` is Task 1.3's #[ignore] and stays untouched.
/// Adversarial, with the control the harness insists on: an effect-ceiling breach reaches a safe
/// state (Void, staged effects discarded, receipts retained), and a run inside the ceiling does
/// not. `refused_at_the_boundary` fails loudly if the control is refused.
#[test]
fn a_horizon_breach_reaches_a_safe_state_and_a_run_inside_it_does_not() {
    let control = settle_outcome_under(Horizon { max_effects: Some(50), ..Horizon::none() });
    let attacked = settle_outcome_under(Horizon { max_effects: Some(1), ..Horizon::none() });
    crate::harness::refused_at_the_boundary(
        "I-12 horizon: an effect-ceiling breach must reach Void",
        &control,
        &attacked,
        |outcome| outcome.state == warrantor_warrant::WarrantState::Settled,
    );
    assert_eq!(attacked.state, warrantor_warrant::WarrantState::Void);
    assert!(attacked.receipts_retained, "void discards staged effects and KEEPS receipts");
}
```

and, in the same commit, `tools/ci/invariant-ratchet.json`:

```json
{
  "format": "warrantor.invariant-ratchet/1",
  "recorded": "2026-09-05",
  "source": "rust/warrant/tests/invariants/",
  "passing_floor": 66,
  "ignored_ceiling": 19,
  "note": "The invariant attack corpus for I-01..I-12. `passing_floor` may only rise; `ignored_ceiling` may only fall. Every ignored test is a recorded violation named in docs/W1-delivery-gaps.md Tier 5 -- the ceiling exists so that silencing a failing test with #[ignore] is a build failure rather than a way to hold the passing count steady. Raise the floor in the same commit that earns it."
}
```

*Test intent:* `python tools/ci/check_invariant_ratchet.py --show-findings` must report the floor as
satisfied at 66 with the ceiling still 19. If the new test cannot be made to pass, the floor stays
at 65 and the test is **not** added with `#[ignore]` to hold the shape — that would raise the
ceiling and fail the build, which is the gate working.

- [ ] **Step 12 — Record the W1 omission in the gaps ledger, then run every gate and write the
      evidence file.** Insert `### 3.7 The horizon governor was a W1 item and was never scheduled —
      found 2026-09-05` before `## Tier 4` (currently line 821 of `docs/W1-delivery-gaps.md`),
      naming: that L3-04 is `status=partial` `W1`; that the partial was the wall-clock half only;
      that no count-shaped bound existed; that the three seed errors above were found by reading the
      code; and what this task did and did not close — in particular that L3-04's verification clause
      names `halt()`, which is Task 1.3's, so the halt here is `supervisor.terminate()` plus
      `settle::void_on_breach`.

```bash
cd rust
cargo metadata --format-version 1 --locked > /dev/null
cargo fmt --all -- --check
cargo clippy -p warrantor-warrant -p warrantor-archive --all-targets -j 2 -- -D warnings
cargo test -p warrantor-warrant --all-targets -j 2
cd ..
python tools/ci/run_python_checks.py test  --report evidence/python-tests.json
python tools/ci/run_python_checks.py lint   --report evidence/python-lint.json
python tools/ci/run_python_checks.py format --report evidence/python-format.json
python tools/ci/check_invariant_ratchet.py --show-findings
python tools/ci/wiring_census.py
python tools/ci/check_docs.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
  docs/W1-delivery-gaps.md docs/task-evidence/task-8.1.md
git commit -s
```

*Test intent:* the Rust gate for the two crates this task touched and the Python gate for the mirror
it changed — per the repository convention that a gate is run for every language in the diff. The
census line must still read `9 of 39` (Rule 4), the ratchet must report 66/19, and
`docs/task-evidence/task-8.1.md` must carry the verbatim output of each command above, the count from
Step 2 matching the diff, and one paragraph naming what is still a guess: whether an effect ceiling
set from real runs is a number an operator can choose without either strangling normal work or
sitting so far above it that it never fires.

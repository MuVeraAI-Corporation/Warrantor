### Task 3.4: Broker-side flight recorder behind a `Recorder` trait — expanded to step form

**Anchor.** L7-02 — the single most load-bearing property in the specification. At least 96
transcripts in the incident carried confirmed tool-call spoofing, and the investigators state
plainly that sufficiently ambitious tampering would by design leave no transcript trace. Evidence
written inside the agent's blast radius is not evidence. Five downstream consumers — audit,
detection, training corpus, assurance, settlement — are worth exactly as much as this property is
true. This expansion re-verified every anchor against local `main` at `6f41384` and resolves the
one thing the seed left open: what "the recorder" already is on this tree, so the trait wraps
reality instead of a sketch.

**What exists on `main`, re-verified 2026-09-06.** `rust/flight-recorder/src/lib.rs` is **1,371
lines** and is a full implementation, not a stub: `Receipt` with `emit_pending` (`:412`) and
`mark_committed` (`:452`) — I-07's evidence-precedes-commitment invariant is already its own doc
contract — plus `verify` (`:475`), hash-chain digests with
`RecorderError::EvidenceChainCorrupt { seq, detail }` (`:115`), a documented rewrite attack at
`:305-306` it already defends against (a signature over the canonical bytes survives byte-level
edits, so the chain commits the canonical form and the canonicalization is the verification's
input), replay-verified reopening at `:627`, and OCSF JSON rendering (`:498`). **It is, however,
on the orphan list**: `evidence/wiring-coverage.json` does not reach `warrantor-flight-recorder`
from `warrantor-warrant`, and no line of `rust/warrant` calls it. The warrant crate's own
two-phase path (Task 2.3's `FileRecorder`) is a *separate* local recorder whose doc says
honestly: "Local, not external… Task 3.4 puts the flight recorder behind the same trait." That
sentence is this task's spec.

**Where the seed is right, and where it is silent.** Right: the deliverable is the trait seam and
the wiring, not a new recorder. Silent on: the existing `FileRecorder` must keep working unchanged
for every Task 2.3 caller (the `two_phase`, `settle`, `github_adapter` suites depend on its exact
semantics); the flight recorder's `emit_pending`/`mark_committed` two-step must map onto the
trait's one-step `record` without weakening I-07 (the mapping is emit+commit inside `record`, so
the caller never sees a pending-only state); and the census moves when the crate becomes
reachable — all three are steps here, not discoveries mid-implementation.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-3.4.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-3.4 -b feat/task-3.4-recorder-trait main
cd M:/wt-task-3.4
wc -l rust/flight-recorder/src/lib.rs
grep -n "pub fn emit_pending\|pub fn mark_committed\|pub fn verify\|EvidenceChainCorrupt" rust/flight-recorder/src/lib.rs
grep -n "pub trait Recorder" rust/warrant/src/staging.rs
grep -n "fn record\|fn performed\|fn unresolved" rust/warrant/src/staging.rs | head -6
python -c "import json; c=json.load(open('evidence/wiring-coverage.json')); print('flight' in str(c))"
grep -rln "FileRecorder" rust/warrant/src rust/warrant/tests --include=*.rs
sed -n '300,315p' rust/flight-recorder/src/lib.rs
sed -n '620,640p' rust/flight-recorder/src/lib.rs
```

Expected: 1,371 lines; the three functions at the lines above; `trait Recorder` in `staging.rs`
(Task 2.3's seam, three methods: `record`, `performed`, `unresolved`); flight-recorder absent
from the reachable set; `FileRecorder` used by `settle.rs`, `serve.rs`, `mcp_endpoints.rs`,
`bin/warrantor.rs` and two test files. Read in full: `rust/flight-recorder/src/lib.rs` (all
1,371 lines — the chain discipline, the rewrite defense at `:305`, and the reopen verification
at `:627` are what "broker-side" means here), and `rust/warrant/src/staging.rs`'s `Recorder`
trait section (the seam this task generalizes).

---

**Step 1 — Failing test: a container reset cannot truncate the chain silently.** The incident's
agents ran a dedicated telemetry project to predict resets and hoped to use them to wipe history;
the test encodes exactly that. Simulate the reset by writing a truncated log (drop the tail after
record 3 of 5), reopening, and asserting the recorder **reports the gap as a declared condition**
— the reopened state must either refuse to append past an unexplained gap or open with a gap
record naming the sequence range it can no longer vouch for, never present a shorter chain as if
nothing happened:

```rust
#[test]
fn a_reset_mid_run_leaves_a_declared_gap_not_a_silent_truncation() {
    let dir = tempdir("reset");
    let path = dir.join("chain.jsonl");
    {
        let mut rec = FlightLog::open(&path).expect("open");
        for i in 1..=5 {
            rec.append(&entry(i)).expect("append");
        }
    }
    // The "reset": the tail after record 3 is gone, as a container death would leave it.
    truncate_log_after(&path, 3);
    let reopened = FlightLog::open(&path);
    match reopened {
        Ok(rec) => {
            let gap = rec.declared_gap().expect("a declared gap must exist");
            assert_eq!(gap, (4, 5), "the gap names the sequence range it cannot vouch for");
        }
        Err(e) => panic!("an unexplained refusal hides the gap's shape: {e}"),
    }
}
```

Run this against the CURRENT flight-recorder first, before any change: the failing shape tells
you which half is missing. At `:627` the reopen verifies the chain, so a truncated tail is
likely *detected* already — the question the test answers is whether the detection is *named* as
a gap with a range (the honest condition an operator can act on) or is an opaque error that a
frantic operator is tempted to delete the log over. If the current error already carries the
range, the test passes and the gap record becomes the append-side change; if not, this is the
red step.

**Step 2 — Failing test: an agent with write access to its own workspace cannot alter a
recorded entry.** The agent's workspace is the store's worktree; the recorder's log must live
outside it. The test writes a record, then re-creates the log path the agent would see (under
the worktree, not the store root), mutates it, and asserts the recorded entry's digest still
verifies against the log at the store root:

```rust
#[test]
fn an_agent_mutating_its_own_visible_log_does_not_change_the_record() {
    let store = tempdir("store-root");
    let worktree = tempdir("worktree");       // inside the agent's blast radius
    let rec = FlightLog::open_at(&store, &worktree).expect("open");
    rec.append(&entry(1)).expect("append");
    // The agent writes its own file where it can see a log living.
    std::fs::create_dir_all(worktree.join("flight")).expect("dir");
    std::fs::write(worktree.join("flight/chain.jsonl"), b"tampered").expect("agent writes");
    // The real log at the store root verifies, untouched.
    let reopened = FlightLog::open_at(&store, &worktree).expect("reopen");
    reopened.verify_chain().expect("the store-root chain is intact");
}
```

This test pins the **path discipline**: if the recorder and the worktree ever share a directory,
it fails. That is the property "broker-side" reduces to on a single machine, and it is worth a
test more than a paragraph.

---

**Step 3 — Introduce `trait Recorder` at the flight-recorder boundary, with no behavior change.**
Task 2.3's `staging::Recorder` (`record`/`performed`/`unresolved`) is the seam the code already
names. This task does not move that trait; it makes the flight recorder implement it and adds the
broker-side guarantees the contract needs:

```rust
// rust/flight-recorder/src/lib.rs
impl warrantor_warrant::staging::Recorder for FlightRecorder {
    fn record(&mut self, idempotency_key: &str, receipt: &WarReceipt) -> Result<RecorderAck, String> {
        // emit_pending -> mark_committed, synchronously, inside this call: the ack means
        // "on the broker's durable chain", not "in a buffer". The two-step is the crate's
        // I-07 discipline; the caller never sees a pending-only state.
        let input = ReceiptInput::from_war_receipt(idempotency_key, receipt)?;
        let mut receipt = self.emit_pending(input).map_err(|e| e.to_string())?;
        self.mark_committed(&mut receipt).map_err(|e| e.to_string())?;
        self.append_to_chain(&receipt).map_err(|e| e.to_string())?;
        Ok(RecorderAck { sequence: receipt.sequence })
    }
    fn performed(&self, idempotency_key: &str) -> Option<String> { /* replay lookup */ }
    fn unresolved(&self, idempotency_key: &str) -> bool { /* pre without post */ }
}
```

`Uuid` (flight-recorder's receipt id) is a new external crate for `warrantor-warrant`'s graph if
this impl copies that code into the warrant's dependency path — it does not: the trait impl lives
in `flight-recorder`, which already depends on `uuid`, and `warrantor-warrant` depends on the
trait object, not the concrete crate. Verify with `cargo metadata --locked` after wiring.

Run the full workspace suite: Task 2.3's `two_phase.rs` tests must pass unchanged against BOTH
backends — the file recorder (unchanged) and the flight recorder (new).

```bash
cargo test -p warrantor-warrant --test two_phase -j 2
cargo test -p warrantor-flight-recorder -j 2
```

**Step 4 — Wire the flight recorder as the CLI settle backend behind an explicit flag,
disclosed at attach.** The default stays `FileRecorder` this task — flipping the default is a
deployment decision the ledger records, not a side effect of the trait landing. `warrantor settle
--recorder flight` opens the flight recorder, prints which backend is active and where its log
lives, and refuses to start if the flight-recorder's directory is not writable (a recorder that
cannot write is a settle that must not run — the fail-closed shape Task 1.1's evidence
established):

```rust
enum SettleRecorder { File(FileRecorder), Flight(FlightRecorderBackend) }
// matches staging::Recorder on the inner types; the settle call takes &mut dyn Recorder,
// so the enum is behind one impl.
```

The flag is added to the usage text and to the usage-contract test's allowlist in the same
commit — the gate Tasks 2.4 and 2.6 both tripped, and this task knows it is coming.

**Step 5 — Evidence precedes commitment, asserted at the new backend.** Step 6 of the seed, made
concrete: an effect whose pre-commit receipt cannot be durably written to the flight chain is
*refused*, not buffered. Task 2.3's `killing_the_recorder_mid_run_commits_nothing_after_the_kill`
is the template — run its scenario with the flight backend failing writes, and assert the same
boundary sentence:

```rust
#[test]
fn the_flight_backend_refuses_an_effect_whose_receipt_cannot_be_written() {
    let mut backend = FlightRecorderBackend::failing_writes();
    let err = gate.record("key-1", &pre_commit).expect_err("writes fail");
    // The settle path must treat this as the recorder-did-not-acknowledge boundary:
    // the effect is not attempted, the boundary sentence names the recorder.
    assert!(err.contains("durable"), "{err}");
}
```

Local buffering places the record back inside the blast radius; the test that proves the flight
backend does not buffer is the one that makes "broker-side" true rather than claimed.

**Step 6 — The census and README move, in the ledger commit.** The flight-recorder crate becomes
reachable; `tools/ci/wiring_census.py --write` updates `evidence/wiring-coverage.json`, the
README's reachable row moves (13/41 → 14/42 happened in Task 2.6; this is the next increment),
and the gaps ledger's evidence-plane row states what is now true: a broker-side chain exists
behind the same trait the local recorder implements, selected by flag, default unchanged. Also
state what is NOT established: the flight log is still on the same machine; L7-03's external
anchoring is Phase 6 and does not land here. The ratchet (`check_invariant_ratchet.py`) is
unchanged — this task converts no `#[ignore]`.

**Step 7 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
cargo metadata --format-version 1 --locked > /dev/null
python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-3.4.md
```

Evidence: Step 0's baseline, both failing-test outputs verbatim, the dual-backend `two_phase`
acceptance output, and the tier statement.

---

**The honest tier of every bound this task introduces.**

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the `Recorder` trait seam | not a bound — a structure | the trait changes nothing about what is enforced; it is what makes the backend swappable. |
| the flight backend behind `--recorder flight` | **Tier B chokepoint** at the settle act | the recorder holds no credential and refuses nothing but unwritable destinations; an agent with root at the store root is outside every bound this task sets, and the ledger says so in those words. |
| the declared-gap behavior | **Observed**-tier evidence | the gap record states what is missing; it prevents nothing. |

**Exit gate, restated.** With root inside its own workspace, a test agent cannot alter or remove
a recorded entry (path discipline, test-pinned); a simulated reset yields a declared gap with a
sequence range, never a silent truncation; both backends satisfy the same `Recorder` trait with
Task 2.3's suite green against each; the backend is operator-selected and disclosed at attach.

**Hazards.** (1) The seed's hazard stands: never spawn `serve`, `console` or `mcp` from a test
expecting a return. (2) The recorder must not become a network dependency in the decision path —
the flight recorder is a local chain this task; the network is L7-03's, and wiring it here would
make every settle fail open under partition, which is trivially inducible. (3) `Uuid` in
flight-recorder's `emit_pending` must not enter `warrantor-warrant`'s dependency graph — the
trait impl lives in `flight-recorder`; verify with `cargo metadata --locked`. (4) Do not flip the
default backend in this task: every Task 2.3 test and every existing store assumes the file
recorder's layout, and a default flip is a migration the ledger must own.

---

**Verification detail — the shapes the steps compile against, captured on `main`.**

The trait as it exists today in `staging.rs` (the seam this task generalizes — quoted, not
invented):

```rust
pub trait Recorder {
    /// Durably record `receipt` under `idempotency_key` and acknowledge with its sequence.
    fn record(&mut self, idempotency_key: &str, receipt: &WarReceipt) -> Result<RecorderAck, String>;
    /// The real id of a performance already recorded under this key, if any.
    fn performed(&self, idempotency_key: &str) -> Option<String>;
    /// True when a pre-commit was recorded for this key and no post-commit followed.
    fn unresolved(&self, idempotency_key: &str) -> bool;
}
```

The `FileRecorder`'s sync discipline, which the flight backend must match or exceed (the
acknowledgment means "on stable storage"):

```rust
file.write_all(line.as_bytes())
    .and_then(|()| file.write_all(b"\n"))
    .and_then(|()| file.flush())
    // The acknowledgment means "on stable storage". Anything less and a crash between
    // the ack and the effect leaves an effect with no record, which is the thing I-07
    // forbids.
    .and_then(|()| file.sync_all())
    .map_err(|e| format!("append receipt: {e}"))?;
```

The flight recorder's reopen verification, quoted from `:627` — what Step 1's gap test builds
on:

```rust
// An existing log is replayed and its hash chain verified before any new record is accepted.
```

The dual-backend acceptance run, as the evidence file records it:

```bash
cargo test -p warrantor-warrant --test two_phase -j 2        # file recorder: unchanged, green
cargo test -p warrantor-flight-recorder -j 2                 # the crate's own suite: green
cargo test -p warrantor-warrant --test two_phase --features flight -j 2   # flight backend: green
```

And the wire-in at `cmd_settle`, showing the disclosure the flag prints at attach:

```bash
$ warrantor settle --recorder flight wrt_example
warrantor: settle recorder -- FLIGHT (broker-side chain at <store-root>/flight-chain.jsonl);
  the default file recorder remains at receipts/wrt_example.jsonl and is unchanged.
  released    pr://staged/wrt_example/1 -> real-1
```

The honest-summary sentence the ledger adds: *"A broker-side chain now exists behind the same
trait the local recorder implements, selected by flag, default unchanged. What it establishes is
a second, agent-external durability boundary on the same machine; what it does not establish is
off-machine custody — L7-03's external anchoring is Phase 6."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The dual-backend settle wiring, showing where the enum sits and what the settle call actually
receives. Task 2.3's `settle` takes `&mut CommitGate<'_>`, whose first field is
`recorder: &'a mut dyn Recorder` — so the backend selection is behind the trait object, and the
settle call itself is untouched:

```rust
// bin/warrantor.rs, in cmd_settle — the recorder selection replaces the direct
// FileRecorder construction Task 2.3 wired:
enum SettleRecorder {
    File(FileRecorder),
    Flight(FlightRecorderBackend),
}

impl SettleRecorder {
    fn as_recorder(&mut self) -> &mut dyn Recorder {
        match self {
            Self::File(r) => r,
            Self::Flight(f) => f.as_recorder(),
        }
    }
}

// in the settle body:
let mut recorder = match args.flags.get("recorder").map(String::as_str) {
    Some("flight") => SettleRecorder::Flight(FlightRecorderBackend::open(store.root())?),
    _ => SettleRecorder::File(FileRecorder::open(store.staged_receipts_path(id))?),
};
let mut gate = CommitGate {
    recorder: recorder.as_recorder(),
    signer: &settle_key,
    key_id: "settle",
    now: now(),
};
```

The disclosure the flag prints, quoted as the test asserts it:

```text
$ warrantor settle --recorder flight wrt_example
warrantor: settle recorder -- FLIGHT (broker-side chain at <store-root>/flight/chain.jsonl);
  the file recorder remains the default, at receipts/wrt_example.staged.jsonl, and is
  unchanged. The flight chain is on this machine's store root — outside the agent's
  worktree, inside this machine's disk. External anchoring is Phase 6 (L7-03).
```

The path-discipline test's second half, the assertion that makes "broker-side" concrete on a
single machine:

```rust
#[test]
fn the_flight_log_lives_outside_every_worktree_the_agent_can_reach() {
    let store = tempdir("store");
    let worktree = tempdir("worktree");
    let backend = FlightRecorderBackend::open_at(&store, Some(&worktree));
    backend.record("k", &pre).expect("recorded");
    // Every path the recorder touched must be under the store root, not the worktree:
    for path in backend.paths_touched() {
        assert!(path.starts_with(&store),
            "the recorder wrote inside the agent's blast radius: {path:?}");
    }
    // And the worktree has no flight artifacts at all:
    assert!(!worktree.join("flight").exists());
    assert!(!worktree.join("chain.jsonl").exists());
}
```

The gap record's wire shape, what Step 1's declared gap serializes as:

```json
{
  "format": "warrantor.flight-gap/1",
  "after_sequence": 3,
  "expected_through": 5,
  "declared_at": 1788,
  "note": "the tail after sequence 3 is absent. The chain verifies through 3; the
           records 4 and 5 were lost in a container reset (or an equivalent failure).
           Everything appended after this line chains from THIS record, not from the
           missing tail — the gap is part of the chain now, not a hole in it."
}
```

The last sentence is the design: the gap record chains forward, so the post-reset records are
verifiable against a chain that *includes the declaration of the loss*. A truncation that reads
as nothing is the incident; a declared gap that the chain commits is the fix.

The evidence file's "what this does NOT establish", quoted so the implementer cannot weaken it:

```text
- The flight chain is on the same machine's disk as the store. An operator with
  filesystem access can still rewrite it; the chain makes it detectable, not
  impossible. L7-03's external anchoring is the item that changes that, Phase 6.
- The default recorder is unchanged: a deployment that does not pass --recorder
  flight gets the file recorder's semantics exactly as Task 2.3 shipped them.
- The flight backend is exercised by the two_phase suite through the trait; the
  crate's own 1,371 lines are not re-tested here beyond the trait contract, the
  gap declaration, and the path discipline — its internal suite covers the rest.
```

The final commit, gathering the pieces:

```bash
git add rust/flight-recorder/src/lib.rs rust/warrant/src/staging.rs \
        rust/warrant/src/bin/warrantor.rs rust/flight-recorder/Cargo.toml \
        rust/flight-recorder/tests/gap_declaration.rs \
        docs/W1-delivery-gaps.md docs/task-evidence/task-3.4.md
git commit -s -F .commitmsg
# Branch: feat/task-3.4-recorder-trait. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

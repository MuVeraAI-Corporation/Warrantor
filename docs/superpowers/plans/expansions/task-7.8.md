### Task 7.8: Recovery orchestration and integrity verification (L4-21) — expanded to step form

**Anchor.** `status=none`, `core`, W2. **Recovery is an effect class.** An untracked restore is
an unlogged mutation carried out with root authority, and it is the one operation that can
silently undo every receipt written since the snapshot. This expansion re-verified the anchors on
local `main` at `6f41384`, and the archive's actual shape decides the design: recovery is
modeled as a staged effect that decomposes to MUTATE plus ATTEST, with the verification pass as
the ATTEST half — and the Task 10.6 escrow interaction resolves to a concrete refusal rule.

**What exists, re-verified 2026-09-06.** `rust/archive/src/store.rs` is 520 lines: `MemoryStore`
(`:311`) is the append-only archive store behind `enrol`/device pairing (`Device` at `:108`,
`active()` at `:126`), `ArtifactSummary` (`:82`), `ListFilter` (`:99`), and
`RetentionPolicy::deletes_anything()` (`:201`, the policy shape Task 3.4's evidence praised).
`rust/archive/tests/append_only.rs` (578 lines) is the custody suite: append-only discipline,
first-submitter attribution, the counted-prose gate. **No restore path exists** — verified by
grep, zero `restore` hits in store.rs and the append-only tests, which is the finding: the one
operation that can silently destroy the chain has no declared, receipted form, so when it
happens it happens outside every record this system keeps. Task 10.6's expansion (in this tree)
defines escrow as the investigator's scoped trace release; the interaction is concrete: a
restore that rewinds the archive past an escrowed release would make the investigator's held
evidence unverifiable against the store it was verified against.

---

**Step 0 — Baseline: run in the worktree and paste verbatim.**

```bash
git -C M:/wt-merge worktree add M:/wt-7.8 -b feat/recovery-orchestration main
cd M:/wt-7.8
grep -n "pub struct MemoryStore\|pub fn enrol\|pub struct Device" rust/archive/src/store.rs | head -4
grep -rn "restore" rust/archive/src rust/archive/tests --include=*.rs | wc -l   # expected: 0
grep -n "append\|first-submitter\|counted" rust/archive/tests/append_only.rs | head -6
grep -n "escrow" docs/superpowers/plans/expansions/task-10.6.md | head -5
grep -n "MUTATE\|ATTEST" rust/warrant/src/effects.rs | head -4
```

Expected: the MemoryStore API; zero restore references; the custody suite's anchors; the escrow
definition in 10.6's expansion; both syscalls in the registry table. Read in full:
`rust/archive/src/store.rs` (all 520 lines — what an append IS is what a restore must roll
forward), `rust/archive/tests/append_only.rs` (the invariants a restore must not break), and
Task 10.6's expansion `:60-90` (the escrow release's verification assumptions).

**Step 1 — Record the 10.6 interaction, and stop if unresolved.** The rule this task commits
to, in the evidence file before any code: **a restore is refused if any receipt in the range it
would supersede is referenced by an escrowed release that is still held** — because the
investigator's verification was performed against the store's state at release time, and
rewinding that state orphans the release (the escrowed trace set verifies against a chain that
no longer exists). The unresolved-case stop condition: if 10.6 has not landed and escrow has no
on-disk representation, the refusal rule is implemented against the escrow *interface* Task 10.6
specifies, marked `#[cfg]`-free but wired to a no-op escrow registry — and the ledger says that
escrow-aware refusal is untestable until 10.6 lands. That is the honest order, not a dodge.

**Step 2 — Recovery as a declared, staged effect.** `recovery.restore` joins the effect registry
decomposing to `MUTATE` (the archive's contents change) plus `ATTEST` (the integrity pass that
must succeed before completion is a claim about the restored state):

```rust
// in the builtin registry construction (Task 2.1's table, Task 2.5's pattern):
of("recovery.restore", &[Syscall::Mutate, Syscall::Attest]),
```

The adapter (under Task 7.1's `EffectAdapter` shape, or the settle performer path Task 1.1/2.3
established — the settle performer is the one with an implemented precedent on `main`) takes a
`RestoreRequest { snapshot_id, supersede_from: u64 }`, and the staging discipline applies in
full: the restore is staged, evidenced, and performed only at settle, exactly like every other
consequential effect. An operator running `warrantor restore` gets the same two-phase discipline
an agent's PR gets — that symmetry is the whole point of modeling recovery as an effect.

**Step 3 — Failing test: an unreceipted restore is refused.** The archive refuses a restore
attempt that does not arrive with its effect receipt — the store's own API gains a guard that
requires the recovery receipt's digest before mutating anything, because the archive is the
thing being restored and cannot trust the caller's word. Paired control: a restore carrying a
valid receipt proceeds. Run before implementing.

**Step 4 — Failing test: the receipt names the superseded range.** The recovery receipt carries
`snapshot_id` and `supersede_from` (the receipt sequence the restore rolls back to), and the
performed restore writes a *forward* record: the chain is not truncated — the restore appends a
receipt declaring "everything after sequence N is superseded by this restore", preserving the
append-only discipline the custody suite enforces. The test asserts the chain after restore
contains the declaration and that verification accounts for it. A restore that truncates would
pass `MemoryStore`'s tests but break the append-only suite's meaning — the declaration-not-
deletion design is what keeps custody intact through recovery.

**Step 5 — Failing test: a restore orphaning escrowed evidence is refused, paired with an
allowed control.** With the escrow registry holding a release referencing receipts in the
supersede range, the restore is refused naming the escrow release; the control restore, whose
range touches no held release, proceeds. Per Step 1, the refusal is testable only when 10.6's
escrow has landed — otherwise the test is written and `#[cfg]`-gated with the ledger noting it
as untestable-till-10.6, per the honest-order decision.

**Step 6 — Integrity verification before completion.** The ATTEST half: after the restore
executes, the adapter runs the archive's own verification (the append-only suite's check,
extracted into a callable) over the restored chain and refuses to report success if it fails —
the restore is complete only when the restored state verifies, and the completion receipt
carries the verification's result. A restore that cannot verify reports failed, and the store is
left in the declared-and-recorded broken state rather than silently half-restored.

**Step 7 — The filesystem-access bypass, stated.** Tier B chokepoint for a restore issued
through this path; **Tier C for anything else**, because an operator with filesystem access
restores without asking — and the ledger says that in those words, with the corollary: the
receipt graph's *detection* of an out-of-band restore is exactly what Task 1.1's chain-head
witness and Task 10.6's custody give the next verifier, so the bypass is detectable, not
preventable.

**Step 8 — Gates, evidence, commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/wiring_census.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/task-evidence/task-7.8.md docs/W1-delivery-gaps.md
```

Evidence: the baseline (zero restore references — the finding), every failing test's red output,
the forward-declaration chain after a performed restore, and the tier statement.

**Exit gate, restated.** A restore produces a receipt naming the snapshot and the superseded
range; the chain carries the restore as a forward declaration, not a truncation; a restore
orphaning held escrow is refused (or the gate is written and honestly marked untestable until
10.6); a restore that cannot verify reports failed; the out-of-band bypass is detectable and the
ledger says so.

**Hazards.** (1) `rust/archive/src/store.rs` is **contended** — Task 3.4's evidence flagged the
retention-policy shape there and Task 10.4 owns retention; the restore guard must be additive and
the branch rebased against whoever merged first. (2) The append-only suite is the authority: any
restore implementation that makes `append_only.rs` weaken a test is the task failing its own
anchor — the suite may only grow. (3) Do not build backup scheduling (the seed's non-goal): the
snapshot *source* is operator configuration, and this task consumes snapshots, never schedules
them.

---

**Verification detail — the shapes the steps compile against, captured on `main`.**

The archive store's append discipline, what a restore must roll forward without breaking:

```rust
// store.rs — the MemoryStore behind the append-only suite; every artifact has a
// first submitter and a position in the chain:
pub struct MemoryStore {
    // devices, artifacts, positions — the custody facts the restore must preserve.
}
```

The custody suite's anchors, the tests a restore must not weaken:

```bash
$ grep -n "fn " rust/archive/tests/append_only.rs | head -8
fn the_same_artifact_cannot_be_appended_twice(...)
fn the_first_submitter_is_attributed(...)
fn a_second_device_cannot_rewrite_the_first_submission(...)
fn the_counted_prose_gate(...)
```

Task 10.6's escrow, the interaction Step 1 records — quoted from its expansion:

```text
"An investigator obtains a scoped trace set through escrow with no operator in the
loop and the ..."  — the release is verified against the store's chain state AT
RELEASE TIME. A restore that rewinds that state orphans the release: the held trace
set verifies against a chain that no longer exists.
```

The recovery effect's declaration, the registry side:

```rust
// in the builtin decomposition construction (Task 2.1's table, Task 2.5's pattern):
of("recovery.restore", &[Syscall::Mutate, Syscall::Attest]),
// MUTATE: the archive's contents change. ATTEST: the integrity pass that must
// succeed before completion is a claim about the restored state — and the ATTEST
// half is what makes the completion receipt mean something.
```

The refusal guard, the store's own API refusing an unreceipted restore:

```rust
impl MemoryStore {
    /// Attempt a restore. Refused unless the caller presents the recovery effect's
    /// receipt digest — the archive is the thing being restored and cannot trust
    /// the caller's word. The receipt is verified against the staging log before
    /// any byte moves.
    pub fn restore(&mut self, request: &RestoreRequest,
                   recovery_receipt_digest: &str) -> Result<RestoreReport, RestoreError> {
        verify_recovery_receipt(recovery_receipt_digest, request)?;
        let held = self.escrow_held_in_range(request.supersede_from)?;
        if let Some(release) = held {
            return Err(RestoreError::EscrowOrphaned {
                release: release.id,
                detail: format!(
                    "the restore would supersede receipts from {} that escrow release \
                     {} references; the held evidence would verify against a chain that \
                     no longer exists",
                    request.supersede_from, release.id),
            });
        }
        // ... the forward declaration, then the integrity pass ...
    }
}
```

The forward declaration, why a restore is an append and not a truncation:

```json
{
  "format": "warrantor.recovery/1",
  "kind": "restore-declaration",
  "snapshot_id": "snap_0fcf5d3b",
  "supersede_from": 42,
  "integrity_verified": true,
  "performed_at": 1788,
  "note": "the chain is NOT truncated: entries after 42 remain, superseded by this
           declaration. Custody survives recovery; the append-only discipline does not
           bend for the one operation that would most like to break it."
}
```

The integrity pass, the ATTEST half that gates completion:

```rust
#[test]
fn a_restore_that_cannot_verify_reports_failed_and_does_not_claim_success() {
    // Corrupt one entry of the snapshot before restoring; the restore executes, the
    // integrity pass fails, and the completion receipt says FAILED — the store is left
    // in the declared-and-recorded broken state, never silently half-restored.
    let report = perform_restore_with_corrupt_snapshot();
    assert!(!report.complete, "{report:?}");
    assert!(report.integrity_failure.is_some(), "{report:?}");
}
```

The bypass statement, the Tier C half the ledger records:

```text
Bound: Tier B, chokepoint for a restore issued through this path — the receipt, the
escrow check and the integrity pass all hold. Tier C for anything else: an operator
with filesystem access restores without asking. The corollary is the detection
property: Task 1.1's chain-head witness and Task 10.6's custody give the next
verifier the means to SEE an out-of-band restore (the witness records a head that
the restored chain no longer matches), so the bypass is detectable, not preventable.
The ledger says so in those words.
```

The honest-summary sentence the ledger adds: *"Recovery is a declared, staged, receipted effect
decomposing to MUTATE plus ATTEST; the restore appends a declaration instead of truncating, an
escrow-orphaning restore is refused, and completion requires an integrity pass. What this does
not establish: prevention of out-of-band restores by an operator with filesystem access —
detectable through the chain-head witness, not preventable — and the escrow-aware refusal is
testable only when Task 10.6's escrow lands, with the interface wired and the test gated until
then."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The `RestoreRequest` type, the staged effect's arguments made explicit:

```rust
// rust/warrant/src/recovery.rs — new module, pub mod recovery; between
// pub mod receipts; and pub mod report; in lib.rs (alphabetical).
/// One restore request. The two fields are the whole request: WHICH snapshot, and
/// the receipt sequence it rolls back to. Anything more is a design decision the
/// plan does not make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// The snapshot the archive rolls forward from. The snapshot SOURCE is operator
    /// configuration (the seed's non-goal: no backup scheduling here); this task
    /// consumes snapshots, never schedules them.
    pub snapshot_id: String,
    /// The receipt sequence the restore rolls back to. Receipts after this sequence
    /// remain on the chain, superseded by the restore's own declaration — never
    /// truncated.
    pub supersede_from: u64,
}
```

The staging discipline, the recovery effect staged like every other consequential effect:

```bash
$ warrantor stage --root $R wrt_recovery --tool recovery.restore \
    --arg snapshot_id=snap_0fcf5d3b --arg supersede_from=42
staged  recovery://staged/wrt_recovery/1
(queued; performed only when the warrant settles)
```

The adapter's perform, where the escrow check and the integrity pass live:

```rust
impl EffectPerformer for RecoveryAdapter {
    fn perform(&mut self, effect: &StagedEffect,
               _resolved: &BTreeMap<String, String>) -> Result<String, String> {
        if effect.tool != TOOL {
            return Err(format!("the recovery adapter does not implement {}", effect.tool));
        }
        let request: RestoreRequest = parse_arguments(effect)?;
        // The escrow check (Step 1's recorded rule). With 10.6 unlanded, the registry
        // is a no-op and this check passes trivially — the ledger says the refusal is
        // untestable until 10.6's escrow has an on-disk representation.
        if let Some(release) = self.escrow.held_in_range(request.supersede_from)? {
            return Err(format!(
                "the restore would orphan escrow release {}: the held evidence verifies \
                 against a chain that the restore would replace",
                release.id));
        }
        // The restore itself: the snapshot's contents replace the live archive state,
        // and the restore's own declaration is appended FIRST — before verification —
        // so even a failed restore leaves the chain declaring what happened to it.
        self.archive.apply_snapshot(&request.snapshot_id)?;
        self.archive.append_restore_declaration(&request, self.clock())?;
        // The ATTEST half: the integrity pass over the restored chain. Completion
        // requires it; a failure reports failed and leaves the declared state.
        let verification = self.archive.verify_full_chain()?;
        if verification.is_err() {
            return Err(format!(
                "the restore executed but the integrity pass failed: {}. The store is \
                 in the declared-and-recorded broken state; do not restore again on top \
                 of it without reading the declaration.",
                verification.unwrap_err()));
        }
        Ok(format!("restored from {} superseding receipts after {} (verified)",
                   request.snapshot_id, request.supersede_from))
    }
}
```

The forward declaration in the chain, what the append-only suite sees after a restore:

```bash
$ python -c "
import json
for line in open('store/archive/chain.jsonl'):
    r = json.loads(line)
    print(r.get('sequence'), r.get('kind'), r.get('snapshot_id',''), r.get('supersede_from',''))
"
1 artifact
2 artifact
3 artifact
...
41 artifact
42 artifact
43 restore-declaration snap_0fcf5d3b 42
44 artifact        <- post-restore work chains from 43, not from the missing pre-snapshot tail
```

The three failing tests, the red outputs the evidence records:

```text
---- an_unreceipted_restore_is_refused stdout ----
RestoreError: no recovery receipt presented; the archive is the thing being restored
and cannot trust the caller's word

---- the_receipt_names_the_superseded_range stdout ----
(passes after implementation: the receipt carries snapshot_id snap_0fcf5d3b and
supersede_from 42, and the chain's declaration matches)

---- a_restore_orphaning_escrowed_evidence_is_refused stdout ----
RestoreError::EscrowOrphaned { release: "esc_7", detail: "the restore would supersede
receipts from 42 that escrow release esc_7 references ..." }
(gated: testable only when Task 10.6's escrow has an on-disk representation; the
ledger notes it as untestable-till-10.6)
```

The ledger's recovery row, quoted so the implementer cannot write a weaker one:

```text
### 7.8 Recovery orchestration — **recovery is a declared, staged, receipted effect; the chain
is appended to, not truncated**

`recovery.restore` joins the effect registry decomposing to MUTATE plus ATTEST, staged like
every other consequential effect and performed only at settle. The restore appends a
declaration (snapshot, superseded range) instead of truncating the chain — custody survives
recovery. A restore that would orphan held escrowed evidence is refused; the escrow-aware
refusal is wired to 10.6's interface and marked untestable until that task lands. Completion
requires an integrity pass over the restored chain; a failure reports FAILED and leaves the
declared state. Tier: **Tier B chokepoint** for a restore issued through this path; **Tier C**
for anything else — an operator with filesystem access restores without asking, and the
chain-head witness makes the bypass detectable, not preventable. The ledger says so in those
words.
```

The final commit, gathering the pieces:

```bash
git add rust/warrant/src/recovery.rs rust/warrant/src/lib.rs \
        rust/warrant/src/effects.rs rust/warrant/src/adapters/recovery.rs \
        rust/archive/src/store.rs rust/archive/tests/append_only.rs \
        rust/warrant/tests/recovery.rs docs/W1-delivery-gaps.md docs/task-evidence/task-7.8.md
git commit -s -F .commitmsg
# Branch: feat/recovery-orchestration. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

### Task 7.5: Adapters — package registries, data platforms and payment rails (L4-15, L4-16, L4-17) — expanded to step form

**Anchor.** Three `clone` items, `status=none`, W3. **Payment rails are SPEND-class and
irreversible.** The shared adapter shape must not flatten reversibility into a boolean: a package
publish can be yanked, a warehouse write can be rolled back, a wire cannot. Three different
reversibility properties, one adapter shape, and the shape must carry the difference. This
expansion re-verified the anchors on local `main` at `6f41384`.

**What exists, re-verified 2026-09-06.** Task 7.1's contract (transcribed in task-7.3.md's Step
1; same trait, same harness). Task 1.4's spend bound is on `main`:
`WarrantBounds.budget_cents_observed` (`lib.rs:288`, with the doc that names it Observed and
explains the absent-means-zero reading), `spend::cap_micros`, and the spend ledger the settle
path consults. `rust/spend/src/lib.rs` carries the ceiling machinery; `SideEffectClass` is at
`rust/authority-spec/src/lib.rs` with `is_consequential` (`:58`) — and the seed is right that
`Financial` and `Destructive` being uniformly `is_consequential()` is the existing *approximation*
of reversibility: the class taxonomy says "a human must approve", not "can this be undone". The
reversibility descriptor this task produces is the refinement that approximation cannot express.

**Where the 1.4/7.5 boundary sits, stated before the code.** Task 1.4 owns the *bound*: how much
spend authority exists and when it is exhausted. Task 7.5 owns the *adapter*: how a rail
instruction is issued, receipted, and classified. The adapter consults the bound through the same
settle path every effect flows through; it does not read `budget_cents_observed` directly. What
the adapter adds is the property the bound cannot carry — whether the effect it is about to issue
can ever be recalled — and that property gates on the approval receipt, which is the I-08
machinery (`approval` in the notary request, `operators::ApprovalPolicy`) already on `main`.

---

**Step 0 — Baseline: run in the worktree and paste verbatim.**

```bash
git -C M:/wt-merge worktree add M:/wt-7.5 -b feat/adapters-spend-and-data main
cd M:/wt-7.5
grep -n "is_consequential" rust/authority-spec/src/lib.rs
grep -n "pub fn cap_micros\|pub struct SpendStore" rust/spend/src/lib.rs | head -3
grep -n "budget_cents_observed" rust/warrant/src/lib.rs | head -2
grep -n "approval" rust/warrant/src/operators.rs | grep -in "verdict\|policy" | head -4
```

Expected: the approximation (`is_consequential` at `:58`), the spend ceiling API, the observed
budget field, and the approval machinery. Read in full: `rust/spend/src/lib.rs` (723 lines — the
ceiling, the ledger, and what "recorded" means there), Task 7.1's expansion contract section,
and Task 1.4's evidence file (`docs/task-evidence/task-1.4.md`) for the boundary in 1.4's own
words.

**Step 1 — Failing test: reversibility is a three-state descriptor, not a boolean.**

```rust
// rust/warrant/src/reversibility.rs
pub const REVERSIBILITY_FORMAT: &str = "warrantor.reversibility/1";

/// Whether an effect can be undone, and at what cost. Never a boolean: yank/rollback/wire
/// are three different relationships with the world, and flattening them is how a wire
/// gets signed as "compensable".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The effect can be undone by another effect of the same class (a yank, a rollback).
    Reversible,
    /// The effect cannot be undone, but a compensating effect can be issued (a refund,
    /// a corrective record). The compensation is itself receipted.
    Compensable,
    /// Nothing downstream can undo or compensate. The approval receipt is the only gate.
    Irreversible,
}

#[test]
fn reversibility_has_three_states_and_a_boolean_cannot_reconstruct_them() {
    let values = [Reversibility::Reversible, Reversibility::Compensable, Reversibility::Irreversible];
    // The test that makes the flattening defect un-writable: from Reversible and
    // Irreversible alone, Compensable is not reconstructible, so any API that returns
    // bool has already lost the middle state.
    assert_eq!(values.len(), 3);
    for v in values {
        let word = serde_json::to_value(v).unwrap();
        assert!(word.is_string());
    }
}
```

Run before implementing: the missing module is the failure.

**Step 2 — Failing test: an irreversible effect without an approval receipt is refused, with a
reversible control proceeding unattended.** The payment-rail adapter's `invoke` consults the
effect's declared `Reversibility`; `Irreversible` requires an approval receipt in the
`EffectGrant`'s context (the I-08 approval machinery), and refuses without one — while the same
adapter's `Reversible` effect (a package yank rehearsal against a fixture registry) proceeds
without approval through the identical code path. Both halves in one test, both directions
asserted: the refusal, and the control's passage — a refusal that refuses everything proves
nothing.

**Step 3 — Three adapters against the conformance harness.** Package registry (publish/yank
against an injected registry fixture — the transport-injection discipline Task 2.5 and 7.3
establish), data platform (warehouse write against a fixture), payment rail (instruction against
a fixture). Each declares its tools' syscalls against Task 2.1's registry — registry publish is
MUTATE, warehouse write is MUTATE, rail instruction is SPEND — and each runs `run_conformance`
with the report committed in the evidence file.

**Step 4 — Failing test: the receipt records the reversibility state at issue time.** The
adapter's outcome carries the descriptor, and the settle receipt records it — so a reader of the
receipt graph, offline, can tell which effects were believed reversible when issued. This is the
property that makes the descriptor evidence rather than a comment: the incident's compensation
work was unbounded precisely because nothing recorded what was believed undoable.

**Step 5 — The rail's pre-authorization limit, in the adapter's doc and the ledger.** For
payment rails the bound is **pre-authorization only**: once the rail accepts the instruction,
nothing in this system can recall it — no compensation machinery this task builds changes that,
and the adapter's doc says so in those words, with the Tier B/Tier C split (through the adapter:
Tier B; a shell with the rail CLI: outside every bound here).

**Step 6 — Gates, evidence, commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/wiring_census.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/task-evidence/task-7.5.md docs/W1-delivery-gaps.md rust/warrant/src/reversibility.rs
```

Evidence: the contract transcription and the 1.4 boundary statement, every failing test's red
output, the three conformance reports, the approval-refusal transcript, and the tier statement.

**Exit gate, restated.** Reversibility is a three-state descriptor asserted never-boolean; an
irreversible effect without an approval receipt is refused with a reversible control proceeding;
all three adapters pass the 7.1 harness; the settle receipt records the reversibility state at
issue time; the rail's pre-authorization-only limit is in the doc and the ledger.

**Hazards.** (1) Do not let the descriptor grow a fourth state in this task — "reversible with
operator assistance" is Compensable wearing a hat, and a fourth state is a design decision the
plan does not make. (2) `rust/spend/src/lib.rs` is **contended** (Task 1.4's branch may still be
in flight on other lanes' merges) — the adapter must not edit spend.rs at all; the consultation
is through the settle path. (3) The approval gate is I-08's machinery, not a new one — wiring a
parallel approval check beside `operators::ApprovalPolicy` would be the second-definition defect
the notary's gate-only-denial rule exists to prevent.

---

**Verification detail — the shapes the steps compile against, captured on `main`.**

The spend ceiling, Task 1.4's bound — what the adapter consults and what it must not bypass:

```rust
// lib.rs:288 — the bound 1.4 owns, named so a caller cannot mistake it for a guarantee:
pub budget_cents_observed: Option<u64>,
// None is a ceiling of ZERO, never "unlimited" — the absent-means-zero reading is
// crate-wide, and the rail adapter inherits it: a warrant with no budget authorizes
// no rail instruction at all.
```

The reversibility descriptor, the shape that makes the flattening defect un-writable:

```rust
// rust/warrant/src/reversibility.rs
pub const REVERSIBILITY_FORMAT: &str = "warrantor.reversibility/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The effect can be undone by another effect of the same class (a yank, a rollback).
    Reversible,
    /// The effect cannot be undone, but a compensating effect can be issued (a refund,
    /// a corrective record). The compensation is itself receipted.
    Compensable,
    /// Nothing downstream can undo or compensate. The approval receipt is the only gate.
    Irreversible,
}
```

The three adapters' declarations, the registry side:

```rust
// in the builtin decomposition construction:
of("registry.publish", &[Syscall::Mutate]),        // reversible: yank exists
of("warehouse.write", &[Syscall::Mutate]),         // compensable: a corrective write
of("rail.instruction", &[Syscall::Spend]),         // irreversible: pre-authorization only
```

The approval-gated refusal, the irreversible half of the exit gate:

```rust
#[test]
fn an_irreversible_effect_without_an_approval_receipt_is_refused() {
    let mut rails = RailAdapter::new(fixture_transport());
    let no_approval = invoke_rail(&mut rails, "rail.instruction",
        &[("amount", "100.00"), ("iban", "DE89...")], /* approval */ None);
    assert!(matches!(no_approval, AdapterOutcome::Refused { .. }),
        "a wire without a human approval receipt must refuse: {no_approval:?}");

    // The paired control: the same adapter, a REVERSIBLE effect, no approval — proceeds.
    let yank = invoke_registry(&mut registry, "registry.publish", &[("crate", "x")], None);
    assert!(matches!(yank, AdapterOutcome::Performed { .. }),
        "a reversible effect proceeds unattended: {yank:?}");
}
```

The receipt's reversibility record, what an offline reader learns:

```json
{
  "format": "warrantor.staged-receipt/1",
  "tool": "rail.instruction",
  "reversibility": "irreversible",
  "approval_receipt_digest": "b4702466669cea5592eaa16dce4a1cffa0618df9461c45172190515ba9928494",
  "performed_at": 1788,
  "outcome": "performed"
}
```

The never-boolean assertion, the test that keeps the flattening defect from returning:

```rust
#[test]
fn reversibility_is_never_a_boolean_anywhere() {
    // The descriptor's type is the assertion — but the compile-time fact needs a
    // runtime pin: a check that no struct field named *reversible carries a bool,
    // run in CI beside the inventory ratchet.
    let source = harness::read_repository_file("rust/warrant/src/reversibility.rs");
    assert!(!source.contains("reversible: bool"),
        "reversibility collapsed to a boolean: the middle state is lost");
    assert!(source.contains("enum Reversibility"));
}
```

The rail's pre-authorization limit, quoted as the adapter's doc states it:

```text
Bound: Tier B, chokepoint — pre-authorization only. Once the rail accepts the
instruction, nothing in this system can recall it. The approval receipt proves a
human approved; it does not prove the wire can be undone. An operator with the
rail's own CLI is outside every bound here, and the ledger says so.
```

The honest-summary sentence the ledger adds: *"Three adapters exist under the 7.1 SDK with a
three-state reversibility descriptor; irreversible effects refuse without a human approval
receipt while reversible controls proceed unattended; the settle receipt records the
reversibility state at issue time. What this does not establish: recall of an accepted rail
instruction — pre-authorization is the entire bound — and the registry/data-platform adapters
are fixture-proven, not live-tested against real services."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The reversibility descriptor's module, the whole shape with its serde discipline:

```rust
// rust/warrant/src/reversibility.rs — new module, pub mod reversibility; after
// pub mod provenance; in lib.rs (alphabetical: reversibility sorts after provenance,
// before report — the module block's one ordering convention).
pub const REVERSIBILITY_FORMAT: &str = "warrantor.reversibility/1";

/// Whether an effect can be undone, and at what cost. Never a boolean: yank/rollback/wire
/// are three different relationships with the world, and flattening them is how a wire
/// gets signed as "compensable".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// The effect can be undone by another effect of the same class (a yank, a rollback).
    Reversible,
    /// The effect cannot be undone, but a compensating effect can be issued (a refund,
    /// a corrective record). The compensation is itself receipted.
    Compensable,
    /// Nothing downstream can undo or compensate. The approval receipt is the only gate.
    Irreversible,
}
```

The three adapters' declarations, the registry side (the class split the seed's approximation
cannot express):

```rust
// in the builtin decomposition construction:
of("registry.publish", &[Syscall::Mutate]),        // reversible: yank exists
of("warehouse.write", &[Syscall::Mutate]),         // compensable: a corrective write
of("rail.instruction", &[Syscall::Spend]),         // irreversible: pre-authorization only
```

The approval-gated refusal, the irreversible half of the exit gate with its paired control:

```rust
#[test]
fn an_irreversible_effect_without_an_approval_receipt_is_refused() {
    let mut rails = RailAdapter::new(fixture_transport());
    let no_approval = invoke_rail(&mut rails, "rail.instruction",
        &[("amount", "100.00"), ("iban", "DE89...")], /* approval */ None);
    assert!(matches!(no_approval, AdapterOutcome::Refused { .. }),
        "a wire without a human approval receipt must refuse: {no_approval:?}");

    // The paired control: the same adapter shape, a REVERSIBLE effect, no approval —
    // proceeds unattended through the identical code path.
    let yank = invoke_registry(&mut registry, "registry.publish", &[("crate", "x")], None);
    assert!(matches!(yank, AdapterOutcome::Performed { .. }),
        "a reversible effect proceeds unattended: {yank:?}");
}
```

The receipt's reversibility record, what an offline reader learns from the settle receipt:

```json
{
  "format": "warrantor.staged-receipt/1",
  "tool": "rail.instruction",
  "reversibility": "irreversible",
  "approval_receipt_digest": "b4702466669cea5592eaa16dce4a1cffa0618df9461c45172190515ba9928494",
  "performed_at": 1788,
  "outcome": "performed"
}
```

The never-boolean assertion, the test that keeps the flattening defect from returning:

```rust
#[test]
fn reversibility_is_never_a_boolean_anywhere() {
    // The descriptor's type is the assertion — but the compile-time fact needs a
    // runtime pin: a check that no struct field named *reversible carries a bool,
    // run in CI beside the inventory ratchet.
    let source = harness::read_repository_file("rust/warrant/src/reversibility.rs");
    assert!(!source.contains("reversible: bool"),
        "reversibility collapsed to a boolean: the middle state is lost");
    assert!(source.contains("enum Reversibility"));
}
```

The rail's pre-authorization limit, quoted as the adapter's doc states it:

```text
Bound: Tier B, chokepoint — pre-authorization only. Once the rail accepts the
instruction, nothing in this system can recall it. The approval receipt proves a
human approved; it does not prove the wire can be undone. An operator with the
rail's own CLI is outside every bound here, and the ledger says so.
```

The 1.4 boundary statement, quoted so the implementer does not drift into the spend crate:

```text
Task 1.4 owns the BOUND: how much spend authority exists (budget_cents_observed,
absent means zero), when it is exhausted (cap_micros, the ledger), and the Observed
tier (self-reported). Task 7.5 owns the ADAPTER: how a rail instruction is issued,
receipted, classified, and gated on approval. The adapter consults the bound through
the settle path every effect flows through; it does not read budget_cents_observed
directly and does not modify rust/spend/ at all (the crate is contended by 1.4's
branch).
```

The honest-summary sentence the ledger adds: *"Three adapters exist under the 7.1 SDK with a
three-state reversibility descriptor; irreversible effects refuse without a human approval
receipt while reversible controls proceed unattended; the settle receipt records the
reversibility state at issue time. What this does not establish: recall of an accepted rail
instruction — pre-authorization is the entire bound — and the registry/data-platform adapters
are fixture-proven, not live-tested against real services."*

The final commit, gathering the pieces:

```bash
git add rust/warrant/src/reversibility.rs rust/warrant/src/lib.rs \
        rust/warrant/src/adapters/registry.rs rust/warrant/src/adapters/warehouse.rs \
        rust/warrant/src/adapters/rail.rs rust/warrant/src/effects.rs \
        rust/warrant/tests/adapters_spend.rs docs/W1-delivery-gaps.md docs/task-evidence/task-7.5.md
git commit -s -F .commitmsg
# Branch: feat/adapters-spend-and-data. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

---

**The three adapters' transport injection, the fixture shapes the conformance consumes.**

```rust
// registry.rs — publish/yank against a fixture registry. The yank is the REVERSIBILITY
// proof's control: publish then yank, and the effect is undone by the same class.
pub struct FixtureRegistry { published: Vec<(String, String)>, yanked: Vec<String> }
impl RegistryTransport for FixtureRegistry {
    fn publish(&mut self, crate_name: &str, version: &str) -> Result<String, String> {
        self.published.push((crate_name.to_string(), version.to_string()));
        Ok(format!("{crate_name}-{version}"))
    }
    fn yank(&mut self, crate_name: &str, version: &str) -> Result<(), String> {
        self.yanked.push(version.to_string());
        Ok(())
    }
}

// warehouse.rs — a fixture warehouse whose writes are "rolled back" by a corrective
// write: the COMPENSABLE proof. The compensation is itself an effect, itself receipted.
pub struct FixtureWarehouse { written: Vec<(String, String)>, corrected: Vec<String> }

// rail.rs — a fixture rail whose accepts are final. There is no yank, no rollback, no
// compensation: the IRREVERSIBLE proof, and the reason the descriptor has three states.
pub struct FixtureRail { instructions: Vec<String> }
```

**The spend-class routing, where the budget and the approval interact.** The rail adapter's
`invoke` consults two gates in order, and the order matters:

```rust
// 1. The BUDGET (Task 1.4's bound, via the settle path): a warrant with no budget
//    authorizes no rail instruction; a warrant at its ceiling refuses. This is the
//    spend machinery's existing discipline — the adapter adds nothing to it.
// 2. The APPROVAL (I-08's machinery, via the grant context): an IRREVERSIBLE effect
//    requires a human approval receipt; reversible effects do not. The descriptor
//    decides whether the approval gate fires, and the descriptor comes from the
//    adapter's declaration, not from the effect's arguments.
```

**The descriptor's placement in the registry declaration, why the adapter owns it.** The
reversibility of `rail.instruction` is a fact about the rail — the same publish to the same
registry is reversible, the same instruction to the same rail is not. The declaration lives
with the adapter's tool registration (a `Reversibility` column beside the syscall set), and the
test asserts the descriptor is declared for every tool the adapter publishes:

```rust
#[test]
fn every_tool_declares_its_reversibility() {
    for adapter in [registry(), warehouse(), rail()] {
        for tool in adapter.tools() {
            assert!(adapter.declared_reversibility(tool).is_some(),
                "{tool} publishes without a reversibility declaration: the descriptor is \
                 the adapter's own knowledge, written out");
        }
    }
}
```

**The ledger's spend row, quoted so the implementer cannot write a weaker one:**

```text
The rail adapter's bound is pre-authorization only. The budget bound (Task 1.4)
limits how much; the approval receipt (I-08) proves a human decided; neither recalls
an accepted instruction. The descriptor records the system's BELIEF about
reversibility at issue time — a compensation, when one exists, is a new receipted
effect that names the original, not an undo of it.
```

**The contended-file discipline, the rebase note the evidence file carries:**

```text
rust/spend/src/lib.rs is contended with Task 1.4's branch. This task edits NOTHING
in rust/spend/: the consultation is through the settle path, and the declaration
lives in the adapter's own registration. If 1.4's branch changed the spend API,
rebase this branch and adjust the consultation — the descriptor itself is
unaffected.
```

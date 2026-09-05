### Task 9.4: Authority-expansion detection and sibling-collusion intersection (L6-09, L6-12)

**Anchor.** Both catalog items are quoted verbatim from
`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html`.

L6-09, line 4222:
`<article class="item" id="L6-09" data-stratum="L6" data-plane="B" data-status="none" data-novelty="novel" data-wave="W2" data-loop="L5">`
— **`status=none`**, `novel`, W2, Plane B. Its `what` clause, line 4226: *"Continuous monitoring for
any path by which effective authority grew: credential harvesting, service impersonation, token
forgery, account creation, configuration drift. Complements L6-01 by watching for expansion that
routes around the chain entirely."* Its own residual, line 4230: *"Detection has latency; the window
between expansion and alarm is a published number, not zero."*

L6-12, line 4258:
`<article class="item" id="L6-12" data-stratum="L6" data-plane="B" data-status="none" data-novelty="novel" data-wave="W2" data-loop="L5">`
with `<span class="tier proposed">PROPOSED · added</span>` — **`status=none`**, `novel`, W2, Plane B.
Its `what` clause, line 4262: *"Two agents under the same parent may hold complementary permissions
(one may read a secret store, another may reach an external destination) that neither could exercise
alone. This control makes information and authority non-transitive between siblings: what one sibling
knows cannot be combined with what another may do unless a warrant explicitly grants the union, and
the kernel tests every population for complementary pairs at admission and on every delegation. Added
from the research source; the OS spec computes the chain vertically (L6-01) but not across siblings."*
Its verification clause, line 4265: *"Seed a population with a read-only sibling and an egress-only
sibling and assert that no composition of sanctioned messages, memory or delegation lets the secret
leave; the population's computed union authority is published in the fleet console and never exceeds
the parent's."*

This is invariant I-02's blind spot. The fold runs down **one** root-first path. Two siblings share an
ancestor but sit on two paths, so there is no chain to fold across them, and nothing in the system
computes a population's total authority at all.

---

**Step 0 — executed, verbatim.** Read-only scratch worktree off **local `main` at `b04164d`** (not
`origin/main`, which is stale at `e4b5f10`):

```
$ cd "M:/Project AumOS - Open Secure AI Alliance/aumos" && git rev-parse main
b04164ddbdc29e001fcf4dd71f43a579cbe2c39a
$ git worktree add --detach M:/wt-e-9.4 main
Preparing worktree (detached HEAD b04164d)
HEAD is now at b04164d Merge branch 'ci/us-english-gate'
$ git ls-tree --name-only main rust/ | grep -c '^rust/[a-z]'
40
```

**Finding 1 — the seed's central premise is false. `i02_no_authority_expansion.rs` contains no
`#[ignore]`, so there is nothing for this task to convert.** The seed says *"Read
`rust/warrant/tests/invariants/i02_no_authority_expansion.rs` in full and quote its `#[ignore]`
reasons"*, and the Phase 9 scope entry says *"9.4 is I-02"* among *"invariants the Task 5.1 corpus
currently reports as violated or unimplemented."* Both are wrong. The file is 214 lines and every one
of its seven tests passes:

```
$ grep -c "#\[ignore" rust/warrant/tests/invariants/i02_no_authority_expansion.rs
0
$ grep -rn "#\[ignore" rust/warrant/tests/invariants/ | cut -d: -f1 | sort -u
rust/warrant/tests/invariants/i01_active_identity.rs
rust/warrant/tests/invariants/i03_purpose_bound_data_use.rs
rust/warrant/tests/invariants/i04_current_policy.rs
rust/warrant/tests/invariants/i05_bounded_revocation_latency.rs
rust/warrant/tests/invariants/i06_exact_artifact_identity.rs
rust/warrant/tests/invariants/i08_non_delegable_human_authority.rs
rust/warrant/tests/invariants/i09_failure_is_safe.rs
rust/warrant/tests/invariants/i10_replay_is_detectable.rs
rust/warrant/tests/invariants/i11_self_change_is_governed.rs
rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs
```

I-02 and I-07 are the only two invariants in the corpus with no recorded finding. The file's own module
doc, lines 6–10, says so in the opposite direction from the seed:

> This is the best-defended invariant in the codebase. Two implementations recompute the intersection —
> `notary::effective_capabilities` for the decision and `evidence::recompute_intersection` for the
> receipt — and the receipt verifier rejects a claimed capability set the chain does not produce. The
> corpus attacks both, and records one seam: the two implementations are separate code paths that
> nothing checks against each other.

The ledger agrees. `evidence/invariants.json` lines 17–26, verbatim, **status word `enforced`**:

```json
      "id": "I-02",
      "statement": "No authority expansion. The intersection of authorities in the delegation chain is the maximum authority; never the union.",
      "status": "enforced",
      "enforced_by": [
        {"crate": "evidence", "symbol": "warrantor_evidence::verify_authority", "test": "rust/evidence/src/lib.rs::authority_expansion_rejected", "note": "error text 'authority expansion; I-02'"},
        {"crate": "evidence", "symbol": "warrantor_evidence::recompute_intersection", "test": "rust/evidence/src/lib.rs::forged_intersection_proof_rejected", "note": ""},
        {"crate": "notary", "symbol": "warrantor_notary::Gate::Authority", "test": "rust/notary/src/lib.rs::gate5_authority_outside_intersection_denies", "note": ""},
        {"crate": "notary", "symbol": "warrantor_notary::effective_capabilities", "test": "rust/notary/src/lib.rs::gate5_authority_intersection_drops_capability_when_a_link_lacks_it", "note": ""}
      ],
      "gap": "The intersection algebra exists once on this tree, in the evidence crate, on the binary's path. (The plan recorded a second implementation in rust/delegation-chain, a crate that is not tracked on origin/main; Task 1.5 owns wherever that algebra lands.)"
```

That `gap` sentence is itself stale in two ways after Task 1.5: `rust/delegation-chain` **is** tracked
on local `main`, and the algebra now lives there rather than in the evidence crate. Correcting it is
part of this task.

The consequence for scope is large and it must be said plainly rather than absorbed: **this task does
not convert a recorded violation and may not claim to.** It adds a new control for a hole the corpus
never recorded, so its ratchet obligation is to raise `passing_floor` by exactly the number of new
passing tests it lands and to leave `ignored_ceiling` untouched.

**Baseline, captured.** `cargo test -p warrantor-evidence -p warrantor-delegation-chain`, tail:

```
     Running tests\delegation_algebra.rs
running 1 test
test granted_is_a_subset_of_every_ancestor_and_every_expansion_is_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.57s

     Running tests\four_deep_revocation.rs
running 4 tests
test revoking_the_middle_spares_the_ancestors ... ok
test an_unknown_warrant_cannot_bind ... ok
test the_deepest_receipt_names_all_four_links ... ok
test revoking_the_root_refuses_every_descendant_at_bind ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

The corpus and the two ratchets:

```
$ python tools/ci/check_invariant_ratchet.py
test result: ok. 66 passed; 0 failed; 18 ignored; 0 measured; 0 filtered out; finished in 0.14s
invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
$ python tools/ci/wiring_census.py
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
```

Reachability, which decides the orphan question before any code is written:

```
$ python -c "import sys; sys.path.insert(0,'tools/ci'); from wiring_census import reachable_crates; \
from pathlib import Path; print(sorted(reachable_crates(Path('rust'))))"
['warrantor-api', 'warrantor-authority-spec', 'warrantor-containment-conformance',
 'warrantor-delegation-chain', 'warrantor-egress', 'warrantor-evidence', 'warrantor-notary',
 'warrantor-spend', 'warrantor-trust-core', 'warrantor-warrant']
```

`warrantor-delegation-chain`, `warrantor-evidence` and `warrantor-warrant` are all reachable, so every
line this task writes lands inside the reached set. **The orphan count stays 30.**

**Finding 2 — Task 1.5's fold is real, and it is narrower than the seed describes.** The seed says
*"there is now exactly one chain fold, `rust/delegation-chain::intersect_chain`, and
`rust/evidence::narrow_chain` is its only consumer of the arithmetic."* Verified true as stated, and
incomplete: `notary::effective_capabilities` at `rust/notary/src/lib.rs:293` is still a `HashSet`
intersection over `notary::DelegationLink` that never touches the fold, and `rust/notary/Cargo.toml`
declares **no** `warrantor-*` dependency. Task 1.5's own evidence file says so, at
`docs/task-evidence/task-1.5.md:203–213`:

> - **The notary still holds a third copy of the fold.** `rust/notary/src/lib.rs:293
>   effective_capabilities` is a `HashSet` intersection over `notary::DelegationLink`, unchanged. […]
> - **The two implementations now genuinely differ on a widening chain, and only the corpus's four
>   cases hide it.** […] For `[["a","b"], ["a","c"]]` the notary would say `["a"]` and the evidence
>   crate says `[]`. […] On the deciding side the seam that test guards is **wider after this task, not
>   narrower** — this is the finding, and it belongs to whoever next revises the notary's chain gate.

That is a live, recorded, unclosed divergence in the file this task edits. It is **not** this task's to
close (see Non-goals), and this task must not add a corpus test that exercises it: doing so would
either fail the build or require a thirteenth `#[ignore]`, which raises `ignored_ceiling` and fails the
build by design.

**Finding 3 — the capability half of sibling collusion is already vacuous; the quantitative half is
not.** `intersection` at `rust/delegation-chain/src/lib.rs:107–132` requires every requested capability
and resource class to exist in the parent, so the union of any sibling set's **capability sets** is
necessarily a subset of the ancestor's. A control that only asked "does the union of capabilities
exceed the ancestor?" would be unfalsifiable. What is genuinely unbounded is arithmetic:

```rust
// rust/delegation-chain/src/lib.rs:125-130
    if requested.expires_at_ms > parent.expires_at_ms {
        return Err(Escalation::Time);
    }
    if requested.budget_micros > parent.budget_micros {
        return Err(Escalation::Budget);
    }
```

Each child is compared against the parent **independently**. `delegate` at line 201 never debits the
parent, so a parent holding `budget_micros: 500_000_000` can issue two children of `400_000_000` each
and the population holds `800_000_000` — an authority the ancestor never had, produced entirely through
sanctioned grants, with no widening link anywhere for `intersect_chain` to name. That is the refusable
hole, and it is the exit gate. The complementary-capability half (L6-12's read-sibling plus
egress-sibling) is real but is a **composition** the ancestor never expressed, not a quantity that
exceeds it; it needs a declaration, and it gets detection rather than a fabricated refusal.

**Finding 4 — the store cannot see downward.** `WarrantStore` (line 174) holds
`warrants: HashMap<String, Warrant>` and `revoked: HashSet<String>`; `chain_of` (line 228) walks
`parent` links **upward** only. There is no `children_of`, no sibling enumeration, and no population
concept anywhere in the workspace. `sibling_branches_independent` (line 465) is the closest thing and
it tests exactly the opposite property: that revoking one sibling leaves the other standing.

**Finding 5 — Task 9.6 has not landed, and there is no channel plane at all.**

```
$ git grep -n "peer_proposal\|PeerProposal\|fn send_message\|struct Message\|agent_to_agent" -- 'rust/**/*.rs'
$ git ls-tree --name-only main rust/ | grep -i "channel\|message\|comm"
$
```

Both empty. `git log --oneline main` shows the six unpushed merges (`b04164d`, `eef1c71`, `f99af94`,
`166551c`, `f06c030`, `c6cb1bb`) and none is 9.6. The seed's claim that *"sibling collusion is
undetectable without it"* is **half right, and the half that is wrong is what makes this task
schedulable.** Collusion over an *unauthenticated message channel* is undetectable without attested
identity — nobody can attribute a message to a sibling they cannot authenticate. But this task's
control never reads a message. It computes over the **warrant lineage the store already holds**, at the
moment a warrant is issued, and refuses the second grant before either agent runs. Attribution is by
construction there: the store knows which id it is minting and which parent it hangs from. **This task
stands without 9.6.** What it cannot do without 9.6 is observe the composition being *exercised* — and
that limit belongs in the product text, not in a footnote.

---

**Non-goals.** Each names the task that owns the excluded thing.

- **Not swarm detection on the receipt graph — Task 6.2 owns that.** 6.2 looks for organization
  (hierarchy, roles, assignment trees) in receipts after the fact. This task refuses a grant before any
  receipt exists. The two must not each claim the other's ground: this one cannot see a population that
  formed without going through `delegate`, and 6.2 cannot refuse anything.
- **Not the channel plane, attested sender identity, or the channel policy language — Task 9.6 owns
  those (L5-06, L5-05), and it has NOT landed.** No message type, broker or delivery path is introduced
  here. A composition exercised over a channel is out of reach until 9.6 exists.
- **Not bounded revocation or its SLA — Task 9.1 owns that (L6-04, I-05), and it is in flight.** 9.1
  also owns the `credential-vault` wiring and, per its own Files list, edits
  `tools/ci/invariant-ratchet.json` claiming `passing_floor` 65 → 68 against the stale 65/19 pair. This
  task reads the floor from its own captured test line at branch time and never assumes a number.
- **Not purpose binding on authority — Task 9.3 owns that (L6-07, I-03).** No purpose field is added to
  `WarrantScope`, `WarrantBounds`, the request, or the receipt.
- **Not cross-organization authority or agent naming — Task 9.5 owns those (L6-08, L6-10).** Every
  sibling relation here is inside one `WarrantStore`. Two ancestors in two organizations are explicitly
  out of reach and named as such in the product text.
- **Not the chain fold itself — Task 1.5 owns it and it has LANDED.** `intersection` and
  `intersect_chain` are consumed, never reimplemented. A second implementation of one contract is the
  defect Task 1.5 existed to remove.
- **Not the notary's third copy of the fold, and not the widening-chain divergence Task 1.5 recorded.**
  Left open, named here and in the evidence file, and assigned in `docs/W1-delivery-gaps.md` § 3.7 to
  whoever next revises the notary's chain gate.
- **Not improvised-channel detection or the shared-surface census — Task 3.6 owns those (L5-02,
  L2-01).** Named below as partial cover for the side-channel blind spot, with no closure claimed.

---

**Files.**

- `rust/delegation-chain/src/lib.rs` — `children_of`, `siblings_of`, `composed_authority`,
  `effective_ceiling_of`, `PopulationEscalation`, `DelegateError::Composed`, the incompatible-pair
  register, and the sibling-aware branch of `delegate`.
- `rust/delegation-chain/tests/sibling_composition.rs` — new integration suite.
- `rust/evidence/src/lib.rs` — `bind_population`, so a receipt can carry the composed union.
- `rust/evidence/tests/population_composition.rs` — new integration suite, including the
  proof-format-unchanged assertion that protects Task 1.5's gate.
- `rust/warrant/tests/invariants/i02_no_authority_expansion.rs` — the corpus tests.
- `evidence/invariants.json` — I-02's stale `gap` sentence, rewritten.
- `tools/ci/invariant-ratchet.json` — `passing_floor` raised, read from the captured test line.
- `docs/W1-delivery-gaps.md` — the two blind spots recorded as findings.
- `docs/task-evidence/task-9.4.md`.

---

**Consumes / Produces.**

Consumes, all present on local `main` at `b04164d`:

```rust
// rust/delegation-chain/src/lib.rs:107
pub fn intersection(parent: &WarrantScope, requested: &WarrantScope) -> Result<WarrantScope, Escalation>
// rust/delegation-chain/src/lib.rs:155
pub fn intersect_chain(chain: &[WarrantScope]) -> Result<WarrantScope, ChainEscalation>
// rust/delegation-chain/src/lib.rs:228
pub fn chain_of(&self, id: &str) -> Vec<Warrant>
// rust/delegation-chain/src/lib.rs:253
pub fn is_valid(&self, id: &str) -> bool
// rust/delegation-chain/src/lib.rs:260
pub fn effective_scope(&self, id: &str) -> Option<&WarrantScope>
// rust/evidence/src/lib.rs:291  (private; the reason units never diverge)
fn scope_of(link: &DelegationLink) -> WarrantScope
// rust/evidence/src/lib.rs:310
pub fn narrow_chain(chain: &[DelegationLink]) -> Result<Vec<String>, EvidenceError>
// rust/evidence/src/lib.rs:360
pub fn bind_authority(store: &WarrantStore, warrant_id: &str) -> Result<Authority, EvidenceError>
// rust/evidence/src/lib.rs:383
pub fn compute_intersection_proof(chain: &[DelegationLink]) -> IntersectionProof
// rust/evidence/src/lib.rs:634
pub fn verify_authority(authority: &Authority) -> Result<(), EvidenceError>
// rust/warrant/tests/invariants/harness.rs:50
pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)
```

Consumes from a task that has **not** landed: Task 9.6's attested sender identity (L5-06). Precisely
what this task would need from it and does not have: a verified binding from an inter-agent message to
the agent principal that sent it, so that a composition being *exercised* over a channel could be
attributed to a named sibling. **This task does not need it to refuse a grant**, because attribution at
issuance comes from the store's own `parent` link. It needs it only to observe exercise, which this
task therefore does not claim. 9.6 is routed to the GLM lane and is unstarted.

Produces:

```rust
/// The composed authority of a sibling set: the union of what the siblings hold. The ONLY union in
/// this crate, and it exists to be compared against a ceiling, never to confer anything.
pub struct ComposedAuthority {
    pub ancestor: String,
    pub members: Vec<String>,          // sorted; deterministic refusal text depends on it
    pub union_capabilities: Vec<String>,
    pub union_resource_classes: Vec<String>,
    pub committed_budget_micros: u64,  // saturating sum
    pub latest_expiry_ms: u64,
}
pub fn composed_authority(&self, ancestor: &str) -> ComposedAuthority;
pub fn children_of(&self, id: &str) -> Vec<Warrant>;      // sorted by id
pub fn siblings_of(&self, id: &str) -> Vec<Warrant>;      // sorted by id, excludes `id`
pub fn effective_ceiling_of(&self, id: &str) -> Result<WarrantScope, ChainEscalation>;
pub fn declare_incompatible(&mut self, left: &str, right: &str);
pub enum PopulationEscalation {
    Budget { ancestor: String, committed_micros: u64, requested_micros: u64, ceiling_micros: u64,
             committed_by: Vec<String> },
    ComplementaryPair { ancestor: String, holder: String, holds: String,
                        requester: String, requests: String },
}
// added variant on the existing enum at rust/delegation-chain/src/lib.rs:272
pub enum DelegateError { /* … */ Composed(PopulationEscalation) }
// rust/evidence
pub fn bind_population(store: &WarrantStore, ancestor: &str) -> Result<PopulationBlock, EvidenceError>;
```

---

**Bound strength.**

**Tier B — chokepoint.** The refusals are `Tier B (chokepoint)` held at **warrant issuance inside one
`WarrantStore`**: `delegate` refuses, in process, at the moment the second grant is attempted. That is
a specific line of code refusing at the moment of attempt, so it is a refusal and not an observation —
but the chokepoint is the issuance API, not cryptography and not the operating system. Nothing here is
`Enforced` in `warrantor_warrant::BoundStrength`'s sense (`rust/warrant/src/lib.rs:198–212`): no
signature, no process link, no netns, no seccomp, no firewall. **What escapes the chokepoint:** a
warrant minted by any path that does not call `WarrantStore::delegate`; a second store process holding
its own copy of the lineage; a forged or harvested token, which by L6-09's own `what` clause *"routes
around the chain entirely"*; and spend itself, because
`warrantor_warrant::WarrantBounds::budget_cents_observed` is documented `Observed` at
`rust/warrant/src/lib.rs:260–269` — this task refuses the *grant* of a budget the population cannot
support, never the dollar leaving.

**Tier C — observed.** The L6-09 detector is `Observed`. It enumerates complementary pairs and the
population's composed union and reports them; it refuses nothing. The catalog item itself sets this
expectation at line 4230: *"Detection has latency; the window between expansion and alarm is a
published number, not zero."*

**The sentence that ships in the product, next to the guarantee and not in a footnote:**

> Warrantor refuses a delegation whose grant would let a population of sibling agents jointly hold more
> than the ancestor that spawned them — the refusal happens when the warrant is issued, and it names
> the ancestor, both siblings and the numbers. **It does not cover:** agents granted authority by two
> different roots, which never share an ancestor here and compose freely; agents coordinating through
> any channel this system does not mediate; authority obtained by forging or harvesting a credential
> rather than by delegation; and spend, which is measured from the agent's own reporting and not
> refused as the money moves. Two of these have detectors that report after the fact. None of them has
> a bound.

**The orphan count does not rise.** Every crate touched — `warrantor-delegation-chain`,
`warrantor-evidence`, `warrantor-warrant` — is already in the ten reachable from `warrantor-warrant`,
verified above. No new crate is created. `python tools/ci/wiring_census.py` must still print
`10 of 40 crates reachable`.

**No new trust root.** The incompatible-pair register is **unsigned local state on the store**, exactly
the weight of the `revoked: HashSet<String>` that already sits beside it at line 176 and already drives
`is_valid`. It establishes only this: *warrants issued through this store, in this process, were checked
against the pairs this process was told about.* It establishes **nothing** about warrants issued
elsewhere, nothing about a second machine, nothing an auditor can verify without trusting the operator
who configured it, and no fact that crosses an organization — that last is Task 9.5's problem, not a
thing this task quietly solves. Nothing is fetched over a network and no key is introduced.

---

**Exit gate.** One command decides pass or fail:

```
python tools/ci/check_invariant_ratchet.py
```

It compiles and runs the whole I-01…I-12 corpus, including the new sibling tests in
`i02_no_authority_expansion.rs`, and then compares the counts against
`tools/ci/invariant-ratchet.json`. It must print `invariant ratchet: ok (N passing at floor N, 18
recorded findings at ceiling 18)` where `N` is the raised floor and the ignored count is still **18**.
A thirteenth `#[ignore]` fails it. A floor raised past what the tests earn fails it. A floor left
unraised while tests are added is caught by review against the captured line.

---

- [ ] **Step 1 — Worktree and branch.**

```
  export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
  cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
  git worktree add M:/wt-9.4-sibling -b feat/sibling-collusion-intersection main
  cd M:/wt-9.4-sibling && export CARGO_TARGET_DIR=M:/wt-9.4-sibling-target
  git rev-parse HEAD   # must be b04164d, NOT origin/main's e4b5f10
```

  Branch from **local `main`**, not `origin/main`: `origin/main` predates Task 1.5, so branching there
  would put this task on a tree with no `intersect_chain` to compose with and it would die at its first
  `cargo` call. **Test intent:** none — this step is verified by `git rev-parse` matching `b04164d`.

- [ ] **Step 2 — Open the evidence file with the two contradicted premises, before writing code.**
  Create `docs/task-evidence/task-9.4.md` and record, with the captured output from Step 0 above: that
  `i02_no_authority_expansion.rs` has zero `#[ignore]`s; that `evidence/invariants.json` gives I-02
  `"status": "enforced"`; that this task therefore converts no recorded violation and raises the floor
  only by the tests it lands; and that Task 9.6 has not landed together with the one thing this task
  would want from it. **Mechanism:** the file itself, plus a comment at the top of the new corpus
  section naming the same fact so a reader of the test file learns it without opening the docs:

```rust
  // -- sibling composition (L6-09, L6-12; Task 9.4) -----------------------------------
  //
  // I-02's `status` in evidence/invariants.json is `enforced`, and it is enforced -- down a chain.
  // These tests attack the axis the fold cannot see: two siblings on two paths under one ancestor.
  // Nothing here converts an `#[ignore]`; this file never had one. Recorded 2026-09-05.
```

  **Test intent:** `harness::source_contains` in Step 10 pins that comment, so deleting the disclosure
  fails the build.

- [ ] **Step 3 — Failing test first: the store cannot see downward.** Add `children_of` and
  `siblings_of` to `WarrantStore`. `warrants` is a `HashMap`, so iteration order is nondeterministic and
  the refusal text in Step 6 depends on member order — **sort by id**, and test that it is sorted.

```rust
  // rust/delegation-chain/tests/sibling_composition.rs
  #[test]
  fn children_and_siblings_are_enumerable_and_deterministically_ordered() {
      let mut store = WarrantStore::new();
      store.issue_root("org", parent_scope());
      for id in ["zeta", "alpha", "mid"] {
          store.delegate("org", id, &child_scope(&["github:write"], 100_000_000)).unwrap();
      }
      let children: Vec<&str> = store.children_of("org").iter().map(|w| w.id.as_str()).collect();
      assert_eq!(children, ["alpha", "mid", "zeta"], "children_of must be sorted by id: the \
          refusal message in DelegateError::Composed names its members, and a HashMap order would \
          make that message differ run to run");
      let siblings: Vec<&str> = store.siblings_of("mid").iter().map(|w| w.id.as_str()).collect();
      assert_eq!(siblings, ["alpha", "zeta"], "siblings_of excludes the warrant itself");
      assert!(store.children_of("alpha").is_empty(), "a leaf has no children");
      assert!(store.siblings_of("ghost").is_empty(), "an unissued id has no siblings");
  }
```

  **Test intent:** the primitive exists, it is total over unknown ids, and its order is a contract
  rather than an accident.

- [ ] **Step 4 — Compose with Task 1.5's fold rather than reading the stored scope.** The ancestor's
  ceiling must be the **folded** scope over its own lineage, obtained from `intersect_chain`, not the
  scope field the store happens to hold. Today they agree because `delegate` narrows at issue; if they
  ever disagree the store is corrupt and the ceiling must not be taken from the corrupt side.

```rust
  /// The ancestor's ceiling, folded from its own root-first lineage with the one delegation algebra
  /// ([`intersect_chain`]). Deliberately NOT `effective_scope`: that returns a stored field, and a
  /// ceiling read from stored state cannot detect a store whose lineage and scopes disagree.
  pub fn effective_ceiling_of(&self, id: &str) -> Result<WarrantScope, ChainEscalation> {
      let scopes: Vec<WarrantScope> = self.chain_of(id).into_iter().map(|w| w.scope).collect();
      intersect_chain(&scopes)
  }
```

```rust
  #[test]
  fn the_ceiling_comes_from_the_fold_and_agrees_with_the_stored_scope() {
      let store = four_deep_population();
      for id in ["org", "lead", "agent"] {
          assert_eq!(
              store.effective_ceiling_of(id).expect("a narrowing lineage folds"),
              *store.effective_scope(id).expect("and it stands"),
              "{id}: the folded ceiling and the stored scope must agree; if they ever diverge the \
               ceiling is the folded one and the store is the thing at fault",
          );
      }
      assert!(store.effective_ceiling_of("ghost").unwrap().capabilities.is_empty(),
          "an unknown ancestor folds an empty chain: confers nothing, already expired");
  }
```

  **Test intent:** the new control's ceiling is derived by the single existing fold, and an unknown
  ancestor confers nothing rather than panicking.

- [ ] **Step 5 — Failing test: prove the hole exists before closing it.** With unmodified `delegate`,
  two siblings that each pass the per-child check compose past the ancestor. This test must **fail** on
  `main`'s behavior in the direction that matters — the two grants both succeed — and then pass once
  Step 6 lands. Write it first, run it, and paste the failure into the evidence file.

```rust
  #[test]
  fn two_lawful_siblings_compose_a_budget_the_ancestor_never_held() {
      // The ancestor holds 500 000 000 micros. Each child asks for 400 000 000: lawful alone,
      // 800 000 000 together. `intersection` compares each child against the parent independently,
      // so nothing in the vertical algebra can see this. There is no widening link for
      // `intersect_chain` to name -- which is exactly why L6-01 does not cover it.
      let mut store = WarrantStore::new();
      store.issue_root("org", scope(&["github:write"], &["repo:acme/*"], 1_000_000, 500_000_000));
      let first = store.delegate("org", "sib-a",
          &scope(&["github:write"], &["repo:acme/api"], 900_000, 400_000_000));
      assert!(first.is_ok(), "the FIRST grant is lawful and must be allowed; a refusal here would \
          mean the control refuses everything and proves nothing");

      let composed = store.composed_authority("org");
      assert_eq!(composed.committed_budget_micros, 400_000_000);
      assert_eq!(composed.members, vec!["sib-a".to_string()]);

      let second = store.delegate("org", "sib-b",
          &scope(&["github:write"], &["repo:acme/web"], 900_000, 400_000_000));
      assert!(second.is_err(), "the SECOND grant composes 800 000 000 micros under a 500 000 000 \
          ceiling and must be refused at the moment of the grant, not observed after the fact");
  }
```

  **Test intent:** the hole is demonstrated with a passing control in the same test, so the later
  refusal cannot be a refusal of everything.

- [ ] **Step 6 — The refusal, and it names both siblings and the ancestor.** Add the sibling-aware
  branch to `delegate`, placed **after** the existing `intersection` call so a request that is not even
  vertically lawful still fails as an `Escalation` and the two failure modes stay distinguishable.
  Sum with `saturating_add`: two `u64` budgets near `u64::MAX` would otherwise wrap and turn a refusal
  into an allow.

```rust
  // in `delegate`, after: let scope = intersection(&parent.scope, requested)?;
  let ceiling = self
      .effective_ceiling_of(parent_id)
      .map_err(|widened| DelegateError::Escalated(widened.escalation))?;
  let composed = self.composed_authority(parent_id);
  let would_commit = composed.committed_budget_micros.saturating_add(scope.budget_micros);
  if would_commit > ceiling.budget_micros {
      return Err(DelegateError::Composed(PopulationEscalation::Budget {
          ancestor: parent_id.to_string(),
          committed_micros: composed.committed_budget_micros,
          requested_micros: scope.budget_micros,
          ceiling_micros: ceiling.budget_micros,
          committed_by: composed.members.clone(),
      }));
  }
```

```rust
  impl std::fmt::Display for PopulationEscalation {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
          match self {
              Self::Budget { ancestor, committed_micros, requested_micros, ceiling_micros,
                             committed_by } => write!(f,
                  "sibling composition under ancestor {ancestor}: {} already commit \
                   {committed_micros} micros and this grant asks {requested_micros} more, which is \
                   {} over the ancestor's ceiling of {ceiling_micros} (authority expansion across \
                   siblings; I-02, L6-12)",
                  committed_by.join(", "),
                  committed_micros.saturating_add(*requested_micros) - ceiling_micros),
              Self::ComplementaryPair { ancestor, holder, holds, requester, requests } => write!(f,
                  "sibling composition under ancestor {ancestor}: {holder} already holds {holds} \
                   and {requester} asks for {requests}, a pair declared incompatible; neither \
                   sibling holds the composition and the ancestor never granted it (L6-12)"),
          }
      }
  }
```

```rust
  #[test]
  fn the_refusal_names_both_siblings_the_ancestor_and_the_arithmetic() {
      let mut store = WarrantStore::new();
      store.issue_root("org", scope(&["github:write"], &["repo:acme/*"], 1_000_000, 500_000_000));
      store.delegate("org", "sib-a",
          &scope(&["github:write"], &["repo:acme/api"], 900_000, 400_000_000)).unwrap();

      // CONTROL: a second sibling whose grant fits under the remaining 100 000 000.
      let mut control_store = store.clone();
      let control = control_store.delegate("org", "sib-b",
          &scope(&["github:write"], &["repo:acme/web"], 900_000, 100_000_000));

      // ATTACK: the same grant, 400 000 000.
      let attacked = store.delegate("org", "sib-b",
          &scope(&["github:write"], &["repo:acme/web"], 900_000, 400_000_000));

      harness_refused(&control, &attacked);   // control Ok, attack Err
      let Err(DelegateError::Composed(escalation)) = attacked else {
          panic!("a sibling composition must fail as Composed, not as a vertical Escalated");
      };
      let text = escalation.to_string();
      for fragment in ["org", "sib-a", "sib-b", "400000000", "500000000", "I-02", "L6-12"] {
          assert!(text.contains(fragment),
              "the refusal must name {fragment} so an operator reading one line knows which two \
               agents and which ancestor: {text}");
      }
  }
```

  Note the attack's own id appears in the message only because `delegate` knows `child_id`; the
  `ComplementaryPair` variant carries `requester` for the same reason. **Test intent:** a refusal
  paired with an allowed control, and a refusal text an operator can act on without a debugger.

- [ ] **Step 7 — The complementary-capability half, declared rather than invented.** L6-12's ceiling is
  not "the ancestor's set" — the ancestor legitimately holds both `secrets:read` and `net:egress`. The
  item's own words are *"unless a warrant explicitly grants the union."* So the composition must be
  **declared** somewhere, and it may not be declared in `WarrantScope`: `Warrant::compute_digest` at
  line 81 covers `(id, scope, parent)`, so a new scope field would change every warrant digest and every
  `links_digest`, breaking Task 1.5's "the proof format is unchanged" gate. It goes on the store,
  unsigned, beside `revoked`.

```rust
  /// Capability pairs no sibling set under one ancestor may jointly hold. Unsigned local state, the
  /// same weight of thing as `revoked`: it binds warrants issued through THIS store in THIS process
  /// and establishes nothing about a warrant issued anywhere else. No new trust root -- see
  /// docs/task-evidence/task-9.4.md.
  pub fn declare_incompatible(&mut self, left: &str, right: &str) { /* normalized, sorted pair */ }
```

```rust
  #[test]
  fn a_declared_incompatible_pair_is_refused_at_the_second_grant_with_an_allowed_control() {
      let seed = || {
          let mut store = WarrantStore::new();
          store.issue_root("org",
              scope(&["secrets:read", "net:egress"], &["*"], 1_000_000, 500_000_000));
          store.delegate("org", "reader",
              &scope(&["secrets:read"], &["vault/*"], 900_000, 1_000)).unwrap();
          store
      };

      // CONTROL: nothing declared, so the egress sibling is granted. It is REPORTED (Step 8),
      // not refused -- a control that were refused would prove the check refuses everything.
      let mut permitted = seed();
      let control = permitted.delegate("org", "sender",
          &scope(&["net:egress"], &["https://*"], 900_000, 1_000));
      assert!(control.is_ok(), "an undeclared pair must still be granted; detection is Tier C");

      // ATTACK: the same two siblings with the pair declared.
      let mut guarded = seed();
      guarded.declare_incompatible("secrets:read", "net:egress");
      let attacked = guarded.delegate("org", "sender",
          &scope(&["net:egress"], &["https://*"], 900_000, 1_000));
      let Err(DelegateError::Composed(PopulationEscalation::ComplementaryPair {
          ancestor, holder, holds, requester, requests })) = attacked else {
          panic!("a declared incompatible pair must refuse as ComplementaryPair: {attacked:?}");
      };
      assert_eq!((ancestor.as_str(), holder.as_str(), requester.as_str()),
                 ("org", "reader", "sender"));
      assert_eq!((holds.as_str(), requests.as_str()), ("secrets:read", "net:egress"));

      // And the ancestor holding BOTH is not a grant of the composition.
      assert!(guarded.effective_scope("org").unwrap().capabilities
                  .contains(&"net:egress".to_string()),
          "the ancestor holds both capabilities individually; that is precisely not the same as \
           having granted their composition to a population");
  }
```

  **Test intent:** the refusal fires only on a declaration, the control proves it is not refusing
  everything, and the last assertion pins the semantic distinction the item turns on.

- [ ] **Step 8 — The L6-09 detector, `Observed` and honest about it.** `composed_authority` plus a
  report over a population: the union, the committed budget, the latest expiry, and every complementary
  pair present whether declared or not. It refuses nothing, and its doc comment says so in the tier
  vocabulary so a caller cannot mistake it for a gate.

```rust
  /// Report a population's composed authority and its complementary pairs.
  ///
  /// `BoundStrength::Observed`: this measures and reports, and refuses nothing. Expansion that
  /// routes around delegation entirely -- a forged token, a harvested credential, an account the
  /// model created -- never appears in `parent` links and is therefore invisible here. That is
  /// L6-09's stated residual, not a defect in this function.
  pub fn authority_expansion_report(&self, ancestor: &str) -> PopulationReport;
```

```rust
  #[test]
  fn the_detector_reports_the_undeclared_pair_it_did_not_refuse() {
      let mut store = WarrantStore::new();
      store.issue_root("org", scope(&["secrets:read", "net:egress"], &["*"], 1_000_000, 10_000));
      store.delegate("org", "reader", &scope(&["secrets:read"], &["vault/*"], 900_000, 1)).unwrap();
      store.delegate("org", "sender", &scope(&["net:egress"], &["https://*"], 900_000, 1)).unwrap();

      let report = store.authority_expansion_report("org");
      assert_eq!(report.members, vec!["reader".to_string(), "sender".to_string()]);
      assert!(report.complementary_pairs.iter().any(|p|
              p.left == "secrets:read" && p.right == "net:egress" && !p.declared_incompatible),
          "the population the store DID allow must still be reported, with declared=false, or the \
           only pairs an operator ever sees are the ones already refused");
      assert_eq!(report.union_capabilities,
                 vec!["net:egress".to_string(), "secrets:read".to_string()],
          "the union is what neither sibling holds alone");
      assert!(report.union_capabilities.iter().all(|c|
              store.effective_ceiling_of("org").unwrap().capabilities.contains(c)),
          "and it is within the ancestor's set -- which is why the capability union alone is NOT \
           the finding; the finding is that no sibling holds the composition");
  }
```

  **Test intent:** detection covers exactly the case refusal does not, and the test states in its own
  message why the union-vs-ancestor comparison is not the interesting one.

- [ ] **Step 9 — Wire it into evidence without moving the proof format.** `bind_population` returns a
  `PopulationBlock` alongside the existing `Authority`, so a receipt can carry the composed union that
  L6-12's verification clause asks to be publishable. The hard requirement is that
  `compute_intersection_proof` output is **byte-identical** before and after, because Task 1.5's exit
  gate says the proof format is unchanged by test and a receipt whose digest moved would fail every
  archived verification.

```rust
  #[test]
  fn adding_the_population_block_does_not_move_the_intersection_proof() {
      let store = four_deep_population();
      let authority = bind_authority(&store, "sub").expect("binds");
      // Digest captured from local main @ b04164d before this task touched anything; if this
      // literal ever needs editing, the proof format moved and every archived receipt is at risk.
      assert_eq!(authority.intersection_proof.algorithm, "warrantor-intersect-v1");
      assert_eq!(authority.intersection_proof,
                 compute_intersection_proof(&authority.chain),
                 "a stranger holding only the chain still recomputes the proof byte for byte");
      verify_authority(&authority).expect("and the bound authority still verifies");

      let population = bind_population(&store, "org").expect("the ancestor's population binds");
      assert_eq!(population.ancestor, "org");
      assert!(population.union_capabilities.iter().all(|c|
              authority.chain[0].capabilities.contains(c)),
          "the published union never exceeds the ancestor's own link");
  }
```

  **Test intent:** the new block is additive; the receipt's existing recomputable proof is pinned
  unchanged in the same test that exercises the new one.

- [ ] **Step 10 — The corpus tests, in `i02_no_authority_expansion.rs`.** Four tests, added under the
  comment from Step 2, all passing. They use `harness::refused_at_the_boundary` so a refused control
  fails loudly instead of counting as a pass.

```rust
  #[test]
  fn the_disclosure_that_this_is_not_a_converted_finding_stays_in_the_file() {
      harness::source_contains(
          "rust/warrant/tests/invariants/i02_no_authority_expansion.rs",
          "Nothing here converts an `#[ignore]`; this file never had one.",
          "I-02 was never a recorded violation. A reader who assumes it was will also assume the \
           ratchet floor rose because a finding closed, which it did not.",
      );
      harness::source_contains(
          "rust/delegation-chain/src/lib.rs",
          "authority expansion across siblings; I-02, L6-12",
          "The sibling refusal must stay labeled with the invariant and the catalog item it serves.",
      );
  }

  #[test]
  fn the_chain_fold_structurally_cannot_see_two_siblings() {
      // Not a defect in intersect_chain -- a statement of its domain, pinned so that a later
      // refactor that "fixes" it here instead of in the population check is caught.
      let mut store = warrantor_delegation_chain::WarrantStore::new();
      store.issue_root("org", ancestor_scope(500_000_000));
      store.delegate("org", "sib-a", &child_scope(400_000_000)).unwrap();
      for id in ["org", "sib-a"] {
          assert!(store.effective_ceiling_of(id).is_ok(),
              "{id}: every path in this store is a lawfully narrowing chain, so the fold reports \
               no escalation -- and it is right: the expansion is across paths, not down one");
      }
  }

  #[test]
  fn hop_06b_two_siblings_composing_past_their_ancestor_are_refused_at_the_second_grant() {
      // Round zero, hop 6, the team variant. The incident's agents formed teams and shared
      // credentials; one agent's slice plus another's is the move, and no forged token is needed.
      let (control, attacked) = sibling_control_pair();
      harness::refused_at_the_boundary(
          "hop 6b: two siblings whose grants compose past their common ancestor",
          &control, &attacked, Result::is_ok,
      );
  }

  #[test]
  fn the_population_union_is_recomputable_by_a_stranger() {
      // I-02's evidence field for the sibling axis: a party holding only the lineage must reproduce
      // the same union, or the number in the console is an assertion rather than evidence.
      let store = sibling_population();
      let first = store.authority_expansion_report("org");
      let second = store.authority_expansion_report("org");
      assert_eq!(first, second, "the report must be deterministic across calls: HashMap iteration \
          order is not, and the members list is what the refusal text prints");
      assert_eq!(first.union_capabilities,
                 warrantor_evidence::bind_population(&store, "org").unwrap().union_capabilities,
                 "the receipt's published union and the detector's union are one number");
  }
```

  **Test intent:** one static label check, one domain statement about the fold, one refusal with a
  control through the harness, and one recomputability check — the same four shapes the existing I-02
  tests use, extended to the sibling axis rather than duplicating
  `rust/evidence/tests/delegation_algebra.rs` (which fuzzes single chains) or
  `rust/evidence/tests/four_deep_revocation.rs` (which fuzzes nothing and tests one lineage's
  revocation).

- [ ] **Step 11 — Record the two blind spots, and claim no closure.** Add to
  `docs/W1-delivery-gaps.md` and to the evidence file, each as a finding with an owner:

  **Blind spot A — separate roots.** Two agents granted by two different `issue_root` calls, or by two
  different organizations, share no ancestor. `composed_authority` returns nothing for them and the
  refusal cannot fire. There is no partial cover and none is claimed; the shape of a fix is Task 9.5's
  cross-organization authority problem, and 9.5 has not started.

  **Blind spot B — side channels.** Two siblings that stay inside their own grants and coordinate
  through a shared cache, a filesystem, a package fetch or a model context compose without ever calling
  `delegate`, so nothing here sees them. **Task 3.6 (improvised-channel detection and the shared-surface
  census, L5-02 + L2-01) is partial cover and is explicitly not closure:** it detects a surface being
  used as a channel after the fact and refuses nothing, and it has not landed. The evidence file must
  say "partial cover, detection only, task unstarted" in those terms.

  **Blind spot C, carried forward not created here — the notary's third fold.** Restate Task 1.5's
  recorded divergence (`docs/task-evidence/task-1.5.md:207–215`) with its example
  `[["a","b"], ["a","c"]]` → notary `["a"]`, evidence `[]`, and record that this task deliberately adds
  no corpus test for it, because the only ways to express a known-failing case are a failing build or a
  thirteenth `#[ignore]` that raises `ignored_ceiling` and fails the build. Owner: whoever next revises
  the notary's chain gate.

  Also rewrite I-02's stale `gap` in `evidence/invariants.json` — the current text describes
  `rust/delegation-chain` as *"a crate that is not tracked on origin/main"*, which local `main`
  falsified:

```json
      "gap": "The chain fold lives once, in rust/delegation-chain::intersect_chain, consumed by warrantor_evidence::narrow_chain. Two things it does not cover. (1) The notary holds a third, unfolded copy at rust/notary/src/lib.rs:293 and the two genuinely differ on a widening chain -- see docs/W1-delivery-gaps.md 3.7. (2) The fold runs down one path, so sibling composition under a shared ancestor is outside its domain; Task 9.4 refuses the budget half at issuance (Tier B) and reports the complementary-capability half (Tier C). Separate roots and side channels remain uncovered."
```

  `status` stays `"enforced"`: I-02's statement is about the delegation chain, and it is enforced down a
  chain. Downgrading the word because a *different* axis is uncovered would make the ledger's own
  vocabulary unreliable, which is a worse defect than a `gap` field that has to be read. The gap field
  is where an uncovered axis belongs, and it now names it. **Test intent:**
  `python tools/ci/check_invariants.py` must still print
  `12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1`.

- [ ] **Step 12 — Raise the floor from the captured line, run every gate, commit.** Run the corpus and
  **read** the count out of the output rather than computing it:

```
  cd M:/wt-9.4-sibling/rust && cargo test -p warrantor-warrant --test invariants 2>&1 | grep "test result:"
  # -> test result: ok. <N> passed; 0 failed; 18 ignored; 0 measured; 0 filtered out
```

  Set `tools/ci/invariant-ratchet.json` `passing_floor` to that `<N>` — expected `70` for the four
  Step-10 tests over the captured baseline of 66, but the file takes the number the run printed, not
  the number this plan predicted. `ignored_ceiling` stays **18**: this task adds no `#[ignore]`, and a
  thirteenth would fail the build. Update the `note` to say the floor rose because Task 9.4 added four
  sibling-axis tests, **not** because a finding closed. Then, in the same commit:

```
  cd M:/wt-9.4-sibling/rust && cargo fmt --all -- --check && \
    cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
  cd M:/wt-9.4-sibling && python tools/ci/check_invariant_ratchet.py    # THE EXIT GATE
  python tools/ci/check_invariants.py
  python tools/ci/wiring_census.py          # must still print: 10 of 40 crates reachable
  python tools/ci/check_us_english.py --files docs/task-evidence/task-9.4.md docs/W1-delivery-gaps.md
  node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/task-evidence/task-9.4.md
  git add -A && git commit -s -m "feat(delegation-chain): refuse a grant two siblings compose past their ancestor"
```

  The Rust gate runs for the one language this task touches plus Python for the CI tools, per the repo
  convention. **Test intent:** the exit-gate command decides the task, the ratchet number is read rather
  than asserted, and the US-English gate runs on every prose file the task writes — including this one's
  evidence file, where `analyses` and the verb `forwards` are correct as written and must not be
  "corrected."

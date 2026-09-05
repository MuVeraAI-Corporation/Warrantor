### Task 9.3: Purpose binding on authority (L6-07)

**Anchor.** The master blueprint's catalog entry is
`<article class="item" id="L6-07" data-stratum="L6" data-plane="B" data-status="none" data-novelty="core" data-wave="W3" data-loop="L4">`
— **`status=none`**, `core`, W3, Plane B. Its `what` clause is the specification, quoted verbatim
from `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html:4202`: *"Data tagged with a
purpose may only be used for that purpose; a warrant carries the purposes it serves; violation fails
closed at the effect boundary."* Its `why` clause names this task's twin: *"It is the authority-side
twin of the egress-side binding in L4-24."*

This is the authority half of **invariant I-03**, and I-03 is the single invariant in the ledger
whose status word is the weakest one the checker allows. Quoted verbatim from
`evidence/invariants.json`:

```json
{
  "id": "I-03",
  "statement": "Purpose-bound data use. Data tagged with a purpose in CPE (P3) is only used for that purpose; violation fails-closed.",
  "status": "unimplemented",
  "enforced_by": [],
  "gap": "Zero references to I-03 in rust/**/*.rs; no CPE implementation exists in any language. Not on the Wave 1 spine; the blueprint's Part 06 READ row records the open decision (tenth syscall or CRED sub-class)."
}
```

The status census across the twelve is `enforced=2, orphaned=2, partial=7, unimplemented=1` — I-03
is that one. `tools/ci/check_invariants.py:135` makes the word load-bearing: *"unimplemented must
list no enforcement"*. The moment this task cites one enforcement site, the word must change and the
checker will refuse a ledger that did not change it.

**Two premise corrections. The code wins; the seed is wrong on both.**

**Correction 1 — a purpose field already exists, and it is already signed.** The seed says *"The
purpose field is defined once, by whichever of 7.7 and 9.3 lands first"*, and Task 7.7 says the same
thing in the other direction. That deadlock is already resolved by the wire contract, which predates
both tasks. `proto/warrantor/identity/v1/agent.proto:29-30` and `:35-36`:

```proto
  // The human-readable purpose of this delegation (e.g. "open a pull request").
  string purpose = 3;
  ...
  // Data classification levels the agent may read (L0..L4 per cross-cutting 17).
  repeated string data_classes = 6;
```

Both fields are inside the signature. `rust/authority-spec/src/lib.rs:190-206`
(`canonical_unsigned_bytes`) folds `"purpose": envelope.purpose` and `"data_classes":
envelope.data_classes` into the canonical CBOR the issuer signs, and the crate's own test at
`rust/authority-spec/src/lib.rs:393-406` proves it binds:

```rust
    #[test]
    fn caller_supplied_bytes_are_ignored_c6() {
        let (mut envelope, sk) = make_signed_envelope("read", vec![], 0);
        let vk = sk.verifying_key();
        // The signature still verifies over the ORIGINAL fields; mutate a field.
        envelope.purpose = "exfiltrate secrets".into();
        let opts = ValidateOptions::coding_agent(&vk);
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::SignatureInvalid)
        ));
    }
```

So the honest statement of the gap is **not** "there is no purpose field". It is: *the purpose is
signed and nothing reads it.* `validate` (`rust/authority-spec/src/lib.rs:223-278`) has exactly five
numbered checks — signature, expiry, side-effect class, consequential approval, delegation depth —
and none of them mentions purpose. The crate's own doc comment enumerates the same five at lines
12-19. A signed string nothing compares is a comment with a signature over it. **`premise_contradicted
= true`**, and the ownership question the seed's Step 3 asks is answered before the task starts:
neither 7.7 nor 9.3 defines the field, both bind to `AgentAuthorityEnvelope.purpose` /
`.data_classes` as already committed, and this task adds the second and third places that field
travels — the warrant's own bounds and the receipt's authority block.

**Correction 2 — the seed's `#[ignore] removal only` for the corpus file is impossible.** Run today,
`hop_02_a_shared_cache_read_for_another_purpose_is_refused` fails on its **control**, not its
attack, so removing the attribute earns nothing. Captured in Step 0. The fixture is wrong, and
`harness.rs:15-16` states the only permitted remedy: *"The remedy for a failing control is always to
fix the attack. It is never to weaken the assertion."*

**Correction 3 — the receipt has five sections, not eight.** `i03`'s doc comment at line 207 says
*"The WAR predicate has eight sections"*; the Rust type has five plus an optional `outcome`. Step 0
captures the real list. This matters because it decides where purpose lands: adding a sixth
top-level section changes the signed body, and Task 10.1 owns that. Purpose goes **inside** the
existing `authority` section.

**Correction 4 — the CLI already calls the goal a purpose, with no mechanism behind it.**
`rust/warrant/src/bin/warrantor.rs:740`: `return fail("--goal is required: a warrant without a
stated purpose cannot be reviewed");` and `rust/warrant/src/lib.rs:374-375` documents `goal` as
*"Human-readable intent. Recorded in every receipt; not enforced."* That is the closest thing to a
purpose on a warrant today, and it is free text nothing intersects. This task must not leave two
words for one idea: `goal` stays the human sentence, `purposes` becomes the machine set, and the
error message stops borrowing the stronger word.

---

**Step 0 — the reads, the commands and the real output.**

Set up a read-only scratch worktree first (this is not the task's branch; Step 1 makes that):

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git worktree add --detach M:/wt-x-93 refs/remotes/origin/main   # HEAD is now at e4b5f10
cd M:/wt-x-93 && export CARGO_TARGET_DIR=M:/wt-x-93-target
```

Read these four in full, at these lengths:

```
$ wc -l rust/warrant/tests/invariants/i03_purpose_bound_data_use.rs \
        rust/authority-spec/src/lib.rs rust/warrant/src/lib.rs rust/evidence/src/lib.rs
   239 rust/warrant/tests/invariants/i03_purpose_bound_data_use.rs
   510 rust/authority-spec/src/lib.rs
   724 rust/warrant/src/lib.rs
   969 rust/evidence/src/lib.rs
  2442 total
```

Also read in full: `rust/warrant/tests/invariants/harness.rs` (128 lines — it defines the two
assertion shapes this task uses), `rust/warrant/tests/invariants/scenario.rs` (184 lines — the
fixtures), `tools/ci/check_invariant_ratchet.py` (the gate) and `tools/ci/check_invariants.py:115-155`
(`check_entry`, which decides whether a ledger status is legal).

**The purpose grep, with the real answer — which is not zero.**

```
$ git grep -c "\bpurpose\b" -- 'rust/**' | sort -t: -k2 -rn | head -6
rust/warrant/tests/invariants/i03_purpose_bound_data_use.rs:19
rust/warrant/src/bin/warrantor.rs:8
rust/warrant/src/serve.rs:5
rust/warrant/src/harness.rs:5
rust/authority-spec/src/lib.rs:4
rust/warrant/src/retention.rs:3

$ git grep -n "purpose\|data_classes" -- proto/warrantor/identity/v1/agent.proto
proto/warrantor/identity/v1/agent.proto:29:  // The human-readable purpose of this delegation (e.g. "open a pull request").
proto/warrantor/identity/v1/agent.proto:30:  string purpose = 3;
proto/warrantor/identity/v1/agent.proto:36:  repeated string data_classes = 6;
```

96 occurrences of the word across `rust/`. **Zero of them are a field on `WarrantBounds` or on the
WAR predicate; four of them are the AAE field being signed and never read.** Both halves of that
sentence are the finding.

**The four `#[ignore]` reasons, verbatim** from `rust/warrant/tests/invariants/i03_purpose_bound_data_use.rs`:

```rust
// :79
#[ignore = "I-03 unimplemented: no purpose field on the authorization request; no plan task fixes it (2026-09-02)"]
// :104
#[ignore = "I-03 unimplemented: bounds carry no purpose, so hop 2 is invisible to the boundary (2026-09-02)"]
// :184
#[ignore = "I-03 unimplemented: receipts carry no provenance label for what drove the action (Task 2.6, 2026-09-02)"]
// :213
#[ignore = "I-03 unimplemented: the WAR predicate has no purpose field (2026-09-02)"]
```

**Run them. This is the output that decides the design.**

```
$ cargo test -p warrantor-warrant --test invariants -j 2 -- --ignored i03
running 4 tests
test i03_purpose_bound_data_use::hop_02_a_shared_cache_read_for_another_purpose_is_refused ... FAILED
test i03_purpose_bound_data_use::hop_10_the_receipt_labels_the_provenance_of_what_drove_the_action ... FAILED
test i03_purpose_bound_data_use::the_authorization_request_carries_a_purpose ... FAILED
test i03_purpose_bound_data_use::the_receipt_carries_the_purpose_the_data_was_tagged_with ... FAILED

---- hop_02_a_shared_cache_read_for_another_purpose_is_refused stdout ----
panicked at warrant\tests\invariants\i03_purpose_bound_data_use.rs:110:5:
control: a narrower grant must be contained by a wider one

---- hop_10_the_receipt_labels_the_provenance_of_what_drove_the_action stdout ----
panicked at warrant\tests\invariants\i03_purpose_bound_data_use.rs:196:5:
the receipt's operation block records what was done but not where the instruction came from, so an
injected instruction and an operator's instruction are indistinguishable in the evidence.
Keys present: ["class", "consequence_tier", "method", "parameters_digest", "reversible", "target"]

---- the_authorization_request_carries_a_purpose stdout ----
panicked at warrant\tests\invariants\i03_purpose_bound_data_use.rs:87:5:
the operation the notary adjudicates names no purpose and no data class, so I-03 has nothing to
bind against. Keys present: ["capabilities_requested", "class", "consequence_tier", "scope"]

---- the_receipt_carries_the_purpose_the_data_was_tagged_with stdout ----
panicked at warrant\tests\invariants\i03_purpose_bound_data_use.rs:218:5:
the WAR predicate's sections are ["actor", "authority", "binding", "decision", "operation"]; none of
them records the purpose that I-03 binds data use to, so a purpose-bound decision could not be
proved after the fact

test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 80 filtered out; finished in 0.02s
```

`hop_02` panics at **line 110**, which is `assert!(wide.contains(&narrow).is_ok(), "control: ...")`.
The cause is in `rust/warrant/src/lib.rs:343-348`: `if other.delegation_depth >= self.delegation_depth`
refuses, and the file's local `bounds()` helper (lines 25-35) sets `delegation_depth: 0` on both
sides, so `0 >= 0` refuses the control. The attack assertion at line 120 is never reached.

**Baseline, for the ratchet arithmetic:**

```
$ cargo test -p warrantor-warrant --test invariants -j 2 | tail -2
test result: ok. 65 passed; 0 failed; 19 ignored; 0 measured; 0 filtered out; finished in 0.23s

$ cat tools/ci/invariant-ratchet.json | grep -E "passing_floor|ignored_ceiling"
  "passing_floor": 65,
  "ignored_ceiling": 19,
```

65 + 19 = 84 tests. `tools/ci/check_invariant_ratchet.py:159` refuses an improvement that did not
raise the baseline: `if result.passed > baseline.passing_floor or result.ignored < baseline.ignored_ceiling`.
So earning one test means `passing_floor: 66` and `ignored_ceiling: 18` **in the same commit**.

**Crate census, so nothing here assumes an absent crate is buildable:**

```
$ git ls-tree --name-only refs/remotes/origin/main rust/ | wc -l
48                       # 39 crate directories + Cargo.lock, Cargo.toml, README.md, 6 Dockerfiles
$ git ls-tree -r --name-only refs/remotes/origin/main -- rust/delegation-chain | wc -l
0                        # ABSENT. Task 1.5 carries it in; see Step 2.
$ python - <<'PY'
import json; d=json.load(open('evidence/wiring-coverage.json'))
print(d['total'], d['reachable'], d['edges'])
PY
39 9 17
$ grep -n "path *=" rust/warrant/Cargo.toml
26:warrantor-trust-core = ...   27:warrantor-authority-spec = ...   32:warrantor-evidence = ...
33:warrantor-notary = ...       37:warrantor-egress = ...           50:warrantor-containment-conformance = ...
56:warrantor-spend = ...
```

Every crate this task edits — `warrant`, `authority-spec`, `evidence` — is already on the reachable
list. **The orphan count cannot rise from this task**, and Step 11 asserts that it did not.

**Consumes: does purpose bind to Task 1.5's authority block, or to the warrant?** Both, and in that
order. Task 1.5's section (plan lines 6951-7006) is fully expanded and produces
`evidence::bind_authority(store, warrant_id) -> Result<Authority, EvidenceError>` and
`evidence::narrow_chain(chain) -> Result<Vec<String>, EvidenceError>`, delegating the algebra to
`warrantor_delegation_chain::intersect_chain` over
`WarrantScope { capabilities, resource_classes, expires_at_ms, budget_micros }` — **which has no
purpose dimension.** So purpose binds to the *warrant* first (it is a bound the issuer states and
`WarrantBounds::contains` intersects) and reaches the *authority block* second, as a new dimension
of `WarrantScope` and `DelegationLink` that 1.5's fold carries. Stating it the other way round
would put purpose in the receipt with nothing in the warrant to put it there.

**A purpose string nothing checks is a comment. The refusal sites, named:**

| # | Site | File:line today | What it refuses |
|---|---|---|---|
| 1 | `WarrantBounds::contains` | `rust/warrant/src/lib.rs:283` | a child bounds set whose `purposes` are not a subset of the parent's |
| 2 | `Warrant::delegate` | `rust/warrant/src/lib.rs:514` — `self.claims.bounds.bounds.contains(&bounds)?` before `sign_claims` | the **issuance** of the widening sub-warrant; it is never signed, so it never exists |
| 3 | `evidence::verify_authority` | `rust/evidence/src/lib.rs:552` | a receipt whose `effective_purposes` is not the recomputed intersection of its chain |
| 4 | `warrantor delegate` (new, Step 6) | — | the same refusal, from a command a user can actually run |

Site 2 is the one that matters and it is currently **unreachable**: `git grep -n delegate
rust/warrant/src/bin/warrantor.rs rust/warrant/src/mcp*.rs rust/warrant/src/serve.rs` prints
nothing. `Warrant::delegate` is library-only, exercised by tests and by no user path. Adding the
purpose dimension without Step 6 would produce a seventh subset check nobody can reach, which is the
exact defect "wire before widen" exists to prevent.

---

**Non-goals.** Each names the task that owns the excluded thing.

1. **Not bounded revocation, and not the revocation of a purpose grant** — **Task 9.1** owns I-05,
   `rust/credential-vault/`, and the propagation SLA. A purpose narrowed after issue is a revocation
   problem, not an intersection problem; this task refuses widening at issue and says nothing about
   withdrawing a purpose already granted.
2. **Not authority expansion across siblings** — **Task 9.4** owns I-02, L6-09 and L6-12. Two
   siblings whose declared purposes compose into one their common ancestor lacks are invisible to a
   chain intersection, and saying so is 9.4's job. This task's algebra is strictly over one chain.
3. **Not egress purpose or data-class binding at the network tier** — **Task 7.7** owns L4-24 and
   L4-19, `rust/egress/src/lib.rs`, and the destination catalog. It also owns
   `notary::VerdictRequest.operation`, which is why `the_authorization_request_carries_a_purpose`
   (`i03:79`) stays ignored here: converting it means adding a field to the notary's request type,
   and its keys today are `["capabilities_requested", "class", "consequence_tier", "scope"]`.
4. **Not provenance labels on tool outputs** — **Task 2.6** owns them, and `i03:184` names it in the
   attribute itself: `(Task 2.6, 2026-09-02)`. `hop_10` stays ignored.
5. **Not a new top-level section on the WAR predicate** — **Task 10.1** owns the signed body
   (Task 7.7's Files block already flags the collision: *"coordinate with Task 10.1, which also
   changes the signed body"*). `the_receipt_carries_the_purpose_the_data_was_tagged_with` (`i03:213`)
   asserts on top-level keys and therefore stays ignored: this task puts purpose **inside**
   `authority`, not beside it.
6. **Not a tenth notary gate** — the corpus guards it directly at `i03:228-239`,
   `the_notary_has_no_purpose_gate_and_does_not_pretend_to`, which asserts
   `notary::Gate::in_order().len() == 9` with the comment *"a tenth must arrive with a suite"*. That
   suite belongs to 7.7. `rust/notary/src/lib.rs` is not in this task's Files.
7. **Not the delegation algebra itself** — **Task 1.5** owns `rust/delegation-chain`, `intersect_chain`,
   `narrow_chain`, `bind_authority` and the `is_valid` fix. This task adds one dimension to types
   1.5 created and does not restructure the fold.
8. **Not cross-organization purpose semantics** — **Task 9.5** owns L6-08/L6-10. Two organizations
   that both use the string `"support-triage"` to mean different things is a naming problem in 9.5,
   not an intersection problem here.
9. **Not data classification as discovery** — the class is declared. Nothing in this task infers a
   data class from content.

---

**Files.**

- `rust/warrant/src/lib.rs` — `WarrantBounds` (add `purposes`, after line 254), `WarrantBounds::contains`
  (one `subset` call, at line 298), `WarrantBounds::validate` (line 352), and the `Default` impl the
  sweep needs. **Not** `bound_strengths()` (line 668) — see Bound strength, and Step 9 asserts the
  absence.
- `rust/warrant/src/bin/warrantor.rs` — `cmd_grant` (`--purpose`), the new `cmd_delegate`, the usage
  block at lines 476-477, and the `--goal` error text at line 740.
- `rust/warrant/examples/emit_bounds_vectors.rs` — 16 `WarrantBounds` literals plus the new vector.
- `rust/authority-spec/src/lib.rs` — a sixth check in `validate`, and `AaeError::PurposeNotHeld`.
- `rust/evidence/src/lib.rs` — `DelegationLink` (line 93), `Authority` (line 115), `narrow_chain` and
  `verify_authority` (line 552), `EvidenceError`.
- `rust/delegation-chain/src/lib.rs` — `WarrantScope.purposes`, `Escalation::Purpose`,
  `intersection`. **Carried in by Task 1.5, not by this task** (Step 2).
- `rust/warrant/tests/invariants/i03_purpose_bound_data_use.rs` — the `bounds()` helper (lines
  25-35), the `hop_02` fixture repair (lines 108-126), one `#[ignore]` removal (line 104).
- `rust/warrant/tests/tier_disclosure.rs` — the absence assertion (Step 9).
- `rust/warrant/tests/delegate_cli.rs` — new.
- `rust/evidence/tests/purpose_intersection.rs` — new.
- `python/warrantor_ml/src/warrantor_ml/tasks/bounds.py` and
  `python/warrantor_ml/tests/test_bounds_interop.py` — the cross-language mirror (Step 10).
- `evidence/invariants.json` — I-03's status, `enforced_by`, `gap`.
- `docs/W1-delivery-gaps.md` — line 1105 (the I-03 row) and its `invariant-corpus:I-03` marker.
- `tools/ci/invariant-ratchet.json` — `passing_floor` 65→66, `ignored_ceiling` 19→18.
- `README.md`, `rust/warrant/README.md` — only if `bound_strengths()` changes, which it must not.
- `docs/task-evidence/task-9.3.md` — new.

**Consumes / Produces.**

Consumes (quoted, with file and line, from `refs/remotes/origin/main` at `e4b5f10`):

- `rust/warrant/src/lib.rs:283` — `pub fn contains(&self, other: &Self) -> Result<(), WarrantError>`
- `rust/warrant/src/lib.rs:284-295` — the private `fn subset(child: &BTreeSet<String>, parent: &BTreeSet<String>, field: &str) -> Result<(), WarrantError>` returning
  `WarrantError::AuthorityExpanded(format!("{field}: child claims {extra:?}, which the parent does not hold"))`
- `rust/warrant/src/lib.rs:498-506` — `pub fn delegate(&self, id: impl Into<String>, goal: impl Into<String>, subject: impl Into<String>, bounds: WarrantBounds, issued_at: u64, issuer: &SigningKey) -> Result<Self, WarrantError>`
- `rust/warrant/src/lib.rs:369-387` — `pub struct WarrantClaims { format, id, goal, subject, bounds, issued_at, settle_authority, parent }`
- `rust/warrant/src/lib.rs:668` — `pub fn bound_strengths() -> Vec<(&'static str, BoundStrength)>` (seven rows today)
- `rust/authority-spec/src/lib.rs:223` — `pub fn validate(envelope: &warrantor_api::identity::v1::AgentAuthorityEnvelope, options: &ValidateOptions<'_>) -> Result<(), AaeError>`
- `rust/authority-spec/src/lib.rs:95-107` — `pub struct ValidateOptions<'a> { issuer_verifying_key, now, allowed_side_effect_classes, max_delegation_depth }`
- `rust/evidence/src/lib.rs:93` — `pub struct DelegationLink { pub issuer: String, pub subject: String, pub capabilities: Vec<String>, pub not_before: u64, pub not_after: u64, pub token_digest: String }`
- `rust/evidence/src/lib.rs:115` — `pub struct Authority { pub chain: Vec<DelegationLink>, pub effective_capabilities: Vec<String>, pub intersection_proof: IntersectionProof }`
- `rust/evidence/src/lib.rs:285` — `pub fn recompute_intersection(chain: &[DelegationLink]) -> Vec<String>`
- `rust/evidence/src/lib.rs:552` — `pub fn verify_authority(authority: &Authority) -> Result<(), EvidenceError>`
- `rust/warrant/tests/invariants/harness.rs:50` — `pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)`
- `rust/warrant/tests/invariants/harness.rs:76` — `pub fn reached_the_boundary_unrefused<T, F>(what: &str, control: &T, attacked: &T, allowed: F)`

Consumes, **does not exist yet** — created by **Task 1.5**, which has **not landed**
(`git ls-tree -r refs/remotes/origin/main -- rust/delegation-chain` prints nothing at `e4b5f10`):

- `rust/delegation-chain/src/lib.rs:42` — `pub struct WarrantScope { pub capabilities: Vec<String>, pub resource_classes: Vec<String>, pub expires_at_ms: u64, pub budget_micros: u64 }`
- `rust/delegation-chain/src/lib.rs:56` — `pub enum Escalation { Capability(String), Resource(String), Time, Budget }`
- `rust/delegation-chain/src/lib.rs:107` — `pub fn intersection(parent: &WarrantScope, requested: &WarrantScope) -> Result<WarrantScope, Escalation>`
- Task 1.5 Produces — `pub fn intersect_chain(chain: &[WarrantScope]) -> Result<WarrantScope, ChainEscalation>`,
  `evidence::narrow_chain(chain: &[DelegationLink]) -> Result<Vec<String>, EvidenceError>`,
  `evidence::bind_authority(store, warrant_id) -> Result<Authority, EvidenceError>`

Produces:

- `rust/warrant/src/lib.rs` — `WarrantBounds.purposes: BTreeSet<String>` and `impl Default for WarrantBounds`
- `rust/warrant/src/lib.rs` — `WarrantError::AuthorityExpanded` gains the `purposes:` field name (no new variant)
- `rust/authority-spec/src/lib.rs` — `AaeError::PurposeNotHeld { requested: String }` and
  `ValidateOptions.held_purposes: &'a [String]`
- `rust/evidence/src/lib.rs` — `DelegationLink.purposes: Vec<String>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`),
  `Authority.effective_purposes: Vec<String>` (same attributes),
  `pub fn recompute_purposes(chain: &[DelegationLink]) -> Vec<String>`
- `rust/delegation-chain/src/lib.rs` — `WarrantScope.purposes: Vec<String>` and `Escalation::Purpose(String)`
- `rust/warrant/src/bin/warrantor.rs` — `warrantor grant --purpose P,P` and `warrantor delegate <parent-id> --id <id> --goal G --tools T,T [--purpose P,P] ...`

**Bound strength.**

Two bounds ship here and they are **not the same tier**. Collapsing them would be the worst defect
this repository can ship, so they are named separately and rendered separately.

- **The delegation bound is Tier A, cryptographic.** A sub-warrant whose `purposes` are not a subset
  of its parent's is refused at `rust/warrant/src/lib.rs:514`, *before* `sign_claims` — so the
  widening child is never signed and does not exist. The mechanism is the same Ed25519 signature over
  `WarrantClaims` that makes `delegation_depth` Enforced, and the refusal happens at the moment the
  widening is attempted (issuance), not at settle. `verify_authority` recomputes the same
  intersection offline from the receipt's chain, so a forged `effective_purposes` is refused by a
  verifier that never touched this machine.
- **There is no Tier A or Tier B bound on *using* data for a purpose, and this task does not create
  one.** `WarrantBounds.purposes` is checked when authority is *delegated*. Nothing checks it when
  an effect is *performed*. That check is Task 7.7's, at the egress broker, and it will be **Tier B,
  chokepoint** — held only for calls that traverse the MCP proxy, which is why `purposes` is
  deliberately absent from `bound_strengths()` (Step 9 asserts the absence with the reason in the
  test name). There is no netns, no seccomp and no firewall in this repository; an agent with shell
  access reaches the network without passing any purpose check, and containment composes with an
  external sandbox.

The sentence that appears in the product, next to the guarantee and not in a footnote:

> **Declared purpose is intersected across the delegation chain.** A sub-warrant cannot be signed
> for a purpose its parent does not hold, and any verifier recomputes that intersection from the
> receipt offline. This does not verify that a declared purpose is the real one, and no mechanism
> can: an agent that declares a narrow purpose and pursues a wider one is not detected here. It also
> does not refuse an individual effect on purpose grounds — that boundary is the egress broker's and
> holds only for calls that traverse it.

Never write "purpose is enforced". Write "declared purpose is intersected across the chain".

**Orphan count.** `warrant`, `authority-spec` and `evidence` are all already reachable
(`evidence/wiring-coverage.json`: `reachable: 9`, `edges: 17`). `rust/delegation-chain` becomes
reachable through Task 1.5's edge, not this task's. This task adds **no** crate and **no** orphan;
the census number it moves is the one that goes up, and Step 11 asserts `reachable >= 9`.

**No new trust root.** Nothing here fetches a purpose vocabulary, resolves a purpose registry, or
validates a purpose string against a service. A purpose is an opaque string the issuer chose, pinned
into signed claims out of band, and compared only by set membership. That establishes that a child
holds no purpose its parent did not write down; it establishes **nothing** about whether the string
means the same thing to two issuers — that is Task 9.5's problem and this task must not imply
otherwise.

**Exit gate.** `python tools/ci/check_invariant_ratchet.py --show-findings` exits 0 while printing
`66 passed; 0 failed; 18 ignored` against a `tools/ci/invariant-ratchet.json` whose
`passing_floor` is 66 and `ignored_ceiling` is 18 — a pass is impossible if the counts and the
baseline were not changed together, and impossible if any assertion was weakened, because
`hop_02`'s refusal now runs through `harness::refused_at_the_boundary`, which fails on a refused
control.

---

- [ ] **Step 1 — Worktree, and confirm the base is what Step 0 measured**

```bash
git -C "M:/Project AumOS - Open Secure AI Alliance/aumos" fetch origin
git worktree add M:/wt-9.3 -b feat/purpose-bound-authority origin/main
export CARGO_TARGET_DIR=M:/wt-9.3-target
cd M:/wt-9.3/rust
cargo metadata --format-version 1 --locked > /dev/null   # must pass before anything is touched
```

Test intent: none yet. The one assertion is that `git rev-parse HEAD` prints the commit Step 0
measured against, so every line number quoted above still points at the code it described. If it
does not, re-run Step 0 before continuing — a line number from a different tree is a fabricated
citation.

- [ ] **Step 2 — Precondition: Task 1.5 has landed, and `rust/delegation-chain` is buildable**

`rust/delegation-chain` is **absent from `origin/main`**. Task 1.5 Step 1 carries it in (copy the two
untracked files, append `"delegation-chain",` to `rust/Cargo.toml` members, regenerate the lock with
`cargo metadata`, `cargo fmt --all`). This task must not repeat that sequence; it must verify it
happened:

```bash
# All three must hold, or stop.
git ls-tree -r --name-only origin/main -- rust/delegation-chain    # must print 2 paths
grep -c '"delegation-chain"' rust/Cargo.toml                       # must print 1
cargo metadata --format-version 1 --locked > /dev/null             # must exit 0
cargo test -p warrantor-delegation-chain -j 2 2>&1 | tail -1       # must print ok. 17 passed
grep -n "pub fn narrow_chain\|pub fn bind_authority" rust/evidence/src/lib.rs   # must print 2 lines
```

If any of those fails, **stop and record why in `docs/task-evidence/task-9.3.md`.** There is no
algebra to extend and no `narrow_chain` to hook into; a task that proceeds anyway invents a second
fold, which is precisely the duplication Task 1.5 exists to remove. The one documented alternative,
if 1.5 is merged but not yet on `origin/main`: rebase this branch onto
`feat/task-1.5-one-delegation-algebra` and say so in the evidence file, so a reviewer knows the
branch is not testable against `main` alone.

Test intent: this step's output *is* the assertion. Capture all five command outputs verbatim into
the evidence file.

- [ ] **Step 3 — Failing test: a warrant cannot delegate a purpose it does not hold**

New file `rust/warrant/tests/purpose_bounds.rs`. Written before the field exists, so it does not
compile — that is the failure this step wants, and the compiler error names the missing field:

```rust
//! Purpose is a dimension of authority, intersected down the chain, never unioned. L6-07, I-03.

use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use warrantor_warrant::{Warrant, WarrantBounds, WarrantError};

const NOW: u64 = 1_700_000_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

fn bounds(purposes: &[&str], depth: u32) -> WarrantBounds {
    WarrantBounds {
        tools: set(&["read_file"]),
        purposes: set(purposes),
        delegation_depth: depth,
        expires_at: NOW + 3_600,
        ..WarrantBounds::default()
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn a_child_may_narrow_the_purpose_set() {
    // THE CONTROL. It must be ALLOWED, or the refusal below proves nothing: it would only show
    // that delegation refuses everything, which is a one-sided test.
    let issuer = key();
    let parent = Warrant::grant(
        "wrt_parent",
        "review the changed files",
        "spiffe://muveraai.com/agent/parent",
        bounds(&["code-review", "support-triage"], 2),
        NOW,
        &issuer,
        &issuer.verifying_key(),
    )
    .expect("parent grants");
    let child = parent.delegate(
        "wrt_child",
        "review the changed files",
        "spiffe://muveraai.com/agent/child",
        bounds(&["code-review"], 1),
        NOW,
        &issuer,
    );
    assert!(
        child.is_ok(),
        "control: narrowing the purpose set must be allowed, got {child:?}"
    );
}

#[test]
fn a_child_may_not_widen_the_purpose_set() {
    let issuer = key();
    let parent = Warrant::grant(
        "wrt_parent",
        "review the changed files",
        "spiffe://muveraai.com/agent/parent",
        bounds(&["code-review"], 2),
        NOW,
        &issuer,
        &issuer.verifying_key(),
    )
    .expect("parent grants");
    let widened = parent.delegate(
        "wrt_child",
        "review the changed files",
        "spiffe://muveraai.com/agent/child",
        bounds(&["code-review", "marketing-analytics"], 1),
        NOW,
        &issuer,
    );
    match widened {
        Err(WarrantError::AuthorityExpanded(message)) => {
            assert!(
                message.contains("purposes") && message.contains("marketing-analytics"),
                "the refusal must name the dimension and the purpose it refused: {message}"
            );
        }
        other => panic!("a widened purpose set must be refused at issue, got {other:?}"),
    }
}
```

Run: `cargo test -p warrantor-warrant --test purpose_bounds -j 2`
Expected: `error[E0560]: struct \`WarrantBounds\` has no field named \`purposes\`` and
`error[E0599]: no function or associated item named \`default\` found`. Test intent: the pair is a
refusal and its control, in that order, and the control comes first in the file so nobody reads the
refusal alone.

- [ ] **Step 4 — Add the field and the subset check; sweep the 66 literals with the compiler**

In `rust/warrant/src/lib.rs`, after `egress_hosts` (line 254), add:

```rust
    /// Declared purposes this warrant serves. **Intersected down the chain, never unioned:** a
    /// sub-warrant may hold a subset and nothing more. Empty means the warrant serves no declared
    /// purpose, never "any purpose" — the same absent-means-none reading as every other bound here.
    ///
    /// This is a *delegation* bound, not an effect bound. Nothing refuses an action because of it;
    /// see `bound_strengths()`'s doc comment for why it is deliberately not in that list, and
    /// `tests/tier_disclosure.rs::purposes_is_not_in_the_tier_list_because_no_action_is_refused`
    /// for the assertion that keeps it out. Purpose checking at the moment of an effect is the
    /// egress broker's, and it is Mediated.
    pub purposes: BTreeSet<String>,
```

In `contains`, after line 298's `egress_hosts` call:

```rust
        subset(&other.purposes, &self.purposes, "purposes")?;
```

The `subset` helper at lines 284-295 already produces the message Step 3 asserts on:
`"purposes: child claims \"marketing-analytics\", which the parent does not hold"`. No new error
variant; `AuthorityExpanded` already carries the field name.

Add a `Default` impl so the 66 literals can use `..WarrantBounds::default()` rather than being
edited one field at a time. It must not be `#[derive(Default)]` on its own — `expires_at: 0` is
refused by `validate()` at line 358, and that refusal is correct:

```rust
impl Default for WarrantBounds {
    /// A warrant that permits nothing and expires immediately. Every field is the absent-means-none
    /// value, so `..Default::default()` can never silently widen a literal that forgot a field.
    /// `validate()` refuses `expires_at: 0`, so a default-constructed bounds cannot be granted.
    fn default() -> Self {
        Self {
            tools: BTreeSet::new(),
            write_paths: BTreeSet::new(),
            egress_hosts: BTreeSet::new(),
            purposes: BTreeSet::new(),
            staged_classes: BTreeSet::new(),
            expires_at: 0,
            budget_cents_observed: None,
            delegation_depth: 0,
        }
    }
}
```

Then let the compiler enumerate the work:

```bash
cargo build --workspace --all-targets -j 2 2>&1 | grep -c "missing field \`purposes\`"
# Expected: 66 -- matches `git grep -c "WarrantBounds {" -- 'rust/**' | awk -F: '{s+=$2} END {print s}'`
git grep -c "WarrantBounds {" -- 'rust/**' | awk -F: '{s+=$2} END {print s}'
# 66, across 36 files; the largest single site is
#   rust/warrant/examples/emit_bounds_vectors.rs (16)
```

Test intent: the two counts must agree. If the compiler reports fewer than 66, a literal is behind a
`#[cfg]` that this platform does not build — and `docs/memory` records that Windows-only paths went
untested for exactly that reason, so run the sweep on both `cargo build --workspace --all-targets`
and `cargo clippy --workspace --all-targets` before believing the number.

- [ ] **Step 5 — Repair `hop_02`'s control, convert it, and remove the one `#[ignore]` this task earns**

The seed says "`#[ignore]` removal only" for this file. Step 0 proved that impossible: the control
fails on `delegation_depth`. Fix the fixture, never the assertion. Replace the local `bounds()`
helper (lines 25-35) and the whole of `hop_02` (lines 103-127) with:

```rust
fn bounds(tools: &[&str], hosts: &[&str], purposes: &[&str], depth: u32) -> WarrantBounds {
    WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        egress_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        purposes: purposes.iter().map(|p| (*p).to_string()).collect(),
        expires_at: scenario::NOW + 3_600,
        delegation_depth: depth,
        ..WarrantBounds::default()
    }
}

/// Round zero, hop 2: shared-cache observation. Two warrants granting the same tools for entirely
/// different purposes used to be byte-identical, so the delegation test that decides whether one
/// may act under the other's authority could not see the difference.
///
/// EARNED 2026-09-05 by Task 9.3. The control had a second defect the ignore hid: both fixtures
/// carried `delegation_depth: 0`, and `contains` refuses a child that is not strictly below its
/// parent, so the control was refused and the attack was never reached. Both are fixed here; the
/// assertion was not weakened, it was strengthened onto `harness::refused_at_the_boundary`, which
/// fails loudly if the control is ever refused again.
#[test]
fn hop_02_a_shared_cache_read_for_another_purpose_is_refused() {
    let wide = bounds(&["read_file", "write_file"], &[], &["code-review"], 2);
    let narrow = bounds(&["read_file"], &[], &["code-review"], 1);

    let for_reviewing_my_own_work = bounds(&["read_file"], &[], &["code-review"], 2);
    let for_reading_another_tenants_cache =
        bounds(&["read_file"], &[], &["tenant-cache-audit"], 1);

    harness::refused_at_the_boundary(
        "hop 2: a grant issued for one purpose must not contain a grant issued for another",
        &wide.contains(&narrow),
        &for_reviewing_my_own_work.contains(&for_reading_another_tenants_cache),
        |outcome| outcome.is_ok(),
    );
}
```

Delete the `#[ignore]` at line 104. Leave the other three attributes exactly as they are — Non-goals
4, 5 and 3 own them, and their reasons still name the right task.

Run:

```bash
cargo test -p warrantor-warrant --test invariants -j 2 2>&1 | tail -2
# Expected: test result: ok. 66 passed; 0 failed; 18 ignored; 0 measured; 0 filtered out
```

Test intent: one recorded invariant violation converted, with a live control. `refused_at_the_boundary`
is the shape that makes the control non-optional: `harness.rs:55-60` fails with *"the CONTROL was
refused, so the attack never reached the boundary and its refusal proves nothing"*.

- [ ] **Step 6 — Wire the refusal to a command a user can run: `warrantor delegate`**

`Warrant::delegate` (`rust/warrant/src/lib.rs:498`) is reachable from no binary, no MCP tool and no
HTTP route today. Six subset checks have been unreachable since they were written; this step makes
all seven reachable, and it is the reason this task changes anything a buyer can see.

Add to `cmd_grant`: `--purpose P,P` parsed with the existing `csv()` helper, stored into
`bounds.purposes`. Add `cmd_delegate`, and add both to the usage block at lines 476-477:

```text
  grant   --goal G --tools T,T --write P,P [--deadline 8h] [--repo .] [--egress H,H]
          [--budget CENTS] [--subject <id>] [--purpose P,P]
  delegate <parent-warrant-id> --id <id> --goal G --tools T,T [--purpose P,P]
          [--write P,P] [--egress H,H] [--budget CENTS] [--subject <id>] [--deadline 8h]
```

Change the `--goal` error at line 740 to stop borrowing the stronger word:

```rust
        return fail(
            "--goal is required: a warrant with no stated intent cannot be reviewed. \
             --goal is the human sentence and is not enforced; --purpose is the machine set and \
             is intersected when this warrant delegates.",
        );
```

New test file `rust/warrant/tests/delegate_cli.rs`, run through the same in-process harness the other
CLI tests use:

```rust
/// The refusal a user can reach. Both directions, because a `delegate` that refuses everything
/// would pass a one-sided test and ship a broken verb.
#[test]
fn delegate_narrows_and_refuses_to_widen_the_purpose_set() {
    let home = tempdir().expect("tempdir");
    run(&home, &["grant", "--goal", "triage", "--tools", "read_file",
                 "--purpose", "code-review,support-triage", "--repo", "."])
        .expect_success();

    // CONTROL: a narrower purpose set delegates.
    let narrowed = run(&home, &["delegate", "wrt_1", "--id", "wrt_1a", "--goal", "triage",
                                "--tools", "read_file", "--purpose", "code-review"]);
    assert_eq!(narrowed.code, 0, "control refused: {}", narrowed.stderr);
    assert!(narrowed.stdout.contains("purposes  code-review"), "{}", narrowed.stdout);

    // ATTACK: a purpose the parent does not hold.
    let widened = run(&home, &["delegate", "wrt_1", "--id", "wrt_1b", "--goal", "triage",
                               "--tools", "read_file", "--purpose", "code-review,marketing-analytics"]);
    assert_ne!(widened.code, 0, "a widened purpose set must exit non-zero");
    assert!(
        widened.stderr.contains("purposes: child claims \"marketing-analytics\""),
        "the refusal must name the purpose: {}",
        widened.stderr
    );
    // And the child must not exist. A refusal that leaves a record is not a refusal.
    assert!(run(&home, &["list"]).stdout.find("wrt_1b").is_none());
}
```

Run: `cargo test -p warrantor-warrant --test delegate_cli -j 2` → `ok. 1 passed`, then
`python tools/ci/wiring_census.py` → `reachable` must not fall below 9.

Test intent: the bound is reachable, refuses at issue, names the dimension and the value, and leaves
no artifact behind. The last assertion is the one that distinguishes Tier A here from Tier C: the
widening sub-warrant was never signed, so there is nothing to clean up.

- [ ] **Step 7 — Failing test: the receipt records the *intersected* purpose set, not the requested one**

Extend the types Task 1.5 owns, in `rust/evidence/src/lib.rs`. Both additions carry
`#[serde(default, skip_serializing_if = ...)]` so a purpose-free receipt canonicalizes to
**byte-identical** bytes and Task 1.5's drift guard still holds — this is a verifier tightening, not
a format change, and `WAR_VERSION` stays `"war/2.0"`:

```rust
pub struct DelegationLink {
    // ... existing six fields unchanged ...
    /// Declared purposes this link confers. Intersected across the chain by `recompute_purposes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purposes: Vec<String>,
}

pub struct Authority {
    pub chain: Vec<DelegationLink>,
    pub effective_capabilities: Vec<String>,
    /// The INTERSECTION of every link's purposes, sorted. Never the requested set, never a union.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_purposes: Vec<String>,
    pub intersection_proof: IntersectionProof,
}
```

New file `rust/evidence/tests/purpose_intersection.rs`:

```rust
fn link(purposes: &[&str]) -> DelegationLink { /* capabilities fixed, purposes varied */ }

#[test]
fn the_receipt_carries_the_intersection_and_a_verifier_refuses_the_requested_set() {
    let chain = vec![link(&["code-review", "support-triage"]), link(&["code-review"])];

    // CONTROL: the honest authority verifies.
    let honest = Authority {
        effective_capabilities: recompute_intersection(&chain),
        effective_purposes: recompute_purposes(&chain),
        intersection_proof: compute_intersection_proof(&chain),
        chain: chain.clone(),
    };
    assert_eq!(honest.effective_purposes, vec!["code-review".to_string()]);
    verify_authority(&honest).expect("control: an honest authority block must verify");

    // ATTACK: claim the requested (wider) set. The union is what a forger writes.
    let mut forged = honest.clone();
    forged.effective_purposes = vec!["code-review".to_string(), "support-triage".to_string()];
    let refused = verify_authority(&forged);
    assert!(
        matches!(&refused, Err(EvidenceError::Authority(m))
                 if m.contains("effective_purposes") && m.contains("support-triage")),
        "a receipt claiming a purpose no link conferred must be refused offline: {refused:?}"
    );
}
```

`verify_authority` gains one comparison, placed beside the existing `effective_capabilities` one at
lines 553-559 so both refusals read alike:

```rust
    let recomputed_purposes = recompute_purposes(&authority.chain);
    if recomputed_purposes != authority.effective_purposes {
        return Err(EvidenceError::Authority(format!(
            "effective_purposes {:?} != recomputed intersection {:?} (purpose widening; I-03/L6-07)",
            authority.effective_purposes, recomputed_purposes
        )));
    }
```

Test intent: the exit-gate clause *"the receipt records the intersected purpose set, not the
requested one"*, proved by a verifier with no access to the issuing machine. Note the second-order
honesty: an older `warrantor verify` build deserializes the receipt, drops the unknown `purposes`
field, recomputes a different `links_digest`, and **refuses** — it does not silently accept. That is
fail-closed, and Step 11 records it as a deliberate property rather than a bug.

- [ ] **Step 8 — Failing test: an empty purpose intersection refuses the action entirely**

Empty must never read as unrestricted. This is the same absent-means-none doctrine
`rust/warrant/src/lib.rs:280-282` already states for every other bound, and it is where a purpose
system most often fails silently. Append to `rust/warrant/tests/purpose_bounds.rs`:

```rust
#[test]
fn a_disjoint_purpose_set_leaves_nothing_and_the_warrant_is_refused() {
    let issuer = key();
    // CONTROL: overlapping purposes leave a non-empty intersection and a usable child.
    let parent = grant(&issuer, bounds(&["code-review", "support-triage"], 2));
    let overlapping = parent.delegate(
        "wrt_ok", "triage", "spiffe://muveraai.com/agent/child",
        bounds(&["support-triage"], 1), NOW, &issuer,
    );
    assert!(overlapping.is_ok(), "control: {overlapping:?}");

    // ATTACK 1: a disjoint set is a widening, not an emptying. Refused by `contains`.
    let disjoint = parent.delegate(
        "wrt_no", "triage", "spiffe://muveraai.com/agent/child",
        bounds(&["marketing-analytics"], 1), NOW, &issuer,
    );
    assert!(matches!(disjoint, Err(WarrantError::AuthorityExpanded(_))), "{disjoint:?}");

    // ATTACK 2: a parent that declares NO purpose has none to hand on, and a child asking for one
    // is refused -- an empty parent set is a ceiling of nothing, exactly as an absent budget is a
    // ceiling of zero (`lib.rs:314-329`).
    let purposeless = grant(&issuer, bounds(&[], 2));
    let asking = purposeless.delegate(
        "wrt_no2", "triage", "spiffe://muveraai.com/agent/child",
        bounds(&["code-review"], 1), NOW, &issuer,
    );
    assert!(matches!(asking, Err(WarrantError::AuthorityExpanded(_))), "{asking:?}");
}

#[test]
fn a_warrant_declaring_no_purpose_is_not_a_warrant_for_every_purpose() {
    // The rendering half of the same rule: `warrantor status` must not print an empty purpose set
    // as a blank line that a reader completes as "unrestricted".
    let rendered = warrantor_warrant::report::render_purposes(&BTreeSet::new());
    assert_eq!(rendered, "purposes  (none declared -- this warrant serves no declared purpose)");
}
```

Test intent: three refusals and one control, plus the rendering rule. The second test exists because
the failure mode for purpose systems is a blank field read as a wildcard, and a blank field is a
rendered claim with no mechanism.

- [ ] **Step 9 — Assert `purposes` stays out of the tier list, with the reason in the test name**

`bound_strengths()` (`rust/warrant/src/lib.rs:668`) answers "which bounds does the system refuse an
action on". `purposes` is not one of them, and adding it as `Enforced` would repeat the `write_paths`
defect the crate's own doc comment describes at lines 648-666: a label promising the system refuses
the action, when nothing does. Adding it as `Mediated` would be worse — it would claim the MCP proxy
checks it, and the proxy does not.

So the absence is deliberate and must be locked. Append to `rust/warrant/tests/tier_disclosure.rs`:

```rust
/// `purposes` is a DELEGATION bound: `contains` refuses a widening sub-warrant at issue. It is not
/// an EFFECT bound -- no line of code refuses an action because of it. `bound_strengths()` is the
/// list of effect bounds, so `purposes` must not appear in it, and no rendering may imply it does.
///
/// The day the egress broker checks purpose (Task 7.7), a row arrives here as `Mediated` WITH the
/// test that observes the refusal. Until then this test is what stops the promotion.
#[test]
fn purposes_is_not_in_the_tier_list_because_no_action_is_refused() {
    let named: BTreeSet<&str> = bound_strengths().into_iter().map(|(name, _)| name).collect();
    assert!(
        !named.contains("purposes"),
        "`purposes` appeared in bound_strengths(). If an effect is now refused on purpose grounds, \
         add the row WITH the test that observes the refusal and the tier that matches where it \
         happens. If not, this is the write_paths mislabel again."
    );
    assert_eq!(named.len(), 7, "bound_strengths() grew or shrank: {named:?}");

    // And the honest disclosure has to be somewhere a reader will meet it.
    let table = render_bounds_table();
    assert!(!table.contains("purposes"), "{table}");
    for readme in ["README.md", "rust/warrant/README.md"] {
        let text = std::fs::read_to_string(harness_root().join(readme)).expect(readme);
        assert!(
            text.contains("Declared purpose is intersected across the delegation chain"),
            "{readme} does not carry the purpose disclosure sentence"
        );
    }
}
```

Test intent: this is the mislabel guard. It also pins the disclosure sentence into both READMEs, so
the product text and the code cannot drift — the same mechanism
`both_readmes_carry_the_bounds_table_generated_from_bound_strengths` (line 287) already uses for the
tier table.

- [ ] **Step 10 — Mirror the dimension in Python, or the cross-language check goes red**

`python/warrantor_ml/tests/test_bounds_interop.py` replays every vector from
`rust/warrant/examples/emit_bounds_vectors.rs` through the Python mirror and asserts the two agree:

```python
    assert python_contained == rust_contained, (
        f"{vector['name']}: Rust says contained={rust_contained}, Python says "
        f"{python_contained}. Rule under test: {vector['rule']}. "
    )
```

Add a `purpose_widened_is_an_expansion` vector on the Rust side and the mirror will disagree, because
`authority_expansions` does not know the dimension. So:

1. `python/warrantor_ml/src/warrantor_ml/tasks/bounds.py`: add `purposes: frozenset[str]` to
   `ReferenceBounds` (line 88) and `BoundProposal` (line 113); add `"purposes"` to
   `REQUIRED_PROPOSAL_FIELDS` (lines 66-74); add `("purposes", child.purposes, parent.purposes)` to
   the subset tuple at line 195 and to the over-grant tuple at line 281.
2. `python/warrantor_ml/tests/test_bounds_interop.py`: read `payload["purposes"]` in `_bounds`, and
   add `"purpose_widened_is_an_expansion"` to the required-vector list in
   `test_the_fixture_covers_every_rule_the_mirror_has_to_reproduce`.

```bash
cargo run -p warrantor-warrant --example emit_bounds_vectors -- \
  > python/warrantor_ml/tests/fixtures/bounds_vectors.json
python -m pytest python/warrantor_ml/tests/test_bounds_interop.py -q
ruff check python/warrantor_ml && ruff format --check python/warrantor_ml
```

Test intent: two implementations of one algebra, in two languages, forced to agree on the new
dimension by a fixture that names the rule. `REQUIRED_PROPOSAL_FIELDS` is the second half:
`ProposalIncomplete` means a model that omits `purposes` is refused rather than defaulted, and
defaulting a purpose set is how "empty means unrestricted" gets in through the side door.

- [ ] **Step 11 — Convert the ledger, raise the ratchet, close the gaps marker — all in one commit**

Four records move together, and the corpus enforces the coupling.
`i03_purpose_bound_data_use.rs:40-67`, `the_absence_of_an_implementation_is_recorded_in_the_ledger`,
counts `"I-03"` occurrences in `rust/**/*.rs` outside the corpus directory and then flips its
assertion:

```rust
    if references == 0 {
        assert!(ledger.contains("invariant-corpus:I-03"), ...);
    } else {
        assert!(!ledger.contains("invariant-corpus:I-03"),
            "I-03 now has {references} implementation references; close the ledger entry and \
             convert this suite's ignored tests to real assertions.");
    }
```

Step 7's `verify_authority` message contains `I-03/L6-07`, so `references` becomes non-zero and the
`invariant-corpus:I-03` marker in `docs/W1-delivery-gaps.md:1105` **must** be removed in the same
commit or this passing test starts failing. That is the rendered-versus-recorded gate, and it is
already built.

1. `docs/W1-delivery-gaps.md:1105` — status `unimplemented` → `partial`; the finding rewritten to
   name exactly what is bound (purpose is intersected across the delegation chain and recomputable
   from the receipt) and exactly what is not (no effect is refused on purpose grounds; the notary's
   request and the WAR predicate's top-level sections still carry none); `Fixed by` → `Task 9.3
   (authority half, landed); Task 7.7 (egress half); Task 2.6 (provenance); Task 10.1 (predicate
   section)`; the `invariant-corpus:I-03` marker deleted.
2. `evidence/invariants.json` — I-03 `"status": "partial"` with two `enforced_by` entries. The
   `statement` field must stay byte-identical to `docs/02-architecture.md` or
   `check_invariants.py:130` refuses it:

```json
  "status": "partial",
  "enforced_by": [
    {
      "crate": "warrant",
      "symbol": "warrantor_warrant::WarrantBounds::contains",
      "test": "rust/warrant/tests/purpose_bounds.rs::a_child_may_not_widen_the_purpose_set",
      "note": "refuses at issue, before sign_claims; the widening sub-warrant is never signed"
    },
    {
      "crate": "evidence",
      "symbol": "warrantor_evidence::recompute_purposes",
      "test": "rust/evidence/tests/purpose_intersection.rs::the_receipt_carries_the_intersection_and_a_verifier_refuses_the_requested_set",
      "note": "offline recomputation; error text 'purpose widening; I-03/L6-07'"
    }
  ],
  "gap": "No effect is refused on purpose grounds: purposes is a delegation bound, not an effect bound, and is deliberately absent from bound_strengths(). The notary's VerdictRequest.operation carries no purpose (Task 7.7) and the WAR predicate has no top-level purpose section (Task 10.1). An older warrantor verify build refuses a purpose-carrying receipt by digest mismatch rather than reading the field -- fail-closed, and recorded here so nobody reads it as a compatibility bug."
```

Both crates are in `check_invariants.py`'s `WARRANT_REACHABLE_CRATES`, so `partial` is legal; the
cited tests exist as `rust/<path>.rs::<name>`; and `symbol_exists` finds both identifiers.

3. `tools/ci/invariant-ratchet.json` — `"passing_floor": 66`, `"ignored_ceiling": 18`, and the
   `recorded` date bumped.

Then run every gate that reads these files:

```bash
python tools/ci/check_invariants.py
# Expected: invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=8, unimplemented=0
python -m pytest tools/ci/test_check_invariants.py -q -p no:cacheprovider
python tools/ci/check_invariant_ratchet.py --show-findings
# Expected: exit 0, and the printed run says: 66 passed; 0 failed; 18 ignored
python tools/ci/wiring_census.py
# Expected: no ::error::; reachable >= 9. This task adds no crate and no orphan.
python tools/ci/check_docs.py
```

Test intent: no number in prose is left ungated. The ratchet refuses both a regression and an
unclaimed improvement (`check_invariant_ratchet.py:159`); the ledger checker refuses a status word
that disagrees with where the evidence lives; the corpus's own static test refuses a gaps file that
still says I-03 is unimplemented. `unimplemented=0` is the sentence this task earns, and it is
printed by a script, not by a person.

- [ ] **Step 12 — Full gate, evidence file, `git commit -s`**

```bash
cd M:/wt-9.3/rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2
cargo build --workspace --all-targets -j 2
cargo metadata --locked > /dev/null
cd M:/wt-9.3
python -m pytest python/warrantor_ml/tests -q && ruff check python/warrantor_ml
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
  docs/task-evidence/task-9.3.md README.md rust/warrant/README.md
```

Run the Rust gate for every language touched — Rust and Python here — and never pipe it through
`head`. `cargo test --workspace` runs on ubuntu in CI only, so run it on this Windows box too: this
task edits 36 files' worth of struct literals and some of them sit behind `#[cfg(windows)]`.

Write `docs/task-evidence/task-9.3.md` carrying, verbatim and not paraphrased: the five Step 2
precondition outputs; the Step 0 `--ignored` run showing `hop_02` failing on line 110 (the premise
correction, so a reviewer can see why the fixture changed); the 66/66 literal-count agreement from
Step 4; the before and after corpus summary lines (`65 passed; 19 ignored` → `66 passed; 18 ignored`);
the `check_invariants.py` census line; and the four `#[ignore]` reasons with, for each, the task that
owns it and why this task did not earn it.

```bash
git add -A
git commit -s -m "feat(authority): intersect declared purpose across the delegation chain (L6-07, I-03)

A purpose was already on the wire and already signed -- agent.proto:30 has carried
\`string purpose = 3\` since Wave 1, and authority-spec folds it into the canonical
CBOR the issuer signs. Nothing read it. A signed string nothing compares is a
comment with a signature over it.

Purpose becomes a dimension of WarrantBounds, intersected by \`contains\` and
therefore refused at issue by \`delegate\` before sign_claims runs, so a
sub-warrant claiming a purpose its parent does not hold is never signed. The
receipt's authority block carries the intersection, and \`verify_authority\`
recomputes it offline, so a receipt claiming the requested set is refused by a
verifier that never touched this machine. \`warrantor delegate\` makes all seven
subset checks reachable from a command for the first time.

What this does NOT do, said here because the product text says it too: no effect
is refused on purpose grounds. \`purposes\` is deliberately absent from
bound_strengths(), and a test named for that reason keeps it out until the egress
broker earns a Mediated row (Task 7.7). Declared purpose is intersected across the
chain; it is not verified, and no mechanism can verify it.

Earns hop_02 in the I-03 corpus. The ignore hid a second defect: both fixtures
carried delegation_depth 0, so the control was refused and the attack was never
reached. Fixed the fixture, moved the assertion onto refused_at_the_boundary,
raised passing_floor 65 -> 66 and lowered ignored_ceiling 19 -> 18 in this commit.
I-03 moves from the ledger's only \`unimplemented\` to \`partial\`."
```

Test intent: the gate output decides, and the commit message states the bound and its limit in the
same breath. Do not merge until this branch is rebased on current `main` and the whole gate is
re-run there — PR CI tests the branch against old `main`, and batch-merging green branches broke
`main` five ways in this program once already.

# Task 10.1 — the causal verdict (STRICT_CAUSAL, L7-01)

A receipt records that an outcome was allowed. This task adds a verdict over the **pathway**: which
authority, which effects, in which order. "Right result, wrong route" is now a violation, refused by
hop index, handle and tool.

It is a format change to a **signed** structure, which is the most consequential kind of change in
this repository, so compatibility is not a side condition of the task — it is half of it. A frozen v1
fixture is pinned in two languages, and every receipt signed before this change still verifies byte
for byte through the canonical round trip.

- **Branch:** `feat/causal-verdict-strict`, from local `main` @ `5d3e44d`.
- **Worktree:** `M:/wt-w6-10.1`, `CARGO_TARGET_DIR=M:/wt-w6-10.1-target`.
- **Disk before the first cargo command:** `M: 1.2T 815G 379G 69% /m` (379 GB free, above the 40 GB floor).

---

## Step 0 — what was true before any code changed

Every number below was measured in this worktree at `5d3e44d`. **The plan's Step 0 figures are all
stale**, because the plan was written against `refs/remotes/origin/main` @ `e4b5f10` and local `main`
is 66+ commits ahead of it. Both sets are shown so the divergence is legible rather than silently
corrected.

```
$ git grep -c "STRICT_CAUSAL\|strict_causal" HEAD ; echo "EXIT=$?"
EXIT=1
```

Zero hits, exit 1 — confirming the plan's one central grep. Nothing in the repository named the
property before this task.

| Gate | Measured here @ `5d3e44d` | The plan's recorded value @ `e4b5f10` |
|---|---|---|
| `tools/ci/wiring_census.py` | `13 of 41 crates reachable from warrantor-warrant over 22 path edges` | `9 of 39 … over 17 path edges` |
| `tools/ci/check_invariants.py` | `12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1` | `enforced=2, orphaned=2, partial=7, unimplemented=1` |
| `tools/ci/check_invariant_ratchet.py` | `ok (82 passing at floor 82, 15 recorded findings at ceiling 15)` | `ok (65 passing at floor 65, 19 recorded findings at ceiling 19)` |
| `cargo test --workspace -j 2` | 150 suites, 1528 passing, 0 failed, 20 ignored (dispatch baseline) | not recorded |

```
$ cargo test -p warrantor-archive --test append_only --test verification_does_not_depend_on_the_archive
test result: ok. 7 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**Who else is in `report.rs`.** `git worktree list` shows 70 worktrees on this repository. One is
directly relevant and is recorded rather than worked around: **`M:/wt-w5-10.1` holds a wave-5 lane's
uncommitted attempt at this same task** — `docs/task-evidence/task-10.1.md`,
`rust/evidence/tests/causal_verdict.rs`, and modifications to `evidence/src/lib.rs`,
`notary/src/lib.rs`, `warrant/src/report.rs`, `warrant/src/settle.rs`, `warrant/src/staging.rs` and
the two Python packages, last written 2026-09-05 22:49 local. Its branch `feat/causal-verdict` sits at
`2ec0638`, an **ancestor of `main`**, with zero commits on it: none of that work is in git. That
worktree was not read for content and not touched. This lane branched
`feat/causal-verdict-strict` from `main` and implemented the task independently. The duplication is a
dispatch fact worth reporting, not a merge conflict: nothing of that lane's exists in any commit.

---

## Test first, and seen red

Two independent red states, both captured before the corresponding production change.

### Red 1 — the silent-drop hole on `notary::ReceiptBody`

`ReceiptBody` derived plain `Deserialize`. Serde drops unknown keys, so a body from a newer format
would deserialize, lose the field, re-canonicalize without it, and fail as
`NotaryError::InvalidSignature` — a version mismatch reported to a third-party auditor as a forgery.
Verbatim, before `#[serde(deny_unknown_fields)]` was added:

```
running 5 tests
test a_v1_body_still_hashes_to_the_digest_it_hashed_to_before_the_causal_verdict ... ok
test the_frozen_v1_bytes_still_parse ... ok
test a_body_carrying_an_unknown_field_is_refused_at_parse_rather_than_silently_stripped ... FAILED
test the_canonical_bytes_of_a_v1_body_are_the_frozen_bytes_character_for_character ... ok
test a_signature_over_anything_but_the_frozen_bytes_is_refused ... ok

failures:

---- a_body_carrying_an_unknown_field_is_refused_at_parse_rather_than_silently_stripped stdout ----

thread 'a_body_carrying_an_unknown_field_is_refused_at_parse_rather_than_silently_stripped' (95220) panicked at notary\tests\v1_receipt_fixture.rs:121:24:
an unknown field must be refused. Accepting it strips the field and then reports the resulting canonical mismatch as a bad signature, which tells an auditor 'forgery' when the truth is 'newer format'.: ReceiptBody { verdict: Allow { effective_capabilities: ["github.create_pr"] }, actor_svid: "spiffe://yourcorp/agents/bot-1", operation_class: "report", timestamp: 1786000000, enforcement_mode: Observed, notary_version: "warrantor-notary/1.0" }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    a_body_carrying_an_unknown_field_is_refused_at_parse_rather_than_silently_stripped

test result: FAILED. 4 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s

error: test failed, to rerun pass `-p warrantor-notary --test v1_receipt_fixture`
```

Note what the same run proves in passing: four assertions about the frozen v1 body were **already
green before any production change**, which is what a format-freeze fixture is supposed to look like.
They are the tests that must not move.

### Red 2 — four mutations, each one caught, each control still green

A test suite for a verdict function must be shown to fail when the verdict stops verdicting. A
compile error would not have shown that, so each check was removed in turn on an otherwise complete
tree.

| Mutation | Result |
|---|---|
| `causal_verdict` returns `Ok(())` unconditionally | `causal_verdict`: **10 passed, 9 failed.** Every refusal test red; every allowed control green |
| Version gate removed from `verify_receipt`; `deny_unknown_fields` removed from `ReceiptBody` | `v1_predicates_still_verify`: 8 passed, **1 failed** (`a_predicate_declaring_an_unknown_version_is_refused_as_a_version_and_not_as_a_forgery`). `v1_receipt_fixture`: 4 passed, **1 failed** |
| Queue-head comparison in `causal_verdict_pinned` short-circuited to `false` | `causal_verdict`: 18 passed, **1 failed** (`a_causality_section_whose_queue_head_does_not_match_the_observed_queue_is_refused`) — and only that one, so the head check is independently covered |
| `skip_serializing_if` dropped from `predicate_version`, so an unset field serializes as `null` | `v1_predicates_still_verify`: 7 passed, **2 failed** — `a_v1_predicate_round_trips_to_the_same_canonical_bytes` and `a_signature_taken_before_this_task_still_verifies`. This is the compatibility guarantee failing exactly when it should |

The nine tests the first mutation turned red, verbatim from that run:

```
test a_step_whose_recorded_index_is_not_its_position_is_a_violation ... FAILED
test the_refusal_fires_for_every_effect_class_and_the_grant_lets_each_through ... FAILED
test a_predicate_with_no_causality_section_is_unrepresentable_rather_than_clean ... FAILED
test a_hop_depending_on_a_handle_no_earlier_hop_minted_is_a_violation ... FAILED
test swapping_two_hops_so_a_dependent_precedes_its_dependency_is_a_violation ... FAILED
test a_declared_step_count_that_disagrees_with_the_steps_is_a_violation ... FAILED
test an_allowed_outcome_over_a_broken_route_is_refused ... FAILED
test a_correct_outcome_reached_through_an_ungranted_middle_hop_is_a_violation ... FAILED
test a_validly_re_signed_reordering_verifies_and_the_causal_verdict_still_refuses_it ... FAILED
test result: FAILED. 10 passed; 9 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
```

---

## The frozen v1 fixtures

Both were derived **before any production change**, and each was derived twice, in two languages,
so neither is "whatever this build currently emits".

**The notary receipt body** — `testvectors/notary/frozen_v1_receipt_body.json`, pinned by
`rust/notary/tests/v1_receipt_fixture.rs` and `python/warrantor_notary/tests/test_notary.py`:

```
CANONICAL_V1={"actor_svid":"spiffe://yourcorp/agents/bot-1","enforcement_mode":"observed","notary_version":"warrantor-notary/1.0","operation_class":"report","timestamp":1786000000,"verdict":{"effective_capabilities":["github.create_pr"],"outcome":"allow"}}
DIGEST_V1=6835a03a44df0556406780dd2fb1cc7b73ed58fde2f03da8073c74f3a22da466
CANONICAL_LENGTH=243 bytes
```

The digest was recomputed independently in Python from the field values under the canonicalization
rule and matched the plan's recorded `DIGEST_V1` character for character, which is a cross-language
confirmation of the plan's fixture rather than a copy of it.

**The evidence predicate** — 1,222 canonical bytes frozen as a literal in
`rust/evidence/tests/v1_predicates_still_verify.rs`, with a real Ed25519 public key and a real
signature over its DSSE PAE, both **generated by Python**, not by Rust. A fixture Rust generated from
Rust would agree with whatever rule Rust now applies; this one cannot.

`canonical_receipt_body` in the notary is **private**, so the plan's Step 2 instruction to assert it
directly is not callable from an integration test. The byte-for-byte claim is instead proved the way a
third party would prove it: sign the frozen string literal with a key the test holds, hand
`verify_receipt` the *rebuilt struct* plus that signature, and require it to verify — which can only
happen if this build canonicalizes the struct to exactly those bytes. Its paired control appends one
space and requires the failure.

---

## What was built

| Path | Change |
|---|---|
| `rust/evidence/src/lib.rs` | `CausalStep` (`:191`), `Causality` (`:213`), `CausalRefusal` (`:226`), `WarPredicate.predicate_version` + `.causality` with `deny_unknown_fields` (`:331`), `check_predicate_version` (`:663`), `causal_verdict` (`:891`), `causal_verdict_pinned` (`:957`), `EvidenceError::UnknownVersion` and `::UnversionedCausality` |
| `rust/evidence/tests/causal_verdict.rs` | New, 19 tests. The F-02 adversarial suite plus an allowed control for every refusal |
| `rust/evidence/tests/v1_predicates_still_verify.rs` | New, 9 tests. The frozen-fixture regression |
| `rust/evidence/examples/issue_sample_chain.rs` | Emits a v1, a v2 and an unknown-version receipt; bundle schema `interop.v1` → `interop.v2` |
| `rust/evidence/Cargo.toml` | `warrantor-authority-spec` as a **dev**-dependency, so the per-effect-class test iterates the real enum. The census counts only shipping dependencies, so this adds no edge |
| `rust/notary/src/lib.rs` | `#[serde(deny_unknown_fields)]` on `ReceiptBody`. **No new field. No v2 body.** |
| `rust/notary/tests/v1_receipt_fixture.rs` | New, 5 tests |
| `testvectors/notary/frozen_v1_receipt_body.json` | New. The two frozen literals |
| `rust/warrant/src/staging.rs` | `causal_trace()` (`:532`) and `causality()` (`:556`). Additive; no behavior change |
| `rust/warrant/src/report.rs` | `Report.causality`, read from the queue in `build_observed`; `sign()` populates `predicate_version`, `causality` and `Outcome.effects`; one new `limitations()` sentence rendered from the section |
| `rust/warrant/src/settle.rs` | Per-effect predicates stay v1, with the reason in a comment |
| `rust/warrant/tests/causal_trace.rs` | New, 7 tests. The product-side wiring proof |
| `python/warrantor_evidence/.../__init__.py` | `PREDICATE_TYPE`, `check_predicate_version`, `UNKNOWN_VERSION` / `UNVERSIONED_CAUSALITY`, read before the signature |
| `python/warrantor_evidence/tests/test_evidence.py` | 8 new tests including v1-and-v2-in-one-run and a correctly-signed unknown version |
| `python/warrantor_notary/tests/test_notary.py` | 3 new tests pinning the frozen body in the second language |
| `docs/W1-delivery-gaps.md` | New §5.4 with the tier table; I-04 and I-07 rows note that Task 10.1 landed and neither moved |

### The design decision that matters most: there is no `authorized` flag

The plan's produced signature is `CausalStep { index, handle, tool, depends_on, authorized: bool }`.
**That field is not here.** A field inside a signed body that *declares* whether a hop was permitted
is a field an attacker who holds any key sets to `true` and re-signs — and the plan's own Step 6
requires the refusal to survive a valid re-sign. So `causal_verdict` recomputes authorization from
`authority.effective_capabilities`, which `verify_authority` already recomputes from the delegation
chain (I-02). The record carries facts; the verdict carries the judgment.

`rust/evidence/tests/causal_verdict.rs` proves this is not a paper distinction:
`a_validly_re_signed_reordering_verifies_and_the_causal_verdict_still_refuses_it` signs the forgery
with a fresh attacker key through the crate's ordinary `issue_atomic`, asserts the forgery's **own**
signature verifies, and then requires `causal_verdict` to refuse it anyway. Its control — the same
attacker key over the unswapped predicate — both verifies and passes.

---

## Tier table — why each bound gets its word and not a stronger one

**The task's headline bound is Tier C, Observed.** `BoundStrength` at `rust/warrant/src/lib.rs`
reserves `Enforced` for cryptography and the operating system and `Mediated` for the proxy
chokepoint. The causal verdict is neither: it refuses **at settle time, over a record**. Nothing
refuses an effect at the moment the agent attempts it, because staged effects are queued rather than
executed. That containment is real and it is not enforcement.

| Property | Word | The line that earns it | What escapes it |
|---|---|---|---|
| The recorded route cannot be altered after signing without a reader detecting it | **Enforced (Tier A)** — cryptographic | `canonical_predicate` (`evidence:441`) puts `causality.steps`, a `Vec` whose index order is signed, into the DSSE PAE; `verify_receipt` refuses the edit. Test: `reordering_the_steps_of_a_signed_predicate_breaks_the_signature` | Anyone holding the issuer key re-signs a different route freely. Only the route *checks* survive that; the signature does not |
| An ungranted hop is refused, by index, handle and tool | **Observed (Tier C)** | `causal_verdict` (`evidence:891`) → `CausalRefusal::UnauthorizedHop`, recomputed from `authority.effective_capabilities` | Nothing refuses the hop at the moment of attempt. The verdict reads a record afterwards |
| A dependent hop preceding its dependency is refused, by index | **Observed (Tier C)** | `CausalRefusal::OrderBroken`, over the ordering relation among handles | Same. The order is judged, never enforced |
| A hop whose recorded index is not its position is refused | **Observed (Tier C)** | `CausalRefusal::IndexBroken` | Only that every refusal above names a number that means something |
| `step_count` cannot disagree with the list it counts | **Observed (Tier C)** | `CausalRefusal::CountMismatch` | Nothing about whether the list itself is complete |
| The route describes the staged log the reader is holding | **Observed (Tier C)** | `causal_verdict_pinned` (`evidence:957`) against `StagingQueue::head_digest` (`staging:472`). Test: `a_section_signed_before_the_log_grew_is_refused_against_the_grown_log` | A reader who never calls it learns nothing. The staged log, the witness log and the issuer key are on one disk — `StagedChainMark`'s own doc already says this is not a defense against an editor with write access |
| A v1 receipt yields a named refusal, never a pass | **Observed (Tier C)** | `CausalRefusal::Unrepresentable`; `::Uninterpretable` for a section under a version this build cannot read | Nothing retro-fits a route onto a historical receipt. By design: a v1 receipt is v1 forever |
| A newer format is refused as a version, not as a forgery | **Observed (Tier C)** | `check_predicate_version` (`evidence:663`) runs **before** the signature check in `verify_receipt` (`evidence:681`); `deny_unknown_fields` on `WarPredicate` and `notary::ReceiptBody` | Builds already deployed have neither, so they still mis-report a v2 receipt as `InvalidSignature`. This protects future readers, not past ones |
| The bundle's rendered causal sentence is true of the section it describes | **Observed (Tier C)** | `limitations()` renders the hop count and the chain head **from** `Causality`; test `the_bundles_causal_sentence_is_rendered_from_the_section_it_describes` asserts both appear | Nothing about whether the section is a complete account of what the agent did |

`bound_strengths()` is deliberately **not** edited. The causal verdict is not a warrant bound, and
adding a row would put a Tier C claim into a table whose readers scan for `Enforced`.

### The sentence that ships in the product

`limitations()` in `rust/warrant/src/report.rs` now renders one of two sentences, chosen by whether a
route was read:

> The causal verdict is computed over the staged-effect order this notary recorded — *N* hop(s),
> pinned to staged-log chain head *H* — and it makes the recorded pathway tamper-evident: an operator
> cannot later rewrite the route without breaking a signature or that chain digest. It does **not**
> prove the recorded route is the route the agent actually took. Effects reach that record by being
> STAGED, and nothing intercepts the agent at each hop, so a route that never passed through the
> staging queue is invisible here. Ordering is this machine's observation of its own queue and not a
> distributed guarantee: two Warrantor installations produce two independent orders and nothing
> reconciles them.

> No staged route was read when this report was built, so its evidence receipt carries no causality
> section, and a causal verdict over that receipt refuses as unrepresentable rather than passing. That
> is not a statement that nothing was staged.

*N* and *H* are read off the section, not written beside it. Two tests hold this:
`no_source_file_under_rust_claims_the_pathway_is_proven_or_enforced` fails if the words "prove the
pathway", "pathway proven", "route verified", "causally enforced" or "proves the pathway" appear in
any `.rs` file under `rust/`, and
`the_products_limitations_carry_the_tamper_evident_sentence_rather_than_a_proof_claim` fails if
`report.rs` loses the tamper-evidence clause or the two disclaimers.

---

## Consumes / Produces

**Consumes** (all present on local `main` @ `5d3e44d`; line numbers **re-measured**, because every one
the plan cites has moved):

```rust
evidence::WarPredicate            rust/evidence/src/lib.rs:331   (plan said :178)
evidence::canonical_predicate     rust/evidence/src/lib.rs:441   (plan said :255)
evidence::verify_receipt          rust/evidence/src/lib.rs:681   (plan said :477 -- that is verify_chain's old line)
evidence::verify_authority        rust/evidence/src/lib.rs:838   (plan said :552)
evidence::issue_atomic            rust/evidence/src/lib.rs:632
notary::ReceiptBody               rust/notary/src/lib.rs:336     (plan said :336 — correct)
notary::receipt_digest_hex        rust/notary/src/lib.rs:458     (plan said :445)
notary::canonical_receipt_body    rust/notary/src/lib.rs:466 — PRIVATE (plan said pub at :453)
StagingQueue::release_order       rust/warrant/src/staging.rs:486 (plan said :473)
StagingQueue::head_digest         rust/warrant/src/staging.rs:472 (plan said :459)
StagedEffect                     rust/warrant/src/staging.rs:116 (plan said :116 — correct)
```

Consumes **nothing** from Task 2.3 — its staged effects already exist, as the plan correctly found.
Task 1.1's correction is honored rather than fought: `verify_effect_receipts` refuses any per-effect
receipt whose mode is not `Advisory`, and `with_effect_receipts` derives its mode word from the
receipts. **This task adds no per-effect causality section**, so it neither touches that refusal nor
gives Task 5.3's Strategy A5 a new surface: `settle.rs`'s `pre_commit_predicate` stays v1, with the
reason in the source — a one-hop record has no order, so a `causal_verdict` returning `Ok` over it
would be a pass that means nothing.

**Produces:**

```rust
// rust/evidence/src/lib.rs
pub struct CausalStep { index: u64, handle: String, tool: String, depends_on: Vec<String> }
pub struct Causality  { queue_head: String, step_count: u64, steps: Vec<CausalStep> }
pub enum CausalRefusal { UnauthorizedHop{index,handle,tool}, OrderBroken{index,missing},
                         IndexBroken{position,declared}, CountMismatch{declared,actual},
                         QueueHeadMismatch{recorded,observed},
                         Unrepresentable{predicate_version}, Uninterpretable{predicate_version} }
pub fn check_predicate_version(&WarPredicate) -> Result<(), EvidenceError>
pub fn causal_verdict(&WarPredicate) -> Result<(), CausalRefusal>
pub fn causal_verdict_pinned(&WarPredicate, observed_queue_head: &str) -> Result<(), CausalRefusal>
// rust/warrant/src/staging.rs
pub fn causal_trace(&self) -> Result<Vec<evidence::CausalStep>, WarrantError>
pub fn causality(&self)   -> Result<evidence::Causality, WarrantError>
```

### Does this collide with Task 10.9 (post-quantum dual signature)? No.

`DualSignedPayload` at `rust/post-quantum/src/lib.rs:72` adds signature *entries beside* an opaque
`payload: serde_json::Value`. Task 10.1 adds fields *inside* the payload. They compose in either
order and neither reads the other's bytes. Concretely: if 10.9 wraps a v2 predicate, the classical and
PQ signatures are both taken over `canonical_json` of the same payload, and the two fields this task
added are already inside it; if 10.1 had landed second, the payload would simply have two more keys.
There is no ordering constraint between them.

**The real collision risk is different, and it is an open finding.** There are now three independent
canonical-JSON implementations in this workspace:

- `rust/notary/src/lib.rs:466` — `canonical_receipt_body`, private
- `rust/evidence/src/lib.rs:441` — `canonical_predicate`, public
- `rust/post-quantum/src/lib.rs:328` — `canonical_json`, private

Spec 11 §1 forbids two authoritative implementations of a security invariant. **This task added no
fourth and consolidated none of the three.** Named here and in `docs/W1-delivery-gaps.md` §5.4 so the
next lane does not rediscover it.

---

## Step 8 — the Task 5.1 corpus: **nothing converted, and here is why**

All three candidate `#[ignore]`s were read, not assumed. `rust/warrant/tests/invariants/` is
otherwise untouched.

| Ignore | What it asserts | Converts? |
|---|---|---|
| `i07_evidence_precedes_commitment.rs` — `the_product_evaluates_…` / the `issue_pre_commit` occurrence check | `harness::occurrences_in_rust_sources("rust/warrant/src", "issue_pre_commit") > 0` | **No.** Task 10.1 never calls `issue_pre_commit` |
| `i04_current_policy.rs` — `the_product_evaluates_policy_more_than_once_per_action` | `notary::verdict(` appears more than once in `rust/warrant/src` | **No.** Task 10.1 adds no evaluation point. One notary call per report, unchanged |
| `i04_current_policy.rs` — `the_post_commit_receipt_records_its_own_policy_evaluation` | `post_commit.…decision.evaluated_at != pre_commit.…decision.evaluated_at` | **No.** Reachable from `rust/evidence`, but its finding is Task 2.3's commit-time re-evaluation, not causality. Claiming it would mean changing `issue_post_commit` for a reason this task does not own |

`tools/ci/invariant-ratchet.json` keeps `passing_floor: 82` and `ignored_ceiling: 15`, unchanged, and
no assertion in the corpus was weakened or deleted. **Nothing converted.** The corpus's own ordinal
gate is unaffected, because this task adds no `#[ignore]`: `ignored_ceiling` is 15, so ignore number
16 would raise it, and that sentence stays in `docs/W1-delivery-gaps.md` and
`docs/task-evidence/task-5.3.md` where the gate reads it.

One corpus file **did** change, and it is a deviation recorded below rather than an exception taken
quietly: `rust/warrant/tests/invariants/scenario.rs` gained two `None` field initializers, because
adding fields to `WarPredicate` breaks every struct literal in the workspace. No assertion moved.

---

## Deviations from the plan

Eighteen, in the order they were found. The code wins over the plan in every one.

1. **Branch name.** `feat/causal-verdict` already existed at `2ec0638` with zero commits, held by the
   abandoned wave-5 worktree described in Step 0. Used `feat/causal-verdict-strict` instead. The
   other worktree was not touched.
2. **Base commit.** Plan says `refs/remotes/origin/main` @ `e4b5f10`; used local `main` @ `5d3e44d`,
   66+ commits ahead. Every Step 0 number differs as a result; both sets are tabled above.
3. **`predicate_version: String` would break every archived signature.** Plan says
   `pub predicate_version: String`. A required `String` serializes as `""` on a v1 predicate, changing
   its canonical bytes and invalidating every signature ever taken. It is
   `Option<String>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`, matching the
   contract the report bundle already documents for `custody`, `revocation`, `egress` and
   `effect_evidence`. Mutation 4 above proves this is load-bearing rather than stylistic.
4. **"The *first* field, so canonical-JSON ordering puts it where a reader hits it early" is false.**
   `canonicalize_value` sorts keys, so `predicate_version` lands between `operation` and `outcome` in
   the signed bytes no matter where it is declared. Declared first anyway, for a human reader, with
   the correction written into the doc comment.
5. **`CausalStep.authorized: bool` dropped**, for the reason argued above. This is the largest
   deviation and the one most worth reading.
6. **`causal_trace` takes no `granted_tools` parameter.** It follows from (5): with nothing to declare,
   there is nothing to pass. Signature is `causal_trace(&self) -> Result<Vec<CausalStep>, _>`.
7. **Four refusal variants added beyond the plan's three.** `IndexBroken` (every other refusal names
   an index, so an index that lies makes them unreadable), `CountMismatch` (`step_count` is a rendered
   number inside a signed body — Rule 6), `QueueHeadMismatch` (the head check needs an *observed* head,
   which `evidence` cannot read, so it is an input to `causal_verdict_pinned`), and `Uninterpretable`.
8. **`Uninterpretable` exists because of Rule 2.** `Unrepresentable`'s message says "carries no
   causality section", which would be **false** for a predicate that carries one under a version this
   build cannot read. One message could not be true of both records, so there are two variants, and
   `readable_causality` checks the section's *absence* first so each message is true of the record it
   describes.
9. **`EvidenceError::UnversionedCausality` added** beyond the plan's `UnknownVersion`: a causal section
   with no version declares no rule for reading itself, and reading it under the v1 rule would mean
   reading a route nothing says how to read.
10. **`notary::canonical_receipt_body` is private**, not `pub` at `:453`. The plan's Step 2 assertion
    is not callable from `tests/`. Replaced with the sign-the-frozen-bytes / verify-the-rebuilt-struct
    construction plus its control, which is a stronger claim, not a weaker one.
11. **`testvectors/notary/vectors.json` cannot hold a frozen receipt body.** Its entries are verdict
    vectors — `{name, description, request_overrides, context_overrides, expected}` — and a canonical
    body has no place in that shape. Added `testvectors/notary/frozen_v1_receipt_body.json` and pinned
    it from **both** languages, which is stronger than the plan's "so the Python interop producer
    covers it too". No existing entry was edited.
12. **`rust/warrant/tests/invariants/scenario.rs` was edited** despite the plan marking the directory
    read-only. Unavoidable: a signed-body field addition breaks every struct literal. Two `None`
    initializers, no assertion touched.
13. **`deny_unknown_fields` also added to `CausalStep` and `Causality`**, not only to the two structs
    the plan names. They are new signed sub-objects and the argument applies to them identically.
14. **The plan's `limitations()` sentence embeds "the wiring census reports 9 of 39 crates".** That
    figure is stale (13 of 41) and, worse, unverifiable by a reader holding only the bundle. The
    census figure is out of the signed sentence; the hop count and chain head — which the reader *can*
    check against the section beside it — are in.
15. **No `causal_check` section was added to `ReportBundle`.** Followed the plan's "smallest possible
    diff" instruction for the contended `report.rs`. Consequence stated in the next section.
16. **`verify_export` does not run the causal verdict**, deliberately. Verification answers "has
    anything changed since signing"; a report recording a *denial* has to keep verifying, or a denial
    could be made to look like tampering. `a_warrant_missing_one_tool_yields_a_causal_refusal_naming_that_hop`
    asserts both halves: the export verifies **and** the causal verdict refuses.
17. **Interop bundle schema bumped** `warrantor.evidence.interop.v1` → `.v2`, with its one assertion
    updated. A fixture that grows without saying so is the silent format drift this whole task is
    about. That file is `.gitignore`d, so this is a producer/consumer change, not a tracked-fixture
    edit.
18. **`canonical_length_bytes` in my own vector file said 244; the truth is 243.** Caught by the
    Python gate, not by review. Recorded because it is precisely the class of defect this task is
    about — a number written *beside* a record instead of measured *from* it — and it happened inside
    the file whose purpose is to stop that.

---

## What this task does NOT establish

Specific, not modest.

1. **It does not establish that the recorded route is the route the agent took.** Effects enter the
   record by being *staged*. `warrantor stage` is a call the agent makes; nothing intercepts a direct
   socket, a direct `git push`, or a shell command. A route that never passed through the staging
   queue produces no `CausalStep` and `causal_verdict` returns `Ok` over the hops it can see. This is
   the residual L7-01's own anchor records: *"pathway checking depends on evidence completeness."*
2. **It does not close the gap it was named after.** The blueprint's `why` says agents built tooling
   to defeat a causal check that did not exist. A check now exists over the *staged* pathway. An agent
   that does not stage is unaffected by it.
3. **It does not make ordering a distributed guarantee.** The order is the order **this** staging
   queue on **this** machine observed. Two installations produce two independent orders and nothing
   reconciles them. No new trust root was created.
4. **The bundle does not render a causal verdict.** `ReportBundle` gained no section, so a reader of
   the bundle sees the staged effects and the honest caveat but not a verdict — they must compute it
   from `signed.evidence_receipt.predicate`. Handed to Task 10.2 and Task 11.4.
5. **`verify_export` does not refuse a causal violation**, by design (deviation 16). A party who runs
   only `verify_export` learns that nothing changed since signing and learns nothing about the route.
6. **It does not defend against a party holding the issuer key.** Such a party re-signs any route.
   What survives is the *verdict*, which is recomputed rather than read — but the verdict is only
   consulted by someone who calls it. This is the same boundary Task 5.3's Strategy A1 and A2 record,
   and `verify_chain_signed_by` still does not exist.
7. **It does not detect a deleted staged log.** `causal_verdict_pinned` compares the recorded head to
   an observed head; a caller who reads an absent log observes `GENESIS` and gets a mismatch, which is
   right — but the mark, the witness log and the issuer key all sit on one disk, and
   `StagedChainMark`'s own documentation already says that is not a defense against an editor with
   write access.
8. **It says nothing about the nine sibling `issue_receipt` implementations.** `computer-use`,
   `content-moderation`, `csam-defense`, `data-plane`, `egress`, `misinformation-defense`,
   `retrieval`, `spend` and `notary` each define their own `issue_receipt` with its own body type and
   canonicalizer. None carries a route, none carries a version field, and only `notary::ReceiptBody`
   gained `deny_unknown_fields`. The chain went into `evidence::WarPredicate` precisely because it is
   the one envelope all ten funnel through, but the ten bodies themselves remain unversioned.
9. **Per-effect receipts carry no route.** `settle::pre_commit_predicate` stays v1, so
   `causal_verdict` over a per-effect receipt returns `Unrepresentable`. That is the honest answer for
   a one-hop record, and it means the per-effect chain is not causally checked — only the report
   receipt is.
10. **Python computes no causal verdict.** Its parity is over the *version gate* only. Adding a second
    implementation of the route checks would create exactly the two-authoritative-implementations
    condition spec 11 §1 forbids, and which this task already names as an open finding for
    canonical JSON. So a Python-only verifier refuses an unknown version and never judges a route.
11. **Older deployed builds still mis-report a v2 receipt as a forgery.** `deny_unknown_fields` and
    the version gate protect readers built from this commit forward. Nothing can reach a binary
    already shipped.
12. **Neither I-04 nor I-07 moved**, and no `#[ignore]` converted. The ledger is unchanged at
    `enforced=2, orphaned=1, partial=8, unimplemented=1`.
13. **It is not a distributed ordering guarantee, a reasoning-trace monitor, a commit-time policy
    re-evaluation, or a retro-fit onto historical receipts.** Those were the plan's non-goals and they
    remain out.

---

## Handoffs

**(a) Task 10.2 — the receipt query language.** The predicate shape is now frozen and versioned, so a
query schema can be built against it. Two properties to design around: `predicate_version` is **not**
the first key in canonical order — canonical JSON sorts, so it sits between `operation` and `outcome`
— and `causality` is an `Option`, so "absent" and "present but empty" are distinguishable and mean
different things (`Unrepresentable` versus a clean pass). A query surface that collapses them
reintroduces the fail-open reading. `PREDICATE_TYPE` is `https://warrantor.dev/ActionReceipt/v2`,
declared once in `rust/evidence/src/lib.rs:44` and asserted equal to the Python constant by
`test_predicate_type_is_the_same_string_rust_declares`. The bundle carries no causal verdict, so 10.2
is the first surface that can render one.

**(b) Task 2.3 — the commit point.** It inherits both `i04_current_policy.rs` `#[ignore]`s, unchanged,
and from this task a `Causality` section that will need a commit-time `decision` block: `issue_post_commit`
still copies the pre-commit's `evaluated_at`, so a post-commit receipt carrying a route still records a
policy evaluation that happened before the route ran. 2.3 also owns the second notary call that would
let the causal verdict be computed at the commit point rather than only over a report.

**(c) Three canonical-JSON implementations, one rule.** `rust/notary/src/lib.rs:466`,
`rust/evidence/src/lib.rs:441`, `rust/post-quantum/src/lib.rs:328`. Spec 11 §1 forbids two
authoritative implementations of a security invariant. This task added no fourth and consolidated
none. Unowned.

---

## The gate, verbatim

Each cargo exit code captured **before** any pipe. Every language this task touched was gated.

```
$ df -h /m | tail -1
M:              1.2T  815G  379G  69% /m          (before the first cargo command)

$ cd rust && cargo fmt --check                              FMT=0
$ cargo clippy --all-targets -- -D warnings                 CLIPPY=0
$ cargo test --workspace -j 2                               CARGO=0
  154 suites, 1568 passing, 0 failed, 20 ignored
  (baseline on main: 150 suites, 1528 passing, 0 failed, 20 ignored
   -> +4 suites, +40 tests, ignored UNCHANGED. The 40 are causal_verdict 19,
      v1_predicates_still_verify 9, causal_trace 7, v1_receipt_fixture 5.)

$ python tools/ci/wiring_census.py
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges     UNCHANGED

$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)     UNCHANGED

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1    UNCHANGED

$ python tools/ci/check_docs.py
RESULT: PASS - 268 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated

$ python tools/ci/check_us_english.py main
us-english: ok

$ python tools/ci/run_python_checks.py test                 PY=0
RESULT: PASS - 54/54 Python projects passed test
```

The suite total is summed from all 154 `test result:` lines, not read off the last one. The counts
came from the captured lines, not from arithmetic over increments.

**The Python gate was verified to have actually executed, not skipped.** The interop tests in both
packages `skipif` on a missing fixture, and this repository has already shipped a green run that
skipped the only checks proving Rust and Python agree. Run directly, with no skips:

```
$ python -m pytest python/warrantor_evidence/tests/test_evidence.py -q
21 passed in 0.14s
$ python -m pytest python/warrantor_notary/tests/test_notary.py -q
15 passed in 0.13s
```

Both fixtures exist on disk after the run (`.evidence_interop.json` at schema
`warrantor.evidence.interop.v2`, carrying `v1_atomic` with no `predicate_version` key, `v2_atomic` at
`PREDICATE_TYPE`, and `unknown_version` at `.../v9`), and the CI annotation reports only the jobs that
ran — so a green summary is not by itself proof the Python gate executed. The two direct runs above are.

### The exit gate this task set for itself

> `cd rust && cargo test -p warrantor-evidence --test causal_verdict --test v1_predicates_still_verify && cargo test -p warrantor-archive --test append_only --test verification_does_not_depend_on_the_archive` passes with the two archive suites showing **7 passed, 2 ignored** and **6 passed, 0 failed** unchanged, and the causal suite showing at least one refusal naming a hop by index and at least one accepted well-formed control.

```
     Running tests\causal_verdict.rs
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.46s
     Running tests\v1_predicates_still_verify.rs
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
     Running tests\append_only.rs
test result: ok. 7 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.11s
     Running tests\verification_does_not_depend_on_the_archive.rs
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s
```

Both archive suites are at the required counts, unchanged. The refusals naming a hop by index are
`a_correct_outcome_reached_through_an_ungranted_middle_hop_is_a_violation` (index 2, handle
`comment://staged/wrt_f02/2`, tool `github.comment`) and
`a_hop_depending_on_a_handle_no_earlier_hop_minted_is_a_violation` (index 2, missing
`pr://staged/wrt_f02/99`); their controls are `the_identical_chain_with_every_hop_granted_passes` and
`a_well_formed_order_passes`. Nine of the nineteen tests are refusals and ten are acceptances, and the
first mutation above shows exactly that split going red and staying green respectively.

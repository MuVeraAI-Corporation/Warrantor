### Task 10.1: The causal verdict — STRICT_CAUSAL, made real (L7-01)

**Anchor.** L7-01 is `status=none`, `novel`, W2. Quoted verbatim from the master blueprint,
`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html:4276`:

```html
<article class="item" id="L7-01" data-stratum="L7" data-plane="F" data-status="none"
         data-novelty="novel" data-wave="W2" data-loop="L2">
```

Its `what` clause, line 4280, is the whole specification:

> A verdict that validates the pathway to an outcome, not merely the outcome. "Right result, wrong
> route" is a violation. The receipt records which authority, which effects, in which order,
> produced the result, and the verdict is computed over that chain rather than over a final
> assertion.

Its `why` clause, line 4281, is why it leads Phase 10: *"This is the highest-leverage single item in
the catalog. Hundreds of agents spent days building tooling to defeat a causal check they believed
existed; it did not."* Its proof gate is F-02, line 4283: *"Produce a correct outcome by an
unauthorized route and assert the verdict is a violation, per effect class."* And its own recorded
residual, line 4284, is the sentence this task must not let the product forget: *"Pathway checking
depends on evidence completeness; gaps in F-04 become gaps here."*

`status=none` is correct as a statement about the verdict. It is **not** correct as a statement about
the data. Four things the seed treats as absent are already on `origin/main`, and the expansion below
is a different task because of it.

**Premise contradicted — five corrections, and one confirmation.**

*Confirmed.* The seed's central grep result is exactly right. There is no causal verdict anywhere:

```
$ git grep -c "STRICT_CAUSAL\|strict_causal" refs/remotes/origin/main
$ echo $?
1
```

Zero hits, exit 1. Nothing in the repository names the property.

*Confirmed.* `ReceiptBody` is at `rust/notary/src/lib.rs:336` and carries exactly the six fields the
seed quotes, verbatim, lines 335–343:

```rust
/// The body of a WAR receipt — what is canonically serialized and signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptBody {
    pub verdict: Verdict,
    pub actor_svid: String,
    pub operation_class: String,
    pub timestamp: u64,
    pub enforcement_mode: EnforcementMode,
    pub notary_version: String,
}
```

*Correction 1 — the chain is already representable in a signed body, just not in that one.* The
seed's load-bearing claim is *"A causal verdict is not merely unimplemented — it is unrepresentable
in the signed body."* That is true of `notary::ReceiptBody` and false of the other signed body in the
same dependency graph. `rust/evidence/src/lib.rs:124–136`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Binding {
    pub receipt_id: String,
    pub phase: Phase,
    /// The parent receipt_id forming the causal chain (None for pre_commit/atomic root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_receipt: Option<String>,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub enforcement_mode: EnforcementMode,
}
```

The comment already says *"forming the causal chain."* And `Outcome` at
`rust/evidence/src/lib.rs:163–172` already carries an ordered effect list:

```rust
/// The outcome — mandatory in post_commit and atomic (spec 01 §3.8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Outcome {
    pub status: String,
    pub outcome_digest: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub effects: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_pointer: Option<String>,
}
```

`evidence::verify_chain` at `rust/evidence/src/lib.rs:477` already refuses a post-commit whose
parent does not match, by name, at lines 505–518. So the prior-receipt pointer, the effect sequence
and the parent check the seed says to build all exist. What does not exist is a verdict computed over
them, and any binding of the *real* effect sequence into the signature — see Correction 3.

*Correction 2 — the version hook the seed points at is in the wrong crate.* The seed says *"So the
first work is versioning, not causality. `notary_version` already exists in the body and is the
hook. Use it."* `notary_version` does exist and is populated at `rust/notary/src/lib.rs:376`. But if
the chain belongs in the evidence predicate (Correction 1), then the body that needs versioning is
`WarPredicate` — and **`WarPredicate` carries no version field at all.** The two constants that look
like one are declared and referenced nowhere:

```
$ git grep -n "WAR_VERSION\|PREDICATE_TYPE" refs/remotes/origin/main -- 'rust/**' 'python/**'
refs/remotes/origin/main:rust/evidence/src/lib.rs:43:pub const WAR_VERSION: &str = "war/2.0";
refs/remotes/origin/main:rust/evidence/src/lib.rs:44:pub const PREDICATE_TYPE: &str = "https://warrantor.dev/ActionReceipt/v2";
```

Two declarations, zero uses. The signed predicate does not say which version it is. Versioning is
still the first work — the seed is right about that — but it is *adding* a version field to
`WarPredicate`, not *using* one that is already there.

*Correction 3 — Task 2.3's staged effects already exist, and they are richer than the seed's
design.* The seed instructs: *"Record whether Task 2.3 has landed; it introduces two-phase staged
effects, and building the chain twice is the waste to avoid."* Task 2.3 has not landed as a task, and
the structure it would build is already on `origin/main` at `rust/warrant/src/staging.rs:114–130`:

```rust
/// A staged effect: an outward-facing action that has been queued but not performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedEffect {
    /// Position in the queue, from 1.
    pub index: u64,
    /// The handle that stands for this effect, e.g. `pr://staged/wrt_7f3a/1`.
    pub handle: String,
    /// The tool that would perform it.
    pub tool: String,
    /// Arguments, verbatim as the agent supplied them.
    pub arguments: BTreeMap<String, String>,
    /// Handles this effect depends on. Derived from arguments that reference other handles.
    pub depends_on: BTreeSet<String>,
    /// When it was staged, epoch seconds.
    pub staged_at: u64,
}
```

That is not a flat sequence. It is a typed dependency DAG with a topological release order at
`rust/warrant/src/staging.rs:473`, an append-only hash-chained log with a length-prefixed digest at
`:341`, and an out-of-band witness at `:90` whose own documentation states its limit. So the "ordered
effect sequence" the seed asks this task to invent already exists, in a stronger form, and the task's
real work is **binding it into the signature and computing a verdict over it** rather than designing
it.

*Correction 4 — `receipt_digest` is already built, already documented for this purpose, and has zero
Rust callers.* `rust/notary/src/lib.rs:431–447`:

```rust
/// The receipt body's canonical SHA-256 digest — what other receipts reference when they chain
/// to this one (e.g. a post_commit receipt chains to its pre_commit).
#[must_use]
pub fn receipt_digest(body: &ReceiptBody) -> [u8; 32] {
```

```
$ git grep -n "receipt_digest" refs/remotes/origin/main -- 'rust/**/*.rs'
refs/remotes/origin/main:rust/notary/src/lib.rs:434:pub fn receipt_digest(body: &ReceiptBody) -> [u8; 32] {
refs/remotes/origin/main:rust/notary/src/lib.rs:445:pub fn receipt_digest_hex(body: &ReceiptBody) -> String {
refs/remotes/origin/main:rust/notary/src/lib.rs:446:    hex::encode(&receipt_digest(body)[..])
```

Definition and self-reference only. The chaining primitive exists and nothing chains.

*Correction 5 — the format change is ten format changes, not one.* The seed says *"Adding a field
changes every signature."* It changes one signature family out of ten. `issue_receipt` is
independently defined in ten crates:

```
$ git grep -n "^pub fn issue_receipt" refs/remotes/origin/main -- 'rust/**/*.rs'
rust/computer-use/src/lib.rs:290           rust/misinformation-defense/src/lib.rs:228
rust/content-moderation/src/lib.rs:278     rust/notary/src/lib.rs:363
rust/csam-defense/src/lib.rs:306           rust/retrieval/src/lib.rs:298
rust/data-plane/src/lib.rs:305             rust/spend/src/lib.rs:328
rust/egress/src/lib.rs:312
```

Each has its own body type, its own canonicalizer and a Python mirror under `python/warrantor_*/`. A
v2 `notary::ReceiptBody` would rewrite one of them and leave nine unchained — which is a worse
outcome than leaving all ten alone, because the product would then have a chained receipt family and
nine unchained ones with no marker saying which is which. **This is the reason the chain goes in the
evidence predicate.** Every one of the ten crates already funnels into `evidence` for its envelope,
and there is exactly one `WarPredicate`.

**Where "right result, wrong route" actually gets in today.** The seed treats the gap as a missing
field. It is a missing *granularity*. The product asks the nine gates exactly one question per
report, over a **set union** of every tool any staged effect would need —
`rust/warrant/src/report.rs:732–740` and `:766–778`:

```rust
        operation: notary::Operation {
            class: REPORT_OPERATION_CLASS.to_string(),
            // What the staged effects would need at settle time. Nothing in `warrantor stage`
            // checks the tool allowlist today, so this gate is the first thing that would notice
            // an effect staged for a tool the warrant does not hold.
            capabilities_requested: staged_tools.clone(),
```

```rust
    let authority_check = AuthorityCheck {
        engine: notary::NOTARY_VERSION.to_string(),
        question: "Does this warrant still hold the authority its staged effects would need at \
                   settle time?"
            .to_string(),
        allowed: verdict.is_allow(),
```

`staged_tools` is collected into a `BTreeSet` at `:641–645`, so gate 5 sees *which tools* and never
*which hop, in what order, depending on what*. A three-hop chain whose middle hop is unauthorized and
whose outcome is permitted denies here **only if** that middle tool is outside `bounds.tools`. If it
is inside — the common case, since a warrant grants a tool set and the route through it is
unconstrained — the union is satisfied, gate 5 allows, and the report's one question has been answered
correctly about a route nobody checked. That is the defect, stated precisely, and it is why Step 4's
adversarial chain has to keep the *outcome* permitted while breaking a *hop*.

**The refusal shape to imitate.** `evidence::verify_chain` already refuses a broken link by name and
by value, `rust/evidence/src/lib.rs:505–518`:

```rust
    match &post_commit.predicate.binding.parent_receipt {
        Some(parent) if parent == &pre_commit.predicate.binding.receipt_id => {}
        Some(other) => {
            return Err(EvidenceError::CommitGate(format!(
                "post_commit parent_receipt ({other}) does not match pre_commit receipt_id ({})",
                pre_commit.predicate.binding.receipt_id
            )));
        }
        None => {
            return Err(EvidenceError::CommitGate(
                "post_commit has no parent_receipt (orphan; I-07)".to_string(),
            ));
        }
    }
```

Note what it does: it distinguishes *wrong parent* from *no parent*, and the second string is asserted
verbatim by Task 5.1's corpus at
`rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs:33`. `CausalRefusal` must be that
specific — `UnauthorizedHop` and `OrderBroken` are separate variants for the same reason, and each
must name its index, because "the chain is bad" is not an auditable refusal.

**The order the signature must carry.** `release_order` at `rust/warrant/src/staging.rs:463–473` is
the order Step 5 signs, and its doc comment states the property that makes the causal verdict
meaningful at all:

```rust
    /// Effects in release order: dependencies before dependents.
    ///
    /// Every prefix of this order is a coherent state, which is what makes a partial release
    /// survivable rather than a mess to untangle.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if the graph contains a cycle. It cannot today — an effect can
    /// only depend on handles that existed when it was staged, so dependencies always point
    /// backwards — but a cycle would mean no safe order exists, and silently picking one would be
    /// worse than refusing.
    pub fn release_order(&self) -> Result<Vec<&StagedEffect>, WarrantError> {
```

Sign *this* order, not the staging order. They differ whenever an agent stages out of dependency
sequence, and the release order is the one the settle engine at `rust/warrant/src/settle.rs:136`
actually executes. A causal verdict computed over the staging order would be a verdict about an order
that never runs.

`premise_contradicted = true`. The seed's finding about the verdict is right; its finding about the
data, its choice of crate, its version hook and its estimate of blast radius are each wrong, and the
code wins on all four.

*One thing the seed got right that is easy to lose:* `operation_class` is a `String` on the wire at
`rust/notary/src/lib.rs:338` while `SideEffectClass` is an enum at `rust/authority-spec/src/lib.rs:42`
(confirmed at that exact line). Do not fix that here. Note it and leave it.

---

**Step 0.** Run every command below and paste its output into `docs/task-evidence/task-10.1.md`
before writing a line of code. The output recorded here is real, captured from a detached worktree at
`refs/remotes/origin/main` @ `e4b5f10` with `CARGO_TARGET_DIR` set outside the checkout.

```
$ export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
$ git grep -c "STRICT_CAUSAL\|strict_causal" refs/remotes/origin/main ; echo "EXIT=$?"
EXIT=1

$ python tools/ci/wiring_census.py
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1

$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)

$ cd rust && cargo test -q -p warrantor-notary -p warrantor-evidence
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.21s
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s

$ cd rust && cargo test -q -p warrantor-archive \
    --test append_only --test verification_does_not_depend_on_the_archive
test result: ok. 7 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.15s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
```

Every crate this task touches is present on `origin/main` and reachable from the binary. No carry-in
sequence is needed:

```
$ git ls-tree --name-only refs/remotes/origin/main rust/ | tr '\n' ' '
… rust/archive rust/authority-spec … rust/evidence … rust/notary … rust/post-quantum … rust/warrant …

$ python -c "import sys;sys.path.insert(0,'tools/ci');\
from wiring_census import reachable_crates,REPOSITORY_ROOT;\
print('\n'.join(sorted(reachable_crates(REPOSITORY_ROOT/'rust'))))"
warrantor-api
warrantor-authority-spec
warrantor-containment-conformance
warrantor-egress
warrantor-evidence
warrantor-notary
warrantor-spend
warrantor-trust-core
warrantor-warrant
```

**The frozen v1 fixture, captured byte-for-byte.** Step 2 needs a real v1 receipt, not a
reconstruction. This is the canonical form and digest of a minimal v1 body, produced by a throwaway
example against `origin/main` and deleted afterward:

```
CANONICAL_V1={"actor_svid":"spiffe://yourcorp/agents/bot-1","enforcement_mode":"observed","notary_version":"warrantor-notary/1.0","operation_class":"report","timestamp":1786000000,"verdict":{"effective_capabilities":["github.create_pr"],"outcome":"allow"}}
DIGEST_V1=6835a03a44df0556406780dd2fb1cc7b73ed58fde2f03da8073c74f3a22da466
```

Six keys, sorted, no whitespace, `serde_json::to_string` over the canonicalized `Value` —
`canonical_receipt_body` at `rust/notary/src/lib.rs:453` plus `canonicalize_value` at `:459`. Freeze
those two strings into the fixture as literals. A fixture that *recomputes* the canonical form proves
nothing about a format change, because it recomputes it under the new rule.

**A defect to fix in Step 3, found while reading.** `ReceiptBody` derives plain `Deserialize` with no
`#[serde(deny_unknown_fields)]`. Serde silently drops unknown fields. So a v2 body handed to a v1
`verify_receipt` deserializes, loses the new fields, re-canonicalizes without them, and fails as
`NotaryError::InvalidSignature` — a version mismatch reported to a third-party auditor as a forgery.
The same hole exists on `WarPredicate`. Whatever version field this task adds must be read *before*
the signature check and must produce its own error variant.

**Read these in full before touching anything.** Do not skim; the corrections above were all found by
reading, and there are more files here than the seed lists because the seed's crate choice was wrong.

| File | Lines | Why |
|---|---|---|
| `rust/notary/src/lib.rs` | 901 | The nine gates (`:201`), `ReceiptBody` (`:336`), `issue_receipt` (`:363`), `verify_receipt` (`:394`), `receipt_digest` (`:434`), `canonical_receipt_body` (`:453`) |
| `rust/evidence/src/lib.rs` | 969 | `Binding.parent_receipt` (`:131`), `Outcome.effects` (`:169`), `WarPredicate` (`:178`), `canonical_predicate` (`:255`), `issue_post_commit` (`:355`), `verify_chain` (`:477`), `verify_authority` (`:552`) |
| `rust/warrant/src/staging.rs` | 500 | **Not in the seed's list, and the most important file in the task.** `StagedChainMark` (`:90`), `StagedEffect` (`:116`), `EffectRegistry::github` (`:168`), `stage` with its type check (`:357`), `head_digest` (`:459`), `release_order` (`:473`) |
| `rust/warrant/src/report.rs` | 1,432 | **Contended — another lane owns it.** Read `build_observed`'s staged section (`:635–679`), the single notary call (`:764`), the `AuthorityCheck` over a *union* of tools (`:766–778`), and `Report::sign` (`:867–938`) where `parent_receipt: None` and `effects: Vec::new()` are hardcoded at `:878` and `:923` |
| `rust/archive/tests/append_only.rs` | 578 | 7 passing, 2 Postgres-ignored. Pins the append-only contract this change must not break |
| `rust/archive/tests/verification_does_not_depend_on_the_archive.rs` | 395 | 6 passing. The four-attack suite, including the fabricated-keypair attack that motivated `verify_export_signed_by`. Pins the offline verification contract |
| `rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs` | 167 | **Read-only.** Task 5.1's corpus is the measuring instrument |
| `rust/warrant/tests/invariants/i04_current_policy.rs` | 130 | **Read-only.** Both its `#[ignore]`s are candidates and both are assessed in Step 8 |
| `rust/post-quantum/src/lib.rs` | ~400 | `DualSignedPayload` (`:72`), `dual_sign` (`:283`), `canonical_json` (`:328`). Read this to answer the 10.9 collision question below |

**Task 10.9 does not collide — and here is the proof, since the seed asks.** `DualSignedPayload` at
`rust/post-quantum/src/lib.rs:69–79`:

```rust
/// A dual-signed payload: Ed25519 now + a PQ algorithm slot. Both verify independently.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DualSignedPayload {
    /// Canonical-JSON payload (the thing being signed).
    pub payload: serde_json::Value,
    /// Classical signature (Ed25519) — present now.
    pub classical: SignatureEntry,
    /// Post-quantum signature (ML-DSA or SLH-DSA) — present when PQ keys are available.
    /// None = "PQ-ready but not yet PQ-signed" (the migration window).
    pub post_quantum: Option<SignatureEntry>,
}
```

10.9 adds signature *entries beside* an opaque payload. 10.1 adds fields *inside* the payload. They
compose, in either order, and neither reads the other's bytes. **The real collision risk is
different and worth writing down:** `post-quantum` carries a third independent canonicalizer
(`canonical_json`, `:328`) alongside `notary::canonical_receipt_body` (`:453`) and
`evidence::canonical_predicate` (`:255`). Three implementations of one security-critical function,
which spec 11 §1 forbids for security invariants. This task must not add a fourth. Say so in the
evidence file and leave the consolidation to whichever task owns it.

---

**Non-goals.**

- **Not the receipt query language.** Task 10.2 (L7-13) reads what this writes. The predicate shape
  must be frozen and its version field landed before a query surface is designed against it;
  otherwise 10.2 ships a schema for a format that changes underneath it.
- **Not reasoning-trace monitoring.** Task 10.7 (L7-11, L7-21) owns anything derived from model
  internals. Causality here is over *effects only*. Conflating the two would let a weak signal
  substantiate a strong claim, which is the specific defect Task 10.7's own anchor is about.
- **Not the commit-time policy re-evaluation.** Task 2.3 owns the second notary call and the staged
  effects' commit point. Task 10.1 computes a verdict over an order; it does not create a new
  evaluation point. `i04`'s two `#[ignore]`s belong to 2.3 and Step 8 says so plainly rather than
  claiming them.
- **Not issuing pre-commit receipts from the product.** Task 1.1 owns wiring `issue_pre_commit` into
  the report path, and `rust/warrant/src/report.rs` is contended. Task 10.1 must work on an
  `Atomic`-phase predicate as well as a two-phase chain, because `Atomic` is what the product signs
  today (`rust/warrant/src/report.rs:877`).
- **Not retro-fitting chains onto historical receipts.** A v1 receipt stays v1 forever, and the
  causal verdict over a v1 receipt is a defined, named refusal — not an error and not a pass.
- **Not a distributed ordering guarantee.** No new trust root: the order is the order **this**
  notary's staging queue observed, on **this** machine. See Bound strength.

**Files.**

| Path | Change |
|---|---|
| `rust/evidence/src/lib.rs` | New `Causality` predicate section; `predicate_version` field; `causal_verdict`; `CausalRefusal`; version read before signature check |
| `rust/evidence/tests/causal_verdict.rs` | New. The F-02 adversarial suite plus its allowed controls |
| `rust/evidence/tests/v1_predicates_still_verify.rs` | New. The frozen-fixture regression |
| `rust/notary/src/lib.rs` | `#[serde(deny_unknown_fields)]` on `ReceiptBody` only. **No new field. No v2 body.** |
| `rust/notary/tests/v1_receipt_fixture.rs` | New. The two frozen literals from Step 0 |
| `testvectors/notary/vectors.json` | Append a frozen v1 vector; do not edit existing entries |
| `rust/warrant/src/staging.rs` | `causal_trace()` — the DAG in topological order as a signable value. Additive; no behavior change |
| `rust/warrant/src/report.rs` | **Contended.** Smallest possible diff: populate `Outcome.effects` and the new `causality` section from the queue. Coordinate before touching |
| `python/warrantor_evidence/src/warrantor_evidence/__init__.py` | Cross-language parity for the version read |
| `docs/W1-delivery-gaps.md` | Tier 5 rows for I-04 (`:1106`) and I-07 (`:1109`); a new row for the causal verdict's tier |
| `docs/task-evidence/task-10.1.md` | Required |

`rust/warrant/tests/invariants/` is **read-only**. Do not edit an assertion in Task 5.1's corpus.

**Consumes / Produces.**

Consumes, all present on `origin/main`:

```rust
// rust/notary/src/lib.rs:336
pub struct ReceiptBody { verdict, actor_svid, operation_class, timestamp,
                         enforcement_mode, notary_version }
// rust/notary/src/lib.rs:363
pub fn issue_receipt(verdict_result: &Verdict, req: &VerdictRequest,
                     enforcement_mode: EnforcementMode, signing_key: &SigningKey,
                     key_id: &str) -> WarReceipt
// rust/notary/src/lib.rs:434
pub fn receipt_digest(body: &ReceiptBody) -> [u8; 32]
// rust/evidence/src/lib.rs:178
pub struct WarPredicate { binding, actor, authority, decision, operation, outcome }
// rust/evidence/src/lib.rs:477
pub fn verify_chain(pre_commit: &WarReceipt, post_commit: &WarReceipt)
    -> Result<(), EvidenceError>
// rust/evidence/src/lib.rs:552
pub fn verify_authority(authority: &Authority) -> Result<(), EvidenceError>
// rust/warrant/src/staging.rs:473
pub fn release_order(&self) -> Result<Vec<&StagedEffect>, WarrantError>
// rust/warrant/src/staging.rs:459
pub fn head_digest(&self) -> &str
```

Does **not** consume anything from Task 2.3 — its staged effects already exist (Correction 3). Does
**not** consume `evidence::WAR_VERSION` or `PREDICATE_TYPE`, because nothing does (Correction 2).

Produces:

```rust
// rust/evidence/src/lib.rs — new
pub struct CausalStep { pub index: u64, pub handle: String, pub tool: String,
                        pub depends_on: Vec<String>, pub authorized: bool }
pub struct Causality { pub queue_head: String, pub step_count: u64,
                       pub steps: Vec<CausalStep> }
pub enum CausalRefusal { UnauthorizedHop { index: u64, handle: String, tool: String },
                         OrderBroken { index: u64, missing: String },
                         Unrepresentable { predicate_version: String } }
pub fn causal_verdict(predicate: &WarPredicate) -> Result<(), CausalRefusal>
// rust/warrant/src/staging.rs — new
pub fn causal_trace(&self, granted_tools: &BTreeSet<String>)
    -> Result<Vec<CausalStep>, WarrantError>
```

**Bound strength.** **Tier C — Observed.** State it bluntly; this item's prominence in the blueprint
is exactly what invites overclaiming, and `BoundStrength` at `rust/warrant/src/lib.rs:197–211`
reserves `Enforced` for cryptography and the operating system and `Mediated` for the proxy
chokepoint. The causal verdict is neither. It refuses at settle time, over a record; nothing refuses
an effect at the moment the agent attempts it, because the effects are queued rather than executed.
That containment is real and it is not enforcement.

The sentence that appears in the product, in `limitations()` at `rust/warrant/src/report.rs:463`
alongside the existing seven:

> The causal verdict is computed over the staged-effect order this notary recorded, and it makes the
> recorded pathway tamper-evident: an operator cannot later rewrite the route without breaking a
> signature or a chain digest. It does **not** prove the recorded route is the route the agent
> actually took. Nothing intercepts the agent at each hop — the wiring census reports 9 of 39 crates
> reachable from the command line — so a route that never passed through the staging queue is
> invisible here. Ordering is this machine's observation, not a distributed guarantee: two
> Warrantor installations produce two independent orders and nothing reconciles them.

Any product text saying "we prove the pathway" is false. "We make the recorded pathway
tamper-evident" is true. `bound_strengths()` at `rust/warrant/src/lib.rs:668` is **not** edited by
this task: the causal verdict is not a warrant bound and adding a row would put a Tier C claim into a
table whose readers scan for `Enforced`.

**The orphan count may not rise.** Every crate touched — `notary`, `evidence`, `warrant`,
`authority-spec` — is already in the reachable set of 9. No new crate is created. `python
tools/ci/wiring_census.py` must still print `9 of 39` at the end, with the same 17 edges.

**Exit gate.** `cd rust && cargo test -p warrantor-evidence --test causal_verdict --test
v1_predicates_still_verify && cargo test -p warrantor-archive --test append_only --test
verification_does_not_depend_on_the_archive` passes with the two archive suites showing **7 passed, 2
ignored** and **6 passed, 0 failed** unchanged, and the causal suite showing at least one refusal
naming a hop by index and at least one accepted well-formed control.

---

- [ ] **Step 1 — Worktree, Step 0 captured verbatim, and the concurrency check.**
      `git worktree add M:/wt-10.1 -b feat/causal-verdict refs/remotes/origin/main`
      Then `export CARGO_TARGET_DIR=M:/wt-10.1-target` — a shared target directory is how the
      cargo-registry race in this repository's memory started. Run every Step 0 command and paste
      real output into `docs/task-evidence/task-10.1.md`, including the `EXIT=1` from the
      `STRICT_CAUSAL` grep. Before writing anything, confirm no other lane holds
      `rust/warrant/src/report.rs`: `git worktree list` and `git log --oneline -5 refs/remotes/origin/main`.
      *Test intent:* none — this step's product is the evidence file's Step 0 section and a
      recorded answer to "who else is in report.rs".

- [ ] **Step 2 — Failing test first: the frozen v1 fixture.** Write
      `rust/notary/tests/v1_receipt_fixture.rs` and `rust/evidence/tests/v1_predicates_still_verify.rs`
      **before** any production change. Embed the two Step 0 literals as `const` strings —
      `CANONICAL_V1` and `DIGEST_V1` — never recomputed from a struct. Assert
      `canonical_receipt_body` over a rebuilt body equals `CANONICAL_V1` byte-for-byte and
      `receipt_digest_hex` equals `DIGEST_V1`. Do the same for a v1 `WarPredicate`: freeze its
      canonical form and a real Ed25519 signature over its DSSE PAE, then assert
      `evidence::verify_receipt` returns `Ok` on it. Append the v1 vector to
      `testvectors/notary/vectors.json` without editing an existing entry, so the Python interop
      producer at `rust/notary/examples/issue_vector_receipts.rs` covers it too.
      *Test intent:* these tests pass now and must still pass after Steps 3–7. They are the only
      thing standing between a format change and a silently broken archive.

- [ ] **Step 3 — Version the predicate, and close the silent-drop hole.** Add
      `pub predicate_version: String` to `WarPredicate` (the *first* field, so canonical-JSON
      ordering puts it where a reader hits it early), populated from the existing but unused
      `PREDICATE_TYPE` at `rust/evidence/src/lib.rs:44`. Add `#[serde(deny_unknown_fields)]` to
      `WarPredicate` and to `notary::ReceiptBody`. In `verify_receipt`, read `predicate_version`
      **before** the signature check and return a new `EvidenceError::UnknownVersion(String)` for
      anything unrecognized. Two canonical rules, one verifier, selected by a field the reader can
      see: absent field means v1, `PREDICATE_TYPE` means v2. **No `notary::ReceiptBody` v2** — a
      second body there strands nine sibling `issue_receipt` implementations (Correction 5).
      *Test intent:* a v2 predicate handed to the v1 rule fails as `UnknownVersion`, naming the
      version, not as `InvalidSignature`. Paired control: a genuine v1 predicate with no version
      field still returns `Ok`.

- [ ] **Step 4 — Failing test: "right result, wrong route" is refused, with its allowed control.**
      Write `rust/evidence/tests/causal_verdict.rs` before `causal_verdict` exists. Build a three-hop
      chain — `github.create_pr` → `github.comment` → `github.request_review` — whose final outcome
      is permitted and whose middle hop uses a tool absent from
      `authority.effective_capabilities`. Assert `causal_verdict` returns
      `Err(CausalRefusal::UnauthorizedHop { index: 2, .. })` and that the rendered message names the
      handle and the tool. **Pair it with the control in the same test file:** the identical chain
      with all three tools granted must return `Ok`. Add a second refusal case —
      `OrderBroken { index, missing }` — where a hop's `depends_on` names a handle no earlier step
      minted, with its own well-formed control. Follow the pattern
      `harness::refused_at_the_boundary` uses in
      `rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs:89–98`: refusal and
      acceptance in one call, so a verifier that refuses everything cannot pass.
      *Test intent:* four assertions, two refusals and two acceptances. Per the blueprint's F-02 gate
      at master:4283, extend the refusal case across effect classes using `SideEffectClass` at
      `rust/authority-spec/src/lib.rs:42` — `Read`, `Write`, `Financial`, `Destructive`, `Physical`.

- [ ] **Step 5 — The chain in the signed bytes: `Causality`, built from the queue that already
      exists.** Add `pub causality: Option<Causality>` to `WarPredicate` and
      `StagingQueue::causal_trace()` to `rust/warrant/src/staging.rs`, built on `release_order()`
      (`:473`) so the order in the signature is the topological order the settle engine will actually
      use, and carrying `head_digest()` (`:459`) as `queue_head` so the predicate is pinned to the
      hash-chained log rather than to a re-listing of it. Populate `Outcome.effects` from the same
      trace — it is `Vec::new()` today at `rust/warrant/src/report.rs:923`. Every field goes through
      `canonical_predicate` (`:255`), so `steps` is a `Vec` whose index order is signed. `Option`
      rather than a defaulted empty struct, for the reason `report.rs:614–616` already gives about
      `spend`: "no queue was read" and "a queue was read and it was empty" are different claims.
      *Test intent:* a predicate whose `causality.queue_head` does not match the queue's real head
      is refused. Control: the matching pair verifies.

- [ ] **Step 6 — Failing test: reordering the effect sequence breaks the signature.** Take a signed
      v2 predicate, swap `causality.steps[0]` and `causality.steps[1]`, re-serialize, and assert
      `evidence::verify_receipt` returns `InvalidSignature`. Then do the harder version, the one that
      actually matters: **re-sign** the reordered predicate with a valid attacker key, prove the
      forgery's own signature verifies, and assert `causal_verdict` still refuses it with
      `OrderBroken`. This is the discipline
      `i07_evidence_precedes_commitment.rs:64–88` established — an unsigned forgery is refused for
      being unsigned and never reaches the gate under test, producing a green result that proves
      nothing.
      *Test intent:* ordering is protected twice — by the signature against an editor, and by
      `causal_verdict` against a re-signer. Control: the unswapped predicate verifies and passes.

- [ ] **Step 7 — `causal_verdict` over the chain, replacing nothing.** Implement it as a separate
      function returning `Result<(), CausalRefusal>`, never folded into `Verdict` or
      `evidence::Verdict`. `decision.verdict` stays exactly what the notary decided; the causal
      verdict is additional. A single field cannot carry both without losing which one refused, and
      "which one refused" is the whole product value here. Handle the v1 case explicitly:
      `causal_verdict` on a predicate with no `causality` section returns
      `Err(CausalRefusal::Unrepresentable { predicate_version })` — a named refusal, not a pass and
      not an error. **No claim without a mechanism:** the `Unrepresentable` variant's message must
      say what is missing, and must not imply the pathway was checked and found clean.
      *Test intent:* a v1 predicate yields `Unrepresentable` naming its version; an `Allow` outcome
      with an unauthorized hop yields `UnauthorizedHop`; a `Deny` outcome with a clean route still
      yields `Ok` from `causal_verdict`, proving the two verdicts are genuinely independent.

- [ ] **Step 8 — Assess the Task 5.1 corpus honestly, and expect to convert nothing.** Three
      `#[ignore]`s are candidates. Read them and report, do not assume:
      `i07_evidence_precedes_commitment.rs:159` —
      `#[ignore = "I-07 orphaned: the product never issues a pre-commit receipt (Task 1.1 / Task 2.3, 2026-09-02)"]` —
      asserts `harness::occurrences_in_rust_sources("rust/warrant/src", "issue_pre_commit") > 0`.
      Task 10.1 does not call `issue_pre_commit`; **this does not convert.**
      `i04_current_policy.rs:115` asserts `notary::verdict(` appears more than once in
      `rust/warrant/src`. Task 10.1 adds no evaluation point; **this does not convert.**
      `i04_current_policy.rs:85` asserts `post_commit.predicate.decision.evaluated_at !=
      pre_commit.predicate.decision.evaluated_at` and lives entirely inside `rust/evidence`, so it is
      *reachable* — but its finding is Task 2.3's commit-time re-evaluation, not causality, and
      claiming it here would mean changing `issue_post_commit` for a reason this task does not own.
      **Leave all three ignored.** Write in the evidence file that nothing converted and why, in
      those words. `tools/ci/invariant-ratchet.json` keeps `passing_floor: 65` and
      `ignored_ceiling: 19`. If the new suites happen to make a corpus test pass, raise the floor in
      the **same commit** — never weaken an assertion to earn a number.
      *Test intent:* `python tools/ci/check_invariant_ratchet.py` prints
      `invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)`, unchanged.

- [ ] **Step 9 — Write the honest tier into the product text and the gaps ledger.** Add the Bound
      strength paragraph above, verbatim, to `limitations()` at `rust/warrant/src/report.rs:463`
      beside the seven that already say what each bound does not cover. Add a Tier 5 row to
      `docs/W1-delivery-gaps.md` for the causal verdict recording Tier C / observed, and update the
      I-04 row (`:1106`) and I-07 row (`:1109`) only to note that Task 10.1 landed the verdict and
      neither invariant moved. **No claim without a mechanism** applies to every string this task
      writes: no comment, log line, error message or generated file may say "pathway proven",
      "route verified" or "causally enforced". Grep for it before committing.
      *Test intent:* a source-text assertion in the causal suite, in the style of
      `harness::source_contains`, that fails if `report.rs` ever loses the tamper-evident sentence —
      and a second that fails if the words "prove the pathway" appear anywhere under `rust/`.

- [ ] **Step 10 — Cross-language parity for the version read.** `python/warrantor_evidence` verifies
      predicates too. Its canonicalizer is dict-generic — `canonical_receipt_body` in
      `python/warrantor_notary/src/warrantor_notary/__init__.py:59` serializes whatever keys the dict
      has — so a v2 predicate canonicalizes correctly in Python **without edits**, which is the
      hazard: it will happily verify a v2 signature while knowing nothing about the version field or
      the causal section. Add the `predicate_version` read and the `UnknownVersion` error to the
      Python verifier so the two languages refuse the same inputs, and extend the interop bundle so
      Python verifies a v1 and a v2 receipt in the same run.
      *Test intent:* `python -m pytest python/warrantor_evidence python/warrantor_notary` passes, and
      an unknown-version predicate raises in Python with the same error code Rust returns. A parity
      test that only checks the happy path is the one this repository already learned to distrust.

- [ ] **Step 11 — Gates for every language touched, evidence file, `git commit -s`.** Run the Rust
      gate (`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` for the workspace) and
      the Python gate (`python tools/ci/run_python_checks.py`), because both were touched. Re-run
      `python tools/ci/wiring_census.py` and confirm `9 of 39 … over 17 path edges`,
      `python tools/ci/check_invariants.py` and confirm `enforced=2, orphaned=2, partial=7,
      unimplemented=1`, and `python tools/ci/check_invariant_ratchet.py` and confirm `65 / 65, 19 /
      19`. Note in the evidence file that the CI annotation reports only the jobs that ran, so a
      green summary is not proof the Python gate executed. Write
      `docs/task-evidence/task-10.1.md` with the exit gate quoted verbatim from this task, the real
      command output beside it, the five premise corrections with their file and line numbers, and
      the three-canonicalizer finding handed forward. Commit with `git commit -s` — the DCO gate
      rejects an unsigned commit.
      *Test intent:* the exit-gate command from this task, pasted with its real output, is the last
      thing in the evidence file. If its output does not show the two archive suites at 7-passed-2-
      ignored and 6-passed, the task is not done regardless of what else is green.

- [ ] **Step 12 — Hand forward what this task deliberately did not do.** Three items, written into
      the evidence file as named handoffs rather than left in a commit message. (a) Task 10.2 may now
      freeze a query schema against `predicate_version` and `Causality`; tell it the version field is
      the first key in canonical order and the section is `Option`, so "absent" and "empty" are
      distinguishable. (b) Task 2.3 inherits both `i04` `#[ignore]`s and, from this task, a
      `Causality` section that will need a commit-time `decision` block to stop copying the
      pre-commit's `evaluated_at`. (c) There are now three independent canonical-JSON
      implementations — `rust/notary/src/lib.rs:453`, `rust/evidence/src/lib.rs:255`,
      `rust/post-quantum/src/lib.rs:328` — against spec 11 §1's rule that no security invariant may
      have two authoritative implementations. This task did not add a fourth and did not consolidate
      the three. Name that as an open finding with its three line numbers.
      *Test intent:* none. This step's product is three named handoffs in the evidence file, each
      pointing at a task ID and a file:line, so the next lane does not rediscover them by reading
      901 lines the way this one did.

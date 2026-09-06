### Task 10.6: Chain of custody, trace escrow, and the independent-investigator access mode (L7-08, L7-18, L7-15)

**Anchor.** Three catalog items, all `status=none`, all `novel`, all W3, all Plane G. Quoted verbatim
from `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html`.

L7-08, line 4360, "Chain-of-custody for evidence handoff":

```html
  <article class="item" id="L7-08" data-stratum="L7" data-plane="G" data-status="none" data-novelty="novel" data-wave="W3" data-loop="L2">
```

> Receipts that survive transfer between organizations, vendor to customer, customer to supervisor,
> insured to insurer, with custody transitions themselves evidenced, and a dispute lifecycle in which
> a challenged receipt freezes, both parties' evidence binds, and the resolution chains to the
> original digest. (line 4364)

Its verification clause, line 4367: *"A disputed receipt is undeletable for the dispute duration; a
custody transition missing from the chain fails verification at the receiving party."* Its anchor
names the record this task exists because of, line 4366: *"The investigators did not see OpenAI's
report before publication and it was out of scope to confirm its claims (S02 p.4): custody between
parties was a bespoke arrangement, not a protocol."*

L7-18, line 4557, "Trace escrow and the investigator enclave", verification clause at line 4564:

> An investigator obtains a scoped trace set through escrow with no operator in the loop and the
> release is receipted; every enclave output verifies against its provenance record; enclave
> credentials expire with the engagement. Blueprint proof gate (G-05): Scoped release exercised
> without exposing unrelated tenant data.

L7-15, line 4521, "Independent-investigator access mode", verification clause at line 4528:

> An investigator's every read is a receipt in the same chain; access expires without action; the
> investigator can verify the scope they were given against the scope they were promised.

All three carry the same recorded residual, lines 4529 and 4565, and it is not softened here:
*"residual (G-05): Escrow concentrates sensitive data; its own compromise is catastrophic."*

**The operator who runs the system is the operator who holds its evidence.** An investigator who must
ask that operator for the trace has no independent access at all. That is the whole task, and the
honest limit of what this repository can build against it is stated in Bound strength rather than
designed around.

---

**Premise contradicted — six corrections, two confirmations.** The seed's Step 0 and Step 7 both point
at things that are not where it says they are, and its Step 2 instructs a stop that would be wrong.
Every correction below was found by reading, and the code wins.

*Correction 1 — `retention.rs` is not in `rust/archive/`.* The seed's Step 0 says "Read `retention.rs`"
in a paragraph otherwise about the archive. There is exactly one:

```
$ find . -name 'retention*' -not -path './.git/*'
./rust/warrant/src/retention.rs
```

`rust/archive/` has a `RetentionPolicy` — `rust/archive/src/store.rs:170` — but it is a different type
in a different crate about a different thing (per-`ArtifactKind` deletion authority on the server,
versus `PrunePolicy` over a local store). Both are read below; they must not be conflated.

*Correction 2 — Step 7's `Coverage` is a category error.* The seed says to assert the coverage surface
"via `harness.rs`'s `Coverage`". `Coverage` exists, but not in
`rust/warrant/tests/invariants/harness.rs`:

```
$ grep -rn "struct Coverage\|enum Coverage" --include=*.rs rust/
rust/warrant/src/harness.rs:67:pub enum Coverage {
$ grep -rn "Coverage" rust/warrant/tests/invariants/
$ echo $?
1
```

And `warrant::harness::Coverage` is about which of an **agent harness's** tool calls traverse the MCP
proxy — `McpOnly`, `McpAndBuiltins(&'static str)`, `ProcessOnly`, `rust/warrant/src/harness.rs:67–74`.
It has nothing to do with evidence coverage. Reusing it for "what escrow does not cover" would put a
sentence about `bash` escaping the proxy into an escrow release. What this task should actually reuse is
the honest-disclosure *pattern* from two counted fields in `rust/warrant/src/retention.rs`:

```rust
// rust/warrant/src/retention.rs:443
    pub default_subjects: usize,
// rust/warrant/src/retention.rs:479
    pub unwitnessed_chains: usize,
```

whose doc at lines 476–478 is the register this task's coverage struct must be written in. Restated
rather than block-quoted, because that doc predates the US-English gate and quoting it verbatim would
import a spelling the gate refuses and a verbatim quote forbids me to edit: for a warrant with no
staged-chain witness, a deleted staged log reads as an empty queue, and the count exists because *"we
cannot prove it for this many"* is the honest form of the answer. That is the sentence pattern, and
`Coverage::sentence()` at `rust/warrant/src/harness.rs:79` is the rendering pattern. Both are borrowed;
neither type is.

*Correction 3 — Step 2's "Stop if not" is wrong, and Task 10.1 has not landed.* The seed says
"Confirm Task 10.1 landed and its chain shape is frozen. Stop if not." Task 10.1 has not landed — local
`main` is at `b04164d` and carries no causal verdict — and stopping would be the wrong call, because
**custody does not bind to a struct shape at all.** See Consumes / Produces. The archive's own rule
settles it: *"the digest must be over the bytes as filed"*
(`rust/archive/tests/verification_does_not_depend_on_the_archive.rs:355`). A custody record over the
filed bytes is stable under any change to `ReceiptBody` or `WarPredicate`, because it never rebuilds
either. Task 10.1's already-expanded section confirms it changes neither in a way that matters here: it
adds `predicate_version` to `WarPredicate` and `#[serde(deny_unknown_fields)]` to
`notary::ReceiptBody`, and explicitly declares **"No `notary::ReceiptBody` v2"**.

*Correction 4 — `origin/main` is stale, so Step 1's base is wrong.*

```
$ git log --oneline -1 refs/remotes/origin/main
e4b5f10 Merge branch 'feat/invariant-ledger'
$ git log --oneline -3 main
b04164d Merge branch 'ci/us-english-gate'
eef1c71 ci: gate US English on the lines a branch adds
f99af94 Merge branch 'feat/task-1.5-one-delegation-algebra' (Task 1.5)
```

Branch from local `main`. Branching from `origin/main` would build custody on a tree without the Task
1.1 mode-escalation correction, which is the single most relevant precedent this task has.

*Correction 5 — `rust/archive` is an orphan crate, and the seed's Files list puts the whole task inside
it.* Verified:

```
$ python tools/ci/wiring_census.py
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
$ python -c "import json; print('warrantor-archive' in json.load(open('evidence/wiring-coverage.json'))['orphaned'])"
True
```

The reachable ten are `warrantor-api`, `warrantor-authority-spec`,
`warrantor-containment-conformance`, `warrantor-delegation-chain`, `warrantor-egress`,
`warrantor-evidence`, `warrantor-notary`, `warrantor-spend`, `warrantor-trust-core`,
`warrantor-warrant`. An investigator-verify path built only in `rust/archive/` is a path nothing a user
runs can reach. **The verification primitive therefore goes in `rust/evidence` (reachable);
`rust/archive` gets the store hook and one off-the-archive test.** This is the same reasoning Task 10.1
used to put the chain in the evidence predicate rather than in one of ten sibling `issue_receipt`
implementations.

*Correction 6 — the seed's Exit gate overclaims, and the overclaim is the one this task must not ship.*
The seed requires: *"any selective withholding breaks a chain and the break is detectable by the
investigator with no privileged access."* That is true of withholding a **member of an enumerated set**
and false of withholding the **enumeration**. An offline verifier holding one file cannot distinguish
deleted evidence from a run that never happened, because the missing thing is missing. This is not a
guess; it is already the recorded conclusion of two independent readings in this repository.
`rust/warrant/src/operators.rs:539–542`, on the existing hash-chained actor log:

```rust
/// Hash-chained: each line carries the previous line's digest, so a removed or edited line is
/// detectable to anyone holding a later copy of the chain. That is the guarantee, and it is smaller
/// than a signature: it proves nothing to a third party who has never seen an earlier head.
```

And Task 5.3's expansion, in flight, reached the same finding independently for its Strategy A7:
*"Strategy 7 (suppression and truncation) is `Unrepresentable`: an offline verifier holding one file
cannot distinguish a run whose evidence was deleted from a run that never happened."* **"The operator
cannot suppress a trace" is not achievable here and this task does not claim it.** What is achievable
is stated precisely in Bound strength, and the difference between the two is the entire honest content
of this task.

*Confirmed 1.* The seed is exactly right that append-only guarantees already exist and that
`verification_does_not_depend_on_the_archive.rs` is the shape the access mode should extend. Both are
captured verbatim in Step 0.

*Confirmed 2.* The seed is exactly right that escrow and retention conflict by construction, and Task
10.4's already-seeded Exit gate already owns the enforcement half: *"a retention deletion that would
remove escrowed evidence is refused."* The resolution is recorded in Step 0 rather than re-designed
here.

---

**Step 0.** Every command below was run on local `main` at `b04164d` in a detached scratch worktree.
Output is verbatim.

*(a) The crate inventory, because a task that assumes an absent crate dies at its first cargo call.*

```
$ git ls-tree --name-only main rust/ | wc -l
46
$ python -c "<count package.name across rust/*/Cargo.toml>"
total 40
REACHABLE: ['warrantor-api', 'warrantor-authority-spec', 'warrantor-containment-conformance',
 'warrantor-delegation-chain', 'warrantor-egress', 'warrantor-evidence', 'warrantor-notary',
 'warrantor-spend', 'warrantor-trust-core', 'warrantor-warrant']
```

Forty packages; forty-six tree entries because `Cargo.toml`, `Cargo.lock`, `README.md` and three
`Dockerfile.*` sit beside them. There is no `rust/guard`. Guard work lives in `rust/eval-guard` and
`python/warrantor_ml`, and neither is touched here.

*(b) The three archive suites, which are the regression floor this task may not lower.*

```
$ cargo test -p warrantor-archive --test append_only --test verification_does_not_depend_on_the_archive --test the_archive_never_serves_a_verdict
     Running tests\append_only.rs
running 9 tests
test the_database_itself_refuses_an_update_to_a_filed_artifact ... ignored, needs Postgres and the archive_admin URL: make archive-up, then make archive-test
test the_runtime_role_holds_no_update_or_delete_grant_on_artifact ... ignored, needs Postgres and the archive_runtime URL: make archive-up, then make archive-test
test retention_defaults_to_no_deletion_authority_at_all ... ok
test the_migration_enforces_append_only_twice_and_grants_no_write_back ... ok
test the_ignored_database_tests_are_the_number_the_docs_claim ... ok
test the_store_trait_offers_no_way_to_update_or_delete_an_artifact ... ok
test the_threat_model_names_no_mitigation_this_crate_does_not_implement ... ok
test resubmitting_identical_bytes_is_idempotent_and_never_rewrites_the_first_submitter ... ok
test different_bytes_under_one_warrant_create_a_second_artifact ... ok
test result: ok. 7 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.15s

     Running tests\the_archive_never_serves_a_verdict.rs
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s

     Running tests\verification_does_not_depend_on_the_archive.rs
running 6 tests
test the_archive_holds_exactly_the_three_formats_warrantor_verify_reads ... ok
test fixtures_are_self_consistent ... ok
test the_anchored_check_refuses_a_genuine_bundle_pinned_to_the_wrong_key ... ok
test the_archive_returns_the_bytes_it_was_given_and_the_digest_proves_it ... ok
test a_client_verifies_an_exported_bundle_with_no_archive_in_the_process ... ok
test a_malicious_archive_cannot_make_a_tampered_bundle_verify ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s
```

*(c) What append-only guarantees exist today, and at which tier.* Four mechanisms, and the crate's own
doc is exact about the limit of each. `rust/archive/src/lib.rs:44–56`:

> Nothing here updates or deletes an artifact. That is enforced twice in
> `migrations/0001_initial.sql` — a `BEFORE UPDATE OR DELETE` trigger and a runtime role with no
> `UPDATE`/`DELETE` grant — because a grant can be misconfigured by an operator and a trigger cannot.
> [...] It is worth being exact about the limit. Append-only is a property of the *application role*,
> not of the storage: whoever owns the database can delete rows out of band, and no trigger stops them.
> What actually carries the custody guarantee is that the artifacts are independently verifiable off
> this archive, against an anchor the reader pinned.

| Mechanism | Where | Tier | What it does not cover |
|---|---|---|---|
| Trait shape: no `update`/`delete` method exists | `rust/archive/src/store.rs:200` trait `ArchiveStore`; asserted at `tests/append_only.rs:193` | **Tier A** for "a caller cannot ask" — the method does not exist to call | Nothing about the database beneath it |
| `BEFORE UPDATE OR DELETE` trigger | `migrations/0001_initial.sql`; asserted `tests/append_only.rs:304`, exercised `:466` (`#[ignore]`) | **Tier A** at the database, against any role including the owner | The database owner can drop the trigger |
| Runtime role holds only `INSERT, SELECT` | asserted `tests/append_only.rs:308`; exercised `:548` (`#[ignore]`) | **Tier A** for the process the server runs as | A misconfigured grant; hence the trigger |
| Idempotence on digest, first submitter keeps attribution | `tests/append_only.rs:106–141` | **Tier A** — `PutOutcome::AlreadyHeld`, never an overwrite | Task 5.3 Strategy A8 attacks exactly this; see Non-goals |

*(d) Retention today, defaulted off.* `rust/archive/src/store.rs:196–199` is the mechanism the escrow
seal must compose with, not replace:

```rust
    #[must_use]
    pub fn deletes_anything(&self) -> bool {
        self.enabled && self.window_seconds.is_some_and(|w| w > 0)
    }
```

`tests/append_only.rs:226` asserts all three failure readings: disabled by default,
enabled-with-no-window grants nothing, zero window grants nothing.

*(e) The escrow-versus-retention resolution, recorded rather than re-designed.* Task 10.4's seeded Exit
gate already reads: *"a retention deletion that would remove escrowed evidence is refused."* So the
split is: **10.6 produces the seal predicate; 10.4 enforces the refusal against it.** 10.6 ships
`is_sealed(digest) -> bool` on the store seam and a test that a sealed digest reports sealed. 10.6 does
**not** add a refusal to any deletion path, because no deletion path exists in `ArchiveStore` to add
one to — the trait has no delete method, which is what `tests/append_only.rs:193` guarantees. If 10.4
lands a deletion path, its own Exit gate obliges it to consult the seal. Recorded; not stopped.

*(f) Task 10.1's status and shape.* Not landed; branch `feat/causal-verdict`. Its expansion's Files
table reads:

```
| `rust/notary/src/lib.rs` | `#[serde(deny_unknown_fields)]` on `ReceiptBody` only. **No new field. No v2 body.** |
```

and its Step 3 adds `pub predicate_version: String` as the first field of `WarPredicate`. That changes
the canonical bytes of a **newly built** predicate and changes nothing about bytes already filed.

*(g) The existing hash-chained custody log, which is the shape to extend.* `ActorRecord` at
`rust/warrant/src/operators.rs:492–513` carries `prev` (line 510) and `digest` (line 512), and its head
crosses into signed evidence as `CustodySection.head` at `rust/warrant/src/report.rs:283`. The
section's doc, `report.rs:269–273`, states the disclosure decision this task inherits:

> **What crosses into signed evidence is the head digest, not the acts.** [...] Copying the acts
> themselves in would put operator names inside an artifact that gets handed to third parties, which is
> a disclosure decision nobody asked for and one this bundle could not un-make.

*(h) The three ratchets, unchanged and to stay unchanged.*

```
$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
$ python tools/ci/wiring_census.py
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
```

*(i) The word "investigator" does not appear in any Rust source.*

```
$ git grep -ci "investigator" main -- 'rust/**/*.rs'
$ echo $?
1
```

Zero hits, exit 1. Nothing is being renamed; this is new surface.

---

**Non-goals.** Each names the task that owns the excluded thing.

1. **Not the causal verdict and not `ReceiptBody`'s shape — Task 10.1** (L7-01). Custody records the
   handoff of bytes; it does not compute what those bytes mean. This task adds no field to
   `notary::ReceiptBody` and no field to `WarPredicate`, and its fixtures are frozen bytes precisely so
   that 10.1's `predicate_version` cannot break them.
2. **Not production evidence-integrity monitors — Task 10.3** (L7-14, L7-19). Everything here is an
   offline verifier over presented files. Nothing emits a runtime alert, and the truncation limit this
   task records is handed to 10.3 by name, whose seeded anchor is *"the monitors must be able to fail
   loudly about the store they live in, which means they cannot live only in it."*
3. **Not retention or jurisdiction policy — Task 10.4** (L7-12, L7-10). 10.6 produces the seal
   predicate; 10.4 enforces deletion refusal against it. 10.6 adds no deletion path and no jurisdiction
   dimension.
4. **Not the offline adversary corpus — Task 5.3, in flight.** Its Strategy A8 already attacks
   first-submitter attribution in `MemoryStore` at `rust/archive/tests/append_only.rs:106`, and its
   Strategy A7 already records suppression as `Unrepresentable`. This task does not add an adversary
   strategy, does not edit `rust/warrant/tests/invariants/`, and does not create
   `rust/archive/tests/adversary_custody.rs` — that path is 5.3's.
5. **Not the investigator's user interface — Task 11.9** (L8-06, L8-28), whose seeded Step 0 reads *"the
   portal must not be able to show a filtered view that verifies, which is 10.6's cryptographic
   property, not a UI permission."* This task produces that property and no pixels.
6. **Not a hosted escrow service, and not a defender enclave.** L7-18 names an on-premises forensic
   enclave with revocable credentials. That is infrastructure, not a verifier, and nothing in this
   repository provisions it. The escrow here is a local sealed manifest plus an out-of-band sequence
   pin, and Bound strength states exactly what that does and does not establish.

---

**Files.**

| Path | Lines today | What this task does |
|---|---|---|
| `rust/evidence/src/custody.rs` | — | **New.** The custody chain, the sealed manifest, `verify_release`, `ReleaseCoverage`. In the reachable crate, per Correction 5. |
| `rust/evidence/src/lib.rs` | 1163 | Add `pub mod custody;` and two `EvidenceError` variants at the enum on line 212. No change to `WarPredicate`, `Binding` or any canonical rule. |
| `rust/evidence/tests/custody_and_escrow.rs` | — | **New.** Every refusal with its allowed control. |
| `rust/archive/src/store.rs` | 520 | Add `fn is_sealed(&self, digest: &str) -> Result<bool, StoreError>` to `ArchiveStore` and `MemoryStore`. **No update, no delete** — `tests/append_only.rs:193` is the arbiter. |
| `rust/archive/tests/escrow_release_verifies_off_the_archive.rs` | — | **New.** One suite, no `#[ignore]`. **Must be added to the hardcoded `files` array at `rust/archive/tests/append_only.rs:360–375` with `EXPECTED` left at 3.** |
| `rust/warrant/src/report.rs` | 1200+ | Add `escrow: Option<EscrowSection>` to `ReportBundle` with `skip_serializing_if`, and one sentence to `limitations()` at `:545`. |
| `rust/warrant/tests/report.rs` | — | Assert a v1 bundle's `bundle_digest` is byte-unchanged by the new optional field, and that the limitation ships. |
| `docs/task-evidence/task-10.6.md` | — | **Required.** Step 0 verbatim, the three ratchet lines before and after, and the product sentence as shipped. |
| `docs/rfcs/W2-evidence-archive.md` | — | The seal and the truncation limit, in the threat model. Watch `tests/append_only.rs:408` — a mitigation named here with no call site fails the build. |

`rust/warrant/tests/invariants/` is **read-only** in this task. `rust/archive/src/http.rs` is
**contended** with Task 10.3 and is not edited here.

---

**Consumes / Produces.**

Consumes, all present on local `main` at `b04164d`:

```rust
// rust/archive/src/lib.rs:94 — the one digest implementation, delegating to warrant's
pub fn sha256_hex(bytes: &[u8]) -> String
// rust/warrant/src/report.rs:456
pub fn sha256_hex(bytes: &[u8]) -> String
// rust/evidence/src/lib.rs:126 — the chain field custody reads and never writes
pub struct Binding { pub receipt_id: String, pub phase: Phase,
                     pub parent_receipt: Option<String>, pub nonce: String,
                     pub issued_at: u64, pub expires_at: u64,
                     pub enforcement_mode: EnforcementMode }
// rust/evidence/src/lib.rs:194
pub struct SignatureEnvelope { pub algorithm: String, pub key_id: String,
                               pub public_key: String, pub value: String }
// rust/evidence/src/lib.rs:478
pub fn verify_receipt(receipt: &WarReceipt) -> Result<(), EvidenceError>
// rust/evidence/src/lib.rs:554
pub fn verify_chain(pre_commit: &WarReceipt, post_commit: &WarReceipt) -> Result<(), EvidenceError>
// rust/notary/src/lib.rs:336 — read, never modified
pub struct ReceiptBody { pub verdict: Verdict, pub actor_svid: String,
                         pub operation_class: String, pub timestamp: u64,
                         pub enforcement_mode: EnforcementMode,
                         pub notary_version: String }
// rust/notary/src/lib.rs:434
pub fn receipt_digest(body: &ReceiptBody) -> [u8; 32]
// rust/warrant/src/report.rs — anchor-free by construction, which is why the anchored form exists
pub fn verify_export(report: &SignedReport) -> Result<(), ReportError>
pub fn verify_export_signed_by(report: &SignedReport, anchor: &VerifyingKey) -> Result<(), ReportError>
// rust/warrant/src/report.rs:279 — the head-only disclosure precedent
pub struct CustodySection { pub acts: usize, pub head: Option<String>,
                            pub chain_intact: bool, pub approvers: usize,
                            pub approvals_required: usize }
// rust/warrant/src/operators.rs:492 — the hash-chain shape to extend
pub struct ActorRecord { pub format: String, pub warrant_id: String, pub act: Act,
                         pub actor: Option<String>, pub via: String, pub at: u64,
                         pub prev: String, pub digest: String }
// rust/archive/src/store.rs:200
pub trait ArchiveStore { fn put_artifact(..) -> Result<PutOutcome, StoreError>; .. }
```

**Does custody bind to the v1 `ReceiptBody` or to Task 10.1's shape? Neither.** It binds to the filed
bytes and their SHA-256, and to two field *names* on `Binding` (`receipt_id`, `parent_receipt`, lines
127 and 131) that 10.1 does not rename. Task 10.1 has **not landed**. What breaks if 10.1 lands first:
**nothing in the custody digest, and exactly one thing in the fixtures.** A custody fixture that
*rebuilds* a `WarPredicate` and hashes the result will change digest the moment `predicate_version`
becomes the predicate's first field. Every fixture in this task therefore freezes bytes as `const`
string literals and never recomputes, which is the same discipline Task 10.1's own Step 2 requires of
its canonical vectors: *"A fixture that recomputes the canonical form proves nothing about a format
change, because it recomputes it under the new rule."* If 10.6 lands first, 10.1 needs no change here
either — `#[serde(deny_unknown_fields)]` on `ReceiptBody` cannot break a verifier that never
deserializes one.

Produces, all new:

```rust
// rust/evidence/src/custody.rs
pub const CUSTODY_FORMAT: &str = "warrantor.custody-act/1";
pub const MANIFEST_FORMAT: &str = "warrantor.escrow-manifest/1";

/// One evidence handoff. `prev` chains it; `digest` is over every field above `digest`.
pub struct CustodyAct { pub format: String, pub artifact_digest: String,
                        pub from_party: String, pub to_party: String,
                        pub purpose: String, pub at: u64,
                        pub prev: String, pub digest: String }
pub struct CustodyHead { pub acts: usize, pub head: Option<String>, pub chain_intact: bool }
pub fn append_act(prior: Option<&CustodyAct>, artifact_digest: &str, from_party: &str,
                  to_party: &str, purpose: &str, at: u64) -> CustodyAct;
pub fn verify_custody_chain(acts: &[CustodyAct]) -> Result<CustodyHead, EvidenceError>;

/// The enumeration. `sequence` is monotone per escrow; `prev_manifest` chains generations.
pub struct EscrowManifest { pub format: String, pub sequence: u64,
                            pub members: Vec<String>, pub custody_head: Option<String>,
                            pub prev_manifest: String, pub sealed_at: u64 }
pub struct SealedManifest { pub manifest: EscrowManifest, pub signature: SignatureEnvelope }
pub fn seal(manifest: EscrowManifest, key: &SigningKey, key_id: &str) -> SealedManifest;

/// What an investigator receives: the seal, the custody chain, and the bytes.
pub struct Release { pub sealed: SealedManifest, pub custody: Vec<CustodyAct>,
                     pub artifacts: BTreeMap<String, Vec<u8>> }

pub enum ReleaseRefusal {
    MemberWithheld { digest: String, sequence: u64 },
    DigestMismatch { claimed: String, actual: String },
    ManifestSignature(String),
    ManifestNotSignedByAnchor { pinned: String, presented: String },
    CustodyChainBroken { index: usize, expected: String, found: String },
    CustodyHeadMismatch { manifest_says: Option<String>, chain_says: Option<String> },
    TruncatedBelowPin { pinned: u64, presented: u64 },
}

/// What the release DOES and DOES NOT establish. `not_covered` is never empty.
pub struct ReleaseCoverage { pub members: usize, pub verified: usize,
                             pub manifest_sequence: u64, pub tail_pinned: bool,
                             pub not_covered: Vec<&'static str> }
impl ReleaseCoverage { pub fn sentence(&self) -> String; }

pub fn verify_release(release: &Release, anchor: &VerifyingKey,
                      pinned_sequence: Option<u64>) -> Result<ReleaseCoverage, ReleaseRefusal>;

// rust/evidence/src/lib.rs — two variants added to the existing enum at :212
    #[error("custody chain broken at act {0}")] CustodyChain(usize),
    #[error("escrow manifest malformed: {0}")] Manifest(String),

// rust/archive/src/store.rs — one read method on the trait, and one write that marks
    fn is_sealed(&self, digest: &str) -> Result<bool, StoreError>;
    fn seal(&mut self, digest: &str, manifest_sequence: u64, at: u64) -> Result<(), StoreError>;

// rust/warrant/src/report.rs — an OPTIONAL section, so v1 bundle digests are unchanged
pub struct EscrowSection { pub manifest_sequence: u64, pub members: usize,
                           pub custody_head: Option<String>, pub sealed_by_key_id: String }
```

**No new trust root.** There is no escrow service, no notary-of-notaries, no neutral third party, and no
network call anywhere in `verify_release`. The escrow is a local file the operator produces and the
sequence pin is a **number the investigator wrote down**, obtainable two ways that already exist: from a
prior release the investigator holds (sequence is monotone, so a second release presenting a lower one
is refused), or from a `CustodySection.head` already inside a separately-held signed report. What this
establishes: any release at or below a sequence the investigator has independently seen is complete
relative to its own manifest, and any custody gap in it is detectable offline. What it does **not**
establish: anything at all about the first release an investigator ever receives, and nothing about
generations the operator sealed and never disclosed.

---

**Bound strength.** Split three ways, because one label over these three properties would be a lie.

**Tier A — cryptographic, refused at the moment of attempt.** Three properties. (1) *Tamper-evidence of
an escrowed artifact*: the manifest member list is SHA-256 digests inside an Ed25519-signed manifest, so
an altered artifact fails `DigestMismatch` at the line that recomputes it, and an altered manifest fails
`ManifestSignature`. (2) *Withholding a member of a disclosed manifest*: a release carrying fewer
artifacts than its manifest enumerates is refused with `MemberWithheld` naming the missing digest — the
verifier returns `Err`, it does not warn. (3) *A missing custody transition*: `verify_custody_chain`
refuses `CustodyChainBroken` when act *n*'s `prev` is not act *n−1*'s `digest`, which is L7-08's
verification clause, *"a custody transition missing from the chain fails verification at the receiving
party,"* made executable. All three are conditional on the investigator holding the issuer key out of
band — `verify_export` is anchor-free by construction and
`rust/archive/tests/verification_does_not_depend_on_the_archive.rs:292` already asserts in both
directions that a bundle signed end to end by any keypair passes it. `verify_release` therefore takes
`anchor: &VerifyingKey` as a required argument, not an option.

**Tier C — observed, and in one case not even that.** *Completeness of the manifest itself.* Nothing
here proves the operator escrowed everything. An operator who never sealed a trace produces a release
that verifies perfectly and omits it, and no examination of the release reveals the omission. The one
partial mitigation is `TruncatedBelowPin`, and it fires only when the investigator supplies a
`pinned_sequence` from a source outside this release — so it is Tier A **at and below the pin** and gives
nothing above it or before it. `ReleaseCoverage.not_covered` is never empty and
`ReleaseCoverage::sentence()` renders it, in the register `Coverage::sentence()` uses at
`rust/warrant/src/harness.rs:79`.

**Not Tier A: the store.** `rust/archive`'s append-only is Tier A at the trigger and Tier A for the
runtime role's grants, and the crate's own doc is right that *"whoever owns the database can delete rows
out of band, and no trigger stops them"* (`rust/archive/src/lib.rs:50–52`). The seal is a marker a
retention pass consults, not a lock. **`is_sealed` refuses nothing.** Task 10.4 owns any refusal built
on it. There is no netns, seccomp or firewall anywhere in this repository and nothing in this task adds
one; no bound here is claimed at the operating system.

**The sentence that appears in the product**, added to `limitations()` at
`rust/warrant/src/report.rs:545` alongside the existing set:

> Escrowed evidence is tamper-evident and its disclosed set is complete: an altered artifact, an altered
> manifest, a missing custody transition or a withheld member of a sealed manifest each fail
> verification at the receiving party, offline, against a key that party pinned. **This does not prove
> everything was escrowed.** The manifest says what was sealed, and nothing in a release says what was
> not. An operator who never sealed a trace produces a release that verifies and omits it, and a release
> truncated at its most recent generation is indistinguishable from a release that is current unless you
> already know a later sequence number. Read a release as complete relative to its own manifest, never
> as complete relative to what happened.

**No claim without a mechanism.** Every clause above has one: `ReleaseRefusal::MemberWithheld`
(refusal), `ReleaseRefusal::CustodyChainBroken` (refusal), `ReleaseRefusal::TruncatedBelowPin`
(refusal), `ReleaseCoverage::not_covered` (generated text), and `limitations()` (shipped file).

**The orphan count may not rise, and does not.** No crate is created. `rust/evidence` is already
reachable; `rust/archive` is already an orphan and **stays** one — this task neither un-orphans it nor
adds a new one. `python tools/ci/wiring_census.py` must still print `10 of 40 crates reachable from
warrantor-warrant over 18 path edges`. Adding `pub mod custody;` to a crate already in the reachable set
adds no edge.

**No recorded invariant violation is converted by this task.** The eighteen `#[ignore]`s in
`rust/warrant/tests/invariants/` are I-01 (2), I-03 (4), I-04 (2), I-05 (2), I-06 (1), I-08 (2), I-09
(1), I-10 (1), I-11 (2) and I-12 (1); none concerns custody, escrow or investigator access.
`tools/ci/invariant-ratchet.json` is therefore **not edited**: `passing_floor` stays 66 and
`ignored_ceiling` stays 18, and the evidence file records the captured line `invariant ratchet: ok (66
passing at floor 66, 18 recorded findings at ceiling 18)` both before and after, read from the tool
output rather than computed. A nineteenth ignore anywhere raises the ceiling and fails the build, which
is the correct outcome.

---

**Exit gate.** One command decides it:

```
cd M:/wt-10.6/rust && cargo test -p warrantor-evidence --test custody_and_escrow && \
cargo test -p warrantor-archive --test append_only --test verification_does_not_depend_on_the_archive --test escrow_release_verifies_off_the_archive && \
cd M:/wt-10.6 && python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py
```

Pass requires all five of: `custody_and_escrow` showing at least seven refusals each with its allowed
control and `0 failed`; `append_only` still `7 passed; 0 failed; 2 ignored`;
`verification_does_not_depend_on_the_archive` still `6 passed; 0 failed`;
`escrow_release_verifies_off_the_archive` passing with no `warrantor_archive` type in the verify call
graph; and the last two lines reading exactly `wiring census: 10 of 40 crates reachable from
warrantor-warrant over 18 path edges` and `invariant ratchet: ok (66 passing at floor 66, 18 recorded
findings at ceiling 18)`. Any other number on either tool line is a failure regardless of the tests.

---

- [ ] **Step 1 — Worktree, Step 0 captured verbatim, and the contention check.**
      `git worktree add M:/wt-10.6 -b feat/custody-and-escrow main`
      Then `export CARGO_TARGET_DIR=M:/wt-10.6-target` — a shared target directory is how this
      repository's cargo-registry race started. Base is local **`main`**, not `origin/main`
      (Correction 4). Run every Step 0 command and paste real output into
      `docs/task-evidence/task-10.6.md`, including the `EXIT=1` from the `investigator` grep and the
      three ratchet lines. Then confirm no other lane holds `rust/archive/src/store.rs` or
      `rust/warrant/src/report.rs`: `git worktree list` and `git log --oneline -5 main`. Task 10.3 is
      seeded to touch `store.rs` and Task 10.1 to touch `report.rs`; if either branch exists, record it
      and take only the lines named in Files.
      *Test intent:* none. This step's product is the evidence file's Step 0 section and a recorded
      answer to "who else is in these two files".

- [ ] **Step 2 — Freeze the fixtures as bytes, before writing any verifier.** Create
      `rust/evidence/tests/custody_and_escrow.rs` with three `const` items: a genuine report export's
      filed bytes, its SHA-256, and a canonical `EscrowManifest` JSON. Take the bytes the way the
      archive does — `serde_json::to_vec_pretty`, which is what `warrantor report --export` writes and
      what `rust/archive/tests/verification_does_not_depend_on_the_archive.rs:330` files — then paste
      them in as literals. **Nothing in this file may rebuild a `WarPredicate` or a `ReceiptBody` and
      hash the result.** That is the whole of the Task 10.1 independence argument.

      ```rust
      /// The digest is over the bytes as filed, which is why nothing in this task binds to a struct
      /// shape. `rust/archive/tests/verification_does_not_depend_on_the_archive.rs:355` is the same
      /// assertion at the store: "the digest must be over the bytes as filed".
      #[test]
      fn the_frozen_fixture_still_hashes_to_its_recorded_digest() {
          assert_eq!(
              warrantor_warrant::report::sha256_hex(FILED_BYTES),
              FILED_DIGEST,
              "the frozen export no longer hashes to its recorded digest. Either the fixture was \
               edited or a canonical rule changed. Do NOT update FILED_DIGEST to match: find out \
               which, because a custody record over bytes whose digest moves is not a custody record."
          );
      }
      ```

      *Test intent:* this test passes on the first commit and must still pass after Task 10.1 lands. It
      is the tripwire that tells the difference between "a canonical rule changed" and "somebody edited
      a fixture".

- [ ] **Step 3 — Failing test: a withheld member of a sealed manifest is refused, with its allowed
      control.** The core assertion of the whole task, and what the seed's Exit gate is about. Write it
      before `verify_release` exists.

      ```rust
      #[test]
      fn a_release_that_withholds_a_sealed_member_is_refused_and_the_complete_one_verifies() {
          let anchor = issuer().verifying_key();
          let (first, second) = (frozen_artifact_a(), frozen_artifact_b());
          assert_ne!(first.0, second.0, "the two members must genuinely differ");

          let manifest = EscrowManifest {
              format: MANIFEST_FORMAT.to_string(),
              sequence: 7,
              members: vec![first.0.clone(), second.0.clone()],
              custody_head: None,
              prev_manifest: String::new(),
              sealed_at: NOW,
          };
          let sealed = seal(manifest, &issuer(), "issuer");

          // -- the CONTROL: everything the manifest names is present, and it verifies -----
          let complete = Release {
              sealed: sealed.clone(),
              custody: vec![],
              artifacts: [first.clone(), second.clone()].into_iter().collect(),
          };
          let coverage = verify_release(&complete, &anchor, None)
              .expect("a complete release must verify, or the refusal below proves nothing");
          assert_eq!(coverage.verified, 2);
          assert_eq!(coverage.members, 2);

          // -- the ATTACK: the operator serves the manifest and withholds one artifact ----
          let mut filtered = complete.clone();
          filtered.artifacts.remove(&second.0);
          let refusal = verify_release(&filtered, &anchor, None)
              .expect_err("a release missing a member its own sealed manifest names must be refused");
          match refusal {
              ReleaseRefusal::MemberWithheld { digest, sequence } => {
                  assert_eq!(digest, second.0, "the refusal must NAME the withheld digest, so the \
                      investigator can say what they were not given rather than only that something \
                      is wrong");
                  assert_eq!(sequence, 7, "and the manifest generation it was sealed into");
              }
              other => panic!("expected MemberWithheld, got {other:?}"),
          }
      }
      ```

      *Test intent:* one refusal, one allowed control, and the refusal must carry the missing digest. A
      verifier that refuses every release fails on the control line, which is why the control is in the
      same test rather than a neighboring one — the pattern `harness::refused_at_the_boundary` enforces
      at `rust/warrant/tests/invariants/harness.rs:50`.

- [ ] **Step 4 — Failing test: the investigator verifies with no privileged access and no archive in the
      call graph.** This is `verification_does_not_depend_on_the_archive.rs`'s positive case extended to
      a release, and it goes in `rust/archive/tests/` for exactly the reason that file gives at its lines
      129–135: the property is only proven by a verification that *could* have touched the archive and
      did not.

      ```rust
      //! The investigator's path, in the crate where the archive is a dependency and is still absent
      //! from the call graph. Mirrors
      //! `verification_does_not_depend_on_the_archive.rs::a_client_verifies_an_exported_bundle_with_no_archive_in_the_process`.

      /// No `ArchiveStore`, no `MemoryStore`, no HTTP, no socket, no `warrantor_archive` type anywhere
      /// below this line. The release arrives as bytes and is checked against a key the investigator
      /// pinned.
      #[test]
      fn an_investigator_verifies_a_release_with_no_archive_and_no_operator_in_the_process() {
          let bytes = std::fs::read(fixture_path("release.json")).expect("the file on a USB stick");
          let release: Release = serde_json::from_slice(&bytes).expect("decode");
          let anchor = pinned_issuer_key();   // parsed from a hex string, not fetched

          let coverage = verify_release(&release, &anchor, None)
              .expect("a genuine release verifies with nothing but the file and the pinned key");
          assert!(coverage.verified > 0);
          assert!(
              !coverage.not_covered.is_empty(),
              "a coverage report with an empty not_covered list is claiming completeness. It is \
               never empty: at minimum the manifest itself is unverified for completeness."
          );
      }
      ```

      Then add this file to the hardcoded `files` array at `rust/archive/tests/append_only.rs:360–375`,
      leaving `EXPECTED` at **3** — the new suite has no `#[ignore]`, so the count is unchanged and
      `the_ignored_database_tests_are_the_number_the_docs_claim` must still pass. That array's own doc,
      `append_only.rs:351–353`, says why: *"a file missing from it is a file this counter silently
      stopped covering."*
      *Test intent:* the positive case, plus the assertion that `not_covered` is never empty — which is
      the mechanism behind the product sentence, checked rather than commented.

- [ ] **Step 5 — Failing test: a broken custody transition is refused at the receiving party, with its
      allowed control.** L7-08's verification clause, made executable. Extend the hash-chain shape
      `ActorRecord` already uses at `rust/warrant/src/operators.rs:509–512`.

      ```rust
      #[test]
      fn a_missing_custody_transition_fails_verification_at_the_receiving_party() {
          // vendor -> customer -> supervisor -> investigator: the handoff L7-08 names.
          let a = append_act(None, FILED_DIGEST, "vendor", "customer", "contractual audit", NOW);
          let b = append_act(Some(&a), FILED_DIGEST, "customer", "supervisor", "examination", NOW + 60);
          let c = append_act(Some(&b), FILED_DIGEST, "supervisor", "investigator", "incident", NOW + 120);

          // -- the CONTROL: the whole chain verifies and the head is the last act ---------
          let head = verify_custody_chain(&[a.clone(), b.clone(), c.clone()])
              .expect("an intact three-hop chain must verify");
          assert_eq!(head.acts, 3);
          assert!(head.chain_intact);
          assert_eq!(head.head.as_deref(), Some(c.digest.as_str()));

          // -- the ATTACK: remove the MIDDLE hop, which is the one an operator would remove
          let refusal = verify_custody_chain(&[a.clone(), c.clone()])
              .expect_err("a chain with a transition removed must not verify");
          match refusal {
              EvidenceError::CustodyChain(index) => assert_eq!(
                  index, 1,
                  "the refusal must name WHICH transition is missing, at the receiving party's end"
              ),
              other => panic!("expected CustodyChain, got {other}"),
          }

          // -- and an EDITED act is the same refusal, not a silent pass -------------------
          let mut edited = b.clone();
          edited.to_party = "a party that never held it".to_string();
          verify_custody_chain(&[a, edited, c])
              .expect_err("an edited act must not verify: its digest no longer covers its contents");
      }
      ```

      *Test intent:* two refusals and one control. The middle hop is removed deliberately — removing the
      tail is the case Step 7 proves is *not* detectable, and conflating the two is exactly the overclaim
      Correction 6 is about.

- [ ] **Step 6 — Failing test: the manifest must be signed by the key the investigator pinned.** The
      fourth attack from `verification_does_not_depend_on_the_archive.rs:253–311`, at the manifest level.
      An operator holding any Ed25519 keypair can produce a fully self-consistent sealed manifest.

      ```rust
      #[test]
      fn a_manifest_sealed_by_the_operators_own_key_is_refused_against_the_pinned_anchor() {
          let anchor = issuer().verifying_key();
          let manifest = escrow_manifest_naming(&[FILED_DIGEST]);

          // The operator seals a manifest saying whatever it likes, with a VALID key it holds.
          // Nothing is inconsistent: the signature verifies against the key it carries.
          let forged = seal(manifest.clone(), &operator_key(), "operator");
          let release = Release { sealed: forged, custody: vec![], artifacts: one_artifact() };

          let refusal = verify_release(&release, &anchor, None).expect_err(
              "a manifest signed by a key that is not the pinned issuer must not verify -- this is \
               the attack that `verification_does_not_depend_on_the_archive.rs:299` already asserts \
               for bundles, and a release is a bundle-of-bundles with the same hole",
          );
          match refusal {
              ReleaseRefusal::ManifestNotSignedByAnchor { pinned, presented } => {
                  assert_eq!(pinned, hex::encode(anchor.to_bytes()),
                      "the refusal must name the key the reader pinned, so they can tell a \
                       wrong-signer from a tampered file");
                  assert_ne!(pinned, presented);
              }
              other => panic!("expected ManifestNotSignedByAnchor, got {other:?}"),
          }

          // The CONTROL: the same manifest sealed by the real issuer verifies.
          let genuine = seal(manifest, &issuer(), "issuer");
          verify_release(
              &Release { sealed: genuine, custody: vec![], artifacts: one_artifact() },
              &anchor, None,
          ).expect("sealed by the pinned issuer, it verifies");
      }
      ```

      *Test intent:* one refusal naming both keys, one control. `verify_release` takes the anchor as a
      required argument for this reason — an optional anchor is a hole, and the archive crate learned
      that already.

- [ ] **Step 7 — Failing test: completeness is NOT claimed, and the truncation limit is asserted as a
      limit.** The most important test in the task, because it asserts the *absence* of a guarantee.

      ```rust
      #[test]
      fn a_truncated_release_verifies_without_a_pin_and_is_refused_with_one() {
          let anchor = issuer().verifying_key();
          // Generation 9 is current. Generation 4 is a real, genuine, complete, sealed release --
          // and it is also what an operator serves to hide five generations of evidence.
          let stale = release_at_sequence(4);

          // -- Half one: with NO pin it VERIFIES, and that is the honest outcome. There is
          //    nothing wrong with the file. An offline verifier holding one release cannot
          //    distinguish "current" from "truncated". Asserting Ok here is what stops a future
          //    refactor from claiming a detection that does not exist.
          let coverage = verify_release(&stale, &anchor, None)
              .expect("a genuine older generation is a genuine file and must verify");
          assert!(!coverage.tail_pinned);
          assert!(
              coverage.not_covered.iter().any(|s| s.contains("truncat")),
              "with no pin, the coverage report MUST say that truncation is undetectable. \
               not_covered was: {:?}", coverage.not_covered
          );
          assert!(
              coverage.sentence().contains("does not prove everything was escrowed"),
              "the rendered sentence is the product's claim; it must not be silent about this"
          );

          // -- Half two: with a pin the investigator obtained elsewhere, it IS refused. This is
          //    the ONLY mechanism by which withholding a whole generation is detectable, and it
          //    needs a number from outside the release -- no new trust root, a number written down.
          let refusal = verify_release(&stale, &anchor, Some(9)).expect_err(
              "presented below a sequence the investigator has already seen, a release is refused",
          );
          assert!(matches!(
              refusal,
              ReleaseRefusal::TruncatedBelowPin { pinned: 9, presented: 4 }
          ), "got {refusal:?}");

          // -- The CONTROL for half two: at or above the pin, it verifies. ----------------
          verify_release(&release_at_sequence(9), &anchor, Some(9))
              .expect("at the pin, a release verifies");
      }
      ```

      Then assert the honest-disclosure surface directly, in the register `retention.rs`'s
      `unwitnessed_chains` established:

      ```rust
      /// `not_covered` is never empty, and one entry is not optional.
      ///
      /// Modeled on `Holdings::unwitnessed_chains` (`rust/warrant/src/retention.rs:479`), whose doc
      /// says it: "Reported because 'we cannot prove it for this many' is the honest form of the
      /// answer." A coverage struct that can render an empty not_covered list is a coverage struct
      /// that can claim completeness, and completeness is the one thing escrow does not establish.
      #[test]
      fn a_coverage_report_can_never_render_an_empty_not_covered_list() {
          for pin in [None, Some(1u64)] {
              let coverage = verify_release(&release_at_sequence(1), &issuer().verifying_key(), pin)
                  .expect("a genuine release");
              assert!(
                  !coverage.not_covered.is_empty(),
                  "not_covered was empty with pin={pin:?}. The manifest's own completeness is \
                   unverifiable in every configuration, so this list has at least one entry always."
              );
          }
      }
      ```

      *Test intent:* one refusal, two controls, and one structural assertion. This is the step that makes
      the seed's Exit gate honest instead of false.

- [ ] **Step 8 — The custody head crosses into signed evidence, and a v1 bundle digest does not move.**
      Add `escrow: Option<EscrowSection>` to `ReportBundle` with
      `#[serde(skip_serializing_if = "Option::is_none")]`, exactly as `custody: Option<CustodySection>`
      was added at `rust/warrant/src/report.rs:389`. Carry only the head digest and counts, never the
      acts — the disclosure decision at `report.rs:269–273` is inherited: *"Copying the acts themselves
      in would put operator names inside an artifact that gets handed to third parties."*

      ```rust
      /// A bundle with no escrow section hashes to exactly what it hashed to before this field
      /// existed. Frozen digest, not a recomputation: `bundle_digest` over a rebuilt bundle would
      /// agree with itself under any rule.
      #[test]
      fn adding_the_optional_escrow_section_does_not_move_a_v1_bundle_digest() {
          const V1_BUNDLE_DIGEST: &str = "<frozen in Step 2>";
          let bundle = v1_bundle_from_frozen_bytes();
          assert!(bundle.escrow.is_none(), "the v1 fixture carries no escrow section");
          assert_eq!(
              report::bundle_digest(&bundle).expect("digest"), V1_BUNDLE_DIGEST,
              "the optional field changed a v1 bundle's canonical bytes. Every export ever filed \
               to an archive would stop verifying. skip_serializing_if is not optional here."
          );

          // And a bundle that DOES carry one hashes differently, or the field is not covered.
          let mut with_escrow = bundle.clone();
          with_escrow.escrow = Some(EscrowSection { manifest_sequence: 7, members: 2,
              custody_head: Some("abc..".into()), sealed_by_key_id: "issuer".into() });
          assert_ne!(report::bundle_digest(&with_escrow).expect("digest"), V1_BUNDLE_DIGEST,
              "the escrow section must be inside the digest, or it is decoration");
      }
      ```

      *Test intent:* two assertions in opposite directions — the absent field must not move the digest
      and the present field must. One without the other is either a compatibility break or an unsigned
      section.

- [ ] **Step 9 — The seal predicate on the store, with no deletion path added.** Add
      `fn is_sealed(&self, digest: &str) -> Result<bool, StoreError>` and
      `fn seal(&mut self, digest: &str, manifest_sequence: u64, at: u64)` to `ArchiveStore`
      (`rust/archive/src/store.rs:200`) and implement both on `MemoryStore`. `is_sealed` is a read;
      `seal` marks and does not lock. Neither refuses anything. Task 10.4 owns any refusal built on them
      — Step 0(e).

      ```rust
      /// The seal is a marker, not a lock, and the trait shape must still forbid mutation.
      #[test]
      fn sealing_marks_and_does_not_lock_and_the_trait_still_offers_no_deletion() {
          let mut store = store_with_devices(&["dev_aaaa"]);
          let artifact = ingested("wrt_archive", "fix the auth token refresh bug");
          store.put_artifact(&artifact, "dev_aaaa", NOW).expect("filed");
          assert!(!store.is_sealed(&artifact.digest).expect("read"), "unsealed by default");
          store.seal(&artifact.digest, 7, NOW).expect("seal into manifest generation 7");
          assert!(store.is_sealed(&artifact.digest).expect("read"));

          // The append-only shape is unchanged. This duplicates
          // `append_only.rs::the_store_trait_offers_no_way_to_update_or_delete_an_artifact` on
          // purpose: a task that adds a method to this trait must re-prove the property here, in
          // its own suite, rather than rely on a neighboring file still passing.
          let source = include_str!("../src/store.rs");
          let trait_body = source.split("pub trait ArchiveStore {").nth(1).expect("trait")
              .split("\n}").next().expect("closed");
          for forbidden in ["fn update_artifact", "fn delete_artifact", "fn unseal",
                            "fn remove_artifact", "fn prune_artifacts", "fn overwrite"] {
              assert!(!trait_body.contains(forbidden),
                  "ArchiveStore declares {forbidden}. `is_sealed` is a read; a seal that can be \
                   lifted through this trait is not a seal, and a deletion path here is Task 10.4's \
                   to argue for, not this task's to open.");
          }
      }
      ```

      *Test intent:* one behavioral pair (unsealed then sealed) and one source-level assertion that the
      trait gained no mutation. `fn unseal` is in the forbidden list deliberately.

- [ ] **Step 10 — Gates, the product sentence, the evidence file, and `git commit -s`.** Run the Exit
      gate command verbatim and paste its output into `docs/task-evidence/task-10.6.md`. Then, in order:
      (1) ship the Bound-strength sentence into `limitations()` at `rust/warrant/src/report.rs:545` —
      **the exact words**, not a paraphrase — and add an assertion in `rust/warrant/tests/report.rs` that
      the phrase `does not prove everything was escrowed` appears in a built bundle's limitations,
      because a limitation nobody asserts is a limitation somebody deletes. (2) Update
      `docs/rfcs/W2-evidence-archive.md`'s threat model with the seal and the truncation limit, then
      re-run
      `cargo test -p warrantor-archive --test append_only the_threat_model_names_no_mitigation_this_crate_does_not_implement`
      — that gate at `append_only.rs:408` fails the build on an RFC row with no call site, and it has
      caught this repository once already. (3) Confirm the three ratchets by reading the captured lines
      rather than computing them:

      ```
      $ python tools/ci/wiring_census.py
      wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
      $ python tools/ci/check_invariant_ratchet.py
      invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
      $ python tools/ci/check_invariants.py
      invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
      ```

      `tools/ci/invariant-ratchet.json` is **not** edited — no recorded violation is converted here.
      (4) `python tools/ci/check_us_english.py --files <changed files>` and
      `node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <changed files>`,
      reading full output from both. (5) `git commit -s` — the DCO gate refuses an unsigned commit —
      with a message saying **why**: the manifest is the boundary of the completeness claim, and this
      task's product is as much the sentence about what escrow does not cover as it is the verifier.
      *Test intent:* the gate run itself, plus the limitations assertion, which is the only mechanism
      that keeps the honest sentence in the product after this branch merges.

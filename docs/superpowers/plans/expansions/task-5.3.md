### Task 5.3: Evidence-integrity adversary

**Anchor.** L0-05, `<article class="item" id="L0-05" data-stratum="L0" data-plane="A" data-status="none" data-novelty="novel" data-wave="W2" data-loop="L5">`. The catalog item's status word is **`status=none`** and it is not softened here: nothing in this repository attacks the evidence plane today. The blueprint states the item as *"A red-team agent given root inside its own workload whose sole goal is to produce a receipt chain that verifies but misrepresents what it did. It runs on every release. Its existence is why evidence must be emitted broker-side, below the agent's reach, rather than by the agent."* Its verification clause is *"Success by the adversary is a P0. Residual, stated on every rendering of a receipt: the record proves what the broker saw, not what happened inside the model."*

This task builds the **deterministic half** of L0-05 and says so in the item's own status. A live red-team agent with root inside a workload cannot run in this repository's CI: there is no sandbox here (Anti-goal 1), no agent runner, and no kernel that could give an adversary root and take it back. What can be built now, and what every downstream consumer of the receipt graph actually depends on, is the offline adversary — a suite that constructs receipt chains an attacker would construct, feeds them to the exact verification functions a third party runs, and records for each one whether the boundary refused, did not refuse, or cannot see the attack at all. When this task lands, L0-05 moves from `none` to `partial`, not to `covered`, and the sentence that earns the promotion names the half that is missing.

I-07 and I-10 are the two invariants this suite decides. The seed is right that they are claims rather than facts today, and Step 0 records exactly how far short each falls.

---

**Step 0.** Run every command below in the scratch worktree and paste the output verbatim into `docs/task-evidence/task-5.3.md`. The output shown here was captured on `origin/main` at `e4b5f10` on 2026-09-05 and is what the task must reproduce before it changes anything.

Files to read **in full** before writing a line, with their line counts on `origin/main`:

| File | Lines | Why |
|---|---|---|
| `rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs` | 167 | The existing I-07 suite. Its four passing tests are the attacks already covered; this task must not re-implement them. |
| `rust/warrant/tests/invariants/i10_replay_is_detectable.rs` | 155 | The existing I-10 suite, same rule. |
| `rust/warrant/tests/invariants/harness.rs` | 128 | `refused_at_the_boundary` and `reached_the_boundary_unrefused` are the two disclosure primitives this task builds on. |
| `rust/warrant/tests/invariants/scenario.rs` | 184 | The baselines every attack mutates, and `sign_as_attacker` — the reason an attack can reach a gate instead of dying at the signature check. |
| `rust/warrant/tests/invariants/round_zero.rs` | 190 | The registry-plus-completeness-scan pattern this task copies for its strategy table. |
| `rust/notary/src/lib.rs` | 901 | The verdict function, the Freshness gate, `ReceiptBody`, `issue_receipt`, `verify_receipt`. |
| `rust/evidence/src/lib.rs` | 969 | The commit gate, `verify_chain`, `verify_authority`, `check_mode_honesty`, and the canonicalization an attacker must reproduce to sign a forgery. |
| `rust/warrant/src/report.rs` | 1200+ (read 1–1200) | The product's only issuance path and the whole offline verifier. |
| `rust/warrant/src/harness.rs` | 1395 | The `Coverage` enum at line 67 — this repository's existing honest-disclosure mechanism, and the shape the new `Reach` type must match. |
| `rust/archive/tests/append_only.rs` | 578 | Custody, first-submitter attribution, and the counted-prose gate at line 355. |
| `rust/archive/tests/verification_does_not_depend_on_the_archive.rs` | 395 | The four existing bundle attacks. Strategy 1 below is their chain-level sibling, not a duplicate. |

Commands, with real captured output:

```text
$ git ls-tree --name-only refs/remotes/origin/main rust/ | grep -c '^rust/[a-z]'
39
$ git ls-tree --name-only refs/remotes/origin/main rust/ | grep -E 'notary|evidence|archive|warrant$'
rust/archive
rust/evidence
rust/notary
rust/warrant
```

Every crate this task touches is on `origin/main`. **No carry-in sequence is needed** — this task adds no crate, and Task 0.1's carry-in shape does not apply. That matters twice: it is why the first `cargo` call in Step 1 succeeds, and it is why the orphan count cannot move (see Bound strength).

```text
$ cd rust && cargo test -p warrantor-warrant --test invariants
test i07_evidence_precedes_commitment::an_orphan_post_commit_is_refused ... ok
test result: ok. 65 passed; 0 failed; 19 ignored; 0 measured; 0 filtered out; finished in 0.35s
```

```text
$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
$ python tools/ci/wiring_census.py
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
$ cat tools/ci/invariant-ratchet.json
{
  "format": "warrantor.invariant-ratchet/1",
  "recorded": "2026-09-02",
  "source": "rust/warrant/tests/invariants/",
  "passing_floor": 65,
  "ignored_ceiling": 19,
  "note": "The invariant attack corpus for I-01..I-12. `passing_floor` may only rise; ..."
}
```

**The `#[ignore]` attributes on I-07 and I-10, quoted verbatim.** An ignore reason is a specification, and these two are the specification this task is measured against:

```rust
// rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs:159
#[ignore = "I-07 orphaned: the product never issues a pre-commit receipt (Task 1.1 / Task 2.3, 2026-09-02)"]
fn the_product_issues_a_pre_commit_before_it_acts() {

// rust/warrant/tests/invariants/i10_replay_is_detectable.rs:147
#[ignore = "I-10 partial: seen_nonces is hardcoded empty in report.rs, so no replay is detectable (Task 1.1 / Task 3.4, 2026-09-02)"]
fn the_product_remembers_the_nonces_it_has_already_seen() {
```

**What `evidence/invariants.json` says about the two, including the status word.** Read with `python -c "import json; [print(json.dumps(i, indent=2)) for i in json.load(open('evidence/invariants.json'))['invariants'] if i['id'] in ('I-07','I-10')]"`:

```json
{ "id": "I-07",
  "status": "partial",
  "enforced_by": [
    { "crate": "evidence", "symbol": "warrantor_evidence::verify_chain",
      "test": "rust/evidence/src/lib.rs::orphan_post_commit_no_parent_rejected",
      "note": "'post_commit has no parent_receipt (orphan; I-07)'" },
    { "crate": "evidence", "symbol": "warrantor_evidence::verify_chain",
      "test": "rust/evidence/src/lib.rs::post_commit_wrong_parent_rejected", "note": "" },
    { "crate": "evidence", "symbol": "warrantor_evidence::issue_pre_commit",
      "test": "rust/evidence/src/lib.rs::an_expired_pre_commit_sinks_the_chain", "note": "" } ],
  "gap": "The commit gate is enforced for callers of verify_chain; no live warrantor effect passes
          through a pre_commit receipt until Task 1.1 wires evidence into the report path.
          Promote to enforced in that PR, on the live-run receipt." }
{ "id": "I-10",
  "status": "partial",
  "enforced_by": [
    { "crate": "notary", "symbol": "warrantor_notary::Gate::Freshness",
      "test": "rust/notary/src/lib.rs::gate3_freshness_replayed_nonce_denies",
      "note": "seen_nonces is a caller-supplied Vec on VerdictContext; no durable nonce store exists in warrant" },
    { "crate": "notary", "symbol": "warrantor_notary::Gate::Freshness",
      "test": "rust/notary/src/lib.rs::gate3_freshness_stale_timestamp_denies", "note": "" } ],
  "gap": "The gate refuses a replay it is told about; nothing on the warrant path remembers nonces
          across calls. Phase 3 recorder (L7-20)." }
```

**Three findings from Step 0 that contradict the seed or the tree, verified against the code.**

1. **The seed's Step 0 cannot be executed as written.** It says *"Read the recorder from Task 3.4 and the verification path in full."* Task 3.4 has not landed; there is no recorder on `origin/main`. `rust/flight-recorder` exists as a directory, and `rust/warrant/Cargo.toml` lines 26–56 declare exactly seven `path` dependencies — `trust-core`, `authority-spec`, `evidence`, `notary`, `egress`, `containment-conformance`, `spend` — and `flight-recorder` is not among them. The census agrees: 9 of 39 crates reachable. So Step 0 reads **the issuance path that exists** (`report.rs:929` `issue_atomic_checked`) and the verification path in full, and the task attacks that. A task written against a recorder that is not there dies at its first `cargo` call.

2. **The tree disagrees with itself about I-07's status word.** `evidence/invariants.json` records `"status": "partial"`. The corpus's own `#[ignore]` at `i07_evidence_precedes_commitment.rs:159` says **`I-07 orphaned`**. Both are on `origin/main`; `python tools/ci/check_invariants.py` passes because it never reads the ignore reasons. This is not cosmetic — `check_invariants.py`'s status rules make `orphaned` mean *no cited crate is reachable from the binary*, and `evidence` **is** reachable, so `partial` is the defensible word and the ignore reason is the one that is wrong. Step 11 corrects the ignore reason to `I-07 partial` and adds an assertion tying the two records together, because a status word that appears in two places and is checked in one is a number waiting to go stale.

3. **The seed's "expensive, so run it on releases only" premise does not hold for what this task can build.** The corpus it sits beside runs 65 tests in 0.35 s; every attack here is a pure function over signed bytes with no network, no model and no process spawn. Running it only on tags would let `main` sit red for weeks between releases, and `.github/workflows/release.yml` is tag-triggered and builds binaries — it has no test gate to hang this on. So the suite runs **on every commit**, inside the counted `invariants` target, and the release gate is satisfied because `required` already depends on the `invariants` job (`.github/workflows/ci.yml:459` `invariants:` … `:507` `invariants,` in the `required` needs list). The seed's Step 5 is contradicted and the reason is recorded in the task evidence.

---

**Non-goals.** Each names the adjacent task that owns the excluded thing. Several are being expanded concurrently; none of their work is specified here.

1. **Common-mode network independence is Task 5.4's.** This task never asks whether two enforcement layers share a failure domain, never reads a sandbox profile, and never touches `deploy/k8s`. An evidence forgery that arrives over a network path is still just bytes at the verifier, and that is the only place this task looks.
2. **Production evidence-integrity monitors are Task 10.3's** (L7-14, L7-19 — *"the monitors must be able to fail loudly about the store they live in, which means they cannot live only in it"*). This task is the **offline** adversary: it runs in CI against constructed inputs and emits no runtime signal. Strategy 7 below demonstrates an attack this suite provably cannot see, and hands it to 10.3 by name rather than pretending to cover it.
3. **Chain of custody, trace escrow and independent-investigator access are Task 10.6's** (L7-08, L7-18, L7-15). Strategy 8 attacks first-submitter attribution in `MemoryStore` because that mechanism already exists at `rust/archive/tests/append_only.rs:106`; it does not design custody, does not add an escrow role, and does not touch who may read what.
4. **Wiring evidence issuance into the live path is Task 1.1's, and the commit point is Task 2.3's.** Both are named in the I-07 ignore reason. This task attacks; it issues no pre-commit receipt and adds no call to `issue_pre_commit`. Fixes are separate commits, exactly as the seed says.
5. **The causal verdict and any change to `ReceiptBody` are Task 10.1's.** See Consumes for how this task's attacks are bound so that 10.1 can extend the body without rewriting them.
6. **No sandbox.** Phase 5's governing rule is explicit and this task obeys it: nothing here creates a namespace, a seccomp filter, or a firewall rule, and nothing here implies containment of an adversary process. The adversary in this task is a set of constructed byte sequences, not a running program.

---

**Files.**

- Create `rust/warrant/tests/invariants/adversary/mod.rs` — the strategy registry, the `Reach` disclosure type, and the completeness scan.
- Create `rust/warrant/tests/invariants/adversary/forgery.rs` — Strategies 1 and 2.
- Create `rust/warrant/tests/invariants/adversary/substitution.rs` — Strategies 3 and 4.
- Create `rust/warrant/tests/invariants/adversary/mislabeling.rs` — Strategies 5 and 6.
- Create `rust/warrant/tests/invariants/adversary/absence.rs` — Strategy 7, the honest negative.
- Modify `rust/warrant/tests/invariants/main.rs` — add `mod adversary;` after line 52.
- Create `rust/archive/tests/adversary_custody.rs` — Strategy 8, in the crate where `warrantor_archive` is already a dependency.
- Modify `tools/ci/invariant-ratchet.json` — `passing_floor` only, in the same commit.
- Modify `rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs:159` — the ignore reason's status word, and nothing else about the test.
- Modify `evidence/invariants.json` — the `gap` text on I-07 and I-10 only; no status change.
- Modify `docs/W1-delivery-gaps.md` — a Tier 5 subsection after line 1068.
- Create `docs/task-evidence/task-5.3.md`.

**Not created:** no new crate, no `[dev-dependencies]` entry, no `[[test]]` target, no CI job.

---

**Consumes** (all exist on `origin/main`; signatures quoted with file and line):

- `rust/evidence/src/lib.rs:339` `pub fn issue_pre_commit(predicate: WarPredicate, key: &SigningKey, key_id: &str) -> WarReceipt`
- `rust/evidence/src/lib.rs:355` `pub fn issue_post_commit(pre_commit: &WarReceipt, outcome: Outcome, key: &SigningKey, key_id: &str) -> WarReceipt`
- `rust/evidence/src/lib.rs:374` `pub fn issue_atomic(predicate: WarPredicate, key: &SigningKey, key_id: &str) -> WarReceipt`
- `rust/evidence/src/lib.rs:401` `pub fn verify_receipt(receipt: &WarReceipt) -> Result<(), EvidenceError>`
- `rust/evidence/src/lib.rs:477` `pub fn verify_chain(pre_commit: &WarReceipt, post_commit: &WarReceipt) -> Result<(), EvidenceError>` — the commit gate, whose orphan refusal reads `"post_commit has no parent_receipt (orphan; I-07)"` at line 515
- `rust/evidence/src/lib.rs:552` `pub fn verify_authority(authority: &Authority) -> Result<(), EvidenceError>`
- `rust/evidence/src/lib.rs:571` `pub fn check_mode_honesty(receipt: &WarReceipt, claims_non_bypassable: bool) -> Result<(), EvidenceError>`
- `rust/evidence/src/lib.rs:255` `pub fn canonical_predicate(predicate: &WarPredicate) -> String` and `:262` `pub fn dsse_pae(payload: &str) -> Vec<u8>` — the two an attacker needs to sign a forgery, which is why `scenario::sign_as_attacker` at `scenario.rs:169` can exist at all
- `rust/notary/src/lib.rs:201` `pub fn verdict(req: &VerdictRequest, ctx: &VerdictContext) -> Verdict`; the Freshness gate is lines 220–233 and denies on `ctx.seen_nonces.contains(&req.nonce)` first, skew second
- `rust/notary/src/lib.rs:363` `pub fn issue_receipt(verdict_result: &Verdict, req: &VerdictRequest, enforcement_mode: EnforcementMode, signing_key: &SigningKey, key_id: &str) -> WarReceipt`
- `rust/warrant/src/report.rs:995` `pub fn verify_export(export: &SignedReport) -> Result<(), ReportError>`
- `rust/warrant/src/report.rs:1146` `pub fn verify_export_signed_by(export: &SignedReport, anchor: &VerifyingKey) -> Result<(), ReportError>`
- `rust/warrant/src/report.rs:1188` `pub fn verify_export_at(export: &SignedReport, now: u64) -> Result<(), ReportError>`
- `rust/warrant/src/report.rs:955` `fn issue_atomic_checked(predicate: evidence::WarPredicate, key: &SigningKey, key_id: &str) -> Result<evidence::WarReceipt, ReportError>` — private, reached only through `SignedReport`'s builder at line 929
- `rust/warrant/tests/invariants/harness.rs:50` `pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)`
- `rust/warrant/tests/invariants/harness.rs:76` `pub fn reached_the_boundary_unrefused<T, F>(what: &str, control: &T, attacked: &T, allowed: F)`
- `rust/warrant/tests/invariants/harness.rs:96` `pub fn source_contains(relative: &str, fragment: &str, why: &str)`
- `rust/warrant/src/harness.rs:67` `pub enum Coverage { McpOnly, McpAndBuiltins(&'static str), ProcessOnly }` with `:79` `pub const fn sentence(self) -> &'static str` and `:99` `pub const fn escapes(self) -> Option<&'static str>` — the shape `Reach` copies
- `rust/archive/src/store.rs` `ArchiveStore::put_artifact` returning `PutOutcome::Stored | PutOutcome::AlreadyHeld`, exercised at `rust/archive/tests/append_only.rs:106`

**The composition risk, answered explicitly.** Task 10.1 is being expanded in parallel and its own finding is that `ReceiptBody` (`rust/notary/src/lib.rs:336`) carries exactly six fields and has no room for a causal chain, so 10.1 will add fields to it. **Every attack in this task binds to the evidence crate's v1 `WarPredicate` (`rust/evidence/src/lib.rs:178`) and to `SignedReport` (`rust/warrant/src/report.rs:369`), not to 10.1's shape.** Where an attack must touch a notary receipt it constructs it through `notary::issue_receipt` and mutates only fields the current `ReceiptBody` already declares, so a field 10.1 adds is signed over automatically and no attack here needs editing. The one place this matters is Strategy 5, which flips `enforcement_mode` — an existing field 10.1 does not remove. If 10.1 does remove or rename it, Strategy 5 fails to compile, which is the correct outcome: a mode field that stops existing is a product change that must be re-argued, not silently absorbed.

**Produces** (new):

```rust
// rust/warrant/tests/invariants/adversary/mod.rs
pub enum Reach {
    RefusedAt(&'static str),
    Unrefused(&'static str),
    Unrepresentable(&'static str),
}
impl Reach {
    pub const fn sentence(self) -> &'static str;
    pub const fn is_a_finding(self) -> bool;
}
pub struct Strategy {
    pub id: &'static str,
    pub name: &'static str,
    pub target: &'static str,
    pub reach: Reach,
    pub test: &'static str,
}
pub const STRATEGIES: [Strategy; 8];
```

Plus, in `docs/task-evidence/task-5.3.md`, the captured before-and-after `test result:` lines and the ratchet's own output.

---

**Bound strength.**

The refusals this suite demonstrates split into two tiers and the split is the product claim:

**Tier A — cryptographic.** Strategies 1, 3, 4, 5 and 6 are refused by Ed25519 signature verification over the DSSE PAE of JCS-canonical JSON (`evidence::verify_receipt`, `evidence/src/lib.rs:401`) or by SHA-256 digest comparison (`report::verify_export`, `report.rs:1009–1015`), plus the anchor comparison at `report.rs:1156`. A specific line of code refuses the byte sequence at the moment it is presented, and no configuration weakens it. These are Tier A **conditional on the reader holding the issuer's key out of band** — `verify_export` is anchor-free by construction and a bundle signed end to end by any keypair passes it, which `rust/archive/tests/verification_does_not_depend_on_the_archive.rs:292` already asserts in both directions and Strategy 1 asserts again at the chain level.

**Tier C — observed, and in one case not even that.** Strategies 2 and 7 are *not* refused. Strategy 2 (backdated evidence on the product path) reaches the boundary unrefused because the product issues an atomic receipt at `report.rs:929` and never a pre-commit, so there is no ordering to violate. Strategy 7 (suppression and truncation) is `Unrepresentable`: an offline verifier holding one file cannot distinguish a run whose evidence was deleted from a run that never happened, because the missing thing is missing. Neither is dressed up. Both are recorded through `Reach`, which prints the honest sentence the way `Coverage::sentence()` does at `rust/warrant/src/harness.rs:79`.

**The sentence that ships in the product**, on every rendering of an adversary result and beside the receipt itself:

> This adversary shows that a receipt cannot be altered, substituted, mislabeled, or re-signed by another key without a reader detecting it — provided that reader pinned the issuer's key out of band. It does **not** show that a missing receipt is detectable: an action that produced no evidence leaves nothing for an offline verifier to refuse. It does not show that the receipt describes what happened inside the model, only what the broker observed. And it is not a live red-team agent: every attack here is a constructed byte sequence checked in CI, not a program given root in a workload.

**Orphan count.** This task adds no crate. `python tools/ci/wiring_census.py` must report `9 of 39 crates reachable from warrantor-warrant over 17 path edges` unchanged, before and after, and Step 11 asserts it. `tools/ci/wiring_census.py` lines 28–29 exclude `[dev-dependencies]` from the census by design, which is a second reason nothing here can move the number — and a reason not to reach for a dev-dependency as a way around a layering problem: it would hide a real edge from the census.

---

**Exit gate.** `cd rust && cargo test -p warrantor-warrant --test invariants && cd .. && python tools/ci/check_invariant_ratchet.py --show-findings` prints `invariant ratchet: ok (N passing at floor N, 19 recorded findings at ceiling 19)` with `N` strictly greater than 65 and the ignored count unchanged at 19 — a run in which the ignored count rose, or in which the floor was not raised to meet the new passing count, is a fail.

---

- [ ] **Step 1 — Worktree, captured baseline, and the failing registry.**

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
git -C "M:/Project AumOS - Open Secure AI Alliance/aumos" worktree add M:/wt-5.3-adversary -b feat/evidence-integrity-adversary refs/remotes/origin/main
cd M:/wt-5.3-adversary && export CARGO_TARGET_DIR=M:/wt-5.3-adversary-target
mkdir -p docs/task-evidence
{ cd rust && cargo test -p warrantor-warrant --test invariants; cd ..; } 2>&1 | tail -3 | tee -a docs/task-evidence/task-5.3.md
python tools/ci/wiring_census.py | tee -a docs/task-evidence/task-5.3.md
python tools/ci/check_invariants.py | tee -a docs/task-evidence/task-5.3.md
```

The three lines appended must read `test result: ok. 65 passed; 0 failed; 19 ignored; …`, `wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges`, and `invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1`. Anything else means the worktree is not at `e4b5f10` and every number below is measured against the wrong baseline.

Then create `rust/warrant/tests/invariants/adversary/mod.rs` with the disclosure type and an **empty** registry, and add `mod adversary;` to `main.rs` after line 52. Test intent: the completeness scan must fail before any strategy exists, so that the scan is proven to be able to fail. A registry whose completeness check has never been red is a check nobody has tested.

```rust
//! The evidence-integrity adversary (L0-05), offline half.
//!
//! Eight strategies against the notary, the evidence envelope and the archive. Each is a named
//! test, each runs against a control with the attack backed out, and each declares what it
//! actually reached through [`Reach`] rather than through its own passing status.
//!
//! # Why a strategy declares its reach
//!
//! Two of the eight are not refused. If those were written as ordinary passing tests the suite
//! would read as eight refusals, which is the phantom-scorer shape this corpus exists to refuse:
//! a control believed to exist, steering decisions, while not existing. `Reach` is the same device
//! `warrantor_warrant::harness::Coverage` uses for MCP mediation -- name the escape in the type,
//! so a renderer cannot omit it by forgetting to.

use crate::harness;

/// What an attack actually reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Refused by a named check, with the control allowed. The string is the check.
    RefusedAt(&'static str),
    /// Reached the boundary and was NOT refused. A recorded finding; the string names the fix.
    Unrefused(&'static str),
    /// The boundary cannot see this attack at all. The string says what could.
    Unrepresentable(&'static str),
}

impl Reach {
    /// One sentence for the operator, in the honest direction.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::RefusedAt(_) => {
                "A reader running the shipped verifier refuses this, and the control proves the \
                 attack reached that refusal rather than dying earlier."
            }
            Self::Unrefused(_) => {
                "This attack is NOT refused today. It is recorded, not fixed, and the named task \
                 is the one that closes it."
            }
            Self::Unrepresentable(_) => {
                "The offline verifier cannot see this attack. Nothing in this suite refuses it and \
                 nothing in this suite should claim to."
            }
        }
    }

    /// True when this strategy is recording a gap rather than a guarantee.
    #[must_use]
    pub const fn is_a_finding(self) -> bool {
        !matches!(self, Self::RefusedAt(_))
    }
}

/// One attack strategy and the test that runs it.
pub struct Strategy {
    pub id: &'static str,
    pub name: &'static str,
    pub target: &'static str,
    pub reach: Reach,
    pub test: &'static str,
}

/// Every strategy. Filled in by Steps 2-9.
pub const STRATEGIES: [Strategy; 0] = [];

#[test]
fn every_strategy_has_a_test_that_exists() {
    // Scan the sources rather than trusting the table, for the reason round_zero gives: a strategy
    // covered by a table entry alone is not covered.
    let directory = harness::repository_root().join("rust/warrant/tests/invariants/adversary");
    let mut corpus = String::new();
    for entry in std::fs::read_dir(&directory).expect("the adversary directory is readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            corpus.push_str(&std::fs::read_to_string(&path).expect("readable strategy file"));
        }
    }
    assert!(
        !STRATEGIES.is_empty(),
        "the adversary registry is empty. An adversary with no strategies is a green result and a \
         false guarantee, which is worse than no adversary."
    );
    for strategy in &STRATEGIES {
        assert!(
            corpus.contains(&format!("fn {}(", strategy.test)),
            "strategy {} ({}) names test `{}`, which does not exist",
            strategy.id,
            strategy.name,
            strategy.test,
        );
    }
}
```

Run `cd rust && cargo test -p warrantor-warrant --test invariants adversary`. Expected: one failure, `the adversary registry is empty`. Capture it.

- [ ] **Step 2 — Strategy A1: forge a chain end to end with a key the adversary holds.**

Test intent: `verify_chain` is anchor-free exactly as `verify_export` is, and an adversary who can author a receipt can sign it. The existing archive test proves this for a *bundle*; nothing proves it for a *chain*, which is what a downstream consumer of the receipt graph actually walks. Both directions are asserted, so a refactor that quietly made `verify_chain` anchor-aware fails on the first assertion rather than leaving a hole nobody noticed.

```rust
// rust/warrant/tests/invariants/adversary/forgery.rs
use crate::{harness, scenario};
use warrantor_evidence as evidence;

/// A1 — a fully self-consistent chain signed by a key that is not the issuer's.
#[test]
fn a1_a_chain_forged_end_to_end_verifies_and_is_caught_only_by_the_anchor() {
    let (issuer, issuer_public) = evidence::generate_keypair();
    let (adversary, _) = evidence::generate_keypair();

    // The control: an honest chain, signed by the issuer.
    let honest_pre =
        evidence::issue_pre_commit(scenario::predicate(evidence::Phase::PreCommit), &issuer, "issuer");
    let honest_post =
        evidence::issue_post_commit(&honest_pre, scenario::outcome(), &issuer, "issuer");
    evidence::verify_chain(&honest_pre, &honest_post).expect("the control chain verifies");

    // The attack: the same shape, describing an operation the agent never performed, signed
    // throughout by the adversary. Nothing is inconsistent -- which is the finding.
    let mut fabricated = scenario::predicate(evidence::Phase::PreCommit);
    fabricated.operation.method = "delete".to_string();
    fabricated.operation.reversible = false;
    let forged_pre = evidence::issue_pre_commit(fabricated, &adversary, "adversary");
    let forged_post =
        evidence::issue_post_commit(&forged_pre, scenario::outcome(), &adversary, "adversary");

    // Direction one: the unanchored chain verifier PASSES. This assertion is why an anchor is
    // required at all, and it must be a hard assertion rather than a comment.
    evidence::verify_chain(&forged_pre, &forged_post).expect(
        "a chain signed end to end by one key IS self-consistent. verify_chain answers 'has this \
         changed since signing', never 'who signed it', and a reader who does not pin a key is \
         reading a document that authenticates itself.",
    );

    // Direction two: pinning the issuer refuses it, and the control passes the same pin.
    let pinned = |receipt: &evidence::WarReceipt| -> bool {
        receipt.signature.public_key == hex::encode(issuer_public.to_bytes())
    };
    harness::refused_at_the_boundary(
        "a chain forged end to end by the adversary's own key, checked against the pinned issuer",
        &honest_post,
        &forged_post,
        |receipt| pinned(receipt),
    );
}
```

The `refused_at_the_boundary` call is what makes this a two-sided test: the control is the honest post-commit, which must satisfy the pin, and only then does the forgery's failure mean anything. Registry entry: `Reach::RefusedAt("the caller's anchor comparison; verify_chain alone does not refuse it")`.

- [ ] **Step 3 — Strategy A2: backdate the evidence, on the product's own path.**

Test intent: this is I-07's direct attack — commit first, author the evidence afterward. `i07_evidence_precedes_commitment.rs:63` already proves `verify_chain` refuses an orphan. What nothing proves is what happens on **the product's path**, where `report.rs:929` issues a single atomic receipt and no ordering exists to violate. That must be recorded as unrefused, not omitted.

```rust
/// A2 — the product's only receipt is issued after the fact, so there is no ordering to break.
#[test]
fn a2_the_products_own_receipt_carries_no_evidence_of_preceding_its_effect() {
    // The control: the evidence crate CAN express the ordering, and refuses an orphan.
    let (key, _) = evidence::generate_keypair();
    let pre = evidence::issue_pre_commit(
        scenario::predicate(evidence::Phase::PreCommit), &key, "issuer");
    let post = evidence::issue_post_commit(&pre, scenario::outcome(), &key, "issuer");
    evidence::verify_chain(&pre, &post).expect("the ordering is expressible and verifies");

    // The attack: the product issues Phase::Atomic, whose definition at evidence/src/lib.rs:58 is
    // "Single-receipt phase; only for routine + reversible actions" -- no parent, no ordering.
    let issued = harness::occurrences_in_rust_sources("rust/warrant/src", "issue_pre_commit");
    let atomic = harness::occurrences_in_rust_sources("rust/warrant/src", "issue_atomic");
    harness::reached_the_boundary_unrefused(
        "an effect whose evidence was authored after it, on the product's own issuance path",
        &(atomic > 0),
        &(issued == 0),
        |reached| *reached,
    );
    harness::source_contains(
        "rust/warrant/src/report.rs",
        "let evidence_receipt = issue_atomic_checked(predicate, key, key_id)?;",
        "The product's single issuance call is the whole of what A2 attacks; if it moves, this \
         strategy is measuring nothing.",
    );
}
```

`reached_the_boundary_unrefused` is used deliberately rather than `#[ignore]`. Its doc at `harness.rs:76–92` says why: it makes the finding executable, and it starts **failing** the moment Task 1.1 wires issuance in, at which point whoever fixed it converts this to `refused_at_the_boundary` and raises the ratchet. Adding a fourteenth `#[ignore]` would instead raise `ignored_ceiling`, which `check_invariant_ratchet.py:154` treats as a build failure — correctly, since it is a widening gap. Registry entry: `Reach::Unrefused("Task 1.1 wires issuance; Task 2.3 supplies the commit point")`.

- [ ] **Step 4 — Strategy A3: lift a valid receipt into a false context.**

Test intent: the replay-into-false-context attack the seed names. The receipt is genuine, verifies on its own, and simply does not describe the bundle it has been attached to. `report.rs:1061` binds `predicate.binding.receipt_id == export.bundle_digest`, so this must fail as a `Binding`, not as a signature — and asserting *which* error is what stops the test from claiming credit for the wrong refusal.

```rust
// rust/warrant/tests/invariants/adversary/substitution.rs
/// A3 — a genuine receipt from one report, attached to another.
#[test]
fn a3_a_genuine_receipt_lifted_onto_a_different_report_is_refused_as_a_binding() {
    let dir = fixtures::tempdir("a3");
    let first = fixtures::genuine_export_of(&dir, &fixtures::stored_as("wrt_a", "the real goal"));
    let second = fixtures::genuine_export_of(&dir, &fixtures::stored_as("wrt_b", "another goal"));
    assert_ne!(
        first.bundle_digest, second.bundle_digest,
        "the two exports must genuinely differ, or this attack swaps a report for itself"
    );

    // Both receipts verify individually before and after the lift; that is the point of the attack.
    evidence::verify_receipt(&second.evidence_receipt).expect("the lifted receipt is genuine");

    let mut grafted = first.clone();
    grafted.evidence_receipt = second.evidence_receipt.clone();
    grafted.notary_receipt = second.notary_receipt.clone();

    harness::refused_at_the_boundary(
        "a valid receipt pair lifted from one report onto another",
        &report::verify_export(&first),
        &report::verify_export(&grafted),
        |result| result.is_ok(),
    );
    let error = report::verify_export(&grafted).expect_err("the graft is refused");
    assert!(
        matches!(error, report::ReportError::Binding(_)),
        "a lifted receipt must fail as a binding, not as a signature -- a signature failure here \
         would mean the attack was malformed and the refusal proves nothing: {error}"
    );
}
```

Registry entry: `Reach::RefusedAt("report::verify_export binding checks, report.rs:1060-1113")`.

- [ ] **Step 5 — Strategy A4: replay the same request and get a second allow.**

Test intent: I-10's direct attack against the product's own context, not against a hand-built one. `report.rs:754` constructs `seen_nonces: Vec::new()` on every call, so the Freshness gate at `notary/src/lib.rs:220` is asked whether a nonce is in an empty set and always answers no. The corpus proves the gate works when told (`i10:59`); nothing proves the product never tells it.

```rust
/// A4 — the same request twice, against the context the product actually builds.
#[test]
fn a4_the_product_context_allows_a_verbatim_replay() {
    let request = scenario::allowed_request();

    // The control: a context that remembers. The gate refuses, at Freshness, by name.
    let mut remembering = scenario::allowed_context();
    remembering.seen_nonces = vec![request.nonce.clone()];
    scenario::assert_denied_at(
        &notary::verdict(&request, &remembering),
        notary::Gate::Freshness,
        "a replay against a context that remembers",
    );

    // The attack: the product's context. Verbatim from report.rs:747-762, empty nonce set.
    let product_shaped = scenario::allowed_context(); // seen_nonces: Vec::new()
    let first = notary::verdict(&request, &product_shaped);
    let second = notary::verdict(&request, &product_shaped);
    harness::reached_the_boundary_unrefused(
        "the identical request replayed against the context report.rs builds",
        &first,
        &second,
        scenario::notary_allowed,
    );
    harness::source_contains(
        "rust/warrant/src/report.rs",
        "seen_nonces: Vec::new()",
        "A4 measures this exact line. When a nonce store lands, this strategy must be converted to \
         refused_at_the_boundary and the ratchet raised in the same commit.",
    );
}
```

Registry entry: `Reach::Unrefused("Task 1.1 for a nonce store; Task 3.4 for one that survives a restart")`. Note what this test does **not** do: it does not weaken `i10`'s existing `#[ignore]`d assertion, and it does not claim replay detection exists at any tier.

- [ ] **Step 6 — Strategy A5: mislabel the enforcement mode inside a signed bundle.**

Test intent: the worst defect this repository can ship, made executable. An adversary who re-signs a report with `EnforcementMode::Mediated` is claiming the decision sat in the enforcement path when it did not. `report.rs:1033` refuses a mode warrantor never issues, and `report.rs:1046` refuses an advisory receipt that could assert non-bypassability. Both must be exercised, and the control must be the genuine advisory report.

```rust
// rust/warrant/tests/invariants/adversary/mislabeling.rs
/// A5 — an advisory report re-signed as mediated.
#[test]
fn a5_a_report_re_signed_as_mediated_is_refused_as_a_mode_escalation() {
    let dir = fixtures::tempdir("a5");
    let genuine = fixtures::genuine_export(&dir);
    assert_eq!(
        genuine.evidence_receipt.predicate.binding.enforcement_mode,
        evidence::EnforcementMode::Advisory,
        "the fixture must be advisory or this attack has nothing to escalate"
    );

    // The adversary edits the mode and RE-SIGNS, so the signature check cannot be what refuses it.
    let (adversary, _) = evidence::generate_keypair();
    let mut predicate = genuine.evidence_receipt.predicate.clone();
    predicate.binding.enforcement_mode = evidence::EnforcementMode::Mediated;
    let escalated = evidence::WarReceipt {
        signature: scenario::sign_as_attacker(&predicate, &adversary, "adversary"),
        predicate,
    };
    evidence::verify_receipt(&escalated)
        .expect("the escalated receipt is validly signed, so its refusal must come from the mode check");

    let mut attacked = genuine.clone();
    attacked.evidence_receipt = escalated;
    harness::refused_at_the_boundary(
        "an advisory report re-signed to claim mediated enforcement",
        &report::verify_export(&genuine),
        &report::verify_export(&attacked),
        |result| result.is_ok(),
    );
    let error = report::verify_export(&attacked).expect_err("the escalation is refused");
    assert!(
        matches!(error, report::ReportError::Mode(_)),
        "a mode escalation must be refused AS a mode escalation. If this reads as a signature or \
         a key-binding failure the refusal is incidental, and an adversary who also re-signs the \
         notary receipt would get through: {error}"
    );
}
```

Registry entry: `Reach::RefusedAt("report::verify_export mode checks, report.rs:1032-1050")`. The `expect` on `verify_receipt` before the boundary call is the rule from `i07:87` applied here: without it, a broken forgery would masquerade as an enforced bound.

- [ ] **Step 7 — Strategy A6: delete a limitation and expand the authority, in one file.**

Test intent: two edits an audited party is most tempted to make. Removing a limitation is refused by the digest; expanding `effective_capabilities` is refused by `verify_authority` at `evidence/src/lib.rs:552`. The second half also records an attack that is **not** refused and should not be: an adversary who edits the delegation chain itself so the intersection genuinely contains the extra capability produces a receipt that verifies, because the chain is the authority. That residual belongs in the record.

```rust
/// A6 — a removed limitation, and two ways to widen authority.
#[test]
fn a6_a_removed_limitation_fails_on_the_digest_and_a_forged_intersection_fails_on_the_proof() {
    let dir = fixtures::tempdir("a6");
    let genuine = fixtures::genuine_export(&dir);
    assert!(
        !genuine.bundle.limitations.is_empty(),
        "the fixture must carry limitations or the first half of this attack tests nothing"
    );

    let mut trimmed = genuine.clone();
    trimmed.bundle.limitations.remove(0);
    harness::refused_at_the_boundary(
        "a bundle with one limitation sentence removed",
        &report::verify_export(&genuine),
        &report::verify_export(&trimmed),
        |result| result.is_ok(),
    );

    // Widening the claimed capabilities without touching the chain: the recomputed intersection
    // disagrees, and verify_authority says so by name.
    let honest = scenario::predicate(evidence::Phase::PreCommit).authority;
    let mut widened = honest.clone();
    widened.effective_capabilities.push("net.admin".to_string());
    harness::refused_at_the_boundary(
        "effective_capabilities widened beyond the chain that produced them",
        &evidence::verify_authority(&honest),
        &evidence::verify_authority(&widened),
        |result| result.is_ok(),
    );
    let error = evidence::verify_authority(&widened).expect_err("the expansion is refused");
    assert!(
        error.to_string().contains("authority expansion; I-02"),
        "the refusal must name the invariant a reader will look up: {error}"
    );

    // The residual, asserted rather than described: an adversary who rewrites the CHAIN gets a
    // receipt that verifies. It must, because the chain is the authority -- and that is exactly
    // why a receipt proves the chain it carries, never that the chain was legitimately issued.
    let mut rewritten_chain = honest.chain.clone();
    rewritten_chain[0].capabilities.push("net.admin".to_string());
    let consistent = evidence::Authority {
        effective_capabilities: evidence::recompute_intersection(&rewritten_chain),
        intersection_proof: evidence::compute_intersection_proof(&rewritten_chain),
        chain: rewritten_chain,
    };
    evidence::verify_authority(&consistent).expect(
        "a rewritten chain with a recomputed proof IS internally consistent. verify_authority \
         checks that the claimed capabilities follow from the chain, not that the chain is real.",
    );
}
```

Registry entry: `Reach::RefusedAt("report digest, report.rs:1009; evidence::verify_authority, evidence/src/lib.rs:552")`, with the residual carried in the strategy's `target` string so it prints wherever the table prints.

- [ ] **Step 8 — Strategy A7: suppress the evidence entirely. The honest negative.**

Test intent: the attack the seed names as "suppress an entry", and the one this suite provably cannot refuse. An offline verifier holding one file cannot tell a deleted receipt from a run that never happened. Writing this as a passing refusal would be the phantom-scorer failure in its purest form, so it is written as `Unrepresentable` and handed to Task 10.3 by name.

```rust
// rust/warrant/tests/invariants/adversary/absence.rs
/// A7 — the missing receipt. Nothing here refuses it, and nothing here pretends to.
#[test]
fn a7_a_suppressed_receipt_is_indistinguishable_from_a_run_that_never_happened() {
    let dir = fixtures::tempdir("a7");
    let genuine = fixtures::genuine_export(&dir);

    // The control: with the file, every check the product ships passes.
    report::verify_export(&genuine).expect("the control verifies");

    // The attack: the adversary deletes the file. There is no `verify_absence` to call, and this
    // assertion says why rather than inventing one.
    let checkers = harness::occurrences_in_rust_sources("rust/warrant/src", "fn verify_absence");
    assert_eq!(
        checkers, 0,
        "if an absence checker now exists, A7 is no longer Unrepresentable: convert this strategy \
         to refused_at_the_boundary against it, update the registry entry, and raise the ratchet."
    );
    assert!(
        !harness::read_repository_file("rust/warrant/src/report.rs").contains("expected_receipts"),
        "the offline verifier holds one file and has no notion of how many receipts a run should \
         have produced. Detecting a gap needs a sequence somebody else keeps, which is Task 10.3's \
         evidence-integrity monitors and Task 10.6's custody record -- not this suite."
    );
}
```

Registry entry: `Reach::Unrepresentable("Task 10.3 evidence-integrity monitors; Task 10.6 custody")`. Truncation by an induced reset is the same finding with a different cause and is recorded in the same strategy rather than as a second one that would imply a second guarantee.

- [ ] **Step 9 — Strategy A8: race the archive for attribution.**

Test intent: the "race the recorder" strategy, aimed at the only recorder that exists. `append_only.rs:106` establishes that a resubmission of identical bytes keeps the **first** submitter's attribution. An adversary who files an agent's export first therefore owns the attribution on that digest forever. The attack must show that the archive does not let the adversary rewrite history, and must record what it does not stop.

This test lives in `rust/archive/tests/adversary_custody.rs`, because `warrantor_archive` is a consumer of `warrantor_warrant`, not the reverse — `rust/archive/Cargo.toml` declares `warrantor-warrant = { path = "../warrant" }`, and adding the mirror edge as a `[dev-dependencies]` on warrant would create a package cycle and hide an edge from the census. The shared `harness` module is a test-target module and is unreachable from another crate, so this test carries its control inline, in the same two-sided shape and with the same message wording.

```rust
// rust/archive/tests/adversary_custody.rs
/// A8 — the adversary files the evidence first and claims the attribution.
#[test]
fn a8_a_first_filer_owns_the_attribution_and_still_cannot_rewrite_the_bytes() {
    let mut store = store_with_devices(&["dev_adversary", "dev_operator"]);
    let artifact = ingested("wrt_race", "fix the auth token refresh bug");

    // The attack: the adversary files first.
    assert_eq!(store.put_artifact(&artifact, "dev_adversary", NOW).expect("filed"), PutOutcome::Stored);
    // The control: the operator files the identical bytes second. It must be accepted -- if the
    // control were refused, the assertion below would be about an error, not about attribution.
    assert_eq!(
        store.put_artifact(&artifact, "dev_operator", NOW + 60).expect("filed again"),
        PutOutcome::AlreadyHeld,
        "the honest second filing must be accepted, or this test measures an error path"
    );

    let held = store.get_artifact(&artifact.digest).expect("read").expect("held");
    assert_eq!(
        held.submitted_by_device, "dev_adversary",
        "RECORDED, not fixed: whoever files first owns the attribution on a digest. The archive is \
         right to refuse to rewrite it -- that is append-only -- and a reader must therefore treat \
         submitted_by_device as 'who filed this', never as 'who produced this'."
    );
    assert_eq!(held.bytes, artifact.bytes, "and the bytes are the ones that were filed");
}
```

Registry entry: `Reach::RefusedAt("MemoryStore::put_artifact returns AlreadyHeld and rewrites nothing")`, with the attribution residual in the `target` string. The completeness scan in `mod.rs` must be widened in this step to also read `rust/archive/tests/adversary_custody.rs`, and to fail if that file is missing — the lesson from `append_only.rs:355`, where a hardcoded file list silently stopped covering a file.

- [ ] **Step 10 — Fill the registry; gate the rendered count against its record.**

Set `pub const STRATEGIES: [Strategy; 8]` with the eight entries above, then add the two tests that keep the table honest. Test intent: a strategy count that appears in prose must be tied to the file it came from, because a stale count is how this program has previously shipped a claim nobody re-checked.

```rust
#[test]
fn the_module_doc_states_the_number_of_strategies_this_suite_actually_has() {
    // Built at run time: a literal count in the needle would be the thing being checked.
    let source = harness::read_repository_file("rust/warrant/tests/invariants/adversary/mod.rs");
    let claimed = format!("{} strategies against the notary", STRATEGIES.len());
    assert!(
        source.contains(&claimed),
        "the module doc claims a different number of strategies than the registry holds ({}). \
         Update both or neither: a documented count nobody checks is how a reviewer reads coverage \
         that does not exist.",
        STRATEGIES.len()
    );
}

#[test]
fn every_finding_names_the_task_that_closes_it_and_no_finding_claims_a_refusal() {
    for strategy in &STRATEGIES {
        match strategy.reach {
            Reach::RefusedAt(check) => assert!(
                !check.is_empty(),
                "strategy {} claims a refusal without naming the check that performs it. A claim \
                 with no mechanism is the defect this whole corpus exists to refuse.",
                strategy.id
            ),
            Reach::Unrefused(fix) | Reach::Unrepresentable(fix) => assert!(
                fix.contains("Task"),
                "strategy {} is a finding and must name the task that closes it, got {fix:?}",
                strategy.id
            ),
        }
        assert!(strategy.reach.sentence().len() > 40);
    }
    assert_eq!(
        STRATEGIES.iter().filter(|s| s.reach.is_a_finding()).count(),
        3,
        "A2, A4 and A7 are the three attacks this suite does not refuse. If that number changes, \
         the product sentence in docs/W1-delivery-gaps.md changes with it, in the same commit."
    );
}
```

Also add the P0 path the seed requires: any strategy whose `Reach` is `RefusedAt` and whose test fails is, by construction, a demonstrated forgery. The failure message on every `refused_at_the_boundary` call already says the attack reached the boundary and was not refused; this step adds one line to the module doc stating that such a failure is a **P0 that blocks the release**, and that the reproducing chain is written to `docs/task-evidence/` rather than only appearing in a CI log. No new machinery: `check_invariant_ratchet.py:143` already fails the build on any corpus failure with the message *"A failing invariant test is a finding"*.

- [ ] **Step 11 — Raise the ratchet, correct the status word, record the gaps, run the full gate, commit.**

```bash
cd M:/wt-5.3-adversary/rust
cargo test -p warrantor-warrant --test invariants 2>&1 | tee -a ../docs/task-evidence/task-5.3.md | tail -3
cargo test -p warrantor-archive --test adversary_custody
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
cd .. && python tools/ci/check_invariant_ratchet.py --show-findings
python tools/ci/check_invariants.py && python -m pytest tools/ci/test_check_invariants.py -q -p no:cacheprovider
python tools/ci/wiring_census.py && python tools/ci/check_docs.py
```

Then, **in one commit**:

- Set `passing_floor` in `tools/ci/invariant-ratchet.json` to the number in the captured `test result:` line — read from the output, never computed here. `check_invariant_ratchet.py:159` fails the build on an *improvement* too, so the floor must move in this commit or CI is red. Leave `ignored_ceiling` at `19`: this task adds no `#[ignore]`, and if the number moved, something was silenced.
- Correct `i07_evidence_precedes_commitment.rs:159` from `"I-07 orphaned: …"` to `"I-07 partial: …"`, keeping the rest of the string byte-identical. Nothing else in the test changes. `check_invariants.py`'s own rule is that `orphaned` means no cited crate is reachable from the binary, and `evidence` is reachable — so the ledger's `partial` is right and the ignore reason was the drift. Add to `fixture.rs` an assertion that each `#[ignore]` reason's status word matches that invariant's `status` in `evidence/invariants.json`, so this pair can never disagree again silently.
- Update the `gap` text on I-07 and I-10 in `evidence/invariants.json` to name this suite's trip-wires — *"Task 5.3 strategy A2 records the unrefused case executably; it starts failing when Task 1.1 lands"* and the same for A4 — leaving both `status` values at `partial`. **No status is promoted by this task**: promotion needs a live-run receipt, and an adversary produces attacks, not receipts.
- Add a Tier 5 subsection to `docs/W1-delivery-gaps.md` after line 1068 carrying the Bound-strength paragraph verbatim, including the three unrefused strategies and their owning tasks.
- Write `docs/task-evidence/task-5.3.md` with every captured command from Step 0 and this step, the before-and-after `test result:` lines, and the three Step 0 contradictions with the evidence for each.
- `git commit -s` (the DCO gate is a required check) with a message explaining why the adversary lives inside the counted `invariants` target rather than in a target of its own: `check_invariant_ratchet.py:87–103` runs `cargo test -p warrantor-warrant --test invariants` and nothing else, so a separate `--test adversary` target would produce a second, ungated number — the exact shape of a check that stops checking.

Exit condition for the step, and for the task: `python tools/ci/check_invariant_ratchet.py --show-findings` prints `invariant ratchet: ok (N passing at floor N, 19 recorded findings at ceiling 19)` with `N > 65`, and `python tools/ci/wiring_census.py` still prints `9 of 39 crates reachable from warrantor-warrant over 17 path edges`.

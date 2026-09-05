//! I-07 — Evidence precedes commitment.
//!
//! > The AAR (P2) is signed *before* the action's effect is visible; the action only commits once
//! > evidence is durable.
//!
//! The commit gate in `evidence::verify_chain` is real and refuses an orphan post-commit by name.
//! The finding is upstream of it: the `warrantor` binary never issues a pre-commit receipt at all,
//! so there is no chain for the gate to verify and nothing that could have been durable before an
//! effect became visible.

use crate::{fixture, harness, scenario};
use warrantor_evidence as evidence;

fn signed_chain() -> (evidence::WarReceipt, evidence::WarReceipt) {
    let (key, _) = evidence::generate_keypair();
    let pre_commit = evidence::issue_pre_commit(
        scenario::predicate(evidence::Phase::PreCommit),
        &key,
        "corpus-i07",
    );
    let post_commit =
        evidence::issue_post_commit(&pre_commit, scenario::outcome(), &key, "corpus-i07");
    (pre_commit, post_commit)
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_commit_gate_names_this_invariant_in_its_refusal() {
    assert_eq!(fixture::invariant("I-07").id, "I-07");
    harness::source_contains(
        "rust/evidence/src/lib.rs",
        "post_commit has no parent_receipt (orphan; I-07)",
        "The orphan refusal is the commit gate. Its text is what a third-party verifier reads.",
    );
    harness::source_contains(
        "rust/evidence/src/lib.rs",
        "/// Signed + durable BEFORE the effect is visible (I-07).",
        "The pre-commit phase must stay documented as the durability point.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_two_phase_chain_verifies_end_to_end() {
    let (pre_commit, post_commit) = signed_chain();
    evidence::verify_chain(&pre_commit, &post_commit).expect("an honest chain verifies");
    assert_eq!(
        post_commit.predicate.binding.parent_receipt.as_deref(),
        Some(pre_commit.predicate.binding.receipt_id.as_str()),
        "the post-commit must point at the pre-commit that preceded it",
    );
    assert!(
        pre_commit.predicate.outcome.is_none(),
        "a pre-commit that already knows the outcome was not signed before the effect",
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn an_orphan_post_commit_is_refused() {
    // The direct attack on I-07: commit first, then author the evidence afterwards with no parent
    // to prove it existed first.
    //
    // The orphan is re-signed rather than hand-edited. `verify_chain` verifies both signatures
    // before it evaluates the commit gate, so an unsigned forgery is refused for being unsigned
    // and never reaches the gate this test is about — a green result proving nothing. An adversary
    // who can author a receipt can sign it, so the corpus signs it too.
    let (pre_commit, post_commit) = signed_chain();
    let (attacker_key, _) = evidence::generate_keypair();

    let mut orphan_predicate = post_commit.predicate.clone();
    orphan_predicate.binding.parent_receipt = None;
    let orphan = evidence::WarReceipt {
        signature: scenario::sign_as_attacker(
            &orphan_predicate,
            &attacker_key,
            "corpus-i07-orphan",
        ),
        predicate: orphan_predicate,
    };

    // Proof the attack reached the gate and not the signature check: the forgery's own signature
    // verifies. Without this line a broken forgery would masquerade as an enforced invariant.
    evidence::verify_receipt(&orphan)
        .expect("the orphan is validly signed, so its refusal must come from the commit gate");

    harness::refused_at_the_boundary(
        "a validly signed post-commit with no pre-commit parent",
        &evidence::verify_chain(&pre_commit, &post_commit),
        &evidence::verify_chain(&pre_commit, &orphan),
        |result| result.is_ok(),
    );
    let error = evidence::verify_chain(&pre_commit, &orphan).expect_err("the orphan is refused");
    assert!(
        error.to_string().contains("orphan; I-07"),
        "the refusal must come from the commit gate and name the invariant, got: {error}",
    );
}

#[test]
fn a_post_commit_pointing_at_a_different_pre_commit_is_refused() {
    // The subtler attack: produce a real pre-commit for a harmless action, commit a different
    // action, and point the post-commit at the harmless receipt.
    let (pre_commit, post_commit) = signed_chain();

    let (other_key, _) = evidence::generate_keypair();
    let mut other_predicate = scenario::predicate(evidence::Phase::PreCommit);
    other_predicate.binding.receipt_id = "rcpt_corpus_unrelated".to_string();
    let unrelated_pre_commit =
        evidence::issue_pre_commit(other_predicate, &other_key, "corpus-i07-other");

    harness::refused_at_the_boundary(
        "a post-commit chained to an unrelated pre-commit",
        &evidence::verify_chain(&pre_commit, &post_commit),
        &evidence::verify_chain(&unrelated_pre_commit, &post_commit),
        |result| result.is_ok(),
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_parent_receipt_field_is_the_proof_of_ordering() {
    let (pre_commit, post_commit) = signed_chain();
    let json = serde_json::to_value(&post_commit).expect("the receipt serializes");
    let binding = json
        .get("predicate")
        .and_then(|predicate| predicate.get("binding"))
        .and_then(|binding| binding.as_object())
        .expect("the receipt carries a binding");

    assert_eq!(
        binding
            .get("parent_receipt")
            .and_then(|value| value.as_str()),
        Some(pre_commit.predicate.binding.receipt_id.as_str()),
        "`parent_receipt` is I-07's evidence field; a receipt that omits it proves no ordering",
    );
    assert_eq!(
        binding.get("phase").and_then(|value| value.as_str()),
        Some("post_commit"),
    );
}

// -- was a finding, earned 2026-09-05 -------------------------------------------------

/// Recorded 2026-09-02 as a finding: nothing in `rust/warrant/src` called `issue_pre_commit`, so
/// the commit gate was implemented, tested, correct — and reached by no shipped action.
///
/// Task 1.1 earned it. `settle::EvidencedPerformer::perform` issues a pre-commit, makes it durable
/// through a [`crate::settle::ReceiptSink`], and returns an error instead of calling the inner
/// performer when it cannot. Live run 2026-09-05, warrant `wrt_d891c73cbcb70a62`.
///
/// **What this test still does not measure.** It counts call sites, not ordering, so it cannot
/// tell issuance from issuance-before-the-effect. That ordering is measured where it can be —
/// `rust/warrant/tests/report_evidence_chain.rs::a_pre_commit_receipt_is_on_disk_before_the_effect
/// _is_performed` counts the lines already durable in the log at the instant the adapter is
/// called. Task 2.3 still owns the commit point for the staged path as a whole.
#[test]
fn the_product_issues_a_pre_commit_before_it_acts() {
    let calls = harness::occurrences_in_rust_sources("rust/warrant/src", "issue_pre_commit");
    assert!(
        calls > 0,
        "the warrant crate never issues a pre-commit receipt, so I-07's ordering guarantee \
         governs no shipped action.",
    );
}

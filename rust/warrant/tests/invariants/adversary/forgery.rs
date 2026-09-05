//! A1 and A2 — forging a chain, and authoring evidence at a time it did not happen.

use warrantor_evidence as evidence;
use warrantor_warrant::report;

use super::fixtures;
use crate::{harness, scenario};

/// A1 — a fully self-consistent chain signed by a key that is not the issuer's.
///
/// `verify_chain` is anchor-free exactly as `verify_export` is, and an adversary who can author a
/// receipt can sign it. `rust/archive/tests/verification_does_not_depend_on_the_archive.rs:292`
/// already proves this for a *bundle*; nothing proved it for a *chain*, which is what a downstream
/// consumer of the receipt graph actually walks. Both directions are asserted, so a refactor that
/// quietly made `verify_chain` anchor-aware fails on the first assertion rather than leaving a hole
/// nobody noticed.
#[test]
fn a1_a_chain_forged_end_to_end_verifies_and_is_caught_only_by_the_anchor() {
    let (issuer, issuer_public) = evidence::generate_keypair();
    let (adversary, _) = evidence::generate_keypair();

    // The control: an honest chain, signed by the issuer.
    let honest_pre = evidence::issue_pre_commit(
        scenario::predicate(evidence::Phase::PreCommit),
        &issuer,
        "issuer",
    );
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
    let expected = hex::encode(issuer_public.to_bytes());
    harness::refused_at_the_boundary(
        "a chain forged end to end by the adversary's own key, checked against the pinned issuer",
        &honest_post,
        &forged_post,
        |receipt: &evidence::WarReceipt| receipt.signature.public_key == expected,
    );
}

/// A2 — the report's own receipt can claim it was issued a day before the report it covers.
///
/// # Why this is not the attack the plan wrote
///
/// The plan's A2 asserted that `rust/warrant/src` never calls `issue_pre_commit`, so no ordering
/// existed to violate. **That is stale.** Task 1.1 landed on this base: `settle.rs:296` issues a
/// pre-commit, `i07_evidence_precedes_commitment.rs::the_product_issues_a_pre_commit_before_it_acts`
/// no longer carries an `#[ignore]`, and
/// `report_evidence_chain.rs::a_pre_commit_receipt_is_on_disk_before_the_effect_is_performed`
/// counts the lines already durable when the adapter is called. Written as planned, A2's control
/// would fail — which is the harness saying the attack no longer reaches anything.
///
/// So A2 attacks what backdating can still reach. `verify_export` binds the **notary** receipt's
/// timestamp to the bundle (`report.rs:1216`, `body.timestamp == export.bundle.generated_at`) and
/// binds six fields of the **evidence** receipt — receipt id, parameters digest, target, class,
/// principal, outcome digest — but never `binding.issued_at`. The asymmetry is the finding: the
/// evidence half of a signed report can name any issuance time it likes, and a reader running the
/// shipped verifier learns nothing about when it was authored.
#[test]
fn a2_the_evidence_receipts_issuance_time_is_not_bound_to_the_report_it_covers() {
    let dir = fixtures::tempdir("a2");
    let genuine = fixtures::settled_export(&dir, "wrt_a2", "backdate the evidence");

    // The control: unmodified, the export verifies and its receipt was issued when it says.
    report::verify_export(&genuine).expect("the control export verifies");
    assert!(
        genuine.evidence_receipt.predicate.binding.issued_at <= genuine.bundle.generated_at,
        "the honest receipt is issued no later than the report it covers"
    );

    // The attack: backdate the evidence receipt a full day and re-sign it with the issuer's own
    // key, so no signature check can be what refuses it. Backdating rather than postdating keeps
    // `issued_at <= expires_at`, so the receipt stays well-formed and the attack reaches the
    // bindings instead of dying in `verify_receipt`.
    let mut predicate = genuine.evidence_receipt.predicate.clone();
    let honest_issued_at = predicate.binding.issued_at;
    predicate.binding.issued_at = honest_issued_at - 86_400;
    let backdated = evidence::WarReceipt {
        signature: scenario::sign_as_attacker(&predicate, &fixtures::issuer(), "issuer"),
        predicate,
    };
    evidence::verify_receipt(&backdated).expect(
        "the backdated receipt must be validly signed, or its refusal would be about the signature \
         and would prove nothing about the time binding",
    );

    let mut attacked = genuine.clone();
    attacked.evidence_receipt = backdated;

    harness::reached_the_boundary_unrefused(
        "a report whose evidence receipt claims it was issued a day before the report itself",
        &report::verify_export(&genuine),
        &report::verify_export(&attacked),
        |result: &Result<(), report::ReportError>| result.is_ok(),
    );
    assert_eq!(
        attacked.evidence_receipt.predicate.binding.issued_at,
        honest_issued_at - 86_400,
        "the attack must actually have moved the time it claims to have moved"
    );
    // The line that makes this measurable: the notary half IS bound, so the gap is specifically
    // the evidence half. If a binding for the evidence receipt's issuance time lands, this test
    // starts failing and whoever landed it converts A2 to refused_at_the_boundary.
    harness::source_contains(
        "rust/warrant/src/report.rs",
        "the notary receipt was issued at a different time than the bundle claims",
        "A2 measures the asymmetry between the two receipts' time bindings. If the notary binding \
         is gone, this strategy is comparing against nothing.",
    );
}

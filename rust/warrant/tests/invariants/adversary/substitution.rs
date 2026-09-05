//! A3 and A4 — putting a genuine record where it does not belong, and using one twice.

use warrantor_evidence as evidence;
use warrantor_notary as notary;
use warrantor_warrant::report;

use super::fixtures;
use crate::{harness, scenario};

/// A3 — a genuine receipt from one report, attached to another.
///
/// The replay-into-false-context attack. The receipt is genuine, verifies on its own, and simply
/// does not describe the bundle it has been attached to. `report.rs` binds
/// `predicate.binding.receipt_id == export.bundle_digest`, so this must fail as a `Binding`, not as
/// a signature — and asserting *which* error is what stops the test from claiming credit for the
/// wrong refusal.
#[test]
fn a3_a_genuine_receipt_lifted_onto_a_different_report_is_refused_as_a_binding() {
    let dir = fixtures::tempdir("a3");
    let first = fixtures::settled_export(&dir, "wrt_a3_first", "the real goal");
    let second = fixtures::settled_export(&dir, "wrt_a3_second", "another goal");
    assert_ne!(
        first.bundle_digest, second.bundle_digest,
        "the two exports must genuinely differ, or this attack swaps a report for itself"
    );

    // Both receipts verify individually before and after the lift; that is the point of the attack.
    evidence::verify_receipt(&second.evidence_receipt).expect("the lifted receipt is genuine");
    notary::verify_receipt(&second.notary_receipt).expect("the lifted notary receipt is genuine");

    let mut grafted = first.clone();
    grafted.evidence_receipt = second.evidence_receipt.clone();
    grafted.notary_receipt = second.notary_receipt.clone();

    harness::refused_at_the_boundary(
        "a valid receipt pair lifted from one report onto another",
        &report::verify_export(&first),
        &report::verify_export(&grafted),
        |result: &Result<(), report::ReportError>| result.is_ok(),
    );
    let error = report::verify_export(&grafted).expect_err("the graft is refused");
    assert!(
        matches!(error, report::ReportError::Binding(_)),
        "a lifted receipt must fail as a binding, not as a signature -- a signature failure here \
         would mean the attack was malformed and the refusal proves nothing: {error}"
    );
}

/// A4 — the same request twice, against the context the product actually builds.
///
/// I-10's direct attack against the product's own context, not against a hand-built one.
/// `report.rs:837` and `settle.rs:168` each construct `seen_nonces: Vec::new()` on every call, so
/// the Freshness gate is asked whether a nonce is in an empty set and always answers no. The corpus
/// proves the gate works when told (`i10_replay_is_detectable::a_captured_request_replayed_verbatim_is_refused`);
/// nothing proved that the product never tells it.
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

    // The attack: the product's context, whose nonce set is empty on every call.
    let product_shaped = scenario::allowed_context();
    let first = notary::verdict(&request, &product_shaped);
    let second = notary::verdict(&request, &product_shaped);
    harness::reached_the_boundary_unrefused(
        "the identical request replayed against the context the product builds",
        &first,
        &second,
        scenario::notary_allowed,
    );

    // Both call sites, so closing one and leaving the other cannot read as closed.
    assert_eq!(
        harness::occurrences_in_rust_sources("rust/warrant/src", "seen_nonces: Vec::new()"),
        2,
        "A4 measures these exact lines -- report.rs for the report path and settle.rs for the \
         staged path. When a nonce store lands, this strategy must be converted to \
         refused_at_the_boundary and the ratchet raised in the same commit."
    );
}

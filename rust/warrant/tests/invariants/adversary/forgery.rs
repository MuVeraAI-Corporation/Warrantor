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
///
/// # A1 is a finding, and the correction that made it one
///
/// A1 shipped as `Reach::RefusedAt("the caller's anchor comparison against the pinned issuer")` and
/// was counted among five refusals. Two independent reviews showed that label had no shipped
/// mechanism behind it. There is no `verify_chain_signed_by`: `rust/evidence/src/lib.rs` exports
/// `verify_receipt`, `verify_receipt_at`, `verify_chain`, `verify_chain_at` and `verify_authority`,
/// while `report::verify_export_signed_by`, `verify_spend_signed_by` and `verify_stop_signed_by`
/// exist for the other three envelopes. So the "caller's anchor comparison" is the four-token
/// closure at the bottom of this test and nothing a reader can call. The proof was a mutation:
/// making `evidence::verify_chain` return `Ok(())` before it verifies anything left a1 **green**
/// while turning two pre-existing I-07 tests red. A strategy that cannot fail for any change to
/// shipped code is not measuring shipped code, so A1 is now
/// [`super::Reach::RefusedOnlyByReaderWrittenCode`] and counts as a finding.
///
/// Two assertions were added rather than the label alone being reworded, because a relabel with no
/// new mechanism is the same defect one level up:
///
/// 1. a negative control that `verify_chain` refuses a tampered chain, so the no-op mutation above
///    now turns a1 red at the line that assumed the verifier does something;
/// 2. a static assertion that no anchored chain verifier ships, so the day one lands a1 goes red
///    and whoever landed it converts A1 to a real `Reach::RefusedAt`.
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

    // The negative control, and the reason it is here: without it, `verify_chain` returning
    // `Ok(())` unconditionally would leave this whole strategy green, because every other
    // `verify_chain` call in this test EXPECTS success. A tampered chain must be refused, or
    // "the forged chain verifies" says nothing about the verifier.
    let mut tampered = honest_post.clone();
    tampered.predicate.binding.parent_receipt = Some("wrt_a1_not_the_parent".to_string());
    evidence::verify_chain(&honest_pre, &tampered).expect_err(
        "verify_chain must refuse a post-commit whose parent pointer does not name the pre-commit. \
         If this passes, verify_chain answers nothing and A1's remaining assertions are vacuous.",
    );

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

    // Direction two: pinning the issuer refuses it, and the control passes the same pin. Note
    // what performs that refusal -- the closure below, written here, in a test. That is the whole
    // reason A1 is registered as a finding rather than as a refusal.
    let expected = hex::encode(issuer_public.to_bytes());
    harness::refused_at_the_boundary(
        "a chain forged end to end by the adversary's own key, checked against the pinned issuer",
        &honest_post,
        &forged_post,
        |receipt: &evidence::WarReceipt| receipt.signature.public_key == expected,
    );

    // And the tripwire that ties the finding to the shipped surface. `verify_export_signed_by`,
    // `verify_spend_signed_by` and `verify_stop_signed_by` exist; the chain has no equivalent, so
    // a reader walking the receipt graph has to write the comparison above themselves.
    assert_eq!(
        harness::occurrences_in_rust_sources("rust/evidence/src", "verify_chain_signed_by"),
        0,
        "an anchored chain verifier now exists in the evidence crate. A1 is no longer a finding: \
         call it here, convert this strategy to Reach::RefusedAt naming that symbol, drop it from \
         the unrefused count in docs/W1-delivery-gaps.md, and raise the ratchet in the same commit."
    );
    for anchored in [
        "verify_export_signed_by",
        "verify_spend_signed_by",
        "verify_stop_signed_by",
    ] {
        assert!(
            harness::occurrences_in_rust_sources("rust/warrant/src", anchored) > 0,
            "A1's finding is that the CHAIN has no anchored verifier while the other envelopes do. \
             {anchored} is gone, so the asymmetry this strategy records no longer exists and the \
             registry entry needs rewriting rather than reinterpreting."
        );
    }
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
/// counts the lines already durable when the adapter is called.
///
/// Written as planned, A2's **attacked** arm fails, not its control — a correction this comment
/// earned by review. The plan passes `control = &(atomic > 0)` and `attacked = &(issued == 0)`; on
/// this base `issue_atomic` occurs 4 times in `rust/warrant/src` so the control is allowed, and
/// `issue_pre_commit` occurs once so `issued == 0` is false and
/// `reached_the_boundary_unrefused`'s second assertion fires with *"this invariant is now
/// enforced -- the attack was refused"*. That is the harness saying the attack no longer reaches
/// anything, and it says it about the attacked value.
///
/// So A2 attacks what backdating can still reach. `verify_export` binds the **notary** receipt's
/// timestamp to the bundle — `body.timestamp == export.bundle.generated_at`, cited by its text
/// rather than by a line number because the line number drifted: this comment read `report.rs:1216`
/// and 1216 is `body.actor_svid == export.bundle.subject`, a neighboring bind that would have made
/// the citation look right at a glance. The text is pinned by the `harness::source_contains` call at
/// the bottom of this test, so it cannot drift the way a number does.
///
/// Against that, `verify_export` reads **seven** fields of the **evidence** receipt's predicate —
/// receipt id, parameters digest, target, class, principal, outcome digest and decision verdict —
/// plus its `binding.enforcement_mode` and a `check_mode_honesty` call. It never reads
/// `binding.issued_at`: the only `issued_at` sites in `report.rs` are the field definition, three
/// issuance sites and one build-time assignment, none of them in the verifier. The asymmetry is the
/// finding: the evidence half of a signed report can name any issuance time it likes, and a reader
/// running the shipped verifier learns nothing about when it was authored.
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
    // The pinned-key path, asserted because a document depends on it. docs/W1-delivery-gaps.md
    // §5.3 ships a summary sentence saying a receipt cannot be "altered ... in its own fields"
    // without a reader detecting it, "provided that reader pinned the issuer's key out of band".
    // A2 is a receipt altered in its own fields and re-signed under the issuer's key, so that
    // sentence has to carry an exclusion for it -- and the exclusion is now derived from this line
    // rather than written beside it. If an issuance-time binding ever lands, this expect fails and
    // the sentence loses its exclusion in the same commit.
    report::verify_export_signed_by(&attacked, &fixtures::issuer().verifying_key()).expect(
        "pinning the issuer does not help against backdating: the attack re-signs with the issuer's \
         own key, so the key-equality check verify_export_signed_by adds is checking a key the \
         attack never changed",
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

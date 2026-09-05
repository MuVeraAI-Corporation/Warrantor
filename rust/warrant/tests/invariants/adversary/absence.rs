//! A7 — suppress the evidence entirely. The honest negative.
//!
//! The attack this suite provably cannot refuse. An offline verifier holding one file cannot tell a
//! deleted receipt from a run that never happened, because the missing thing is missing. Writing
//! this as a passing refusal would be the phantom-scorer failure in its purest form, so it is
//! recorded as [`super::Reach::Unrepresentable`] and handed to the tasks that could see it.

use warrantor_warrant::report;

use super::fixtures;
use crate::harness;

/// A7 — a suppressed effect is indistinguishable from an effect that never happened.
///
/// Two effects are performed and two chains are written. The adversary exports a bundle describing
/// only the first. The result is not a tampered file that a verifier refuses — it is a **valid**
/// file, signed, internally consistent, describing one effect, and there is nothing in it or beside
/// it that says a second one ever existed.
///
/// The distinguishing information lives in a sequence somebody else keeps. That is Task 10.3's
/// evidence-integrity monitors (which must be able to fail loudly about the store they live in, so
/// they cannot live only in it) and Task 10.6's custody record. Truncation by an induced reset is
/// the same finding with a different cause and is recorded here rather than as a second strategy
/// that would imply a second guarantee.
#[test]
fn a7_a_suppressed_receipt_is_indistinguishable_from_a_run_that_never_happened() {
    let dir = fixtures::tempdir("a7");
    let (genuine, honest) =
        fixtures::settled_export_and_receipts(&dir, "wrt_a7", "suppress a chain");

    // The control: with both chains, every check the product ships passes.
    report::verify_export(&genuine).expect("the control verifies");
    assert_eq!(
        honest.len(),
        4,
        "the fixture must hold two complete chains, or there is nothing to suppress"
    );
    assert_eq!(
        genuine
            .bundle
            .effect_evidence
            .as_ref()
            .expect("the control lists its chains")
            .effects
            .len(),
        2,
        "the control's bundle must describe two effects"
    );

    // The attack: export the same run describing only the first chain. Not a tampered file -- a
    // truthful-looking one, built and signed by the product's own path.
    let suppressed =
        fixtures::export_built_over(&dir, "wrt_a7", "suppress a chain", honest[..2].to_vec());
    let listed = suppressed
        .bundle
        .effect_evidence
        .as_ref()
        .expect("the attacked bundle lists its chains")
        .effects
        .len();
    assert_eq!(
        listed, 1,
        "the attack must actually have dropped a chain from the record"
    );

    // Both verify. That is the whole finding: verification cannot separate them.
    report::verify_export(&genuine).expect("the two-effect export verifies");
    report::verify_export(&suppressed).expect(
        "the one-effect export verifies too. An offline verifier holding one file cannot tell a \
         suppressed chain from a run that only ever had one effect -- the evidence of the deletion \
         is the thing that was deleted.",
    );
    report::verify_export_signed_by(&suppressed, &fixtures::issuer().verifying_key())
        .expect("and pinning the issuer does not help: the suppressed export is genuinely signed");

    // There is no `verify_absence` to call, and these assertions say why rather than inventing one.
    assert_eq!(
        harness::occurrences_in_rust_sources("rust/warrant/src", "fn verify_absence"),
        0,
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

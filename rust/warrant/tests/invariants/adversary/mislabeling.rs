//! A5, A6 and A9 — claiming a bound the system does not hold.
//!
//! These three are the worst defect class this repository can ship: a bound mislabeled *inside a
//! signed bundle*. It has happened once. Task 1.1's original branch claimed `verify_export` refused
//! a per-effect receipt carrying a mode other than `Advisory`, and nothing read the field; three
//! independent adversarial reviews found it, and commit `a84711b` closed it. A5 attacks that fix
//! rather than re-running the test that shipped with it; A9 is what attacking the fix turned up.

use warrantor_evidence as evidence;
use warrantor_warrant::report;

use super::fixtures;
use crate::{harness, scenario};

/// Flip a receipt's enforcement mode and re-sign it with the report's own issuer key, preserving
/// every other field including phase, parent pointer and outcome.
///
/// Re-signing with the *issuer's* key is the whole point: it means no signature check can be what
/// refuses the result, so a refusal has to come from a check that actually reads the mode.
fn re_signed_as(
    receipt: &evidence::WarReceipt,
    mode: evidence::EnforcementMode,
) -> evidence::WarReceipt {
    let mut predicate = receipt.predicate.clone();
    predicate.binding.enforcement_mode = mode;
    evidence::WarReceipt {
        signature: scenario::sign_as_attacker(&predicate, &fixtures::issuer(), "issuer"),
        predicate,
    }
}

/// A5 — a `mediated` per-effect receipt cannot be smuggled past the fix, including unlisted.
///
/// # What this attacks, and why it is not the plan's A5
///
/// The plan's A5 was written before commit `a84711b` and aims at a hole that no longer exists:
/// `verify_effect_receipts` now refuses any per-effect receipt whose mode is not `Advisory`, and
/// `report_evidence_chain.rs::a_per_effect_receipt_claiming_mediated_is_refused_even_under_the_reports_own_key`
/// already pins the listed-receipt vector on both verify paths. Re-implementing that would be a
/// second copy of an existing assertion, not an attack.
///
/// So A5 attacks the fix at its edge: **the receipt the bundle does not list.** The mode loop runs
/// over the whole of `export.effect_receipts` *before* the bundle's effect lines are walked and
/// before the count reconciliation at the end, so an adversary cannot append a `mediated` claim as
/// an unaccounted receipt and have it refused for the wrong reason — or worse, reach a code path
/// where the count check short-circuits first and the mode is never read. This test asserts the
/// ordering by asserting the *message*: an unlisted mediated receipt must be refused for its mode,
/// not for being unaccounted.
///
/// The second half attacks the report-level receipt with the same re-signing trick, which the
/// report-level mode **family** refuses — not the single line the registry first named. Neutering
/// only `export.evidence_receipt.predicate.binding.enforcement_mode != evidence_mode` leaves this
/// test green, because the `check_mode_honesty(.., true).is_ok()` belt-and-braces check below it
/// fires instead and is also a `ReportError::Mode`, which is all the assertion reads. Both die when
/// the whole family is neutered, so the substantive claim — an escalation is refused, as a `Mode` —
/// is real and mutation-sensitive; the attribution to one line was not, and the registry entry now
/// names the family and the variant.
///
/// **Result: the fix holds on both vectors.** An attack refused is a result. What the fix does *not*
/// cover is in A9, and that is a finding rather than a claim of coverage here.
#[test]
fn a5_a_mediated_per_effect_receipt_is_refused_even_when_the_bundle_does_not_list_it() {
    let dir = fixtures::tempdir("a5");
    let (genuine, honest) =
        fixtures::settled_export_and_receipts(&dir, "wrt_a5", "escalate a mode");

    // The allowed control, first. Without it, a verifier that refused everything would pass this
    // test twice over.
    assert!(
        honest
            .iter()
            .all(|r| r.predicate.binding.enforcement_mode == evidence::EnforcementMode::Advisory),
        "settle must issue advisory per-effect receipts, or this attack has nothing to escalate"
    );
    report::verify_export(&genuine).expect("the unmodified export verifies");

    // Vector one: append a mediated receipt the bundle's effect_evidence section does not list.
    let smuggled = re_signed_as(&honest[0], evidence::EnforcementMode::Mediated);
    evidence::verify_receipt(&smuggled).expect(
        "the smuggled receipt must be validly signed under the issuer's own key, or its refusal \
         would be about the signature and the mode check would never be reached",
    );
    let mut unlisted = genuine.clone();
    unlisted.effect_receipts.push(smuggled);

    harness::refused_at_the_boundary(
        "a mediated per-effect receipt appended to an export whose bundle does not list it",
        &report::verify_export(&genuine),
        &report::verify_export(&unlisted),
        |result: &Result<(), report::ReportError>| result.is_ok(),
    );
    let error = report::verify_export(&unlisted)
        .expect_err("the smuggled mediated receipt is refused")
        .to_string();
    assert!(
        error.contains("mediated") || error.contains("enforcement mode"),
        "an unlisted mediated receipt must be refused FOR ITS MODE, not for being unaccounted. If \
         this reads as a count mismatch, the mode loop no longer runs before the reconciliation and \
         an adversary gets to choose which check answers: {error}"
    );

    // Vector two: the report's own receipt, re-signed as mediated under the issuer's key.
    let mut escalated = genuine.clone();
    escalated.evidence_receipt = re_signed_as(
        &genuine.evidence_receipt,
        evidence::EnforcementMode::Mediated,
    );
    evidence::verify_receipt(&escalated.evidence_receipt)
        .expect("the escalated report receipt is validly signed");
    harness::refused_at_the_boundary(
        "the report's own evidence receipt re-signed to claim mediated enforcement",
        &report::verify_export(&genuine),
        &report::verify_export(&escalated),
        |result: &Result<(), report::ReportError>| result.is_ok(),
    );
    let error = report::verify_export(&escalated).expect_err("the escalation is refused");
    assert!(
        matches!(error, report::ReportError::Mode(_)),
        "a mode escalation must be refused AS a mode escalation. If this reads as a signature or a \
         key-binding failure the refusal is incidental, and an adversary who also re-signs the \
         notary receipt would get through: {error}"
    );

    // And on the pinned-key path, which is the one an auditor holding the issuer's key runs.
    assert!(
        report::verify_export_signed_by(&unlisted, &fixtures::issuer().verifying_key()).is_err(),
        "the pinned-key path must refuse the unlisted mediated receipt as well"
    );
}

/// A6 — a removed limitation, and two ways to widen authority.
///
/// Two edits an audited party is most tempted to make. Removing a limitation is refused by the
/// bundle digest; expanding `effective_capabilities` is refused by `evidence::verify_authority`. The
/// third part records an attack that is **not** refused and should not be: an adversary who edits
/// the delegation chain itself, so the recomputed intersection genuinely contains the extra
/// capability, produces an authority that verifies — because the chain *is* the authority. That
/// residual belongs in the record rather than in a footnote.
#[test]
fn a6_a_removed_limitation_fails_on_the_digest_and_a_forged_intersection_fails_on_the_proof() {
    let dir = fixtures::tempdir("a6");
    let genuine = fixtures::settled_export(&dir, "wrt_a6", "widen the authority");
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
        |result: &Result<(), report::ReportError>| result.is_ok(),
    );
    assert!(
        matches!(
            report::verify_export(&trimmed).expect_err("the trim is refused"),
            report::ReportError::Digest { .. }
        ),
        "removing a limitation must be refused by the digest over the bundle, so that an attacker \
         who cannot re-sign has nothing to try"
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
        |result: &Result<(), evidence::EvidenceError>| result.is_ok(),
    );
    let error = evidence::verify_authority(&widened).expect_err("the expansion is refused");
    assert!(
        error.to_string().contains("authority expansion; I-02"),
        "the refusal must name the invariant a reader will look up: {error}"
    );

    // The residual, asserted rather than described: an adversary who rewrites the CHAIN gets an
    // authority that verifies. It must, because the chain is the authority -- and that is exactly
    // why a receipt proves the chain it carries, never that the chain was legitimately issued.
    let mut rewritten_chain = honest.chain.clone();
    rewritten_chain[0]
        .capabilities
        .push("net.admin".to_string());
    let consistent = evidence::Authority {
        effective_capabilities: evidence::recompute_intersection(&rewritten_chain),
        intersection_proof: evidence::compute_intersection_proof(&rewritten_chain),
        chain: rewritten_chain,
    };
    evidence::verify_authority(&consistent).expect(
        "a rewritten chain with a recomputed proof IS internally consistent. verify_authority \
         checks that the claimed capabilities follow from the chain, not that the chain is real.",
    );
    assert!(
        consistent
            .effective_capabilities
            .contains(&"net.admin".to_string()),
        "the residual is only a residual if the widened capability actually survived"
    );
}

/// A9 — the bundle's own sentence can claim `mediated` while every receipt says `advisory`.
///
/// # The hole the fix left, found by attacking the fix
///
/// Commit `a84711b` closed two things: `verify_effect_receipts` now refuses a per-effect receipt
/// whose mode is not `Advisory` (A5 confirms that holds), and `with_effect_receipts` derives the
/// bundle's mode word from the receipts instead of hardcoding it. The second is a **build-time**
/// derivation. Nothing on the **verify** path re-derives it.
///
/// So the mode word inside the signed bundle is a rendered number that is not gated against its
/// record. An audited party — using its own legitimate issuer key, forging nothing — builds the
/// bundle around `mediated` receipts so the sentence reads "each mediated", signs it, and then ships
/// the export carrying the honest `advisory` receipts. Every id, handle, tool, subject and status
/// still lines up, so `verify_export` passes, `verify_export_signed_by` passes under the party's own
/// pinned key, and the human-readable disclosure inside the signed bundle asserts a
/// non-bypassability the receipts beside it deny.
///
/// This is recorded, not fixed. The fix is one comparison in `verify_effect_receipts` — recompute
/// the mode phrase from `export.effect_receipts` and refuse a bundle whose sentence disagrees — and
/// it is a product change that must be argued in its own commit, exactly as this task's non-goals
/// say. When it lands, this test starts failing and whoever landed it converts A9 to
/// `refused_at_the_boundary` and raises the ratchet.
#[test]
fn a9_the_bundles_rendered_mode_word_is_not_gated_against_the_receipts_on_the_verify_path() {
    let dir = fixtures::tempdir("a9");
    let (genuine, honest) =
        fixtures::settled_export_and_receipts(&dir, "wrt_a9", "overstate the tier");

    // The control: built and signed honestly, the sentence says advisory and the export verifies.
    report::verify_export(&genuine).expect("the control export verifies");
    let honest_sentence = genuine
        .bundle
        .limitations
        .iter()
        .find(|l| l.contains("per-effect receipt chain"))
        .expect("the bundle says something about the chains")
        .clone();
    assert!(
        honest_sentence.contains("advisory") && !honest_sentence.contains("mediated"),
        "the control's sentence must say advisory: {honest_sentence}"
    );

    // The attack: build the bundle around mediated twins so the derived sentence says `mediated`,
    // sign it, then ship the honest advisory receipts inside it. Same ids, same handles, same
    // statuses -- only the mode differs, and only in the receipts the bundle no longer describes.
    let mediated: Vec<evidence::WarReceipt> = honest
        .iter()
        .map(|r| re_signed_as(r, evidence::EnforcementMode::Mediated))
        .collect();
    let mut attacked = fixtures::export_built_over(&dir, "wrt_a9", "overstate the tier", mediated);
    let overstated = attacked
        .bundle
        .limitations
        .iter()
        .find(|l| l.contains("per-effect receipt chain"))
        .expect("the rebuilt bundle says something about the chains")
        .clone();
    assert!(
        overstated.contains("mediated"),
        "the rebuilt bundle must claim mediated, or there is no mislabel to detect: {overstated}"
    );
    attacked.effect_receipts = honest.clone();

    harness::reached_the_boundary_unrefused(
        "a signed bundle whose sentence claims `mediated` while every receipt it carries says \
         `advisory`",
        &report::verify_export(&genuine),
        &report::verify_export(&attacked),
        |result: &Result<(), report::ReportError>| result.is_ok(),
    );

    // The mislabel, stated as an assertion so it cannot be read as a hypothetical.
    assert!(
        attacked
            .effect_receipts
            .iter()
            .all(|r| r.predicate.binding.enforcement_mode == evidence::EnforcementMode::Advisory),
        "the shipped receipts are advisory"
    );
    assert!(
        attacked
            .bundle
            .limitations
            .iter()
            .any(|l| l.contains("each mediated")),
        "and the signed bundle beside them says mediated"
    );
    // And the pinned-key path does not catch it either, because the party holds the key it pinned.
    report::verify_export_signed_by(&attacked, &fixtures::issuer().verifying_key()).expect(
        "the pinned-key path passes too: pinning answers `whose key was that`, never `is this \
         bundle's prose true about its own receipts`",
    );
    harness::source_contains(
        "rust/warrant/src/report.rs",
        "let mut modes: Vec<&str> = receipts",
        "A9 measures the gap between this build-time derivation and the verify path. If the \
         derivation moves, this strategy is measuring nothing.",
    );
}

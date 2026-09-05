//! I-01 — No active identity, no action.
//!
//! > Every action carries a verifiable AAE (P1) with a valid, unrevoked SPIFFE SVID.
//!
//! The notary's Identity gate implements this faithfully as a decision. What the corpus finds is
//! that on the one path in the shipped binary that reaches the notary, the revocation set handed
//! to that gate is a hardcoded empty vector — so the gate is real and its input is not.

use crate::{fixture, harness, scenario};
use warrantor_notary as notary;

// ── static ────────────────────────────────────────────────────────────────────────────

#[test]
fn the_identity_gate_is_declared_against_this_invariant() {
    assert_eq!(fixture::invariant("I-01").id, "I-01");
    harness::source_contains(
        "rust/notary/src/lib.rs",
        "/// I-01: SVID absent, expired, revoked, or unverifiable.",
        "I-01's gate must stay labeled with the invariant it serves, or the ledger citing it \
         becomes unverifiable.",
    );
    assert_eq!(
        notary::Gate::in_order()[1],
        notary::Gate::Identity,
        "Identity must be the second gate: an action is adjudicated only after the actor is \
         known, and only containment (I-12) may precede it.",
    );
}

// ── runtime ───────────────────────────────────────────────────────────────────────────

#[test]
fn an_absent_svid_is_refused() {
    let context = scenario::allowed_context();
    let mut request = scenario::allowed_request();
    request.actor.svid = String::new();
    let verdict = notary::verdict(&request, &context);
    scenario::assert_denied_at(&verdict, notary::Gate::Identity, "an actor with no SVID");
}

// ── adversarial ───────────────────────────────────────────────────────────────────────

#[test]
fn hop_09_a_reused_third_party_credential_is_refused_at_the_identity_gate() {
    // Round zero, hop 9. The incident's agent reused a credential belonging to a third party.
    // Encoded here as an actor presenting an SVID that the issuer has since revoked: everything
    // else about the request is untouched and valid, which is what makes the refusal attributable
    // to identity rather than to a malformed request.
    let request = scenario::allowed_request();
    let control = notary::verdict(&request, &scenario::allowed_context());

    let mut context = scenario::allowed_context();
    context.revoked_svids = vec![scenario::SUBJECT.to_string()];
    let attacked = notary::verdict(&request, &context);

    harness::refused_at_the_boundary(
        "hop 9: a revoked third-party credential",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(&attacked, notary::Gate::Identity, "a revoked SVID");
}

#[test]
fn an_expired_svid_cannot_carry_an_otherwise_valid_action() {
    let control = notary::verdict(&scenario::allowed_request(), &scenario::allowed_context());

    let mut request = scenario::allowed_request();
    request.actor.svid_not_after = scenario::NOW;
    let attacked = notary::verdict(&request, &scenario::allowed_context());

    harness::refused_at_the_boundary(
        "an SVID expiring exactly now",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(&attacked, notary::Gate::Identity, "an expired SVID");
}

// ── evidence field ────────────────────────────────────────────────────────────────────

#[test]
fn the_receipt_records_the_identity_that_was_refused() {
    let mut context = scenario::allowed_context();
    context.revoked_svids = vec![scenario::SUBJECT.to_string()];
    let request = scenario::allowed_request();
    let verdict = notary::verdict(&request, &context);

    let (signing_key, _) = notary::generate_keypair();
    let receipt = notary::issue_receipt(
        &verdict,
        &request,
        notary::EnforcementMode::Observed,
        &signing_key,
        "corpus-i01",
    );

    notary::verify_receipt(&receipt).expect("the corpus receipt verifies");
    assert_eq!(
        receipt.body.actor_svid,
        scenario::SUBJECT,
        "the receipt must name the SVID whose action was refused; a refusal nobody can attribute \
         is not evidence",
    );
    assert_eq!(
        receipt.body.verdict,
        notary::Verdict::Deny {
            gate: notary::Gate::Identity
        },
        "the receipt must carry the gate, and only the gate",
    );
}

// ── finding ───────────────────────────────────────────────────────────────────────────

/// FINDING (I-01, currently violated). `rust/warrant/src/report.rs` is the only call to
/// `notary::verdict` in the shipped binary, and it constructs its `VerdictContext` with
/// `revoked_svids: Vec::new()`. The Identity gate is therefore evaluated against a revocation set
/// that is empty by construction: no SVID can ever be revoked on the product's own path, so the
/// half of I-01 that says "unrevoked" is unenforced there.
///
/// Note the contrast the same function draws for itself: `contained_scopes` carries a comment
/// saying an empty value "is a statement about what was supplied, never a claim that containment
/// was checked and found clear". `revoked_svids` and `seen_nonces` are given the same empty value
/// and no such disclaimer.
///
/// Fixed by: Task 1.1 (evidence and notary into the report path) supplying a real revocation
/// source, and Task 3.1 (agent principals from SPIFFE SVIDs) making the subject an issued identity
/// rather than the `DEFAULT_CLI_SUBJECT` constant. Recorded 2026-09-02.
#[test]
#[ignore = "I-01 currently violated: revoked_svids is hardcoded empty in report.rs (Task 1.1 / Task 3.1, 2026-09-02)"]
fn the_products_own_notary_call_consults_a_revocation_source() {
    let report = harness::read_repository_file("rust/warrant/src/report.rs");
    assert!(
        !report.contains("revoked_svids: Vec::new()"),
        "report.rs hands the Identity gate an empty revocation set, so I-01's \"unrevoked\" \
         clause cannot fire on the only path that reaches the notary.",
    );
}

/// FINDING (I-01, currently violated). Every local action runs as one hardcoded principal.
/// `DEFAULT_CLI_SUBJECT` is a string constant, not an SVID that was issued, bound to a workload,
/// or checkable against an issuer. I-01 asks for a *verifiable* AAE with a *valid* SVID; a
/// constant satisfies neither adjective.
///
/// Fixed by: Task 3.1 (agent principals at five grains from SPIFFE SVIDs). Recorded 2026-09-02.
#[test]
#[ignore = "I-01 currently violated: the CLI subject is a hardcoded constant, not an issued SVID (Task 3.1, 2026-09-02)"]
fn the_local_subject_is_an_issued_identity_rather_than_a_constant() {
    let library = harness::read_repository_file("rust/warrant/src/lib.rs");
    assert!(
        !library.contains(
            "pub const DEFAULT_CLI_SUBJECT: &str = \"spiffe://muveraai.com/agent/local\""
        ),
        "the local action path presents a compile-time constant as its SPIFFE SVID; nothing \
         issued it and nothing can revoke it.",
    );
}

//! I-05 — Revocation latency is bounded.
//!
//! > Identity revocation (I1) propagates to all replicas in <5s; credential revocation (R4) in
//! > <1s.
//!
//! Both halves exist in the repository and neither is reachable from the product. The credential
//! side is implemented in `rust/credential-vault`, which the `warrantor` binary does not link. The
//! identity side has no implementation at all: `revoked_svids` is a `Vec<String>` the caller
//! supplies, and the one caller supplies an empty one.
//!
//! Within a single decision the latency is zero, which is what the runtime checks below establish.
//! That is a real property and it is not the property I-05 states, because a revocation nobody
//! delivers propagates in no time to no one.

use crate::{fixture, harness, scenario};
use warrantor_notary as notary;

// -- static ---------------------------------------------------------------------------

#[test]
fn the_credential_revocation_budget_is_declared_as_one_second() {
    assert_eq!(fixture::invariant("I-05").id, "I-05");
    harness::source_contains(
        "rust/credential-vault/src/lib.rs",
        "pub const REVOKE_BUDGET: Duration = Duration::from_secs(1);",
        "I-05's credential half is a number, and this constant is the only place it is written \
         as code rather than as prose.",
    );
    harness::source_contains(
        "rust/credential-vault/src/lib.rs",
        "a revoked credential MUST stay revoked across a restart (I-05)",
        "The durability half of revocation: a vault that forgets on restart has an unbounded \
         effective latency.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_revocation_is_effective_within_the_decision_that_sees_it() {
    let mut context = scenario::allowed_context();
    context.revoked_svids = vec![scenario::SUBJECT.to_string()];
    let verdict = notary::verdict(&scenario::allowed_request(), &context);
    scenario::assert_denied_at(&verdict, notary::Gate::Identity, "a revoked SVID");
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn a_revocation_landing_between_the_start_check_and_the_commit_stops_the_commit() {
    // The window I-05 bounds: the agent passed authorization, the operator revoked, and the agent
    // acts. The revocation must win. The identical request is evaluated twice; only the context
    // moves, which is what makes this a latency test rather than a credential test.
    let request = scenario::allowed_request();
    let at_start = notary::verdict(&request, &scenario::allowed_context());

    let mut at_commit_context = scenario::allowed_context();
    at_commit_context.revoked_svids = vec![scenario::SUBJECT.to_string()];
    let at_commit = notary::verdict(&request, &at_commit_context);

    harness::refused_at_the_boundary(
        "a revocation landing between the start check and the commit",
        &at_start,
        &at_commit,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &at_commit,
        notary::Gate::Identity,
        "a mid-action revocation",
    );
}

/// FINDING (I-05, orphaned). Round zero, hop 5: the incident's agent used a credential shared
/// with another system. A shared credential is the case revocation latency cannot help with,
/// because the unit of revocation is the identity and the credential is not bound to one — and the
/// crate that would bind them, `credential-vault`, is not in the `warrantor` binary's dependency
/// graph. Its 1-second budget and its restart-durability test are real, tested, and unreachable
/// from the product.
///
/// Fixed by: no task in the 2026-09-02 implementation plan links `credential-vault`. Task 0.3's
/// orphan census is where the crate is counted; nothing yet wires it. Recorded 2026-09-02.
#[test]
#[ignore = "I-05 orphaned: credential-vault is not linked by the warrantor binary, so hop 5 has no boundary (2026-09-02)"]
fn hop_05_the_product_links_a_credential_vault_that_can_revoke() {
    let manifest = harness::read_repository_file("rust/warrant/Cargo.toml");
    assert!(
        manifest.contains("warrantor-credential-vault"),
        "I-05's credential half lives in a crate the product does not link, so a shared \
         credential has nothing to revoke it. The 1-second budget binds no shipped code path.",
    );
}

/// FINDING (I-05, unimplemented). The identity half — propagation to all replicas in under five
/// seconds — has no implementation. There is no revocation source, no propagation, and no replica
/// set; `VerdictContext::revoked_svids` is a vector the caller fills, and the product's one caller
/// fills it with nothing.
///
/// Fixed by: Task 3.1 (agent principals at five grains from SPIFFE SVIDs) supplies the identity
/// plane a revocation list could come from. Recorded 2026-09-02.
#[test]
#[ignore = "I-05 unimplemented: no revocation source exists for the identity half (Task 3.1, 2026-09-02)"]
fn a_revocation_source_exists_for_the_identity_half() {
    let report = harness::read_repository_file("rust/warrant/src/report.rs");
    assert!(
        !report.contains("revoked_svids: Vec::new()"),
        "the only consumer of the Identity gate supplies a revocation set that is empty by \
         construction, so the five-second propagation bound governs nothing.",
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_receipt_proves_which_action_the_revocation_stopped() {
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
        "corpus-i05",
    );
    notary::verify_receipt(&receipt).expect("the corpus receipt verifies");
    assert_eq!(receipt.body.timestamp, scenario::NOW);
    assert_eq!(
        receipt.body.actor_svid,
        scenario::SUBJECT,
        "a revocation without an attributable receipt cannot be shown to have taken effect \
         within any latency bound",
    );
}

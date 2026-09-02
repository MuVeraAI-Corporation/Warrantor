//! I-06 — Artifact identity is exact.
//!
//! > A model/skill/dataset is identified by its content digest, not its name or URI.
//!
//! The Artifacts gate is written correctly: a digest is admitted only if the caller marked it
//! verified *and* the context's independently resolved set contains it, so neither half alone
//! suffices. The finding is that the product hands that gate an empty artifact list and an empty
//! verified set, which means the one gate standing between a named plugin and execution has never
//! been asked a question.

use crate::{fixture, harness, scenario};
use warrantor_notary as notary;

const HONEST_DIGEST: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
const SUBSTITUTED_DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// A request that executes one artifact, named only by its digest.
fn request_for(digest: &str, verified: bool) -> notary::VerdictRequest {
    let mut request = scenario::allowed_request();
    request.operation.class = "artifact.execute".to_string();
    request.artifacts = vec![notary::ArtifactDigest {
        digest: digest.to_string(),
        verified,
    }];
    request
}

/// A context whose provider has resolved exactly the honest digest.
fn context_resolving_the_honest_digest() -> notary::VerdictContext {
    let mut context = scenario::allowed_context();
    context.verified_artifacts = vec![HONEST_DIGEST.to_string()];
    context
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_artifacts_gate_is_declared_against_this_invariant() {
    assert_eq!(fixture::invariant("I-06").id, "I-06");
    harness::source_contains(
        "rust/notary/src/lib.rs",
        "/// I-06: a digest unverified, unsigned, or mismatched.",
        "The Artifacts gate must stay labeled with the invariant it serves.",
    );
    harness::source_contains(
        "rust/notary/src/lib.rs",
        "// Gate 6 — Artifacts (I-06). Every digest verified + provider-resolved.",
        "Both halves of the check are the point: a caller-asserted flag alone would let the \
         requester vouch for its own artifact.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn an_unverified_digest_is_refused() {
    let verdict = notary::verdict(
        &request_for(HONEST_DIGEST, false),
        &context_resolving_the_honest_digest(),
    );
    scenario::assert_denied_at(
        &verdict,
        notary::Gate::Artifacts,
        "a digest the caller did not verify",
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn hop_08_a_substituted_plugin_body_is_refused_at_the_artifacts_gate() {
    // Round zero, hop 8: plugin execution. The plugin keeps its name and its entry in whatever
    // registry admitted it; only the bytes change. Under I-06 the digest is the identity, so the
    // substitution is a different artifact and the provider has never resolved it.
    let control = notary::verdict(
        &request_for(HONEST_DIGEST, true),
        &context_resolving_the_honest_digest(),
    );
    let attacked = notary::verdict(
        &request_for(SUBSTITUTED_DIGEST, true),
        &context_resolving_the_honest_digest(),
    );

    harness::refused_at_the_boundary(
        "hop 8: a plugin whose body was substituted under the same name",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &attacked,
        notary::Gate::Artifacts,
        "a digest no provider resolved",
    );
}

#[test]
fn a_requester_cannot_vouch_for_its_own_artifact() {
    // The attack that a single-flag gate would fall to: assert `verified: true` for a digest the
    // provider never saw. Both halves must hold, so the assertion buys nothing.
    let control = notary::verdict(
        &request_for(HONEST_DIGEST, true),
        &context_resolving_the_honest_digest(),
    );

    let mut empty_provider = scenario::allowed_context();
    empty_provider.verified_artifacts = Vec::new();
    let attacked = notary::verdict(&request_for(HONEST_DIGEST, true), &empty_provider);

    harness::refused_at_the_boundary(
        "a caller asserting verification the provider never performed",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &attacked,
        notary::Gate::Artifacts,
        "a self-vouched artifact",
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_receipt_records_the_refusal_without_naming_the_digest_that_failed() {
    // I-06's evidence field is the receipt's verdict. It must say Artifacts and nothing more:
    // spec 11 §4 keeps the denial coarse, because an agent that learns which digest was rejected
    // learns the shape of the admitted set and can search it.
    let request = request_for(SUBSTITUTED_DIGEST, true);
    let verdict = notary::verdict(&request, &context_resolving_the_honest_digest());

    let (signing_key, _) = notary::generate_keypair();
    let receipt = notary::issue_receipt(
        &verdict,
        &request,
        notary::EnforcementMode::Observed,
        &signing_key,
        "corpus-i06",
    );
    notary::verify_receipt(&receipt).expect("the corpus receipt verifies");

    assert_eq!(
        receipt.body.verdict,
        notary::Verdict::Deny {
            gate: notary::Gate::Artifacts
        },
    );
    let rendered = serde_json::to_string(&receipt).expect("the receipt serializes");
    assert!(
        !rendered.contains(SUBSTITUTED_DIGEST) && !rendered.contains(HONEST_DIGEST),
        "the receipt leaks which digest was adjudicated; the denial must carry the gate and \
         nothing else",
    );
}

// -- finding --------------------------------------------------------------------------

/// FINDING (I-06, partial). `report.rs` builds its `VerdictRequest` with `artifacts: Vec::new()`
/// and its `VerdictContext` with `verified_artifacts: Vec::new()`. The Artifacts gate therefore
/// iterates an empty list and passes, on every action, unconditionally. Nothing in the shipped
/// binary identifies a tool, skill or model by digest at the moment of use, so hop 8 has no
/// boundary to reach in the product — only in the notary the product barely consults.
///
/// Fixed by: Task 2.2 (signed tool and skill admission manifests) and Task 2.4 (EXEC admission by
/// content digest and declared execution surface). Recorded 2026-09-02.
#[test]
#[ignore = "I-06 partial: the product supplies no artifacts and no verified set, so the gate never fires (Task 2.2 / Task 2.4, 2026-09-02)"]
fn the_product_submits_artifacts_to_the_artifacts_gate() {
    let report = harness::read_repository_file("rust/warrant/src/report.rs");
    assert!(
        !report.contains("verified_artifacts: Vec::new()"),
        "the Artifacts gate is handed an empty resolved set by the only code that calls it, so \
         I-06 is enforced over the empty set of artifacts.",
    );
}

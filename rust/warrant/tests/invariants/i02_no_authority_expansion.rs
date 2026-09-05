//! I-02 — No authority expansion.
//!
//! > The intersection of authorities in the delegation chain is the maximum authority; never the
//! > union.
//!
//! This is the best-defended invariant in the codebase. Two implementations recompute the
//! intersection — `notary::effective_capabilities` for the decision and
//! `evidence::recompute_intersection` for the receipt — and the receipt verifier rejects a claimed
//! capability set the chain does not produce. The corpus attacks both, and records one seam: the
//! two implementations are separate code paths that nothing checks against each other.

use crate::{fixture, harness, scenario};
use warrantor_evidence as evidence;
use warrantor_notary as notary;

fn chain(link_capabilities: &[&[&str]]) -> Vec<evidence::DelegationLink> {
    link_capabilities
        .iter()
        .enumerate()
        .map(|(index, capabilities)| evidence::DelegationLink {
            issuer: format!("issuer-{index}"),
            subject: format!("subject-{index}"),
            capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
            not_before: scenario::NOW - 60,
            not_after: scenario::NOW + 3_600,
            token_digest: format!("digest-{index}"),
        })
        .collect()
}

fn honest_authority(link_capabilities: &[&[&str]]) -> evidence::Authority {
    let chain = chain(link_capabilities);
    evidence::Authority {
        effective_capabilities: evidence::recompute_intersection(&chain),
        intersection_proof: evidence::compute_intersection_proof(&chain),
        chain,
    }
}

// -- static ---------------------------------------------------------------------------

#[test]
fn both_implementations_name_this_invariant_in_their_refusal() {
    assert_eq!(fixture::invariant("I-02").id, "I-02");
    harness::source_contains(
        "rust/evidence/src/lib.rs",
        "(authority expansion; I-02)",
        "The receipt verifier's refusal text is what a third party reads when a chain is forged.",
    );
    harness::source_contains(
        "rust/notary/src/lib.rs",
        "/// I-02: requested operation not in the recomputed intersection.",
        "The Authority gate must stay labeled with the invariant it serves.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn the_chain_intersects_rather_than_unions() {
    let recomputed = evidence::recompute_intersection(&chain(&[
        &["fs.read", "fs.write", "net.egress"],
        &["fs.read", "net.egress"],
        &["fs.read"],
    ]));
    assert_eq!(
        recomputed,
        vec!["fs.read".to_string()],
        "three links narrowing to one capability must yield exactly that capability; a union \
         would yield three",
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn a_capability_dropped_by_one_link_cannot_be_exercised() {
    // The union trap. The actor holds fs.write and so does the first link; the second link does
    // not. Under an intersection the capability is gone; under a union it survives.
    let mut request = scenario::allowed_request();
    request.actor.own_capabilities = vec!["fs.read".to_string(), "fs.write".to_string()];
    request.actor.delegation_chain[0].capabilities =
        vec!["fs.read".to_string(), "fs.write".to_string()];
    request.actor.delegation_chain.push(notary::DelegationLink {
        delegatee_svid: scenario::SUBJECT.to_string(),
        capabilities: vec!["fs.read".to_string()],
        not_before: scenario::NOW - 60,
        not_after: scenario::NOW + 3_600,
        signature_verified: true,
    });

    let mut control_request = request.clone();
    control_request.operation.capabilities_requested = vec!["fs.read".to_string()];
    let control = notary::verdict(&control_request, &scenario::allowed_context());

    let mut attacked_request = request;
    attacked_request.operation.capabilities_requested = vec!["fs.write".to_string()];
    let attacked = notary::verdict(&attacked_request, &scenario::allowed_context());

    harness::refused_at_the_boundary(
        "a capability the last link dropped",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(&attacked, notary::Gate::Authority, "the union trap");
}

#[test]
fn hop_06_a_forged_admin_token_does_not_survive_receipt_verification() {
    // Round zero, hop 6. The incident's agent forged an administrative token. Encoded here as a
    // receipt whose authority block claims a capability the chain never granted -- the wire form
    // of the same move, and the one a third-party verifier must catch without privileged access.
    let control = honest_authority(&[&["fs.read", "fs.write"], &["fs.read"]]);

    let mut attacked = control.clone();
    attacked
        .effective_capabilities
        .push("admin.grant".to_string());
    attacked.effective_capabilities.sort();

    harness::refused_at_the_boundary(
        "hop 6: an authority block claiming a forged admin capability",
        &evidence::verify_authority(&control),
        &evidence::verify_authority(&attacked),
        |result| result.is_ok(),
    );
    let error = evidence::verify_authority(&attacked).expect_err("the forgery is refused");
    assert!(
        error.to_string().contains("authority expansion; I-02"),
        "the refusal must name the invariant it enforced, got: {error}",
    );
}

#[test]
fn a_forged_intersection_proof_is_refused_even_when_the_capability_set_is_honest() {
    // The subtler forgery: leave effective_capabilities correct and lie in the proof, betting the
    // verifier only checks one of the two.
    let control = honest_authority(&[&["fs.read", "net.egress"], &["fs.read"]]);

    let mut attacked = control.clone();
    attacked.intersection_proof.result_digest = "00".repeat(32);

    harness::refused_at_the_boundary(
        "an intersection proof forged over an honest capability set",
        &evidence::verify_authority(&control),
        &evidence::verify_authority(&attacked),
        |result| result.is_ok(),
    );
    let error = evidence::verify_authority(&attacked).expect_err("the forged proof is refused");
    assert!(
        error.to_string().contains("forged proof; I-02"),
        "got: {error}"
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_intersection_proof_is_recomputable_by_a_stranger() {
    // The evidence field for I-02 is `authority.intersection_proof`. It is only evidence if a
    // party holding no shared state recomputes the same digests from the chain alone.
    let authority = honest_authority(&[&["fs.read", "net.egress"], &["fs.read"]]);
    let recomputed = evidence::compute_intersection_proof(&authority.chain);
    assert_eq!(
        recomputed, authority.intersection_proof,
        "a verifier holding only the chain must reproduce the proof byte for byte",
    );
    assert_eq!(recomputed.algorithm, "warrantor-intersect-v1");
}

// -- standing guard -------------------------------------------------------------------

/// The intersection is computed twice by two crates that share no code: `notary` decides,
/// `evidence` proves. They agree today, and nothing structural makes them agree tomorrow -- no
/// shared implementation, no cross-check, no conformance vector -- so a divergence would produce
/// a receipt that verifies against a decision nobody made.
///
/// This is the standing guard against that, not a finding. Task 1.5 (one delegation algebra) is
/// where the duplication itself is repaired. Recorded 2026-09-02.
#[test]
fn the_two_intersection_implementations_still_agree() {
    let cases: [&[&[&str]]; 4] = [
        &[&["a", "b", "c"], &["b", "c"], &["c"]],
        &[&["a"], &["b"]],
        &[&["a", "b"]],
        &[&["x", "y"], &["y", "x"]],
    ];
    for case in cases {
        let evidence_result = evidence::recompute_intersection(&chain(case));

        let actor = notary::Actor {
            svid: scenario::SUBJECT.to_string(),
            svid_not_after: scenario::NOW + 3_600,
            own_capabilities: case[0].iter().map(|c| (*c).to_string()).collect(),
            delegation_chain: case
                .iter()
                .map(|capabilities| notary::DelegationLink {
                    delegatee_svid: scenario::SUBJECT.to_string(),
                    capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
                    not_before: scenario::NOW - 60,
                    not_after: scenario::NOW + 3_600,
                    signature_verified: true,
                })
                .collect(),
        };
        assert_eq!(
            notary::effective_capabilities(&actor),
            evidence_result,
            "the deciding and the proving implementations of I-02 disagree on {case:?}; a receipt \
             would verify against a decision nobody made",
        );
    }
}

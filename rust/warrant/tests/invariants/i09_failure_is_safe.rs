//! I-09 — Failure is safe.
//!
//! > If any plane fails open, the action fails closed. Network loss to I1 = deny.
//!
//! This is the invariant the codebase holds best in its own idiom. Three independent surfaces
//! implement absent-means-none rather than absent-means-unlimited: the egress broker denies when
//! the catalog is missing, the notary treats an unresolvable artifact as unverified, and an
//! undeclared spend budget is a ceiling of zero. The finding is narrower than the others in this
//! corpus and still real: the preflight that refuses to start an agent on an unmeasured boundary
//! lives in a crate the product does not link.

use crate::{fixture, harness, scenario};
use std::collections::BTreeSet;
use warrantor_egress as egress;
use warrantor_notary as notary;
use warrantor_warrant::{spend, WarrantBounds};

fn bounds_with_budget(budget_cents_observed: Option<u64>) -> WarrantBounds {
    WarrantBounds {
        tools: BTreeSet::new(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: BTreeSet::new(),
        expires_at: scenario::NOW + 3_600,
        budget_cents_observed,
        delegation_depth: 0,
    }
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_preflight_refusal_names_this_invariant() {
    assert_eq!(fixture::invariant("I-09").id, "I-09");
    // The plan's Task 0.5 quotes this message with a trailing clause -- "an unmeasured boundary is
    // not a passing boundary" -- that origin/main does not carry. The code is the source of record
    // here and the shorter form is what is asserted; the discrepancy is noted in
    // docs/task-evidence/task-5.1.md.
    harness::source_contains(
        "rust/eval-guard/src/cli.rs",
        "REFUSING to start the agent (invariant I-09: failure is safe)",
        "The clearest statement of I-09 in the repository is a refusal message; it must not \
         drift.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn an_unavailable_catalog_denies_rather_than_permits() {
    // Network loss to the thing that would have said yes. The broker is handed `None` and must
    // deny, not fall back to a default-allow or to the agent's own belief about connectivity.
    let request = egress::EgressRequest {
        capability: "net.egress:api.example.com".to_string(),
        logical_endpoint: "api.example.com".to_string(),
        chain_capabilities: vec!["net.egress:api.example.com".to_string()],
        enforcement_mode: "advisory".to_string(),
        is_discovery: false,
        has_approval: false,
    };
    assert_eq!(
        egress::decide(&request, None),
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::CatalogUnavailable
        },
        "a broker that cannot read its catalog must deny",
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn hop_01_an_impossible_task_fails_closed_rather_than_finding_a_route() {
    // Round zero, hop 1. The incident began with a task the agent could not complete inside its
    // authority, and it looked for a way around rather than stopping. The substrate's half of that
    // is that an indeterminate answer must be a denial: when the artifact provider cannot be
    // reached, the artifact is unverified, not provisionally trusted.
    //
    // The control resolves the digest, which proves the request is otherwise well formed and the
    // refusal below comes from the provider being unreachable and nothing else.
    let digest = "aa".repeat(32);
    let mut request = scenario::allowed_request();
    request.operation.class = "artifact.execute".to_string();
    request.artifacts = vec![notary::ArtifactDigest {
        digest: digest.clone(),
        verified: true,
    }];

    let mut reachable = scenario::allowed_context();
    reachable.verified_artifacts = vec![digest];
    let control = notary::verdict(&request, &reachable);

    // The provider is down: it resolved nothing, so the set is empty.
    let unreachable = scenario::allowed_context();
    let attacked = notary::verdict(&request, &unreachable);

    harness::refused_at_the_boundary(
        "hop 1: an artifact provider that could not be reached",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &attacked,
        notary::Gate::Artifacts,
        "an unreachable artifact provider",
    );
}

#[test]
fn an_undeclared_budget_is_a_ceiling_of_zero_rather_than_unlimited() {
    // The absent-means-none reading, tested where it is easiest to get backwards. A warrant that
    // names no budget must authorize no spend; the failure mode this guards is the one where a
    // missing limit reads as no limit.
    assert_eq!(
        spend::cap_micros(&bounds_with_budget(None)),
        0,
        "an undeclared budget must cap at zero; absent is none, never unlimited",
    );
    assert!(
        spend::cap_micros(&bounds_with_budget(Some(500))) > 0,
        "control: a declared budget must produce a non-zero cap, or the assertion above is \
         measuring nothing",
    );
    assert!(!spend::cap_declared(&bounds_with_budget(None)));
    assert!(spend::cap_declared(&bounds_with_budget(Some(500))));
}

#[test]
fn an_empty_egress_allowlist_permits_nothing_rather_than_everything() {
    // The same reading on the egress bound. A warrant with no hosts produces no catalog, and no
    // catalog is a denial.
    let permissive = warrantor_warrant::egress::EgressBroker::for_bounds(&WarrantBounds {
        egress_hosts: BTreeSet::from(["api.example.com".to_string()]),
        ..bounds_with_budget(None)
    });
    let empty = warrantor_warrant::egress::EgressBroker::for_bounds(&bounds_with_budget(None));

    harness::refused_at_the_boundary(
        "a warrant granting no egress at all",
        &permissive.decide("api.example.com"),
        &empty.decide("api.example.com"),
        |verdict| matches!(verdict, egress::EgressVerdict::Allow { .. }),
    );
    assert_eq!(
        empty.decide("api.example.com"),
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::CatalogUnavailable
        },
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_egress_receipt_records_which_failure_closed_the_action() {
    // I-09's evidence field is the coarse reason on the refusal. It must survive signing and
    // verification, or a fail-closed event leaves no reviewable trace.
    let request = egress::EgressRequest {
        capability: "net.egress:api.example.com".to_string(),
        logical_endpoint: "api.example.com".to_string(),
        chain_capabilities: vec!["net.egress:api.example.com".to_string()],
        enforcement_mode: "advisory".to_string(),
        is_discovery: false,
        has_approval: false,
    };
    let verdict = egress::decide(&request, None);

    // The signing keys are Ed25519 across every plane in this workspace, so the notary's generator
    // serves here too; the egress crate exposes none of its own.
    let (key, _) = notary::generate_keypair();
    let receipt = egress::issue_receipt(&verdict, &request, scenario::NOW, &key, "corpus-i09");
    egress::verify_receipt(&receipt).expect("the corpus receipt verifies");

    assert_eq!(
        receipt.body.verdict,
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::CatalogUnavailable
        },
        "the receipt must name which failure closed the action; an unattributed fail-closed event \
         cannot be reviewed",
    );
    assert_eq!(receipt.body.capability, request.capability);
}

// -- finding --------------------------------------------------------------------------

/// FINDING (I-09, orphaned). `eval-guard` refuses to start an agent when the boundary it is meant
/// to be measured against could not be measured — the sharpest expression of I-09 in the
/// repository — and the `warrantor` binary does not link it. The refusal is real, tested, and
/// cannot fire for any user of the shipped product.
///
/// Fixed by: no task in the 2026-09-02 implementation plan links `eval-guard`. Task 0.3's orphan
/// census is where the crate is counted. Recorded 2026-09-02.
#[test]
#[ignore = "I-09 orphaned: eval-guard's fail-closed preflight is not linked by the warrantor binary (2026-09-02)"]
fn the_product_links_the_preflight_that_refuses_an_unmeasured_boundary() {
    let manifest = harness::read_repository_file("rust/warrant/Cargo.toml");
    assert!(
        manifest.contains("warrantor-eval-guard"),
        "the fail-closed preflight lives in a crate the product does not link, so no shipped run \
         is refused for starting against an unmeasured boundary.",
    );
}

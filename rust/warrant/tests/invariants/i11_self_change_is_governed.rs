//! I-11 — Self-change is governed.
//!
//! > An agent cannot modify its own enforcement boundary, policy, or identity.
//!
//! # Two layers that disagree
//!
//! The `warrant` crate holds this well. Its egress catalog is *derived* from bounds that live
//! inside signed claims, so there is no catalog object an agent could edit, and the capability
//! token it hands an agent has no field that could grant settle authority. Both are structural,
//! not policed, which is the strongest form this invariant takes anywhere in the repository.
//!
//! The `egress` broker underneath it holds nothing. `decide()` takes the catalog as a parameter
//! from its caller and never inspects `signature`. Three of its ten `DenyReason` variants —
//! `AgentCannotAmendCatalog`, `CatalogInvalidSignature` and `RedirectOutOfSet` — are declared,
//! documented, and rendered by `warrant/src/egress.rs`, and constructed by nothing anywhere in the
//! workspace. One of them names this invariant in its own doc comment.
//!
//! The composition hazard is the finding. `warrant` is safe because of a property of `warrant`,
//! not because the broker enforces anything, so the second consumer of that broker inherits no
//! protection and the rendered refusal strings suggest otherwise.

use crate::{fixture, harness, scenario};
use std::collections::BTreeSet;
use warrantor_egress as egress;
use warrantor_warrant::egress as warrant_egress;
use warrantor_warrant::{WarrantBounds, CAPABILITY_TTL_SECONDS};

fn bounds(hosts: &[&str], tools: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        staged_classes: BTreeSet::new(),
        expires_at: scenario::NOW + 3_600,
        budget_cents_observed: None,
        delegation_depth: 1,
    }
}

fn catalog_for(endpoints: &[&str]) -> egress::DestinationCatalog {
    let mut catalog = egress::DestinationCatalog {
        version: "corpus/1".to_string(),
        entries: endpoints
            .iter()
            .map(|endpoint| egress::CatalogEntry {
                logical_endpoint: (*endpoint).to_string(),
                addresses: vec![(*endpoint).to_string()],
                tls_identity: None,
                permitted_methods: Vec::new(),
                expires_at: scenario::NOW + 3_600,
            })
            .collect(),
        digest: String::new(),
        signature: None,
    };
    catalog.digest = catalog.compute_digest();
    catalog
}

fn request_for(endpoint: &str) -> egress::EgressRequest {
    egress::EgressRequest {
        capability: format!("net.egress:{endpoint}"),
        logical_endpoint: endpoint.to_string(),
        chain_capabilities: vec!["net.egress".to_string()],
        enforcement_mode: "advisory".to_string(),
        is_discovery: false,
        has_approval: false,
    }
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_catalog_amendment_refusal_names_this_invariant() {
    assert_eq!(fixture::invariant("I-11").id, "I-11");
    harness::source_contains(
        "rust/egress/src/lib.rs",
        "/// An agent attempted to amend the catalog (I-11 — self-change protection).",
        "This doc comment is the only place the broker claims I-11. It must not be deleted \
         quietly; it must be made true.",
    );
}

/// FINDING (I-11, unimplemented at the broker). Three denial reasons exist as declarations and as
/// rendered strings, and nothing in the workspace ever constructs one. `AgentCannotAmendCatalog`
/// is I-11's own reason; `CatalogInvalidSignature` is the check that would make a catalog
/// trustworthy on its own terms; `RedirectOutOfSet` is round zero's hop 4.
///
/// A rendered refusal for a decision no code can reach is worse than an absent one: it puts the
/// sentence "an agent cannot amend the destination catalogue" in front of a reader as though
/// something had decided it. (That sentence is quoted verbatim from `warrant/src/egress.rs`,
/// British spelling and all; the house standard is US English and this is a quotation carve-out.)
///
/// Fixed by: Task 2.5 (generic HTTP adapter over the destination catalog), which is where a real
/// catalog with a signature and a redirect set arrives. Recorded 2026-09-02.
#[test]
#[ignore = "I-11 unimplemented at the broker: three DenyReason variants are rendered and never constructed (Task 2.5, 2026-09-02)"]
fn every_denial_reason_the_broker_renders_can_actually_be_reached() {
    // A denial is *constructed* as `reason: DenyReason::X`. Counting that form separates a reason
    // a decision can reach from one that only exists as a variant and a match arm.
    let constructed = |reason: &str| {
        harness::occurrences_in_rust_sources(
            "rust/egress/src",
            &format!("reason: DenyReason::{reason}"),
        )
    };

    // The control. If these are zero the probe is broken, not the invariant, and every assertion
    // below would be a false pass.
    for reachable in ["NotInCatalog", "MetadataRange", "CatalogUnavailable"] {
        assert!(
            constructed(reachable) > 0,
            "control: DenyReason::{reachable} is constructed by decide() and the probe must see \
             it, or this test measures nothing",
        );
    }

    for unreachable in [
        "AgentCannotAmendCatalog",
        "CatalogInvalidSignature",
        "RedirectOutOfSet",
    ] {
        assert!(
            constructed(unreachable) > 0,
            "DenyReason::{unreachable} is declared in the broker and rendered as prose by \
             warrant/src/egress.rs, and no decision anywhere constructs it. The refusal it renders \
             cannot happen.",
        );
    }
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_child_warrant_cannot_widen_the_bounds_it_was_delegated() {
    // Self-change in its most direct form: an agent holding a warrant issues itself a broader one.
    // `WarrantBounds::contains` is evaluated when a child is issued, so an out-of-bounds child
    // never exists rather than being caught later at use time.
    //
    // The children carry `delegation_depth: 0` because a child must be strictly below its parent;
    // giving both depth 1 makes the control fail on the depth check and the attack never reaches
    // the destination comparison at all. The harness caught exactly that while this was written.
    let parent = bounds(&["api.example.com"], &["read_file"]);
    let narrower = WarrantBounds {
        delegation_depth: 0,
        ..bounds(&["api.example.com"], &[])
    };
    let wider = WarrantBounds {
        delegation_depth: 0,
        ..bounds(&["api.example.com", "attacker.example.net"], &["read_file"])
    };

    harness::refused_at_the_boundary(
        "a child warrant claiming a destination its parent never held",
        &parent.contains(&narrower),
        &parent.contains(&wider),
        |result| result.is_ok(),
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn hop_07_persistent_admin_users_cannot_be_added_to_a_warrant_derived_catalog() {
    // Round zero, hop 7: the incident's agent created administrative users that outlived the
    // session. The substrate analogue is adding a durable entry to the set that decides what the
    // agent may reach.
    //
    // At the `warrant` layer this is structurally impossible and the test passes: the catalog is
    // derived on each call from bounds inside signed claims, so there is no catalog object to
    // amend and no amendment that would survive.
    let granted = warrant_egress::EgressBroker::for_bounds(&bounds(&["api.example.com"], &[]));
    let control = granted.decide("api.example.com");
    let attacked = granted.decide("attacker.example.net");

    harness::refused_at_the_boundary(
        "hop 7: a destination the agent added rather than the operator",
        &control,
        &attacked,
        |verdict| matches!(verdict, egress::EgressVerdict::Allow { .. }),
    );
    assert_eq!(
        attacked,
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::NotInCatalog
        },
    );

    // And the derivation is total: two brokers built from the same bounds produce the same
    // catalog digest, so there is no per-instance state an agent could have mutated between them.
    let again = warrant_egress::EgressBroker::for_bounds(&bounds(&["api.example.com"], &[]));
    assert_eq!(granted.catalog_digest(), again.catalog_digest());
    assert_eq!(granted.catalogued(), 1);
}

#[test]
fn hop_07_the_broker_beneath_it_accepts_a_catalog_the_caller_extended() {
    // The same hop, one layer down, where it succeeds.
    //
    // This test PASSES and what it records is a violation: the broker is handed its catalog by its
    // caller and has no way to tell an operator-issued catalog from one an agent extended. The
    // control proves the endpoint is otherwise refused, so the allow below is caused by the
    // amendment and nothing else. `warrant` is safe from this because of a property of `warrant`;
    // any other consumer of this crate inherits nothing.
    let operator_catalog = catalog_for(&["api.example.com"]);
    let amended_catalog = catalog_for(&["api.example.com", "attacker.example.net"]);
    let request = request_for("attacker.example.net");

    assert_eq!(
        egress::decide(&request, Some(&operator_catalog)),
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::NotInCatalog
        },
        "control: the destination must be refused under the operator's catalog, or the amendment \
         below proves nothing",
    );

    harness::reached_the_boundary_unrefused(
        "hop 7: a catalog the agent extended with its own destination",
        &egress::decide(&request_for("api.example.com"), Some(&operator_catalog)),
        &egress::decide(&request, Some(&amended_catalog)),
        |verdict| matches!(verdict, egress::EgressVerdict::Allow { .. }),
    );
}

#[test]
fn an_unsigned_catalog_is_accepted_without_comment() {
    // The check that would have caught the amendment above. `DestinationCatalog::signature` is an
    // `Option<String>`; `decide()` never reads it. A catalog with no signature at all is treated
    // exactly like a signed one, so `CatalogInvalidSignature` cannot fire and the digest field is
    // decoration.
    //
    // This test PASSES and records the violation, for the reason given on the previous test.
    let unsigned = catalog_for(&["api.example.com"]);
    assert!(unsigned.signature.is_none(), "the fixture is unsigned");

    let mut forged = unsigned.clone();
    forged.signature = Some("00".repeat(64));
    forged.entries.push(egress::CatalogEntry {
        logical_endpoint: "attacker.example.net".to_string(),
        addresses: vec!["attacker.example.net".to_string()],
        tls_identity: None,
        permitted_methods: Vec::new(),
        expires_at: scenario::NOW + 3_600,
    });
    // The digest is left stale on purpose: it no longer covers the entries. Nothing checks it.

    harness::reached_the_boundary_unrefused(
        "a catalog carrying a forged signature over a stale digest",
        &egress::decide(&request_for("api.example.com"), Some(&unsigned)),
        &egress::decide(&request_for("attacker.example.net"), Some(&forged)),
        |verdict| matches!(verdict, egress::EgressVerdict::Allow { .. }),
    );
}

/// FINDING (I-11, unimplemented). Round zero, hop 4: the incident reached the internet through a
/// cache that followed a redirect. `EgressRequest` has no field for a redirect target and
/// `decide()` takes no second look after a response arrives, so the broker cannot see a redirect
/// at all — `RedirectOutOfSet` is unreachable because the input that would trigger it does not
/// exist. Pinning the first destination is not egress closure when the destination can forward.
///
/// Fixed by: Task 2.5 (generic HTTP adapter over the destination catalog) for the redirect set,
/// and Task 5.2 (`warrantor prove-egress`) for the closure itself. Recorded 2026-09-02.
#[test]
#[ignore = "I-11 unimplemented: the broker cannot observe a redirect, so hop 4 has no boundary (Task 2.5 / Task 5.2, 2026-09-02)"]
fn hop_04_a_redirect_out_of_the_resolved_set_is_refused() {
    let request = request_for("api.example.com");
    let json = serde_json::to_value(&request).expect("the request serializes");
    let fields = json.as_object().expect("the request is an object");
    assert!(
        fields.contains_key("redirect_target") || fields.contains_key("resolved_set"),
        "the egress request names one destination and nothing about where that destination may \
         forward to. Keys present: {:?}",
        fields.keys().collect::<Vec<_>>(),
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_capability_token_has_no_field_that_could_grant_settle_authority() {
    // I-11's evidence field at the warrant layer is the shape of the token itself. An agent that
    // reaches the daemon socket — which it can, running as the same user — still cannot settle,
    // void or renew, because the token it holds carries no scope field at all and the authority to
    // settle is a separate key inside the signed claims.
    //
    // Asserted over the serialized form rather than the type, so adding a field is a failure here
    // rather than a silent widening.
    let token = warrantor_warrant::CapabilityToken {
        warrant_id: "wrt_corpus".to_string(),
        subject: scenario::SUBJECT.to_string(),
        expires_at: scenario::NOW + CAPABILITY_TTL_SECONDS,
        signature: "00".repeat(64),
    };
    let json = serde_json::to_value(&token).expect("the token serializes");
    let fields: Vec<&str> = json
        .as_object()
        .expect("the token is an object")
        .keys()
        .map(String::as_str)
        .collect();

    // serde_json orders object keys, so the expected list is sorted rather than declaration order.
    assert_eq!(
        fields,
        vec!["expires_at", "signature", "subject", "warrant_id"],
        "the capability token grew a field. There is no scope field by design: a token that \
         cannot express settle authority cannot be tricked into carrying it.",
    );
    // A const assertion: the TTL is the bound that still applies when process linkage cannot help
    // — on a platform with no parent-death signal an agent can outlive a supervisor crash — so a
    // widening of it is a change to this invariant's last line of defense, not a tuning knob.
    const { assert!(CAPABILITY_TTL_SECONDS <= 300) };
}

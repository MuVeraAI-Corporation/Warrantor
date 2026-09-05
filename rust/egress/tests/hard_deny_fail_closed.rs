//! The fail-closed decision L4-25 owns, and the one shared matcher behind it.
//!
//! `rust/egress/tests/metadata_floor.rs` (commit `c6cb1bb`) already asserts nine spellings of the
//! metadata service by name. This file does **not** repeat them. It asserts the two things that fix
//! deliberately left open:
//!
//! 1. **Failing closed.** A literal that is *shaped* like a numeric address and does not parse as
//!    one used to be passed through to `Allow`. `999.1.1.1`, `0x` and `169.254.169.254.5` are not
//!    hostnames — no registrable top-level domain is entirely numeric (RFC 3696 §2) — so they could
//!    only ever have been addresses, and an address the broker cannot classify is an address the
//!    broker cannot claim is safe.
//!
//!    The floor does **not** fail closed on an ordinary DNS name, and that is a decision rather
//!    than an omission. `EgressBroker::for_bounds` in `rust/warrant/src/egress.rs` copies the
//!    warrant's `egress_hosts` straight into the address field, so every hostname bound a developer
//!    writes is an unparseable address by construction. A floor that refused those would refuse the
//!    whole shipping path. The controls at the bottom of this file are what stops that regression.
//!
//! 2. **One matcher, two crates.** `warrantor-egress` and `warrantor-egress-filter` both decide
//!    whether an address is the metadata service. Two implementations are two rules waiting to
//!    disagree — which is exactly the defect `c6cb1bb` fixed in one of them and not the other. This
//!    file asserts they agree, address by address, by asking both.

use warrantor_egress::{
    decide, test_catalog, CatalogEntry, DenyReason, EgressRequest, EgressVerdict,
};
use warrantor_egress_filter::hard_deny;

fn request(endpoint: &str) -> EgressRequest {
    EgressRequest {
        capability: format!("net.egress:{endpoint}"),
        logical_endpoint: endpoint.to_string(),
        chain_capabilities: vec!["net.egress".to_string()],
        enforcement_mode: "advisory".to_string(),
        is_discovery: false,
        has_approval: false,
    }
}

fn verdict_for(address: &str) -> EgressVerdict {
    let mut catalog = test_catalog();
    catalog.entries.push(CatalogEntry {
        logical_endpoint: "probe".to_string(),
        addresses: vec![address.to_string()],
        tls_identity: None,
        permitted_methods: vec!["GET".to_string()],
        expires_at: u64::MAX,
    });
    catalog.digest = catalog.compute_digest();
    decide(&request("probe"), Some(&catalog))
}

/// Literals that could only ever have been an address, and are not one.
const ADDRESS_SHAPED_BUT_UNPARSEABLE: &[(&str, &str)] = &[
    ("an octet out of range", "999.1.1.1"),
    ("a hex prefix with no digits", "0x"),
    ("five dotted labels, the last numeric", "169.254.169.254.5"),
    ("a decimal too large for 32 bits", "2852039166000000"),
    ("nothing at all", ""),
];

#[test]
fn an_address_shaped_literal_that_does_not_parse_is_refused_rather_than_passed_through() {
    let mut passed_through = Vec::new();
    for (why, literal) in ADDRESS_SHAPED_BUT_UNPARSEABLE {
        match verdict_for(literal) {
            EgressVerdict::Deny {
                reason: DenyReason::UnparseableAddress,
            } => {}
            other => passed_through.push(format!("  {literal:<20} {why}\n      -> {other:?}")),
        }
    }
    assert!(
        passed_through.is_empty(),
        "{} of {} address-shaped literals were not refused. An address the broker cannot classify \
         is an address it cannot claim is safe, and passing it through is the AX-05 lesson being \
         relearned:\n{}",
        passed_through.len(),
        ADDRESS_SHAPED_BUT_UNPARSEABLE.len(),
        passed_through.join("\n")
    );
}

/// The controls that keep the fail-closed half from swallowing the shipping path. Every one of
/// these is a value `EgressBroker::for_bounds` puts in the address field today.
#[test]
fn a_hostname_bound_is_still_allowed_because_the_floor_does_not_resolve_dns() {
    for host in [
        "api.github.com",
        "registry.npmjs.org",
        "example.com",
        "localhost",
        "internal-service",
        "169.254.169.254.nip.io",
    ] {
        assert!(
            matches!(verdict_for(host), EgressVerdict::Allow { .. }),
            "{host} is a name, not a malformed address. Refusing it would refuse every hostname \
             bound a warrant can carry: {:?}",
            verdict_for(host)
        );
    }
}

/// And the numeric controls, so the refusal above cannot be passing by refusing everything.
#[test]
fn a_public_address_is_still_allowed() {
    for ok in [
        "93.184.216.34",
        "8.8.8.8",
        "2606:4700:4700::1111",
        "10.0.1.5",
    ] {
        assert!(
            matches!(verdict_for(ok), EgressVerdict::Allow { .. }),
            "{ok} must still reach Allow: {:?}",
            verdict_for(ok)
        );
    }
}

/// The two crates decide the same question and must not diverge. This is the assertion that makes
/// the dependency edge load-bearing rather than decorative: delete the edge and this file will not
/// compile.
#[test]
fn the_broker_and_the_filter_agree_address_by_address() {
    let corpus = [
        "169.254.169.254",
        "100.100.100.200",
        "2852039166",
        "0xa9fea9fe",
        "0251.0376.0251.0376",
        "::ffff:169.254.169.254",
        "HTTP://169.254.169.254",
        "FE80::1",
        " 169.254.169.254",
        "fd00:a405::1",
        "metadata.google.internal",
        "999.1.1.1",
        // and the allowed controls, so agreement is not agreement-on-refusing-everything
        "93.184.216.34",
        "8.8.8.8",
        "10.0.1.5",
        "api.github.com",
        "169.254.169.254.nip.io",
    ];
    let mut disagreements = Vec::new();
    for literal in corpus {
        let filter_refused = hard_deny::refuse(literal).is_refused();
        let broker_refused = matches!(verdict_for(literal), EgressVerdict::Deny { .. });
        if filter_refused != broker_refused {
            disagreements.push(format!(
                "  {literal:<28} filter refused={filter_refused} broker refused={broker_refused}"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "the broker and the filter disagree about {} of {} addresses. Two matchers for one rule is \
         the defect that let eight spellings of the metadata service through:\n{}",
        disagreements.len(),
        corpus.len(),
        disagreements.join("\n")
    );
    // The control: the corpus must contain both polarities, or "no disagreements" is vacuous.
    assert!(
        corpus.iter().any(|l| hard_deny::refuse(l).is_refused()),
        "the corpus contains nothing the floor refuses, so agreement proves nothing"
    );
    assert!(
        corpus.iter().any(|l| !hard_deny::refuse(l).is_refused()),
        "the corpus contains nothing the floor allows, so agreement proves nothing"
    );
}

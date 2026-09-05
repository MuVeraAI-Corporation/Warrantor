//! The metadata floor, tested by spelling rather than by prefix.
//!
//! `rust/egress/src/lib.rs:32` documents the metadata ranges as *"never catalog-addable"*, and
//! `metadata_range_always_denied` in the crate's own tests asserts that for exactly one spelling:
//! the dotted-quad `169.254.169.254`. The check behind the claim is a case-sensitive
//! `str::starts_with` over three prefixes, so every other way of writing the same address reaches
//! Allow while the comment says it cannot.
//!
//! These are the spellings an HTTP client or an OS resolver accepts for the same host. A floor that
//! holds only for the canonical form is not a floor; it is one entry in a deny list.
//!
//! UPDATE (Task 7.1, L4-25). Everything above describes the defect this file was written against and
//! is kept as the record of it. The matcher no longer lives in this crate: it moved to
//! `warrantor_egress_filter::hard_deny`, so that `Policy` -- which had five of its own paths to an
//! Allow for these addresses -- and this broker consult one rule rather than two. The assertions
//! below are unchanged and still run through `warrantor_egress::decide`, which now delegates. The
//! delegated matcher is **wider** than the prose above: it also refuses IPv6 unique-local
//! `fc00::/7`, and every refusal but the unparseable one reaches this crate's callers as
//! `DenyReason::MetadataRange`, whatever the floor's own reason was.
//!
//! (This paragraph shipped twice in `5e1b5a5` -- a copy-paste defect an adversarial review caught.
//! The duplicate is removed here rather than silently, because the file that carries the branch's
//! "one matcher, not two" argument handing a reader the same paragraph twice is worth naming.)

use warrantor_egress::{
    decide, test_catalog, CatalogEntry, DenyReason, EgressRequest, EgressVerdict,
};

fn request(endpoint: &str) -> EgressRequest {
    EgressRequest {
        capability: format!("net.egress:{endpoint}"),
        logical_endpoint: endpoint.to_string(),
        chain_capabilities: vec!["net.egress".to_string()],
        enforcement_mode: "mediated".to_string(),
        is_discovery: false,
        has_approval: false,
    }
}

/// Put one address in the catalog under a logical endpoint and ask the broker about it.
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

/// Every one of these resolves to a cloud metadata service or a link-local address.
/// The first row is the spelling the existing test already covers; the rest are the same hosts.
const METADATA_SPELLINGS: &[(&str, &str)] = &[
    ("dotted quad, the canonical form", "169.254.169.254"),
    (
        "Alibaba Cloud metadata, absent from METADATA_RANGES",
        "100.100.100.200",
    ),
    ("decimal integer form of 169.254.169.254", "2852039166"),
    ("hexadecimal form of 169.254.169.254", "0xa9fea9fe"),
    (
        "octal dotted form of 169.254.169.254",
        "0251.0376.0251.0376",
    ),
    ("IPv4-mapped IPv6 form", "::ffff:169.254.169.254"),
    (
        "uppercase scheme, which trim_start_matches does not strip",
        "HTTP://169.254.169.254",
    ),
    (
        "uppercase IPv6 link-local, which starts_with does not match",
        "FE80::1",
    ),
    (
        "leading space, which trim_start_matches does not strip",
        " 169.254.169.254",
    ),
];

#[test]
fn every_metadata_spelling_is_refused() {
    let mut reached_allow = Vec::new();
    for (why, address) in METADATA_SPELLINGS {
        match verdict_for(address) {
            EgressVerdict::Deny {
                reason: DenyReason::MetadataRange,
            } => {}
            other => reached_allow.push(format!("  {address:<32} {why}\n      -> {other:?}")),
        }
    }
    assert!(
        reached_allow.is_empty(),
        "{} of {} metadata spellings were not refused as MetadataRange:\n{}",
        reached_allow.len(),
        METADATA_SPELLINGS.len(),
        reached_allow.join("\n")
    );
}

/// The paired allowed control. Without this, the test above passes if `decide` refuses everything,
/// which would prove nothing at all.
#[test]
fn a_public_address_is_still_allowed() {
    let verdict = verdict_for("93.184.216.34");
    assert!(
        matches!(verdict, EgressVerdict::Allow { .. }),
        "a public address must still reach Allow, else the floor above is untested: {verdict:?}"
    );
}

/// A second allowed control, so one unlucky address cannot make the pair look sound.
#[test]
fn a_second_public_address_is_still_allowed() {
    let verdict = verdict_for("8.8.8.8");
    assert!(
        matches!(verdict, EgressVerdict::Allow { .. }),
        "control address must be allowed: {verdict:?}"
    );
}

/// The PrivateRange variant exists and is documented, and nothing constructs it. So the rule
/// "private ranges denied unless explicitly catalogued" has no mechanism.
///
/// This test pins the CURRENT behavior rather than asserting the documented rule, because three
/// existing tests depend on a private address being allowed once catalogued. What it prevents is the
/// variant being silently deleted, or being given a body without that decision being made
/// deliberately.
///
/// UPDATE (Task 7.1, L4-25). Task 7.1 read this pin, made the decision, and **left the variant
/// without a mechanism**. L4-25 names the metadata service and link-local addresses, not RFC-1918,
/// and constructing the variant would mean refusing a catalogued private address, contradicting
/// `valid_capability_resolves_to_allow`, `receipt_round_trip_verifies` and
/// `net_egress_wildcard_allows` in this crate plus `private_egress_can_be_explicitly_opted_out_of`
/// in `warrantor-egress-filter`. What Task 7.1 did remove is the empty `if` branch whose comment
/// reasoned itself into a no-op. The pin below is byte-for-byte unchanged and still reads zero.
/// See `docs/task-evidence/task-7.1.md`.
///
/// CORRECTION (adversarial review of `5e1b5a5`). "L4-25 names the metadata service and link-local
/// addresses, not RFC-1918" is true of L4-25 and was misleading about what shipped: the floor also
/// refuses IPv6 unique-local `fc00::/7`, which is the IPv6 analog of RFC-1918, and refuses it
/// *unamendably*. So the IPv4 half of "private ranges" is left to a flag an operator can turn off
/// while the IPv6 half is not negotiable at all. That asymmetry was not stated when it landed.
#[test]
fn private_range_is_allowed_once_catalogued_and_the_variant_is_never_constructed() {
    let verdict = verdict_for("10.0.1.5");
    assert!(
        matches!(verdict, EgressVerdict::Allow { .. }),
        "a catalogued private address is allowed today: {verdict:?}"
    );
    let source = include_str!("../src/lib.rs");
    // The variant is declared unqualified inside the enum, so the qualified path appears only
    // where the variant is CONSTRUCTED or matched. Zero is the honest count today.
    assert!(
        source.contains("    PrivateRange,"),
        "DenyReason::PrivateRange should still be declared; removing it is a deliberate          decision belonging to Task 7.1, not a silent edit."
    );
    let constructions = source.matches("DenyReason::PrivateRange").count();
    assert_eq!(
        constructions, 0,
        "DenyReason::PrivateRange is declared but never constructed: the branch that would build          it has an empty body. If this count rose, the private-range rule was given a mechanism,          which is Task 7.1's decision (L4-25) and changes what three existing tests assert about          a catalogued private address."
    );
}

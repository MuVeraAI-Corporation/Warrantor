//! L4-25's floor: the cloud metadata service and link-local addresses are refused *in a layer no
//! warrant, policy edit or agent action can amend*.
//!
//! `fix/egress-metadata-floor` (commit `c6cb1bb`) made the floor **correct** in
//! `warrantor-egress`: nine spellings of the metadata service are refused by name in
//! `rust/egress/tests/metadata_floor.rs`. It did not make the floor **unamendable**, and it did
//! not touch this crate at all.
//!
//! Five independent public paths through `Policy` reached `Action::Allow` for a metadata or
//! link-local address before this file existed. They were counted by compiling a probe, not by
//! reading the plan — which lists four, two of which do not hold:
//!
//! | path | verified verdict before the floor |
//! |---|---|
//! | `PolicyBuilder::new()` alone + `allow_ip` | `Deny/PrivateIp` — **not** a hole; `PolicyBuilder::default()` sets `deny_private: true` |
//! | `deny_private_egress(false)` alone on the defaults, for `169.254.169.254` | `Deny/CanaryIp` — **not** a hole; the address is a compiled-in canary |
//! | `PolicyBuilder::new()` + `deny_private_egress(false)` + `allow_ip` | `Allow/Allowlisted` — hole 1 |
//! | `with_defaults()` + `deny_private_egress(false)` for `fe80::1` | `Allow/Allowlisted` — hole 2; `DEFAULT_CANARY_IPS` names no IPv6 link-local address |
//! | a serialized `Policy` stating `"canary_ips": []` | `Allow/Allowlisted` — hole 3; the field carries no `#[serde(default)]` |
//! | a `Policy` struct literal (every field is `pub`) | `Allow/Allowlisted` — hole 4 |
//! | `with_defaults()` + `allow_domain("metadata.google.internal")` | `Allow/Allowlisted` — hole 5, and the worst: it needs no amendment of anything |
//!
//! Hole 5 is absent from the plan. It is the strongest of the five because the fully-defaulted
//! policy admits it: there is no canary *hostname* list, so the name of the metadata service is
//! allowlistable by a policy that has weakened nothing.

use std::net::IpAddr;
use warrantor_egress_filter::{Action, Policy, PolicyBuilder};

const META: &str = "169.254.169.254";
const LL6: &str = "fe80::1";

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test literal parses")
}

/// A `Policy` built by struct literal with every guard turned off — the weakest policy the type
/// system permits anyone to construct.
fn weakest_possible(allow: &[IpAddr], domains: &[&str]) -> Policy {
    Policy {
        blocked_domains: Vec::new(),
        allowlisted_domains: domains.iter().map(|d| (*d).to_string()).collect(),
        allowlisted_ips: allow.to_vec(),
        canary_ips: Vec::new(),
        deny_private_egress: false,
    }
}

// ---------------------------------------------------------------------------------------------
// The five verified amendment paths. Each row is one path, and each must be refused.
// ---------------------------------------------------------------------------------------------

#[test]
fn hole_1_builder_without_defaults_and_without_private_deny_cannot_reach_the_metadata_service() {
    let policy = PolicyBuilder::new()
        .deny_private_egress(false)
        .allow_ip(META)
        .build()
        .expect("builds");
    let decision = policy.decide_ip(ip(META));
    assert_eq!(
        decision.action,
        Action::Deny,
        "PolicyBuilder::new() knows no canary and deny_private_egress(false) removes the range \
         check, so before the floor this reached Allow/Allowlisted: {decision:?}"
    );
}

#[test]
fn hole_2_opting_out_of_private_deny_cannot_reach_an_ipv6_link_local_address() {
    let policy = PolicyBuilder::with_defaults()
        .deny_private_egress(false)
        .allow_ip(LL6)
        .build()
        .expect("builds");
    let decision = policy.decide_destination("[fe80::1]");
    assert_eq!(
        decision.action,
        Action::Deny,
        "DEFAULT_CANARY_IPS names no IPv6 link-local address, so the boolean is the ONLY control \
         over fe80::/10 and turning it off opened the range: {decision:?}"
    );
}

#[test]
fn hole_3_a_serialized_policy_stating_an_empty_canary_list_cannot_reach_the_metadata_service() {
    // `canary_ips` carries no `#[serde(default)]`, so a supplied config states the whole list and
    // `[]` is accepted. This is a config file on disk, not a code change.
    let json = r#"{"blocked_domains":[],"allowlisted_domains":[],"canary_ips":[],
        "allowlisted_ips":["169.254.169.254"],"deny_private_egress":false}"#;
    let policy: Policy = serde_json::from_str(json).expect("deserializes");
    let decision = policy.decide_ip(ip(META));
    assert_eq!(
        decision.action,
        Action::Deny,
        "a serialized policy must not be able to state away the floor: {decision:?}"
    );
}

#[test]
fn hole_4_a_policy_struct_literal_cannot_reach_the_metadata_service() {
    let policy = weakest_possible(&[ip(META)], &[]);
    for spelling in [
        META,
        "[::ffff:169.254.169.254]",
        "100.100.100.200",
        "[fe80::1]",
    ] {
        let decision = policy.decide_destination(spelling);
        assert_eq!(
            decision.action,
            Action::Deny,
            "every Policy field is pub, so a struct literal bypasses PolicyBuilder entirely; \
             {spelling} must still be refused: {decision:?}"
        );
    }
}

#[test]
fn hole_5_the_metadata_hostname_cannot_be_allowlisted_even_by_a_fully_defaulted_policy() {
    // The path the plan does not name. There is no canary *hostname* list, so before the floor
    // this reached Allow with nothing weakened at all.
    for policy in [
        PolicyBuilder::with_defaults()
            .allow_domain("metadata.google.internal")
            .build()
            .expect("builds"),
        weakest_possible(&[], &["metadata.google.internal"]),
    ] {
        let decision = policy.decide_destination("metadata.google.internal");
        assert_eq!(
            decision.action,
            Action::Deny,
            "the metadata service named by DNS must be refused by the floor, not allowlistable: \
             {decision:?}"
        );
    }
}

#[test]
fn the_numeric_spellings_of_the_metadata_service_are_not_allowlistable_as_hostnames() {
    // `decide_destination` sends "2852039166" down the *hostname* path, because it does not parse
    // as an `IpAddr`. Allowlisting that string therefore used to reach Allow while naming the same
    // 32-bit address as `169.254.169.254`.
    for spelling in ["2852039166", "0xa9fea9fe", "0251.0376.0251.0376"] {
        let policy = weakest_possible(&[], &[spelling]);
        let decision = policy.decide_destination(spelling);
        assert_eq!(
            decision.action,
            Action::Deny,
            "{spelling} is the metadata service written another way: {decision:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The allowed controls. A floor that refuses everything passes every test above and proves
// nothing, so these are not optional.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_floor_still_allows_a_lawful_public_address() {
    for ok in ["8.8.8.8", "203.0.113.9"] {
        let policy = PolicyBuilder::with_defaults()
            .allow_ip(ok)
            .build()
            .expect("builds");
        let decision = policy.decide_ip(ip(ok));
        assert_eq!(
            decision.action,
            Action::Allow,
            "{ok} is a lawful allowlisted destination and must still reach the network: \
             {decision:?}"
        );
    }
}

#[test]
fn the_floor_still_allows_a_lawful_public_hostname() {
    for ok in ["api.github.com", "example.com", "registry.npmjs.org"] {
        let policy = PolicyBuilder::with_defaults()
            .allow_domain(ok)
            .build()
            .expect("builds");
        let decision = policy.decide_destination(ok);
        assert_eq!(
            decision.action,
            Action::Allow,
            "{ok} is an ordinary hostname the floor must not touch: {decision:?}"
        );
    }
}

#[test]
fn the_floor_leaves_rfc_1918_to_the_policy_that_already_governs_it() {
    // RFC-1918 is deliberately NOT in the floor. `deny_private_egress` still governs it, and this
    // crate's `private_egress_can_be_explicitly_opted_out_of` still asserts the opt-out works.
    // Widening the floor to cover 10/8 would have broken that test and three in `warrantor-egress`
    // that depend on a catalogued private address being reachable.
    let policy = PolicyBuilder::with_defaults()
        .deny_private_egress(false)
        .allow_ip("10.0.0.1")
        .build()
        .expect("builds");
    assert_eq!(
        policy.decide_ip(ip("10.0.0.1")).action,
        Action::Allow,
        "the floor covers the metadata service and link-local ranges, not RFC-1918"
    );
}

// ---------------------------------------------------------------------------------------------
// The source half. Absence IS the mechanism, and no behavioral test can see a parameter that has
// not been added yet: every assertion above would stay green if a later commit added
// `refuse(literal, allow_override: bool)` and threaded a flag through.
// ---------------------------------------------------------------------------------------------

/// The module's shipping code: comment lines removed, so the gate reads code rather than prose, and
/// the `#[cfg(test)]` block removed, so the gate reads the surface a caller gets rather than the
/// assertion messages that describe what the floor deliberately leaves alone.
fn floor_code() -> String {
    let full = include_str!("../src/hard_deny.rs");
    let marker = "#[cfg(test)]";
    let shipping = match full.find(marker) {
        Some(at) => &full[..at],
        None => full,
    };
    assert!(
        shipping.len() < full.len(),
        "the gate expected a {marker} block to trim. If the module stopped having one, the trim \
         silently became a no-op and this gate would start reading test prose as shipping code."
    );
    shipping
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_floor_module_accepts_no_configuration_value_of_any_kind() {
    let code = floor_code();

    // The control. If the probe cannot see what IS there, every assertion below is a false pass.
    for present in ["IpAddr", "pub fn refuse", "FloorVerdict::Refused"] {
        assert!(
            code.contains(present),
            "the source gate cannot see {present:?} in hard_deny.rs, so it is broken and proves              nothing about what is absent"
        );
    }

    // The strongest form of the gate: the two decision signatures, pinned verbatim. Adding a
    // second parameter to either — a flag, an options struct, a policy reference — changes this
    // string and fails here, which no behavioral assertion above could detect.
    for signature in [
        "pub fn refuse(literal: &str) -> FloorVerdict {",
        "pub fn refuse_ip(ip: IpAddr) -> FloorVerdict {",
    ] {
        assert!(
            code.contains(signature),
            "the floor's decision signature is no longer {signature:?}. One argument is the whole              mechanism: there must be nothing to pass that could change the answer."
        );
    }

    // `: bool` is parameter and field syntax; `-> bool` is a return type and is fine. `&self` is a
    // borrowed receiver, which would mean the answer depends on state someone can set. A by-value
    // `self` on the two `Copy` verdict enums is not that, and is deliberately not forbidden.
    for forbidden in [
        "&self",
        "&mut self",
        ": bool",
        "Policy",
        "Config",
        "Options",
        "deny_private",
        "allowlist",
        "canary_ips",
        "override",
        "struct Floor",
    ] {
        assert!(
            !code.contains(forbidden),
            "hard_deny.rs contains {forbidden:?}. The floor is unamendable only because there is              nothing to pass it; a configuration value, a receiver or a policy reference in this              module is L4-25 being quietly withdrawn while every behavioral test stays green."
        );
    }
}

#[test]
fn the_floor_is_consulted_before_anything_that_reads_a_configured_field() {
    // The ordering is load-bearing: the floor must be reached on the way to Allow, not after it.
    // `decide_ip` places it after the canary check (so a config that DID name the address still
    // reports CanaryIp) and before the private check and the allowlist.
    let policy = include_str!("../src/lib.rs");
    let floor_at = policy
        .find("hard_deny::refuse_ip(norm)")
        .expect("decide_ip consults the floor");
    let allowlist_at = policy
        .find(".allowlisted_ips")
        .expect("decide_ip consults the allowlist");
    assert!(
        floor_at < allowlist_at,
        "the floor is consulted at byte {floor_at} and the allowlist at {allowlist_at}: an          allowlist entry evaluated first would punch a hole straight through the floor"
    );
}

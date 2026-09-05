//! L4-25's floor: the cloud metadata service, link-local addresses and IPv6 unique-local `fc00::/7`
//! are refused *in a layer no warrant, policy edit or agent action can amend*.
//!
//! `fix/egress-metadata-floor` (commit `c6cb1bb`) made the floor **correct** in
//! `warrantor-egress`: nine spellings of the metadata service are refused by name in
//! `rust/egress/tests/metadata_floor.rs`. It did not make the floor **unamendable**, and it did
//! not touch this crate at all.
//!
//! Five independent public paths through `Policy` reached `Action::Allow` for a metadata or
//! link-local address before this file existed. They were counted by compiling a probe rather than
//! by reading the plan, and the count came out at five where the plan enumerates four amendable
//! surfaces:
//!
//! | path | verified verdict before the floor |
//! |---|---|
//! | `PolicyBuilder::new()` + `deny_private_egress(false)` + `allow_ip` | `Allow/Allowlisted` — hole 1 |
//! | `with_defaults()` + `deny_private_egress(false)` for `fe80::1` | `Allow/Allowlisted` — hole 2; `DEFAULT_CANARY_IPS` names no IPv6 link-local address |
//! | a serialized `Policy` stating `"canary_ips": []` | `Allow/Allowlisted` — hole 3; the field carries no `#[serde(default)]` |
//! | a `Policy` struct literal (every field is `pub`) | `Allow/Allowlisted` — hole 4 |
//! | `with_defaults()` + `allow_domain("metadata.google.internal")` | `Allow/Allowlisted` — hole 5, and the worst: it needs no amendment of anything |
//!
//! Hole 5 is absent from the plan. It is the strongest of the five because the fully-defaulted
//! policy admits it: there is no canary *hostname* list, so the name of the metadata service is
//! allowlistable by a policy that has weakened nothing.
//!
//! CORRECTION (adversarial review of `5e1b5a5`). An earlier revision of this header claimed the plan
//! "lists four, two of which do not hold". It does not. The plan's list is headed *"Four independent
//! amendable paths, **none of which the boolean alone opens**"*, and its own probe output already
//! records `WITH_DEFAULTS + false + allow_ip -> Deny / CanaryIp <-- the seed's claimed hole: NOT a
//! hole`. The plan disproved that claim and attributed it to the seed; presenting the disproof as a
//! correction of the plan inflated what this task found. What this task actually added to the plan's
//! four is hole 5 and the `fe80::/10` observation behind hole 2, which stand on their own.
//!
//! # What each hole test asserts, and why the reason matters
//!
//! Every refusal test below asserts the `DecisionReason`, not only `Action::Deny`. The plan warned
//! about this in advance and an adversarial review proved the warning load-bearing: with the
//! metadata address list neutralized, `hole_4` stayed green because `100.100.100.200` was never on a
//! path to `Allow` in that policy and fell through to `DecisionReason::DefaultDeny`. A test that
//! accepts any denial cannot tell "refused by the floor" from "refused for not being catalogued".

use std::net::IpAddr;
use warrantor_egress_filter::hard_deny::{self, FloorReason, FloorVerdict, FLOOR_ADDRESSES};
use warrantor_egress_filter::{Action, DecisionReason, Policy, PolicyBuilder};

const META: &str = "169.254.169.254";
const LL6: &str = "fe80::1";

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test literal parses")
}

/// The reason a floor refusal carries, for comparison against an expected rule word.
fn floor_reason(rule: &str) -> DecisionReason {
    DecisionReason::HardDenyFloor {
        rule: rule.to_string(),
    }
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
// The five verified amendment paths. Each row is one path, and each must be refused *by the floor*
// — the rule word is asserted, because `DefaultDeny` is a false pass.
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
    assert_eq!(
        decision.reason,
        floor_reason("metadata_service"),
        "the refusal must come from the floor, not from DefaultDeny or the private check: \
         {decision:?}"
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
    assert_eq!(
        decision.reason,
        floor_reason("link_local"),
        "fe80::/10 must be refused as link_local, not swept up by some other check: {decision:?}"
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
    assert_eq!(
        decision.reason,
        floor_reason("metadata_service"),
        "the floor, not a residual default, must be what refuses it: {decision:?}"
    );
}

#[test]
fn hole_4_a_policy_struct_literal_cannot_reach_the_metadata_service() {
    let policy = weakest_possible(&[ip(META)], &[]);
    // Each spelling carries the rule word it must be refused under. `100.100.100.200` is the row
    // that made the reason assertion necessary: it is not allowlisted here, so with the address list
    // neutralized it still returned Deny — under `DefaultDeny`, which proves nothing about a floor.
    for (spelling, rule) in [
        (META, "metadata_service"),
        ("[::ffff:169.254.169.254]", "metadata_service"),
        ("100.100.100.200", "metadata_service"),
        ("[fe80::1]", "link_local"),
    ] {
        let decision = policy.decide_destination(spelling);
        assert_eq!(
            decision.action,
            Action::Deny,
            "every Policy field is pub, so a struct literal bypasses PolicyBuilder entirely; \
             {spelling} must still be refused: {decision:?}"
        );
        assert_eq!(
            decision.reason,
            floor_reason(rule),
            "{spelling} must be refused BY THE FLOOR as {rule}. A bare Action::Deny here is \
             satisfied by DefaultDeny, which would stay green with the floor's address list \
             neutralized: {decision:?}"
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
        assert_eq!(
            decision.reason,
            floor_reason("metadata_service"),
            "the DNS name must be refused as metadata_service, not merely un-allowlisted: \
             {decision:?}"
        );
    }
}

#[test]
fn every_hostname_on_the_public_list_is_refused_by_the_floor() {
    // `FLOOR_HOSTNAMES` grew a fourth entry, `instance-data`, which had no test: deleting it left
    // the whole suite green. Iterating the const rather than a hand-copied corpus means the list
    // cannot grow a member that nothing exercises.
    for &name in hard_deny::FLOOR_HOSTNAMES {
        let policy = weakest_possible(&[], &[name]);
        let decision = policy.decide_destination(name);
        assert_eq!(
            decision.action,
            Action::Deny,
            "{name} is on FLOOR_HOSTNAMES and must be refused even when allowlisted: {decision:?}"
        );
        assert_eq!(
            decision.reason,
            floor_reason("metadata_service"),
            "{name} must be refused as metadata_service: {decision:?}"
        );
        assert_eq!(
            hard_deny::refuse(name),
            FloorVerdict::Refused(FloorReason::MetadataService),
            "the floor itself must refuse {name}, not just the Policy above"
        );
    }
    assert!(
        hard_deny::FLOOR_HOSTNAMES.contains(&"instance-data"),
        "instance-data was added to FLOOR_HOSTNAMES by Task 7.1 and had no assertion behind it; \
         this pins that the entry is still there as well as still refused"
    );
}

#[test]
fn every_address_on_the_public_list_is_actually_refused() {
    // The defect this replaces: `FLOOR_ADDRESSES` shipped as a `pub` list of strings that nothing
    // read, beside a private typed list that did the matching. An address added to the documented
    // list was not refused, and no test noticed. The list is now the matcher, and this asserts it.
    assert!(
        !FLOOR_ADDRESSES.is_empty(),
        "emptying FLOOR_ADDRESSES must not be a silent no-op"
    );
    for addr in FLOOR_ADDRESSES {
        assert_eq!(
            hard_deny::refuse_ip(IpAddr::V4(*addr)),
            FloorVerdict::Refused(FloorReason::MetadataService),
            "{addr} is on the public list the doc calls the mechanism, so the floor must refuse it \
             as metadata_service"
        );
        assert_eq!(
            hard_deny::refuse(&addr.to_string()),
            FloorVerdict::Refused(FloorReason::MetadataService),
            "{addr} must be refused through the literal path as well as the typed one"
        );
    }
    // The control. A list-driven refusal test passes trivially if the floor refuses everything.
    assert_eq!(
        hard_deny::refuse_ip(ip("8.8.8.8")),
        FloorVerdict::NotRefused,
        "an ordinary public address is not on the list and must reach NotRefused"
    );
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
        assert_eq!(
            decision.reason,
            floor_reason("metadata_service"),
            "{spelling} names 169.254.169.254 and must be refused as metadata_service, not as an \
             unrecognized hostname: {decision:?}"
        );
    }
}

#[test]
fn the_rule_word_discriminates_between_the_ranges_it_reports() {
    // `FloorReason::as_str` is documented as "a stable word for logs and receipts" and the
    // `HardDenyFloor { rule }` field as "which floor rule refused". Both were unasserted in every
    // direction: collapsing all four arms to one word, or swapping LinkLocal with UniqueLocal, left
    // the suite green. These are the four words, and the two ranges that are easiest to confuse.
    assert_eq!(FloorReason::MetadataService.as_str(), "metadata_service");
    assert_eq!(FloorReason::LinkLocal.as_str(), "link_local");
    assert_eq!(FloorReason::UniqueLocal.as_str(), "unique_local");
    assert_eq!(
        FloorReason::AddressShapedButUnparseable.as_str(),
        "address_shaped_but_unparseable"
    );
    assert_eq!(
        hard_deny::refuse_ip(ip("fe80::1")),
        FloorVerdict::Refused(FloorReason::LinkLocal),
        "fe80::/10 is link-local, not unique-local"
    );
    assert_eq!(
        hard_deny::refuse_ip(ip("fd12:3456:789a::1")),
        FloorVerdict::Refused(FloorReason::UniqueLocal),
        "fc00::/7 is unique-local, not link-local"
    );
    assert_eq!(
        hard_deny::refuse_ip(ip("169.254.1.1")),
        FloorVerdict::Refused(FloorReason::LinkLocal),
        "169.254.0.0/16 outside the metadata address is link-local, not a metadata service"
    );
    // The control: a public address in neither range.
    assert_eq!(
        hard_deny::refuse_ip(ip("2606:4700::1")),
        FloorVerdict::NotRefused,
        "an ordinary global IPv6 address must not be swept into either range"
    );
}

#[test]
fn refuse_ip_normalizes_a_mapped_ipv6_address_for_a_third_party_caller() {
    // `hard_deny::normalize` is `pub` and documented as making a mapped IPv6 form judged as the
    // IPv4 address it routes to — the exact bypass class this module exists to close. It was dead in
    // every call path inside the workspace: `Policy::decide_ip` normalizes first, and `refuse`
    // reaches `refuse_ip` through `canonical_ip`, which unwraps too. Inserting `return ip;` at the
    // head of `normalize` left the whole suite green. A third-party caller of the `pub` API gets no
    // such pre-normalization, so this asserts the guarantee at the boundary that offers it.
    let mapped: IpAddr = "::ffff:169.254.169.254".parse().expect("parses");
    assert!(
        matches!(mapped, IpAddr::V6(_)),
        "the test literal must still be an un-normalized V6 value, or this proves nothing"
    );
    assert_eq!(
        hard_deny::refuse_ip(mapped),
        FloorVerdict::Refused(FloorReason::MetadataService),
        "refuse_ip must unwrap a mapped IPv6 address itself, not rely on its caller having done it"
    );
    assert_eq!(
        hard_deny::normalize(mapped),
        ip(META),
        "normalize must return the IPv4 address the wrapper routes to"
    );
    // The control: a mapped ordinary address unwraps too, and is not refused.
    let mapped_ok: IpAddr = "::ffff:8.8.8.8".parse().expect("parses");
    assert_eq!(hard_deny::normalize(mapped_ok), ip("8.8.8.8"));
    assert_eq!(
        hard_deny::refuse_ip(mapped_ok),
        FloorVerdict::NotRefused,
        "unwrapping must not turn an ordinary address into a refusal"
    );
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
fn the_floor_leaves_ipv4_private_ranges_to_the_policy_that_already_governs_it() {
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
        "the floor covers the metadata services, IPv4 169.254.0.0/16, IPv6 fe80::/10 and IPv6 \
         unique-local fc00::/7 — but NOT IPv4 RFC-1918, which deny_private_egress still governs"
    );
}

#[test]
fn the_ipv6_analog_of_rfc_1918_is_in_the_floor_and_the_opt_out_cannot_reach_it() {
    // The asymmetry the tier table and the RFC-1918 control above both understated. `fc00::/7` is
    // the IPv6 analog of RFC-1918 and the floor refuses it *unamendably*, while IPv4 RFC-1918 is
    // left to a flag an operator may turn off. On `f99af94` this exact policy returned
    // `Allow/Allowlisted`; the change is deliberate and is asserted here so it is not silent.
    let ula: IpAddr = ip("fd12:3456:789a::1");
    let policy = PolicyBuilder::new()
        .deny_private_egress(false)
        .allow_ip("fd12:3456:789a::1")
        .build()
        .expect("builds");
    let decision = policy.decide_ip(ula);
    assert_eq!(
        decision.action,
        Action::Deny,
        "an explicitly allowlisted unique-local address on a fully opted-out policy is still \
         refused, which is a behavior change from f99af94: {decision:?}"
    );
    assert_eq!(
        decision.reason,
        floor_reason("unique_local"),
        "and the reason must name the rule, because the shipping broker will report it under the \
         coarser word `metadata_range`: {decision:?}"
    );
    // The control, in the same polarity as the assertion above: opting out DOES still reach the
    // IPv4 range, so this test is about fc00::/7 specifically and not about the opt-out being dead.
    let v4 = PolicyBuilder::new()
        .deny_private_egress(false)
        .allow_ip("172.16.0.1")
        .build()
        .expect("builds");
    assert_eq!(
        v4.decide_ip(ip("172.16.0.1")).action,
        Action::Allow,
        "the IPv4 opt-out still works; only its IPv6 counterpart is unreachable"
    );
}

// ---------------------------------------------------------------------------------------------
// The source half. Absence IS the mechanism, and no behavioral test can see a parameter that has
// not been added yet: every assertion above would stay green if a later commit added
// `refuse(literal, allow_override: bool)` and threaded a flag through.
//
// It is an ENUMERATED DENYLIST over one file's text, and it is not a proof. An adversarial review
// defeated the previous token list with an amendment that added no parameter at all — a
// process-global `AtomicBool` plus a `std::env::var` read — which left both pinned signatures
// byte-for-byte and shipped green, while turning nine tests red once the variable was set. Those
// tokens are enumerated now. A channel nobody has enumerated is still invisible, which is why the
// test below is named for the tokens it checks rather than for "no configuration value of any kind".
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

/// Every token whose presence in the floor's shipping code would mean the answer can depend on
/// something other than the address.
///
/// Two groups. The first is a parameter or a receiver: a value someone passes in. The second is
/// *ambient* state — a global, an environment read, an interior-mutability cell — which needs no
/// parameter and which the first list could not see.
///
/// `"static "` is deliberately absent: `&'static str` contains it, so forbidding it would fire on
/// `FloorReason::as_str`. `"static mut"` and the concrete cell types are the reachable spellings.
fn forbidden_tokens() -> &'static [&'static str] {
    &[
        // Passed in.
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
        // Ambient. Added after an adversarial review shipped an amendment past the list above.
        "std::env",
        "env::var",
        "set_var",
        "static mut",
        "AtomicBool",
        "AtomicUsize",
        "OnceLock",
        "OnceCell",
        "lazy_static",
        "thread_local",
        "RefCell",
        "Mutex",
        "RwLock",
    ]
}

#[test]
fn the_floor_module_contains_no_enumerated_amendment_channel() {
    let code = floor_code();

    // The control. If the probe cannot see what IS there, every assertion below is a false pass.
    for present in ["IpAddr", "pub fn refuse", "FloorVerdict::Refused"] {
        assert!(
            code.contains(present),
            "the source gate cannot see {present:?} in hard_deny.rs, so it is broken and proves \
             nothing about what is absent"
        );
    }

    // The second control, and the one the previous revision lacked: a denylist proves nothing
    // unless it would actually fire on the amendment it exists to stop. This is the text of the
    // amendment an adversarial review shipped green against `5e1b5a5` — no parameter added, both
    // signatures byte-for-byte identical, and nine tests red only when the variable was set.
    let demonstrated_amendment = "static FLOOR_ENABLED: AtomicBool = AtomicBool::new(true);\n\
         if !FLOOR_ENABLED.load(Relaxed) || std::env::var(\"WARRANTOR_FLOOR_OFF\").is_ok() {";
    assert!(
        forbidden_tokens()
            .iter()
            .any(|t| demonstrated_amendment.contains(t)),
        "the token list no longer catches the non-parameter amendment that defeated its previous \
         revision, so it has been weakened rather than strengthened"
    );

    // The strongest form of the gate: the two decision signatures, pinned verbatim. Adding a
    // second parameter to either — a flag, an options struct, a policy reference — changes this
    // string and fails here, which no behavioral assertion above could detect.
    for signature in [
        "pub fn refuse(literal: &str) -> FloorVerdict {",
        "pub fn refuse_ip(ip: IpAddr) -> FloorVerdict {",
    ] {
        assert!(
            code.contains(signature),
            "the floor's decision signature is no longer {signature:?}. One argument is the whole \
             mechanism: there must be nothing to pass that could change the answer."
        );
    }

    // `: bool` is parameter and field syntax; `-> bool` is a return type and is fine. `&self` is a
    // borrowed receiver, which would mean the answer depends on state someone can set. A by-value
    // `self` on the two `Copy` verdict enums is not that, and is deliberately not forbidden.
    for forbidden in forbidden_tokens() {
        assert!(
            !code.contains(forbidden),
            "hard_deny.rs contains {forbidden:?}. A configuration value, a receiver, a policy \
             reference OR an ambient switch in this module is L4-25 being quietly withdrawn while \
             every behavioral test stays green. This gate is an enumerated list, not a proof: it \
             catches the channels named in forbidden_tokens() and nothing else."
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
        "the floor is consulted at byte {floor_at} and the allowlist at {allowlist_at}: an \
         allowlist entry evaluated first would punch a hole straight through the floor"
    );
}

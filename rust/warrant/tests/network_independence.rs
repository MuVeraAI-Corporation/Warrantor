//! Common-mode independence drills for the egress path (Task 5.4, L2-03 / L0-10).
//!
//! Each drill removes one layer and asks whether the destination is still refused. A drill that
//! only ever refuses proves nothing, so every drill is paired with a control in which the same
//! machinery ALLOWS the destination.
//!
//! The drills measure the *current, honest* answer rather than the answer the blueprint wants. On
//! this tree that answer is: a permitted destination is guarded by exactly one enforcement point,
//! and wiring a second policy engine does not change that. See
//! `docs/05-network-common-mode-analysis.md`.

use std::collections::BTreeSet;

use warrantor_warrant::egress::{
    independence, EgressBroker, EgressVerdict, SecondaryFilter, INDEPENDENCE_NOTE,
};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::{sandbox, SideEffectClass, WarrantBounds};

const PERMITTED: &str = "api.github.com";
const OUTSIDE: &str = "exfil.example.com";
const TOOL: &str = "github.get_file";

fn bounds(egress: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: BTreeSet::new(),
        write_paths: BTreeSet::new(),
        egress_hosts: egress.iter().map(|s| (*s).to_string()).collect(),
        staged_classes: BTreeSet::new(),
        expires_at: 4_000_000_000,
        budget_cents_observed: None,
        delegation_depth: 0,
    }
}

// ── the two drills the anchor's verification clause asks for ──────────────────────────

#[test]
fn drill_one_layer_a_removed_and_something_else_must_still_refuse() {
    let b = bounds(&[PERMITTED]);

    // Control: with layer A in place the broker ALLOWS the permitted host. Without this the
    // refusal below could be a refusal of everything, which measures nothing.
    assert!(
        matches!(
            EgressBroker::for_bounds(&b).decide(PERMITTED),
            EgressVerdict::Allow { .. }
        ),
        "control: a permitted host must be allowed by layer A, or this drill is one-sided",
    );

    // Layer A removed. The only other LAYER in this repository is the network namespace, and it is
    // deliberately NOT emitted for a warrant that permits any host.
    let profile = sandbox::profile(&b, "/home/u/wt", sandbox::Confinement::Bubblewrap);
    assert!(
        !profile.argv.iter().any(|a| a == "--unshare-net"),
        "sandbox.rs lines 333-346 promise no netns for a permitted-egress warrant",
    );

    // What DOES stand behind layer A is a second policy engine at the same enforcement point. It
    // refuses, which is the honest result of this task -- and the next assertion is the one that
    // stops anybody reading that refusal as a second boundary.
    let filter = SecondaryFilter::default_deny();
    assert_eq!(
        filter.decide(PERMITTED).action,
        warrantor_egress_filter::Action::Deny,
        "the second engine's default is deny, so a host the operator never allowlisted is refused",
    );

    // The drill's real finding: the refusal above came from the same process, at the same
    // enforcement point. Removing layer A does not leave a second BOUNDARY standing.
    let with_second = independence(&b, Some(&filter));
    assert_eq!(
        with_second.engines, 2,
        "two evaluators are consulted for a permitted host",
    );
    assert_eq!(
        with_second.intercepts, 1,
        "and they share one enforcement point, so the double path does not exist: L2-03 stays none",
    );
}

#[test]
fn drill_two_layer_b_removed_and_layer_a_must_still_refuse() {
    // Layer B is already absent for any permitted-egress warrant, so "disabling" it is a no-op.
    // That is the finding: a drill that cannot change the outcome is a drill against a layer that
    // was never standing.
    let b = bounds(&[PERMITTED]);
    let broker = EgressBroker::for_bounds(&b);

    // Layer A alone still refuses a destination outside the bound. The allowed control in drill one
    // proves it is not refusing everything.
    assert_eq!(
        broker.decide(OUTSIDE),
        EgressVerdict::Deny {
            reason: warrantor_warrant::egress::DenyReason::NotInCatalog
        },
    );

    // And the count is one, not two. This is the number the record and the product both render.
    let alone = independence(&b, None);
    assert_eq!(
        alone.intercepts, 1,
        "a permitted host is guarded once; L2-03 is status=none until this is 2",
    );
    assert!(
        alone.shared_axes.contains(&"configuration_source"),
        "one field drives both layers in opposite directions; that must be named, not implied",
    );
}

#[test]
fn a_no_egress_warrant_is_the_only_two_layer_case_and_it_guards_nothing() {
    // The one configuration with two layers standing. Both refuse, and there is no permitted
    // destination for either of them to be independent about.
    let b = bounds(&[]);
    let profile = sandbox::profile(&b, "/home/u/wt", sandbox::Confinement::Bubblewrap);
    assert!(profile.argv.iter().any(|a| a == "--unshare-net"));
    assert_eq!(
        EgressBroker::for_bounds(&b).decide(PERMITTED),
        EgressVerdict::Deny {
            reason: warrantor_warrant::egress::DenyReason::CatalogUnavailable
        },
    );
    assert_eq!(EgressBroker::for_bounds(&b).catalogued(), 0);

    let two = independence(&b, None);
    assert_eq!(two.intercepts, 2);
    assert!(
        two.layers.contains(&"network_namespace"),
        "the netns is the second layer, and only in this configuration",
    );
    assert!(
        !two.guards_a_permitted_destination,
        "two layers over an empty bound guard nothing: there is no permitted destination",
    );
}

// ── the axes, asserted rather than described ──────────────────────────────────────────

#[test]
fn the_axes_are_asserted_not_described() {
    let permitting = bounds(&[PERMITTED]);
    let filter = SecondaryFilter::default_deny();
    let with_second = independence(&permitting, Some(&filter));

    // 1. POLICY ENGINE -- disjoint at the evaluator once the second engine is wired. This is the
    //    one axis this task moved.
    assert!(!with_second.shared_axes.contains(&"policy_engine"));

    // 2. ADDRESS FLOOR -- still shared, and this is the axis the plan could not know about. Task
    //    7.1 put the single deny floor in `warrantor-egress-filter::hard_deny` and made
    //    `warrantor-egress` delegate to it, so BOTH evaluators consult the same two functions.
    //    One matcher prevents drift; it also couples the engines. Both are true.
    assert!(
        with_second.shared_axes.contains(&"address_floor"),
        "both evaluators call warrantor_egress_filter::hard_deny; a defect there fails both",
    );

    // 3. CONFIGURATION SOURCE -- shared for the pair of LAYERS, because one warrant field drives
    //    the proxy catalog and the netns in opposite directions.
    assert!(with_second.shared_axes.contains(&"configuration_source"));

    // 4. CREDENTIAL -- neither holds one. Independent by absence; say so, do not claim design.
    assert!(!with_second.shared_axes.contains(&"credential"));

    // 5. TELEMETRY PATH -- shared. Both refusals land in the same in-process maps, and the netns
    //    produces no telemetry at all.
    assert!(with_second.shared_axes.contains(&"telemetry_path"));

    // 6. CLOCK -- shared. `bounds.expires_at` drives both.
    assert!(with_second.shared_axes.contains(&"clock"));

    // 7. DNS RESOLUTION -- shared by absence. A shared blind spot is a common mode.
    assert!(with_second.shared_axes.contains(&"dns_resolution"));

    // 8. ENFORCEMENT POINT -- shared, and unchanged by this task. The axis the blueprint's four do
    //    not include and the one a reader assumes.
    assert!(with_second.shared_axes.contains(&"enforcement_point"));

    // And the control, so none of the above is an artifact of a struct that shares everything:
    // with no second engine, `policy_engine` IS shared and there is one evaluator.
    let alone = independence(&permitting, None);
    assert!(alone.shared_axes.contains(&"policy_engine"));
    assert_eq!(alone.engines, 1);
    assert_eq!(alone.intercepts, 1);
    assert_eq!(
        with_second.intercepts, 1,
        "two engines, one enforcement point: still one",
    );
}

// ── the second engine narrows and never widens ────────────────────────────────────────

#[test]
fn the_second_engine_allows_what_the_operator_permitted() {
    // The allowed control for every refusal above. Without this, `SecondaryFilter` could be a
    // function that returns Deny unconditionally and the whole suite would still be green.
    let filter = SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_domain(PERMITTED)
            .build()
            .expect("the operator policy builds"),
    );
    assert_eq!(
        filter.decide(PERMITTED).action,
        warrantor_egress_filter::Action::Allow,
        "an operator allowlist entry must reach Allow, or the refusals above measure nothing",
    );
    assert_eq!(
        filter.decide(OUTSIDE).action,
        warrantor_egress_filter::Action::Deny
    );

    // And the pair that matters most: an allowlist entry must not punch a hole to the metadata
    // service. This is Task 7.1's non-amendable floor, and it must survive being wired.
    let generous = SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_ip("169.254.169.254")
            .deny_private_egress(false)
            .build()
            .expect("builds"),
    );
    let decision = generous.decide("169.254.169.254");
    assert_eq!(
        decision.action,
        warrantor_egress_filter::Action::Deny,
        "hard_deny::refuse_ip runs before the allowlist AND before the private-range flag; that \
         must survive wiring. Decision was {decision:?}",
    );
}

#[test]
fn the_second_engine_can_never_overturn_the_broker() {
    // The dangerous direction. An operator file that allows a host the WARRANT does not name must
    // still be refused, or the second engine is a widening mechanism rather than a narrowing one --
    // and a warrant field the operator can override is not a bound.
    let narrow = bounds(&[PERMITTED]);
    let generous = SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_domain(OUTSIDE)
            .build()
            .expect("builds"),
    );

    // The filter, asked on its own, allows it. That is the control: the attack really does reach
    // the boundary.
    assert_eq!(
        generous.decide(OUTSIDE).action,
        warrantor_egress_filter::Action::Allow,
        "control: the operator file really does allow this host, so the refusal below is the \
         broker's and not an accident",
    );

    // And the broker still refuses, because it decided first.
    assert_eq!(
        EgressBroker::for_bounds(&narrow).decide(OUTSIDE),
        EgressVerdict::Deny {
            reason: warrantor_warrant::egress::DenyReason::NotInCatalog
        },
        "the broker refused first and the filter must not be able to un-refuse it",
    );
}

// ── the same properties, through the proxy that actually runs ─────────────────────────

fn call_to(host: &str) -> ToolCall {
    ToolCall {
        tool: TOOL.to_string(),
        arguments: [("url".to_string(), format!("https://{host}/x"))]
            .into_iter()
            .collect(),
        side_effect: SideEffectClass::Read,
    }
}

fn proxy_over(hosts: &[&str], secondary: Option<SecondaryFilter>) -> Proxy {
    // The tool must be in the allowlist. `Proxy::decide` checks `bounds.tools` BEFORE the egress
    // loop, so a warrant with an empty tool set refuses under `bound: "tools"` and the egress
    // decision is never reached -- a refusal that looks right and measures nothing.
    let mut warrant_bounds = bounds(hosts);
    warrant_bounds.tools.insert(TOOL.to_string());
    let proxy = Proxy::new(warrant_bounds, ProxyMode::Enforce, EffectRegistry::github());
    match secondary {
        Some(filter) => proxy.with_secondary_filter(filter),
        None => proxy,
    }
}

#[test]
fn through_the_proxy_the_second_engine_cannot_overturn_the_broker() {
    // The dangerous direction, at the call site that ships. An operator file that allows a host the
    // WARRANT does not name must still be refused.
    let mut proxy = proxy_over(
        &[PERMITTED],
        Some(SecondaryFilter::from_policy(
            warrantor_egress_filter::PolicyBuilder::with_defaults()
                .allow_domain(OUTSIDE)
                .build()
                .expect("builds"),
        )),
    );

    let decision = proxy.decide(&call_to(OUTSIDE));
    assert!(
        matches!(&decision, Decision::Deny { bound, .. } if *bound == "egress_hosts"),
        "the broker refused first and the filter must not be able to un-refuse it: {decision:?}",
    );
    // And the refusal was attributed to the BROKER, not to the second engine -- the record must say
    // which evaluator decided, or an operator is sent to the wrong configuration file.
    assert_eq!(
        proxy.egress_refusals().len(),
        1,
        "the broker's refusal is the one recorded",
    );
    assert!(
        proxy.secondary_refusals().is_empty(),
        "the second engine never ran for this destination, so it must record nothing",
    );
}

#[test]
fn through_the_proxy_the_second_engine_narrows_what_the_warrant_permitted() {
    // The narrowing direction, and the allowed control for it. The warrant permits the host; the
    // operator's file does not; the call is refused and the refusal is attributed to the filter.
    let mut narrowed = proxy_over(&[PERMITTED], Some(SecondaryFilter::default_deny()));
    let decision = narrowed.decide(&call_to(PERMITTED));
    assert!(
        matches!(&decision, Decision::Deny { bound, .. } if *bound == "egress_hosts"),
        "a host the operator's engine denies must be refused: {decision:?}",
    );

    let recorded = narrowed.secondary_refusals();
    assert_eq!(recorded.len(), 1, "the second engine's refusal is recorded");
    assert_eq!(recorded[0].destination, PERMITTED);
    assert!(
        recorded[0].rule.contains("default_deny"),
        "the rule must be the engine's own reason, read off the decision: {:?}",
        recorded[0].rule,
    );
    assert!(
        narrowed.egress_refusals().is_empty(),
        "the broker allowed this host, so it must not be credited with the refusal",
    );
    // The sentence is derived from that record, and it refuses the enforcement-point reading.
    assert!(
        recorded[0].sentence().contains("not a second boundary"),
        "the rendered sentence must bound the claim it makes: {}",
        recorded[0].sentence(),
    );

    // THE ALLOWED CONTROL. Same warrant, same proxy shape, an operator engine that permits the
    // host: the call is forwarded. Without this the refusal above could be a proxy that refuses
    // everything.
    let mut permitted = proxy_over(
        &[PERMITTED],
        Some(SecondaryFilter::from_policy(
            warrantor_egress_filter::PolicyBuilder::with_defaults()
                .allow_domain(PERMITTED)
                .build()
                .expect("builds"),
        )),
    );
    assert_eq!(
        permitted.decide(&call_to(PERMITTED)),
        Decision::Forward,
        "control: both engines permit this host, so it must be forwarded",
    );
    assert!(permitted.secondary_refusals().is_empty());
}

#[test]
fn the_proxy_reports_the_independence_of_the_configuration_it_is_actually_running() {
    // Rule 2, applied to a number: the count must be read off the running proxy, not off a
    // hypothetical one. A proxy with no second engine reports one engine even though the type is
    // available, and a proxy with one reports two.
    let alone = proxy_over(&[PERMITTED], None);
    assert_eq!(alone.egress_independence().engines, 1);
    assert!(alone.secondary_filter().is_none());

    let paired = proxy_over(&[PERMITTED], Some(SecondaryFilter::default_deny()));
    assert_eq!(paired.egress_independence().engines, 2);
    assert_eq!(
        paired.egress_independence().intercepts,
        1,
        "wiring the engine must not move the intercept count",
    );
    assert!(paired.secondary_filter().is_some());
}

// ── the sentence that bounds the count ────────────────────────────────────────────────

#[test]
fn the_note_names_all_three_absent_enforcement_mechanisms() {
    // No claim without a mechanism. A count of policy domains rendered without this clause is read
    // as a count of enforcement points.
    for absent in ["network namespace", "seccomp filter", "firewall"] {
        assert!(
            INDEPENDENCE_NOTE.contains(absent),
            "INDEPENDENCE_NOTE must name {absent:?} as absent",
        );
    }
    assert!(
        INDEPENDENCE_NOTE.contains("not a count of enforcement points"),
        "the note's job is to refuse the enforcement-point reading, in those words",
    );
    assert!(
        INDEPENDENCE_NOTE.contains("neither engine resolves DNS"),
        "the shared DNS blind spot is the concrete exploit the anti-correlation opens",
    );
}

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
    independence, independence_sentence, EgressBroker, EgressVerdict, SecondaryFilter,
    INDEPENDENCE_AXES, INDEPENDENCE_NOTE,
};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall, SECONDARY_FILTER_BOUND};
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
        max_tool_calls: Some(100),
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
    //
    // CORRECTION. This assertion used to name `hard_deny::refuse_ip` while observing something else
    // entirely. `169.254.169.254` is in `DEFAULT_CANARY_IPS`, and `Policy::decide_ip` checks
    // `canary_ips` BEFORE the floor, so the refusal it saw was `CanaryIp` -- a refusal that reads a
    // configured field, the exact opposite of what the message claimed. And it asserted only the
    // action, never the reason, so deleting the entire `hard_deny::refuse_ip` arm from `decide_ip`
    // left this suite fully green. Task 7.1's own suite caught that with six failures; the
    // `address_floor` axis THIS branch introduced caught it with none, because the axis was asserted
    // only by a hardcoded `true` inside `independence()`.
    //
    // So: assert the reason, not just the action, and separate the two mechanisms.
    let generous = SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_ip("169.254.169.254")
            .deny_private_egress(false)
            .build()
            .expect("builds"),
    );
    let canary = generous.decide("169.254.169.254");
    assert_eq!(
        canary.action,
        warrantor_egress_filter::Action::Deny,
        "an allowlist entry must not punch a hole to the metadata service: {canary:?}",
    );
    assert_eq!(
        canary.reason,
        warrantor_egress_filter::DecisionReason::CanaryIp,
        "this address is refused by the CANARY list, which the canary check reaches first. Naming \
         the floor here is what hid the floor's absence: {canary:?}",
    );

    // The floor itself, on an address only the floor covers. `169.254.1.1` is link-local, so
    // `hard_deny::refuse_ip` refuses it -- and it is in no `canary_ips` list, the allowlist names
    // it, and `deny_private_egress(false)` disables the private check. Nothing but the floor can
    // produce this Deny, so deleting the floor turns this red.
    let floor_only = SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_ip("169.254.1.1")
            .deny_private_egress(false)
            .build()
            .expect("builds"),
    );
    let floored = floor_only.decide("169.254.1.1");
    assert_eq!(
        floored.action,
        warrantor_egress_filter::Action::Deny,
        "hard_deny::refuse_ip runs before the allowlist AND before the private-range flag; that \
         must survive wiring. Decision was {floored:?}",
    );
    assert!(
        matches!(
            floored.reason,
            warrantor_egress_filter::DecisionReason::HardDenyFloor { .. }
        ),
        "and it must be the FLOOR that refused, not a configured field: the floor is the axis \
         `address_floor` names as shared, so a measurement that reports it shared while nothing \
         behaviorally depends on it reports a failure domain that may not exist. Decision was \
         {floored:?}",
    );

    // The IPv6 half of the same floor, which no configured list covers either.
    let ula = floor_only.decide("fd00:beef::1");
    assert!(
        matches!(
            ula.reason,
            warrantor_egress_filter::DecisionReason::HardDenyFloor { .. }
        ),
        "an IPv6 unique-local address is floor territory too: {ula:?}",
    );

    // THE ALLOWED CONTROL for the floor. A floor that refused every address would satisfy both
    // assertions above and prove nothing, so an ordinary routable address the operator allowlisted
    // must still reach Allow through the same policy.
    let routable = floor_only.decide("93.184.216.34");
    assert_eq!(
        routable.action,
        warrantor_egress_filter::Action::Deny,
        "control setup: this address is not in that policy's allowlist",
    );
    let allowlisted = SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_ip("93.184.216.34")
            .build()
            .expect("builds"),
    );
    let allowed = allowlisted.decide("93.184.216.34");
    assert_eq!(
        allowed.action,
        warrantor_egress_filter::Action::Allow,
        "control: the floor must not refuse a routable address, or the two Denies above are a \
         verifier that refuses everything: {allowed:?}",
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
        matches!(&decision, Decision::Deny { bound, .. } if *bound == SECONDARY_FILTER_BOUND),
        "a host the operator's engine denies must be refused under the second engine's own bound,          because the warrant's egress_hosts bound permitted it: {decision:?}",
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

// ── the record the gate writes, against the answer this crate computes ────────────────

#[test]
fn the_gate_agrees_with_the_rust_answer() {
    // `tools/ci/network_independence.py` runs without cargo, so its axis table is a MIRROR of
    // `independence()` and cannot call it. Its comment used to name this test as the thing that
    // kept the two from drifting, and this test did not exist: flipping one answer in the Python
    // table and running `--write` produced a publishable record that disagreed with
    // `independence()` while every Rust test stayed green. This is the cross-check, field by
    // field, for both configurations the record publishes. The Python gate refuses a record that
    // disagrees with its own table; this refuses a record that disagrees with the code.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../evidence/network-independence.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    let record: serde_json::Value = serde_json::from_str(&text).expect("the record is JSON");
    let number = |field: &str| -> u64 {
        record[field]
            .as_u64()
            .unwrap_or_else(|| panic!("{field} must be a number in {}", path.display()))
    };
    let names = |field: &str| -> Vec<String> {
        record[field]
            .as_array()
            .unwrap_or_else(|| panic!("{field} must be a list in {}", path.display()))
            .iter()
            .map(|value| value.as_str().expect("names are strings").to_string())
            .collect()
    };

    let product = independence(&bounds(&[PERMITTED]), None);
    let wired = independence(
        &bounds(&[PERMITTED]),
        Some(&SecondaryFilter::default_deny()),
    );
    let empty = independence(&bounds(&[]), None);

    assert_eq!(
        number("independent_intercepts_on_a_permitted_host"),
        u64::try_from(product.intercepts).expect("fits"),
        "the published intercept count must be the one this crate computes",
    );
    assert_eq!(
        number("policy_engines_the_product_runs"),
        u64::try_from(product.engines).expect("fits"),
        "one engine in the configuration the product runs",
    );
    assert_eq!(
        number("policy_engines_once_the_second_is_wired"),
        u64::try_from(wired.engines).expect("fits"),
        "two once a caller of the library wires the second",
    );
    assert_eq!(
        names("configuration_sources_the_product_runs"),
        product.configuration_sources,
        "the product reads the signed claims and nothing else",
    );
    assert_eq!(
        names("axes"),
        INDEPENDENCE_AXES,
        "the axis list is the Rust constant's"
    );
    assert_eq!(
        names("shared_axes_the_product_runs"),
        product.shared_axes,
        "the shared axes in a shipped run: every axis but credential, because one engine has \
         nothing to be disjoint from",
    );
    assert_eq!(
        names("shared_axes_once_the_second_is_wired"),
        wired.shared_axes,
        "the shared axes once a second engine is wired: policy_engine stops being shared",
    );
    assert_eq!(names("layers_on_a_permitted_host"), product.layers);
    assert_eq!(names("layers_on_an_empty_bound"), empty.layers);
}

// ── the sentence that bounds the count ────────────────────────────────────────────────

#[test]
fn the_note_names_all_three_absent_enforcement_mechanisms() {
    // No claim without a mechanism. The count is published with no enforcement mechanism standing
    // behind it, so the note must name every mechanism a reader would otherwise assume.
    for absent in ["network namespace", "seccomp filter", "firewall"] {
        assert!(
            INDEPENDENCE_NOTE.contains(absent),
            "INDEPENDENCE_NOTE must name {absent:?} as absent",
        );
    }
    // CORRECTION. This assertion used to require "not a count of enforcement points", which pinned
    // a sentence that was FALSE about the number it sat beside: every surface the gate polices
    // publishes `intercepts`, and `intercepts` IS the enforcement-point count. The label now has to
    // match the record, and the old wording is refused outright so it cannot come back.
    assert!(
        INDEPENDENCE_NOTE.contains("is a count of enforcement points"),
        "the note accompanies the INTERCEPT count on every surface, so it must label that count \
         correctly: {INDEPENDENCE_NOTE}",
    );
    assert!(
        !INDEPENDENCE_NOTE.contains("count of policy domains, not a count of enforcement points"),
        "that clause mislabels the published number in the unsafe direction -- it tells the reader \
         the count does not bound enforcement points, when the count IS the enforcement count: \
         {INDEPENDENCE_NOTE}",
    );
    assert!(
        INDEPENDENCE_NOTE.contains("engine count is a count of policy domains"),
        "and the policy-domain clause must be attached to the ENGINE count, which is the number it \
         is true of: {INDEPENDENCE_NOTE}",
    );
    // The remedy clause must not offer a remedy this branch proves unavailable. `sandbox::profile`
    // omits `--unshare-net` for any warrant that permits a host, which is exactly the configuration
    // this count is about, so "unless you launched the confinement profile yourself" invited the
    // reader to believe a boundary was one command away.
    assert!(
        INDEPENDENCE_NOTE.contains("does not add one for a warrant that permits any host"),
        "the note must say the confinement profile adds nothing here, not imply it would: \
         {INDEPENDENCE_NOTE}",
    );
    assert!(
        !INDEPENDENCE_NOTE.contains("unless you launched the confinement profile"),
        "the withdrawn remedy clause must stay withdrawn: {INDEPENDENCE_NOTE}",
    );
    assert!(
        INDEPENDENCE_NOTE.contains("no engine at that point resolves DNS"),
        "the shared DNS blind spot is the concrete exploit the anti-correlation opens",
    );

    // THE ESCAPE CLAUSE, asserted by value. A Mediated bound's sentence must state what escapes
    // it (Task 0.4), and this is the one clause of the constant the suite did not pin: the
    // adversarial review replaced "passes neither" with "passes through both" and both suites
    // stayed green, because only the Python gate required it, and only on the Markdown copies.
    assert!(
        INDEPENDENCE_NOTE.contains("passes neither the proxy nor any engine inside it"),
        "the note must name what escapes the count, and it is everything that does not traverse \
         the proxy: {INDEPENDENCE_NOTE}",
    );
    assert!(
        !INDEPENDENCE_NOTE.contains("passes through both"),
        "the inverted escape clause reads as containment: {INDEPENDENCE_NOTE}",
    );

    // NO ENGINE COUNT IN THE CONSTANT. Its doc promises it carries only clauses that hold in every
    // configuration, and it used to say "Two policy engines decide at that one point" while the
    // shipped binary decides with one. A number belongs in `independence_sentence`, which reads it
    // off the record for the configuration that is actually running.
    assert!(
        !INDEPENDENCE_NOTE.chars().any(|c| c.is_ascii_digit()),
        "the constant carries no number; numbers come from independence_sentence: \
         {INDEPENDENCE_NOTE}",
    );
    for spelled in [
        "one policy engine",
        "One policy engine",
        "two policy engines",
        "Two policy engines",
        "both engines",
        "neither engine",
        "neither of them",
    ] {
        assert!(
            !INDEPENDENCE_NOTE.contains(spelled),
            "{spelled:?} is an engine count in words, true of only one configuration: \
             {INDEPENDENCE_NOTE}",
        );
    }
    // And the two configurations the product can be in both carry their own number, read off the
    // record, so nothing is lost by taking the count out of the constant.
    let alone = independence_sentence(&independence(&bounds(&[PERMITTED]), None));
    let paired = independence_sentence(&independence(
        &bounds(&[PERMITTED]),
        Some(&SecondaryFilter::default_deny()),
    ));
    assert!(alone.contains("1 policy engine decides"), "{alone}");
    assert!(paired.contains("2 policy engines decide"), "{paired}");
}

#[test]
fn the_count_sentence_labels_each_number_with_the_field_it_came_from() {
    // Rule 2 as a test. `independence_sentence` may not print a number under a word the record does
    // not support, so each label is checked against the field its number was read from.
    let permitted = independence(
        &bounds(&[PERMITTED]),
        Some(&SecondaryFilter::default_deny()),
    );
    let rendered = independence_sentence(&permitted);
    assert_eq!(permitted.intercepts, 1);
    assert_eq!(permitted.engines, 2);
    assert!(
        rendered.contains("1 enforcement point acts on a destination this warrant permits"),
        "the intercept count must be rendered as an ENFORCEMENT count: {rendered}",
    );
    assert!(
        rendered.contains("2 policy engines decide"),
        "the engine count must be rendered as an ENGINE count: {rendered}",
    );
    assert!(
        rendered.contains("engine count is a count of policy domains and is not a second boundary"),
        "and the engine count must carry its own bounding clause: {rendered}",
    );

    // THE EMPTY-BOUND CONTROL, and the reason this is a function rather than a second constant. A
    // no-egress warrant has TWO layers standing. Rendering that 2 as a double network path is the
    // overclaim the whole analysis refuses, so the sentence must say what the 2 does not buy.
    let empty = independence(&bounds(&[]), None);
    let rendered_empty = independence_sentence(&empty);
    assert_eq!(
        empty.intercepts, 2,
        "the netns stands only for an empty bound"
    );
    assert!(
        rendered_empty.contains("none of them guards a permitted destination"),
        "two layers over nothing must not read as a double path: {rendered_empty}",
    );
    assert!(
        rendered_empty.contains("This is not a double network path"),
        "and it must refuse that reading in words: {rendered_empty}",
    );
    assert!(
        !rendered_empty.contains("acts on a destination this warrant permits"),
        "the permitted-destination clause must not fire when nothing is permitted: \
         {rendered_empty}",
    );
}

#[test]
fn the_measurement_records_which_configuration_source_each_engine_read() {
    // `SecondarySource::as_str` claimed its word appeared in `Independence`. It did not: the type
    // had zero readers in the whole workspace, and being `pub` hid that from both `dead_code` and
    // `clippy -D warnings`. The attribution is now carried, and asserted per source.
    let alone = independence(&bounds(&[PERMITTED]), None);
    assert_eq!(
        alone.configuration_sources,
        vec!["warrant_claims"],
        "the broker reads the signed bounds and nothing else",
    );

    let compiled = independence(
        &bounds(&[PERMITTED]),
        Some(&SecondaryFilter::default_deny()),
    );
    assert_eq!(
        compiled.configuration_sources,
        vec!["warrant_claims", "compiled_default"],
        "a filter that fell back to the compiled policy must not be recorded as an operator file",
    );

    let inline = independence(
        &bounds(&[PERMITTED]),
        Some(&SecondaryFilter::from_policy(
            warrantor_egress_filter::PolicyBuilder::with_defaults()
                .allow_domain(PERMITTED)
                .build()
                .expect("builds"),
        )),
    );
    assert_eq!(
        inline.configuration_sources,
        vec!["warrant_claims", "inline_policy"],
        "an in-process policy is its own source and must be distinguishable from the fallback",
    );
}

#[test]
fn the_second_engine_can_be_built_from_a_real_operator_file() {
    // `from_operator_config` is the reason the second engine buys anything at all -- a source that
    // did NOT read the warrant's signed claims -- and it had zero callers and no fixture. So the
    // second engine's whole justification was exercised by no test that opens a real file.
    let directory =
        std::env::temp_dir().join(format!("warrantor-secondary-source-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("the temp directory is creatable");
    let path = directory.join("egress-filter.json");
    let policy = warrantor_egress_filter::PolicyBuilder::with_defaults()
        .allow_domain(PERMITTED)
        .build()
        .expect("builds");
    std::fs::write(
        &path,
        serde_json::to_string(&policy).expect("a policy serializes"),
    )
    .expect("the fixture is writable");

    let from_file = SecondaryFilter::from_operator_config(&path).expect("the fixture parses");
    let measured = independence(&bounds(&[PERMITTED]), Some(&from_file));
    assert_eq!(
        measured.configuration_sources,
        vec!["warrant_claims", "operator_file"],
        "a policy read off disk must be recorded as the operator file it came from",
    );

    // A wiring test, not a constructor test: the engine built from that file actually decides.
    assert_eq!(
        from_file.decide(PERMITTED).action,
        warrantor_egress_filter::Action::Allow,
        "control: the operator's file permits this host, so the engine built from it must allow it",
    );
    assert_eq!(
        from_file.decide("not-in-the-file.example").action,
        warrantor_egress_filter::Action::Deny,
        "and it must still refuse a host the file does not name",
    );

    // A file that is present and WRONG must be a refusal, never a silent fallback to a filter that
    // permits more. The doc says so; nothing asserted it.
    std::fs::write(&path, "{ not json").expect("the fixture is writable");
    assert!(
        matches!(
            SecondaryFilter::from_operator_config(&path),
            Err(warrantor_warrant::egress::SecondaryConfigError::Malformed { .. })
        ),
        "a malformed operator file must refuse to build a filter rather than fall back",
    );

    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(&directory).ok();
}

// ── the record behind a rendered refusal ──────────────────────────────────────────────

#[test]
fn the_rendered_rule_is_the_engine_s_own_reason_and_not_one_literal() {
    // `SecondaryRefusal::new`'s comment reads "Derived from the decision, not written beside it",
    // and the type exists to satisfy Rule 2. Nothing enforced it: only `DefaultDeny` was ever
    // exercised on this branch, the single assertion was `rule.contains("default_deny")`, and
    // replacing the two-line serialization with a hardcoded `"\"default_deny\""` literal left all
    // 833 tests in this package and the CI gate green.
    //
    // A derivation is only demonstrated by two different inputs producing two different outputs, so
    // this drives a SECOND reason through the same path and asserts the rendered rule differs.
    let mut blocked = proxy_over(
        &[PERMITTED],
        Some(SecondaryFilter::from_policy(
            warrantor_egress_filter::PolicyBuilder::with_defaults()
                .allow_domain(PERMITTED)
                .block_domain(PERMITTED)
                .build()
                .expect("builds"),
        )),
    );
    let decision = blocked.decide(&call_to(PERMITTED));
    assert!(
        matches!(&decision, Decision::Deny { bound, .. } if *bound == SECONDARY_FILTER_BOUND),
        "a blocklisted host must be refused by the second engine: {decision:?}",
    );
    let recorded = blocked.secondary_refusals();
    assert_eq!(recorded.len(), 1);
    assert!(
        recorded[0].rule.contains("blocked_domain"),
        "the rule must be THIS decision's reason. A hardcoded \"default_deny\" literal passes the \
         default-deny test and fails here, which is the point: {:?}",
        recorded[0].rule,
    );
    assert!(
        !recorded[0].rule.contains("default_deny"),
        "and it must not carry the other engine's reason: {:?}",
        recorded[0].rule,
    );
    // The rendered sentence is read off the same record, so it must carry the same rule.
    assert!(
        recorded[0].sentence().contains("blocked_domain"),
        "the sentence renders the record's own rule, not a restatement of it: {}",
        recorded[0].sentence(),
    );

    // THE PAIRED CASE. The default-deny engine on the same host renders a DIFFERENT rule. Two
    // inputs, two outputs, from one serialization: that is what "derived" means.
    let mut defaulted = proxy_over(&[PERMITTED], Some(SecondaryFilter::default_deny()));
    defaulted.decide(&call_to(PERMITTED));
    let other = defaulted.secondary_refusals();
    assert_eq!(other.len(), 1);
    assert!(
        other[0].rule.contains("default_deny"),
        "the fallback engine's own reason: {:?}",
        other[0].rule,
    );
    assert_ne!(
        recorded[0].rule, other[0].rule,
        "two engines with two reasons must render two rules. If these are equal, the rule is a \
         literal and the attribution the type was created for does not exist.",
    );
}

#[test]
fn a_repeated_refusal_is_counted_and_the_most_frequent_is_reported_first() {
    // `SecondaryRefusal.count` is documented as "how many times this exact refusal happened" and
    // `secondary_refusals()` as "most frequent first". No test on this branch ever produced a
    // repeated refusal or a second distinct one, so both mechanisms were decoration: no-oping the
    // `.and_modify(|existing| existing.count += 1)` in `deny_secondary` AND deleting the whole
    // `out.sort_by(...)` left all 833 tests in this package green at once. That is verbatim the
    // defect the previous wave found in the broker's counter.
    let second = "registry.npmjs.org";
    let mut proxy = proxy_over(&[PERMITTED, second], Some(SecondaryFilter::default_deny()));

    // Twice for one destination, once for the other. A looping agent is the case the counter is for.
    proxy.decide(&call_to(PERMITTED));
    proxy.decide(&call_to(PERMITTED));
    proxy.decide(&call_to(second));

    let recorded = proxy.secondary_refusals();
    assert_eq!(
        recorded.len(),
        2,
        "two distinct destinations, deduplicated to two records: {recorded:?}",
    );
    assert_eq!(
        recorded[0].destination, PERMITTED,
        "most frequent first: the twice-refused destination must lead. A missing sort leaves these \
         in BTreeMap key order, where {second:?} sorts ahead of {PERMITTED:?}: {recorded:?}",
    );
    assert_eq!(
        recorded[0].count, 2,
        "the repeat must be counted, not merely deduplicated: {recorded:?}",
    );
    assert_eq!(
        recorded[1].count, 1,
        "and the once-refused destination must stay at one: {recorded:?}",
    );

    // The ordering is by count and not by name, which is what distinguishes a real sort from the
    // map's own order. `api.github.com` < `registry.npmjs.org`, so a key-ordered list would put
    // PERMITTED first for the wrong reason -- assert the reverse case too.
    let mut reversed = proxy_over(&[PERMITTED, second], Some(SecondaryFilter::default_deny()));
    reversed.decide(&call_to(second));
    reversed.decide(&call_to(second));
    reversed.decide(&call_to(PERMITTED));
    let flipped = reversed.secondary_refusals();
    assert_eq!(
        flipped[0].destination, second,
        "with the counts the other way round the order must flip. If it does not, the list is in \
         key order and the sort is decoration: {flipped:?}",
    );
    assert_eq!(flipped[0].count, 2, "{flipped:?}");
    assert_eq!(flipped[1].count, 1, "{flipped:?}");
}

// ── the durable record names the engine that refused ──────────────────────────────────

#[test]
fn a_second_engine_refusal_is_attributed_to_the_engine_in_memory_and_on_disk() {
    // CORRECTION (second adversarial review). A second-engine refusal was booked under the
    // `egress_hosts` bound -- the bound that had just PERMITTED the destination -- so the CLI
    // printed `denied <tool> xN (egress_hosts)` and sent the developer to widen a warrant bound
    // that was already wide enough. Worse: `record_refusals` drops `egress_hosts` authority
    // requests because the broker's refusals are written in full from `EgressRefusal`, and the
    // second engine has no `EgressRefusal`, so its refusals were written down nowhere.
    let mut proxy = proxy_over(&[PERMITTED], Some(SecondaryFilter::default_deny()));
    let decision = proxy.decide(&call_to(PERMITTED));

    // In memory: the per-tool counter every surface reads carries the engine's bound, not the
    // warrant's, and the broker is not credited with a refusal it did not make.
    assert!(
        matches!(&decision, Decision::Deny { bound, .. } if *bound == SECONDARY_FILTER_BOUND),
        "{decision:?}",
    );
    let requests = proxy.authority_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].bound, SECONDARY_FILTER_BOUND);
    assert!(
        !requests
            .iter()
            .any(|request| request.bound == "egress_hosts"),
        "the warrant's egress bound permitted this host and must not be named as refusing it",
    );
    assert!(proxy.egress_refusals().is_empty());

    // THE CONTROL: the broker's own refusal keeps the warrant's bound. Same proxy shape, a host
    // outside the warrant; the label must differ, or the label is decoration.
    let mut broker_refuses = proxy_over(&[PERMITTED], Some(SecondaryFilter::default_deny()));
    let outside = broker_refuses.decide(&call_to(OUTSIDE));
    assert!(
        matches!(&outside, Decision::Deny { bound, .. } if *bound == "egress_hosts"),
        "{outside:?}",
    );

    // On disk: written under the engine's bound with the destination and the engine's own rule.
    // `record_refusals` alone writes NOTHING for this session, which is the defect the review
    // found; `record_secondary_refusals` is what writes it.
    let directory = std::env::temp_dir().join(format!(
        "warrantor-secondary-refusal-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("the temp directory is creatable");
    let written_by_the_old_path = warrantor_warrant::serve::record_refusals(
        &directory,
        "wrt_secondary",
        &proxy.authority_requests(),
        &proxy.egress_refusals(),
        1_700_000_000,
    )
    .expect("records");
    assert_eq!(
        written_by_the_old_path, 0,
        "the per-tool counter is not written as a bare Tool record; the full record follows",
    );
    let written = warrantor_warrant::serve::record_secondary_refusals(
        &directory,
        "wrt_secondary",
        &proxy.secondary_refusals(),
        1_700_000_000,
    )
    .expect("records");
    assert_eq!(written, 1);

    let log = warrantor_warrant::serve::read_refusals(&directory, "wrt_secondary");
    assert_eq!(log.unreadable_lines, 0);
    assert_eq!(log.records.len(), 1, "{:?}", log.records);
    let record = &log.records[0];
    assert_eq!(record.kind, warrantor_warrant::serve::RefusalKind::Egress);
    assert_eq!(record.bound, SECONDARY_FILTER_BOUND);
    assert_eq!(record.destination.as_deref(), Some(PERMITTED));
    assert_eq!(record.argument.as_deref(), Some("url"));
    assert!(
        record
            .reason
            .as_deref()
            .is_some_and(|rule| rule.contains("default_deny")),
        "the durable reason is the engine's own rule, read off the refusal: {record:?}",
    );
    assert_eq!(record.count, 1);

    std::fs::remove_dir_all(&directory).ok();
}

// ── the order of the two engines, asserted where both refuse ──────────────────────────

#[test]
fn the_broker_decides_before_the_second_engine_so_a_refusal_is_attributed_to_the_engine_that_made_it(
) {
    // Test-rigor finding P2 (second adversarial review): reordering `Proxy::decide` so the second
    // engine is consulted BEFORE the broker left every suite green, because the only attribution
    // test wired a filter that ALLOWED the outside host and so could not see the order. Under that
    // mutation a host the broker refuses is recorded as a second-engine refusal, and the operator
    // is sent to the operator file for a bound the signed warrant set.
    //
    // Both engines refuse here: the warrant does not name OUTSIDE, and the default-deny filter
    // names nothing. Which record the refusal lands in is therefore the order, and nothing else.
    let mut proxy = proxy_over(&[PERMITTED], Some(SecondaryFilter::default_deny()));
    let decision = proxy.decide(&call_to(OUTSIDE));
    assert!(
        matches!(&decision, Decision::Deny { bound, .. } if *bound == "egress_hosts"),
        "the broker runs first, so the warrant's bound is the one that refused: {decision:?}",
    );
    assert_eq!(
        proxy.egress_refusals().len(),
        1,
        "the broker's refusal is the one recorded",
    );
    assert!(
        proxy.secondary_refusals().is_empty(),
        "the second engine must never be consulted for a destination the broker already refused; \
         a record here means the engines run in the wrong order: {:?}",
        proxy.secondary_refusals(),
    );
    if let Decision::Deny { reason, .. } = &decision {
        assert!(
            !reason.contains("second policy engine"),
            "the sentence the agent sees must not name an engine that did not decide: {reason}",
        );
    }

    // THE CONTROL, same proxy: a host the warrant permits reaches the second engine and is refused
    // by it, recorded on the other side. If both maps were empty above because nothing ran, this
    // would be empty too.
    proxy.decide(&call_to(PERMITTED));
    assert_eq!(proxy.secondary_refusals().len(), 1);
    assert_eq!(proxy.secondary_refusals()[0].destination, PERMITTED);
}

// ── two documented properties that no test constrained ────────────────────────────────

#[test]
fn the_normalized_form_travels_with_the_refusal_and_is_the_form_the_engine_decided_against() {
    // Test-rigor finding R5 (second adversarial review): `SecondaryRefusal.normalized` is documented
    // as "the form the filter actually decided against, which makes a normalization bypass
    // visible", and no test read it: replacing it with `String::new()` left both suites green.
    //
    // A host written with capitals and a trailing dot is the case the field exists for: the
    // destination the proxy resolved and the form the engine decided against differ, and a reader
    // of the refusal has to be able to see both. The odd form has to be what the WARRANT permits,
    // because the broker matches the bound verbatim -- it does not normalize -- and a call it
    // refuses never reaches the second engine (the order test above). That is worth knowing on
    // its own: the broker's exact match refuses in the safe direction, so a normalization bypass
    // can only be attempted against the engine that normalizes, which is why the field exists.
    let odd = "API.GitHub.COM.";
    let mut proxy = proxy_over(&[odd], Some(SecondaryFilter::default_deny()));
    let engine_saw = SecondaryFilter::default_deny().decide(odd).normalized;
    assert!(
        !engine_saw.is_empty(),
        "control: the engine normalizes this host to something",
    );

    let call = ToolCall {
        tool: TOOL.to_string(),
        arguments: [("url".to_string(), format!("https://{odd}/x"))]
            .into_iter()
            .collect(),
        side_effect: SideEffectClass::Read,
    };
    let decision = proxy.decide(&call);
    assert!(
        matches!(&decision, Decision::Deny { bound, .. } if *bound == SECONDARY_FILTER_BOUND),
        "{decision:?}",
    );
    let recorded = proxy.secondary_refusals();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].normalized, engine_saw,
        "the refusal carries the form the engine decided against, read off its decision",
    );
    assert_ne!(
        recorded[0].normalized, recorded[0].destination,
        "and for this host it differs from the destination as named, which is what makes a \
         normalization bypass visible: {:?}",
        recorded[0],
    );
}

#[test]
fn an_unreadable_operator_file_is_a_refusal_to_build_a_filter_and_not_a_silent_default() {
    // Test-rigor finding R6 (second adversarial review): `SecondaryConfigError`'s doc says "Every
    // variant is a refusal to build a filter, never a silent fallback", and `from_operator_config`
    // says a missing file "is NOT an error to be swallowed here". Only the Malformed arm was
    // asserted; replacing the Unreadable arm with `return Ok(Self::default_deny())` left both
    // suites green. That fallback would be the exact silent default the doc forbids, and it would
    // report `compiled_default` for a run the operator believed was reading their file.
    let directory =
        std::env::temp_dir().join(format!("warrantor-secondary-absent-{}", std::process::id()));
    let absent = directory.join("no-such-egress-filter.json");
    assert!(!absent.exists(), "control: the fixture path must not exist");
    let built = SecondaryFilter::from_operator_config(&absent);
    assert!(
        matches!(
            &built,
            Err(warrantor_warrant::egress::SecondaryConfigError::Unreadable { path, .. })
                if path.contains("no-such-egress-filter.json")
        ),
        "an absent operator file must refuse to build a filter and name the path: {built:?}",
    );
    // The error names the path the operator has to look at, in the sentence a CLI would print.
    let message = built.expect_err("refused").to_string();
    assert!(
        message.contains("could not be read") && message.contains("no-such-egress-filter.json"),
        "{message}",
    );
}

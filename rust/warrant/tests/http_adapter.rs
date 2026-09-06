//! L4-27: the governed HTTP call. The agent names a capability, never a destination; the
//! payload's data class is bounded by the catalog entry; every call's timing is recorded.

use serde_json::Value;
use warrantor_warrant::adapters::http::{
    tool_spec, ARG_BODY, ARG_CAPABILITY, ARG_DATA_CLASS, ARG_METHOD, ARG_PATH, TOOL,
};
use warrantor_warrant::egress::{capability_for, EgressBroker, DESTINATION_KEYS};
use warrantor_warrant::{SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn bounds(hosts: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: ["git", TOOL].into_iter().map(str::to_string).collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    }
}

/// The L4-23 static gate: no destination-shaped parameter exists on the published schema, and
/// the schema is closed, so a destination is unexpressible rather than refused.
#[test]
fn the_http_schema_has_no_destination_parameter_and_is_closed() {
    let broker = EgressBroker::for_bounds(&bounds(&["api.github.com"]));
    let spec = tool_spec(&broker);
    assert_eq!(spec.name, TOOL);
    let schema = spec.input_schema;
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].as_object().expect("properties");
    for key in DESTINATION_KEYS {
        assert!(!properties.contains_key(*key), "schema publishes destination key {key}");
    }
    let capabilities: Vec<&str> = schema["properties"][ARG_CAPABILITY]["enum"]
        .as_array()
        .expect("capability enum")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(capabilities, vec![capability_for("api.github.com").as_str()]);
    let required: Vec<&str> = schema["required"].as_array().expect("required").iter().filter_map(Value::as_str).collect();
    for key in [ARG_CAPABILITY, ARG_METHOD, ARG_PATH, ARG_DATA_CLASS] {
        assert!(required.contains(&key), "{key} must be required");
    }
    assert!(!required.contains(&ARG_BODY));
}

/// A warrant with no egress publishes a capability enum that is EMPTY, not absent: the tool is
/// still described, and nothing can be put in it.
#[test]
fn a_warrant_with_no_egress_publishes_an_empty_capability_enum() {
    let broker = EgressBroker::for_bounds(&bounds(&[]));
    let schema = tool_spec(&broker).input_schema;
    assert_eq!(schema["properties"][ARG_CAPABILITY]["enum"], Value::Array(vec![]));
}

use std::collections::BTreeMap;
use warrantor_warrant::adapters::http::capability_refusal;
use warrantor_warrant::egress::DenyReason;
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

fn call(pairs: &[(&str, &str)]) -> ToolCall {
    ToolCall { tool: TOOL.to_string(), arguments: args(pairs), side_effect: SideEffectClass::Write }
}

fn proxy(hosts: &[&str]) -> Proxy {
    Proxy::new(bounds(hosts), ProxyMode::Enforce, EffectRegistry::builtin())
}

/// A capability the catalog does not hold is refused under the egress bound, and the refusal
/// names the argument and the reason, so the report can count it.
#[test]
fn an_uncataloged_capability_is_refused_and_recorded() {
    let mut proxy = proxy(&["api.github.com"]);
    let decision = proxy.decide(&call(&[
        (ARG_CAPABILITY, &capability_for("evil.example.com")),
        (ARG_METHOD, "GET"),
        (ARG_PATH, "/"),
        (ARG_DATA_CLASS, "public"),
    ]));
    assert!(matches!(decision, Decision::Deny { bound: "egress_hosts", .. }), "{decision:?}");
    let refusal = proxy.egress_refusals();
    assert_eq!(refusal.len(), 1);
    assert_eq!(refusal[0].argument, ARG_CAPABILITY);
    assert_eq!(refusal[0].reason, DenyReason::NotInCatalog);
}

/// A raw address in the capability field -- a URL, a host, an IP -- is not a capability.
#[test]
fn a_raw_address_in_the_capability_field_is_refused_as_not_a_capability() {
    for raw in ["https://api.github.com/zen", "api.github.com", "203.0.113.9"] {
        let mut proxy = proxy(&["api.github.com"]);
        let decision = proxy.decide(&call(&[
            (ARG_CAPABILITY, raw),
            (ARG_METHOD, "GET"),
            (ARG_PATH, "/"),
            (ARG_DATA_CLASS, "public"),
        ]));
        assert!(matches!(decision, Decision::Deny { .. }), "{raw}: {decision:?}");
        assert_eq!(proxy.egress_refusals()[0].reason, DenyReason::NotACapability, "{raw}");
    }
}

/// The schema has no `url`; if a client sends one anyway, the existing destination scan still
/// decides it -- and the cataloged capability does not launder the extra host.
#[test]
fn a_smuggled_url_argument_is_still_decided_by_the_destination_scan() {
    let mut proxy = proxy(&["api.github.com"]);
    let decision = proxy.decide(&call(&[
        (ARG_CAPABILITY, &capability_for("api.github.com")),
        (ARG_METHOD, "GET"),
        (ARG_PATH, "/"),
        (ARG_DATA_CLASS, "public"),
        ("url", "https://evil.example.com/x"),
    ]));
    assert!(matches!(decision, Decision::Deny { bound: "egress_hosts", .. }), "{decision:?}");
}

/// A permitted capability stages: the agent gets a handle and nothing goes over the wire.
#[test]
fn a_cataloged_capability_stages_the_call() {
    let mut proxy = proxy(&["api.github.com"]);
    let decision = proxy.decide(&call(&[
        (ARG_CAPABILITY, &capability_for("api.github.com")),
        (ARG_METHOD, "GET"),
        (ARG_PATH, "/zen"),
        (ARG_DATA_CLASS, "public"),
    ]));
    assert!(matches!(decision, Decision::Stage { .. }), "{decision:?}");
    assert!(proxy.egress_refusals().is_empty());
}

#[test]
fn capability_refusal_ignores_other_tools() {
    let broker = EgressBroker::for_bounds(&bounds(&[]));
    let other = ToolCall { tool: "git".to_string(), arguments: args(&[]), side_effect: SideEffectClass::Read };
    assert!(capability_refusal(&other, &broker).is_none());
}

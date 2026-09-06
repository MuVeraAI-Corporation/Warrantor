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

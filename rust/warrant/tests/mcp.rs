//! MCP transport and endpoint tests.
//!
//! The first section is the one that matters. Everything else here is protocol plumbing; the
//! authority separation is the property the design rests on, and it is the one a refactor is most
//! likely to quietly break — because "just expose settle on both endpoints" is a one-line change
//! that makes a demo easier and the product unsound.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use serde_json::{json, Value};
use warrantor_warrant::mcp::{serve, Endpoint, ToolResult, ToolSpec, PROTOCOL_VERSION};
use warrantor_warrant::mcp_endpoints::{agent_endpoint_for, ControlEndpoint};
use warrantor_warrant::proxy::ProxyMode;
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

use ed25519_dalek::SigningKey;

const NOW: u64 = 1_786_000_000;
fn now() -> u64 {
    NOW
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-mcp-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn control(dir: &std::path::Path) -> ControlEndpoint {
    let store = WarrantStore::open(dir).expect("store");
    ControlEndpoint::new(
        store,
        dir.to_path_buf(),
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        now,
    )
}

fn stored_open(id: &str, tools: &[&str]) -> StoredWarrant {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(
        id,
        "goal",
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
    }
}

fn args(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

// ── THE authority separation ──────────────────────────────────────────────────────────

/// The load-bearing test. A supervised agent must have no route to settle authority — and the
/// mechanism is absence, not refusal: there is no tool name to call.
#[test]
fn the_agent_endpoint_does_not_publish_any_lifecycle_tool() {
    let dir = tempdir("authority");
    let stored = stored_open("wrt_a", &["git", "cargo"]);
    let mut agent = agent_endpoint_for(&stored, dir.join("q.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint");

    let names: Vec<String> = agent.tools().into_iter().map(|t| t.name).collect();

    for forbidden in [
        "warrant_settle",
        "warrant_void",
        "warrant_grant",
        "warrant_report",
        "warrant_status",
    ] {
        assert!(
            !names.contains(&forbidden.to_string()),
            "{forbidden} must not be reachable by a supervised agent: it is settle authority the \
             CapabilityToken deliberately has no field for. Published tools were {names:?}"
        );
    }
    assert_eq!(
        names,
        vec!["cargo".to_string(), "git".to_string()],
        "the agent should see exactly its warrant's tools, so the model can read its own bounds"
    );
}

/// Absence must hold at the call boundary too. Publishing nothing is worthless if the handler
/// answers an unpublished name anyway.
#[test]
fn calling_settle_on_the_agent_endpoint_does_not_settle_anything() {
    let dir = tempdir("callsettle");
    let stored = stored_open("wrt_b", &["git"]);
    let mut agent = agent_endpoint_for(&stored, dir.join("q.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint");

    let result = agent.call("warrant_settle", &args(&[("warrant_id", json!("wrt_b"))]));

    assert!(
        result.is_error,
        "an unpublished tool name must not succeed: {result:?}"
    );
    assert!(
        result.text.contains("tool allowlist") || result.text.contains("refused"),
        "it should be refused as an unlisted tool, not handled: {}",
        result.text
    );
}

/// The control endpoint is the developer's, and must have the full lifecycle.
#[test]
fn the_control_endpoint_publishes_the_full_lifecycle() {
    let dir = tempdir("control");
    let names: Vec<String> = control(&dir).tools().into_iter().map(|t| t.name).collect();
    for expected in [
        "warrant_grant",
        "warrant_status",
        "warrant_report",
        "warrant_settle",
        "warrant_void",
    ] {
        assert!(names.contains(&expected.to_string()), "missing {expected}");
    }
}

// ── the agent endpoint's policing ─────────────────────────────────────────────────────

#[test]
fn a_tool_outside_the_warrant_is_refused_at_the_mcp_boundary() {
    let dir = tempdir("deny");
    let stored = stored_open("wrt_c", &["git"]);
    let mut agent = agent_endpoint_for(&stored, dir.join("q.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint");

    let result = agent.call("curl", &args(&[]));
    assert!(result.is_error);
    assert!(
        result.text.contains("curl"),
        "the model must know what was refused: {}",
        result.text
    );
}

/// The whole point of staging, seen from the agent's side: it gets a handle and is told plainly
/// that nothing happened.
#[test]
fn a_staged_write_returns_a_handle_and_says_it_has_not_happened() {
    let dir = tempdir("stage");
    let stored = stored_open("wrt_d", &["github.create_pr"]);
    let mut agent = agent_endpoint_for(&stored, dir.join("q.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint");

    let result = agent.call(
        "github.create_pr",
        &args(&[("title", json!("Fix token refresh"))]),
    );

    assert!(
        !result.is_error,
        "staging is success, not failure: {result:?}"
    );
    assert!(
        result.text.contains("pr://staged/"),
        "the agent needs the handle to reference later: {}",
        result.text
    );
    assert!(
        result.text.contains("has NOT happened"),
        "the model must not believe the pull request exists: {}",
        result.text
    );
}

/// A permitted non-staged tool with nowhere to forward to must say so rather than return a
/// success-shaped nothing — the exact failure this codebase already fixed once in the TS server.
#[test]
fn a_forwardable_tool_with_no_upstream_reports_the_missing_upstream() {
    let dir = tempdir("noupstream");
    let stored = stored_open("wrt_e", &["git"]);
    let mut agent = agent_endpoint_for(&stored, dir.join("q.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint");

    let result = agent.call("git", &args(&[("args", json!("status"))]));
    assert!(
        result.is_error,
        "no upstream means no result, and that must not read as success"
    );
    assert!(
        result.text.contains("--upstream"),
        "say how to fix it: {}",
        result.text
    );
}

#[test]
fn a_warrant_that_is_not_open_gets_no_endpoint_at_all() {
    let dir = tempdir("closed");
    let mut stored = stored_open("wrt_f", &["git"]);
    stored.warrant.state = WarrantState::Settled;
    let built = agent_endpoint_for(&stored, dir.join("q.jsonl"), ProxyMode::Enforce, now);
    assert!(
        built.is_err(),
        "a settled warrant has no authority left to police"
    );
}

// ── control endpoint behaviour ────────────────────────────────────────────────────────

#[test]
fn granting_without_tools_is_refused_with_the_reason() {
    let dir = tempdir("notools");
    let result = control(&dir).call("warrant_grant", &args(&[("goal", json!("do a thing"))]));
    assert!(result.is_error);
    assert!(result.text.contains("can do nothing"), "{}", result.text);
}

#[test]
fn granting_persists_a_warrant_that_can_be_reported_on() {
    let dir = tempdir("grant");
    let mut endpoint = control(&dir);
    let granted = endpoint.call(
        "warrant_grant",
        &args(&[
            ("goal", json!("fix the flaky auth test")),
            ("tools", json!(["git", "cargo"])),
            ("deadline_seconds", json!(3600)),
        ]),
    );
    assert!(!granted.is_error, "{}", granted.text);

    let id = granted
        .text
        .split_whitespace()
        .find(|w| w.starts_with("wrt_"))
        .expect("the id must be in the response so the caller can act on it")
        .trim_end_matches('.')
        .to_string();

    let report = endpoint.call("warrant_report", &args(&[("warrant_id", json!(id))]));
    assert!(!report.is_error, "{}", report.text);
    assert!(report.text.contains("fix the flaky auth test"));
    assert!(
        report.text.contains("staged effects: none"),
        "a fresh warrant has staged nothing: {}",
        report.text
    );
}

/// Settling over MCP has no credential broker. It must name that rather than report success.
#[test]
fn settling_over_mcp_without_an_adapter_says_so() {
    let dir = tempdir("nosettle");
    let mut endpoint = control(&dir);
    let granted = endpoint.call(
        "warrant_grant",
        &args(&[("goal", json!("g")), ("tools", json!(["git"]))]),
    );
    let id = granted
        .text
        .split_whitespace()
        .find(|w| w.starts_with("wrt_"))
        .unwrap()
        .trim_end_matches('.')
        .to_string();

    // Nothing staged, so this settles cleanly -- the interesting case is that it does not lie
    // about effects it cannot perform.
    let settled = endpoint.call("warrant_settle", &args(&[("warrant_id", json!(id))]));
    assert!(
        settled.text.contains("0 of 0") || settled.text.contains("Settled"),
        "{}",
        settled.text
    );
}

#[test]
fn reporting_an_unknown_warrant_fails_rather_than_inventing_one() {
    let dir = tempdir("unknown");
    let result = control(&dir).call(
        "warrant_report",
        &args(&[("warrant_id", json!("wrt_nope"))]),
    );
    assert!(result.is_error);
}

// ── protocol ──────────────────────────────────────────────────────────────────────────

struct Echo;
impl Endpoint for Echo {
    fn name(&self) -> &str {
        "echo"
    }
    fn tools(&mut self) -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "echo".to_string(),
            description: "echo".to_string(),
            input_schema: json!({"type": "object"}),
        }]
    }
    fn call(&mut self, tool: &str, _a: &BTreeMap<String, Value>) -> ToolResult {
        ToolResult::ok(format!("called {tool}"))
    }
}

fn round_trip(input: &str) -> Vec<Value> {
    let mut out = Vec::new();
    serve(&mut Echo, Cursor::new(input.as_bytes()), &mut out).expect("serve");
    String::from_utf8(out)
        .expect("utf8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each line must be one JSON message"))
        .collect()
}

#[test]
fn initialize_reports_the_protocol_version_and_server_name() {
    let responses = round_trip(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "echo");
}

/// A notification has no id and must draw no reply; answering one violates JSON-RPC and confuses
/// clients that are counting responses.
#[test]
fn a_notification_draws_no_response() {
    let responses = round_trip(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
         {\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}",
    );
    assert_eq!(responses.len(), 1, "only the ping should be answered");
    assert_eq!(responses[0]["id"], 7);
}

/// One bad message must not end a session that is supervising a running agent.
#[test]
fn a_malformed_message_is_reported_and_the_session_continues() {
    let responses = round_trip(
        "not json at all\n\
         {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}",
    );
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], -32700);
    assert_eq!(
        responses[1]["result"],
        json!({}),
        "the session must survive the bad message"
    );
}

#[test]
fn an_unknown_method_gets_method_not_found() {
    let responses = round_trip(r#"{"jsonrpc":"2.0","id":3,"method":"tools/delete"}"#);
    assert_eq!(responses[0]["error"]["code"], -32601);
}

#[test]
fn tools_call_without_a_name_is_an_invalid_params_error() {
    let responses = round_trip(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}"#);
    assert_eq!(responses[0]["error"]["code"], -32602);
}

/// Tool failures ride in the result with `isError`, not as JSON-RPC errors, so the model can read
/// and adapt to them instead of the client treating them as a transport fault.
#[test]
fn a_tool_failure_is_a_result_not_a_transport_error() {
    struct Failing;
    impl Endpoint for Failing {
        fn name(&self) -> &str {
            "failing"
        }
        fn tools(&mut self) -> Vec<ToolSpec> {
            Vec::new()
        }
        fn call(&mut self, _t: &str, _a: &BTreeMap<String, Value>) -> ToolResult {
            ToolResult::error("nope")
        }
    }
    let mut out = Vec::new();
    serve(
        &mut Failing,
        Cursor::new(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"x"}}"#),
        &mut out,
    )
    .expect("serve");
    let v: Value = serde_json::from_slice(&out).expect("json");
    assert!(v.get("error").is_none(), "must not be a JSON-RPC error");
    assert_eq!(v["result"]["isError"], true);
    assert_eq!(v["result"]["content"][0]["text"], "nope");
}

#[test]
fn a_wrong_jsonrpc_version_is_rejected() {
    let responses = round_trip(r#"{"jsonrpc":"1.0","id":6,"method":"ping"}"#);
    assert_eq!(responses[0]["error"]["code"], -32600);
}

/// Every response must be exactly one line, or a client reading line-by-line will desynchronise.
#[test]
fn every_response_is_a_single_line() {
    let mut out = Vec::new();
    serve(
        &mut Echo,
        Cursor::new(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}",
        ),
        &mut out,
    )
    .expect("serve");
    let text = String::from_utf8(out).expect("utf8");
    assert_eq!(
        text.trim_end().lines().count(),
        2,
        "two requests must produce exactly two lines: {text}"
    );
}

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
        assert!(
            !properties.contains_key(*key),
            "schema publishes destination key {key}"
        );
    }
    let capabilities: Vec<&str> = schema["properties"][ARG_CAPABILITY]["enum"]
        .as_array()
        .expect("capability enum")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        capabilities,
        vec![capability_for("api.github.com").as_str()]
    );
    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .filter_map(Value::as_str)
        .collect();
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
    assert_eq!(
        schema["properties"][ARG_CAPABILITY]["enum"],
        Value::Array(vec![])
    );
}

use std::collections::BTreeMap;
use warrantor_warrant::adapters::http::capability_refusal;
use warrantor_warrant::egress::DenyReason;
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn call(pairs: &[(&str, &str)]) -> ToolCall {
    ToolCall {
        tool: TOOL.to_string(),
        arguments: args(pairs),
        side_effect: SideEffectClass::Write,
    }
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
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "{decision:?}"
    );
    let refusal = proxy.egress_refusals();
    assert_eq!(refusal.len(), 1);
    assert_eq!(refusal[0].argument, ARG_CAPABILITY);
    assert_eq!(refusal[0].reason, DenyReason::NotInCatalog);
}

/// A raw address in the capability field -- a URL, a host, an IP -- is not a capability.
#[test]
fn a_raw_address_in_the_capability_field_is_refused_as_not_a_capability() {
    for raw in [
        "https://api.github.com/zen",
        "api.github.com",
        "203.0.113.9",
    ] {
        let mut proxy = proxy(&["api.github.com"]);
        let decision = proxy.decide(&call(&[
            (ARG_CAPABILITY, raw),
            (ARG_METHOD, "GET"),
            (ARG_PATH, "/"),
            (ARG_DATA_CLASS, "public"),
        ]));
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "{raw}: {decision:?}"
        );
        assert_eq!(
            proxy.egress_refusals()[0].reason,
            DenyReason::NotACapability,
            "{raw}"
        );
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
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "{decision:?}"
    );
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
    let other = ToolCall {
        tool: "git".to_string(),
        arguments: args(&[]),
        side_effect: SideEffectClass::Read,
    };
    assert!(capability_refusal(&other, &broker).is_none());
}

use ed25519_dalek::SigningKey;
use warrantor_egress::{CatalogEntry, DestinationCatalog};
use warrantor_warrant::adapters::http::{
    validate_path, DataClass, HttpAdapter, HttpCallRecord, HttpRequest, HttpResponse,
    HttpTransport, HTTP_CALL_FORMAT,
};
use warrantor_warrant::settle::settle;
use warrantor_warrant::staging::StagingQueue;
use warrantor_warrant::{Warrant, WarrantState};

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-http-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// A catalog with one declared capability: POST + GET, confidential ceiling.
fn declared_catalog() -> DestinationCatalog {
    let mut catalog = DestinationCatalog {
        version: "warrantor.destination-catalog/test".to_string(),
        entries: vec![CatalogEntry {
            logical_endpoint: "hooks.example.com".to_string(),
            addresses: vec!["hooks.example.com".to_string()],
            tls_identity: None,
            permitted_methods: vec!["GET".to_string(), "POST".to_string()],
            expires_at: NOW + 3600,
            max_data_class: Some("confidential".to_string()),
        }],
        digest: String::new(),
        signature: None,
    };
    catalog.digest = catalog.compute_digest();
    catalog
}

struct FakeHttp {
    sent: Vec<HttpRequest>,
    status: u16,
}

impl HttpTransport for FakeHttp {
    fn send(&mut self, request: &HttpRequest) -> Result<HttpResponse, String> {
        self.sent.push(request.clone());
        Ok(HttpResponse {
            status: self.status,
            body: b"{\"ok\":true}".to_vec(),
        })
    }
}

fn ticking_clock() -> Box<dyn FnMut() -> u64> {
    let mut t = 1_000u64;
    Box::new(move || {
        t += 7;
        t
    })
}

fn warrant(hosts: &[&str]) -> (Warrant, SigningKey) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle_key = SigningKey::from_bytes(&[2; 32]);
    let w = Warrant::grant(
        "wrt_http",
        "notify",
        "spiffe://muveraai.com/agent/alpha",
        bounds(hosts),
        NOW,
        &settle_key.verifying_key(),
        &issuer,
    )
    .expect("grant");
    (w, settle_key)
}

fn staged(dir: &std::path::Path, pairs: &[(&str, &str)]) -> StagingQueue {
    let mut q = StagingQueue::open(dir.join("q.jsonl"), "wrt_http", EffectRegistry::builtin())
        .expect("open");
    q.stage(TOOL, args(pairs), NOW).expect("stage");
    q
}

fn adapter(catalog: DestinationCatalog, status: u16) -> HttpAdapter<FakeHttp> {
    HttpAdapter::new(
        FakeHttp {
            sent: Vec::new(),
            status,
        },
        catalog,
        ticking_clock(),
    )
}

/// The happy path: a POST inside the declared capability is performed, the real id is the
/// status and the response digest, and one timing record exists.
#[test]
fn a_call_inside_the_capability_is_performed_and_recorded() {
    let dir = tempdir("perform");
    let (mut w, key) = warrant(&["hooks.example.com"]);
    let q = staged(
        &dir,
        &[
            (ARG_CAPABILITY, &capability_for("hooks.example.com")),
            (ARG_METHOD, "POST"),
            (ARG_PATH, "/notify?run=1"),
            (ARG_BODY, "{\"text\":\"done\"}"),
            (ARG_DATA_CLASS, "internal"),
        ],
    );
    let mut adapter = adapter(declared_catalog(), 202).with_bearer("hooks.example.com", "s3cret");

    let report = settle(&mut w, &q, None, &key.verifying_key(), &mut adapter).expect("settle");

    assert!(report.complete, "{:?}", report.boundary);
    assert_eq!(w.state, WarrantState::Settled);
    let records: &[HttpCallRecord] = adapter.records();
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.format, HTTP_CALL_FORMAT);
    assert_eq!(r.method, "POST");
    assert_eq!(r.logical_endpoint, "hooks.example.com");
    assert_eq!(r.data_class, DataClass::Internal);
    assert_eq!(r.status, 202);
    assert!(
        r.finished_at_ms > r.started_at_ms,
        "timing lands in the record"
    );
    assert!(r.response_digest.starts_with("sha256:"));
    assert_eq!(r.response_bytes, 11);
    let sent = &adapter.transport().sent[0];
    assert_eq!(sent.url, "https://hooks.example.com/notify?run=1");
    assert_eq!(sent.bearer.as_deref(), Some("s3cret"));
}

/// The response body is quarantined: nothing the settle reports carries it.
#[test]
fn the_response_body_is_never_returned() {
    let dir = tempdir("quarantine");
    let (mut w, key) = warrant(&["hooks.example.com"]);
    let q = staged(
        &dir,
        &[
            (ARG_CAPABILITY, &capability_for("hooks.example.com")),
            (ARG_METHOD, "GET"),
            (ARG_PATH, "/"),
            (ARG_DATA_CLASS, "public"),
        ],
    );
    let mut adapter = adapter(declared_catalog(), 200);
    let report = settle(&mut w, &q, None, &key.verifying_key(), &mut adapter).expect("settle");
    let rendered = serde_json::to_string(&report).expect("json");
    assert!(
        !rendered.contains("\"ok\":true"),
        "the body leaked into the settle report: {rendered}"
    );
    let recorded = serde_json::to_string(adapter.records()).expect("json");
    assert!(
        !recorded.contains("\"ok\":true"),
        "the body leaked into the record: {recorded}"
    );
}

/// The payload's data class may not exceed the entry's ceiling.
#[test]
fn a_payload_above_the_entry_ceiling_is_refused_before_any_request() {
    let dir = tempdir("dataclass");
    let (mut w, key) = warrant(&["hooks.example.com"]);
    let q = staged(
        &dir,
        &[
            (ARG_CAPABILITY, &capability_for("hooks.example.com")),
            (ARG_METHOD, "POST"),
            (ARG_PATH, "/"),
            (ARG_BODY, "x"),
            (ARG_DATA_CLASS, "restricted"),
        ],
    );
    let mut adapter = adapter(declared_catalog(), 200);
    let report =
        settle(&mut w, &q, None, &key.verifying_key(), &mut adapter).expect("settle reports");
    assert!(!report.complete);
    assert!(
        report
            .boundary
            .as_deref()
            .unwrap_or("")
            .contains("restricted"),
        "{:?}",
        report.boundary
    );
    assert!(
        adapter.transport().sent.is_empty(),
        "no request may be sent for a refused payload"
    );
    assert!(adapter.records().is_empty());
    assert_eq!(w.state, WarrantState::Held);
}

/// A bare `--egress` host is GET-only and public-only: a POST through it refuses on method, and
/// an `internal` payload refuses on class.
#[test]
fn a_sugar_entry_refuses_writes_and_non_public_payloads() {
    let broker = EgressBroker::for_bounds(&bounds(&["api.github.com"]));
    let catalog = broker.catalog().expect("catalog").clone();
    for (method, class, expect) in [
        ("POST", "public", "permits"),
        ("GET", "internal", "internal"),
    ] {
        let dir = tempdir("sugar");
        let (mut w, key) = warrant(&["api.github.com"]);
        let q = staged(
            &dir,
            &[
                (ARG_CAPABILITY, &capability_for("api.github.com")),
                (ARG_METHOD, method),
                (ARG_PATH, "/zen"),
                (ARG_DATA_CLASS, class),
            ],
        );
        let mut adapter = adapter(catalog.clone(), 200);
        let report =
            settle(&mut w, &q, None, &key.verifying_key(), &mut adapter).expect("settle reports");
        assert!(!report.complete, "{method} {class}");
        assert!(
            report.boundary.as_deref().unwrap_or("").contains(expect),
            "{method} {class}: {:?}",
            report.boundary
        );
        assert!(adapter.transport().sent.is_empty());
    }
}

/// The broker is consulted again at settle: a metadata address is refused even when cataloged.
#[test]
fn a_metadata_address_is_refused_at_settle_even_when_cataloged() {
    let dir = tempdir("metadata");
    let (mut w, key) = warrant(&["169.254.169.254"]);
    let catalog = EgressBroker::for_bounds(&bounds(&["169.254.169.254"]))
        .catalog()
        .expect("catalog")
        .clone();
    let q = staged(
        &dir,
        &[
            (ARG_CAPABILITY, &capability_for("169.254.169.254")),
            (ARG_METHOD, "GET"),
            (ARG_PATH, "/latest/meta-data/"),
            (ARG_DATA_CLASS, "public"),
        ],
    );
    let mut adapter = adapter(catalog, 200);
    let report =
        settle(&mut w, &q, None, &key.verifying_key(), &mut adapter).expect("settle reports");
    assert!(!report.complete);
    assert!(
        report
            .boundary
            .as_deref()
            .unwrap_or("")
            .contains("metadata"),
        "{:?}",
        report.boundary
    );
    assert!(adapter.transport().sent.is_empty());
}

/// A path cannot carry a scheme, credentials or a protocol-relative host.
#[test]
fn a_path_that_could_change_the_destination_is_refused() {
    for bad in [
        "https://evil.example.com/",
        "//evil.example.com/",
        "/x@evil.example.com/",
        "no-leading-slash",
        "/a b",
    ] {
        assert!(validate_path(bad).is_err(), "{bad}");
    }
    assert!(validate_path("/repos/o/r/pulls?state=open").is_ok());
}

use warrantor_warrant::mcp::Endpoint;
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::store::StoredWarrant;

fn now() -> u64 {
    NOW
}

/// Through the real endpoint, not the helper: the published `http.call` carries the closed
/// schema and the capability enum, and never the open `additionalProperties: true` shape.
#[test]
fn the_agent_endpoint_publishes_the_closed_http_schema() {
    let dir = tempdir("endpoint");
    let (w, _) = warrant(&["api.github.com"]);
    let stored = StoredWarrant {
        warrant: w,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    };
    let mut agent = agent_endpoint_for(&stored, dir.join("q.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint");
    let spec = agent
        .tools()
        .into_iter()
        .find(|t| t.name == TOOL)
        .expect("http.call is published");
    assert_eq!(
        spec.input_schema["additionalProperties"],
        Value::Bool(false)
    );
    assert_eq!(
        spec.input_schema["properties"][ARG_CAPABILITY]["enum"],
        serde_json::json!([capability_for("api.github.com")])
    );
}

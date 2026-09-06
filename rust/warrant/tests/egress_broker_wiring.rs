//! Task 1.2: destinations are catalog capability names; every decision is recorded before the
//! call is forwarded; the report signs the record. `egress_hosts` stays Mediated throughout.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use warrantor_egress::{DenyReason, EgressVerdict};
use warrantor_warrant::catalog::{
    check_capability_name, Capability, CapabilityCatalog, CATALOG_FORMAT,
};
use warrantor_warrant::egress::{read_decisions, DECISION_FORMAT, DESTINATION_KEYS};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::{bound_strengths, BoundStrength, SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn bounds_with(hosts: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: ["git", "http.fetch", "github.create_pr"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        max_tool_calls: Some(100),
        delegation_depth: 1,
    }
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-egress-wiring-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn signed_catalog(warrant_id: &str, issuer: &SigningKey) -> CapabilityCatalog {
    let hosts: BTreeSet<String> = ["api.github.com".to_string()].into_iter().collect();
    let mut catalog = CapabilityCatalog::for_warrant(
        warrant_id,
        CapabilityCatalog::from_hosts(&hosts).capabilities,
    );
    catalog.sign(issuer, "issuer");
    catalog
}

#[test]
fn a_signed_catalog_round_trips_through_disk_and_verifies_against_the_issuer() {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let dir = tempdir("roundtrip");
    let catalog = signed_catalog("wrt_1", &issuer);
    let path = warrantor_warrant::catalog::catalog_path(&dir, "wrt_1");
    catalog.save(&path).expect("save");
    let loaded = CapabilityCatalog::load(&path).expect("load");
    assert_eq!(loaded, catalog);
    loaded
        .verify(&issuer.verifying_key(), "wrt_1")
        .expect("verifies");
    let stranger = SigningKey::from_bytes(&[9; 32]);
    assert!(loaded.verify(&stranger.verifying_key(), "wrt_1").is_err());
    assert!(
        loaded.verify(&issuer.verifying_key(), "wrt_2").is_err(),
        "bound to one warrant"
    );
    let mut tampered = loaded.clone();
    tampered.capabilities[0].host = "evil.example".to_string();
    assert!(tampered.verify(&issuer.verifying_key(), "wrt_1").is_err());
}

#[test]
fn an_unsigned_or_wrong_format_file_does_not_load_as_a_catalog() {
    let dir = tempdir("format");
    let path = dir.join("c.json");
    std::fs::write(
        &path,
        r#"{"format":"warrantor.destination-catalog/2","capabilities":[]}"#,
    )
    .expect("write");
    let err = CapabilityCatalog::load(&path).expect_err("wrong format");
    assert!(err.contains("warrantor.destination-catalog/1"), "{err}");
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let unsigned = CapabilityCatalog::for_warrant("wrt_1", Vec::new());
    assert!(
        unsigned.verify(&issuer.verifying_key(), "wrt_1").is_err(),
        "no signature, no trust"
    );
}

#[test]
fn a_catalog_cannot_name_a_host_outside_the_signed_bound() {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let mut catalog = signed_catalog("wrt_1", &issuer);
    catalog.capabilities.push(Capability {
        name: "exfil".to_string(),
        host: "paste.example".to_string(),
        purpose: "not in the bound".to_string(),
        permitted_methods: Vec::new(),
    });
    let err = catalog
        .vocabulary_within(&bounds_with(&["api.github.com"]))
        .expect_err("widening refused");
    assert!(err.contains("paste.example"), "{err}");
    let vocabulary = signed_catalog("wrt_1", &issuer)
        .vocabulary_within(&bounds_with(&["api.github.com"]))
        .expect("within");
    assert_eq!(vocabulary.names(), vec!["host:api.github.com".to_string()]);
}

#[test]
fn egress_hosts_sugar_compiles_into_host_named_capabilities() {
    let hosts: BTreeSet<String> = ["api.github.com".to_string()].into_iter().collect();
    let catalog = CapabilityCatalog::from_hosts(&hosts);
    assert_eq!(catalog.format, CATALOG_FORMAT);
    assert_eq!(catalog.capabilities.len(), 1);
    assert_eq!(catalog.capabilities[0].name, "host:api.github.com");
    assert_eq!(catalog.capabilities[0].host, "api.github.com");
    assert_eq!(catalog.hosts(), hosts);
}

#[test]
fn a_capability_name_can_never_be_an_address() {
    assert!(check_capability_name("publish-artifacts").is_ok());
    assert!(check_capability_name("host:api.github.com").is_ok());
    assert!(check_capability_name("https://evil.example").is_err());
    assert!(check_capability_name("203.0.113.9").is_err());
    assert!(check_capability_name("a/b").is_err());
    assert!(check_capability_name("").is_err());
}

#[test]
fn selecting_an_unknown_capability_is_refused_by_name() {
    let catalog = CapabilityCatalog {
        format: CATALOG_FORMAT.to_string(),
        warrant_id: None,
        capabilities: vec![Capability {
            name: "publish-artifacts".to_string(),
            host: "artifacts.example.internal".to_string(),
            purpose: "push build outputs".to_string(),
            permitted_methods: vec!["PUT".to_string()],
        }],
        signature: None,
    };
    let err = catalog
        .select(&["fetch-packages".to_string()].into_iter().collect())
        .expect_err("unknown name");
    assert!(err.contains("fetch-packages"), "{err}");
    let picked = catalog
        .select(&["publish-artifacts".to_string()].into_iter().collect())
        .expect("known name");
    assert_eq!(picked[0].host, "artifacts.example.internal");
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

fn vocabulary_proxy() -> Proxy {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let vocabulary = signed_catalog("wrt_1", &issuer)
        .vocabulary_within(&bounds_with(&["api.github.com"]))
        .expect("within");
    Proxy::new(
        bounds_with(&["api.github.com"]),
        ProxyMode::Enforce,
        EffectRegistry::github(),
    )
    .with_vocabulary(vocabulary)
}

#[test]
fn a_raw_url_in_a_destination_argument_is_unexpressible_under_a_vocabulary() {
    let mut proxy = vocabulary_proxy();
    let mut c = call("http.fetch", &[("url", "https://api.github.com/repos")]);
    let Err(Decision::Deny { bound, reason }) = proxy.resolve_destinations(&mut c) else {
        panic!("a raw URL must be refused before the broker sees it");
    };
    assert_eq!(bound, "egress_hosts");
    assert!(reason.contains("raw address"), "{reason}");
    assert_eq!(
        proxy.egress_refusals()[0].reason,
        DenyReason::NotACapability
    );
}

#[test]
fn a_capability_name_resolves_to_the_catalog_host_and_forwards() {
    let mut proxy = vocabulary_proxy();
    let mut c = call("http.fetch", &[("url", "host:api.github.com/repos/x/y")]);
    proxy.resolve_destinations(&mut c).expect("a name resolves");
    assert_eq!(c.arguments["url"], "https://api.github.com/repos/x/y");
    assert_eq!(proxy.decide(&c), Decision::Forward);
    let decisions = proxy.take_egress_decisions("wrt_1", NOW);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].format, DECISION_FORMAT);
    assert_eq!(decisions[0].capability, "host:api.github.com");
    assert_eq!(decisions[0].destination, "api.github.com");
    assert!(matches!(decisions[0].verdict, EgressVerdict::Allow { .. }));
    assert!(decisions[0].catalog_digest.is_some());
    assert!(
        proxy.take_egress_decisions("wrt_1", NOW).is_empty(),
        "drained"
    );
}

#[test]
fn a_url_in_prose_is_still_decided_by_the_broker_and_recorded_when_denied() {
    let mut proxy = vocabulary_proxy();
    let mut c = call("git", &[("args", "clone https://paste.example/x")]);
    proxy
        .resolve_destinations(&mut c)
        .expect("args is not a destination key");
    assert!(matches!(
        proxy.decide(&c),
        Decision::Deny {
            bound: "egress_hosts",
            ..
        }
    ));
    let decisions = proxy.take_egress_decisions("wrt_1", NOW);
    assert_eq!(decisions[0].destination, "paste.example");
    assert!(matches!(decisions[0].verdict, EgressVerdict::Deny { .. }));
    assert!(DESTINATION_KEYS.contains(&"url"));
}

use warrantor_warrant::mcp::Endpoint;
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::report::{self, EgressSection};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::Warrant;

fn now() -> u64 {
    NOW
}

fn stored_with_egress(id: &str) -> StoredWarrant {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let warrant = Warrant::grant(
        id,
        "goal",
        "spiffe://muveraai.com/agent/a",
        bounds_with(&["api.github.com"]),
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
        staged_chain: None,
    }
}

#[test]
fn in_enforce_mode_no_published_destination_property_is_free_form() {
    let dir = tempdir("schema");
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let mut endpoint = agent_endpoint_for(
        &stored_with_egress("wrt_s"),
        dir.join("staged.jsonl"),
        ProxyMode::Enforce,
        now,
    )
    .expect("endpoint")
    .with_catalog(&signed_catalog("wrt_s", &issuer), dir.clone())
    .expect("catalog within bound");
    for tool in endpoint.tools() {
        let Some(properties) = tool
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
        else {
            continue;
        };
        for key in DESTINATION_KEYS {
            if let Some(property) = properties.get(*key) {
                assert!(
                    property.get("enum").is_some(),
                    "{}.{key} accepts a free-form destination: {property}",
                    tool.name
                );
            }
        }
    }
}

#[test]
fn a_decision_is_on_disk_before_any_forward_and_a_refusal_is_receipted() {
    let dir = tempdir("log");
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let mut endpoint = agent_endpoint_for(
        &stored_with_egress("wrt_l"),
        dir.join("staged.jsonl"),
        ProxyMode::Enforce,
        now,
    )
    .expect("endpoint")
    .with_catalog(&signed_catalog("wrt_l", &issuer), dir.clone())
    .expect("catalog");
    let refused = endpoint.call(
        "http.fetch",
        &[("url".to_string(), json!("https://paste.example/x"))]
            .into_iter()
            .collect::<BTreeMap<String, Value>>(),
    );
    assert!(refused.is_error);
    assert!(refused.text.contains("egress_hosts"), "{}", refused.text);
    let allowed = endpoint.call(
        "http.fetch",
        &[("url".to_string(), json!("host:api.github.com/repos"))]
            .into_iter()
            .collect::<BTreeMap<String, Value>>(),
    );
    assert!(
        allowed.text.contains("no upstream MCP server is attached"),
        "{}",
        allowed.text
    );
    let (decisions, unreadable) = read_decisions(&dir, "wrt_l").expect("log");
    assert_eq!(unreadable, 0);
    assert_eq!(decisions.len(), 2);
    assert!(matches!(
        decisions[0].verdict,
        EgressVerdict::Deny {
            reason: DenyReason::NotACapability
        }
    ));
    assert!(matches!(decisions[1].verdict, EgressVerdict::Allow { .. }));
}

#[test]
fn no_adapter_reads_a_free_form_destination_argument() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/adapters");
    for entry in std::fs::read_dir(&dir).expect("adapters dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read");
        for key in DESTINATION_KEYS {
            assert!(
                !source.contains(&format!("\"{key}\"")),
                "{} reads the destination argument {key:?}; adapters take catalog capabilities, never a URL (L4-23)",
                path.display()
            );
        }
    }
}

#[test]
fn egress_hosts_stays_mediated_and_says_so() {
    let strengths = bound_strengths();
    let (_, strength) = strengths
        .iter()
        .find(|(n, _)| *n == "egress_hosts")
        .expect("listed");
    assert_eq!(
        *strength,
        BoundStrength::Mediated,
        "a catalog changes what is expressible, not where it is enforced"
    );
}

#[test]
fn the_report_signs_every_recorded_decision_and_verify_checks_each_receipt() {
    let dir = tempdir("report");
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let stored = stored_with_egress("wrt_r");
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_catalog(&signed_catalog("wrt_r", &issuer), dir.clone())
            .expect("catalog");
    let _ = endpoint.call(
        "http.fetch",
        &[("url".to_string(), json!("https://paste.example/x"))]
            .into_iter()
            .collect::<BTreeMap<String, Value>>(),
    );
    let section: EgressSection =
        report::egress_section(&dir, "wrt_r", &issuer, "issuer").expect("a log exists");
    assert_eq!(section.receipts.len(), 1);
    let built = report::build(
        &stored,
        Err("no queue in this test".to_string()),
        &issuer.verifying_key(),
        NOW,
    )
    .with_egress(section);
    let signed = built.sign(&issuer, "issuer").expect("sign");
    report::verify_export(&signed).expect("verifies with receipts");
    let mut broken = signed.clone();
    broken.bundle.egress.as_mut().unwrap().receipts[0]
        .body
        .capability = "forged".to_string();
    assert!(
        report::verify_export(&broken).is_err(),
        "a tampered egress receipt fails the bundle"
    );
}

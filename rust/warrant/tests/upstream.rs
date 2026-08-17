//! Forwarding: the half of the proxy that did not exist for the first eight releases.
//!
//! Every test here spawns a **real child process** speaking real MCP over real pipes. That is
//! deliberate and it is what the previous absence cost: the `Decision::Forward` arm was covered by
//! a test asserting it returned an error, and the error it returned told the operator to pass a
//! flag the binary did not have. A stub in memory would have kept that green forever.
//!
//! The upstream is `warrantor selftest-upstream` — this same binary, in the mode that publishes
//! two harmless tools — so the chain under test is the one an operator actually gets, and no
//! third-party server has to be installed to run `cargo test`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use warrantor_warrant::mcp::Endpoint;
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::proxy::ProxyMode;
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::upstream::{UpstreamSet, UpstreamSpec};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
fn now() -> u64 {
    NOW
}

/// The binary under test, as an upstream spec. Built directly rather than parsed, because a build
/// directory is allowed to contain spaces and `UpstreamSpec::parse` splits on whitespace.
fn selftest_spec(name: &str) -> UpstreamSpec {
    UpstreamSpec {
        name: name.to_string(),
        program: env!("CARGO_BIN_EXE_warrantor").to_string(),
        args: vec!["selftest-upstream".to_string()],
    }
}

/// This binary's *control* endpoint — the one that publishes lifecycle tools, and the one no agent
/// may ever be pointed at.
fn control_spec(name: &str, root: &std::path::Path) -> UpstreamSpec {
    UpstreamSpec {
        name: name.to_string(),
        program: env!("CARGO_BIN_EXE_warrantor").to_string(),
        // The command comes first: this binary's parser reads argv[1] as the verb, so
        // `warrantor --root X mcp` prints usage and exits, which reaches this client as a server
        // that closed rather than as the lifecycle refusal under test.
        args: vec![
            "mcp".to_string(),
            "--root".to_string(),
            root.to_string_lossy().to_string(),
        ],
    }
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-upstream-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
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
        "forward a call",
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
        staged_chain: None,
    }
}

fn args(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn timeout() -> Duration {
    // Generous, because this spawns and links a debug binary on a loaded CI runner, and a flaky
    // timeout in a transport test teaches people to re-run rather than to read.
    Duration::from_secs(30)
}

// ── the thing that did not work ───────────────────────────────────────────────────────

#[test]
fn a_permitted_call_reaches_the_upstream_and_its_answer_comes_back() {
    let dir = tempdir("forward");
    let stored = stored_open("w-forward", &["selftest.echo"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_upstreams(
                UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
            );

    let result = endpoint.call("selftest.echo", &args(&[("text", json!("round trip"))]));
    assert!(
        !result.is_error,
        "a permitted call must not come back as an error: {}",
        result.text
    );
    assert_eq!(result.text, "round trip");
    assert_eq!(endpoint.forwarding_counts(), Some((1, 0)));
}

#[test]
fn with_no_upstream_attached_the_refusal_names_a_flag_that_exists() {
    // The regression this whole file exists for. For eight releases this arm told the operator to
    // pass `--upstream`, and `--upstream` was not a flag. The message may change; what may not is
    // that it names a remedy the binary can actually perform.
    let dir = tempdir("nowhere");
    let stored = stored_open("w-nowhere", &["selftest.echo"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint");

    let result = endpoint.call("selftest.echo", &args(&[("text", json!("hello"))]));
    assert!(result.is_error);
    assert!(
        result.text.contains("--upstream"),
        "the refusal should name the remedy: {}",
        result.text
    );
    assert_eq!(
        endpoint.forwarding_counts(),
        None,
        "a session with nothing attached forwarded nothing BECAUSE there was nowhere to forward \
         to, which is not the same fact as an attached session that forwarded zero calls"
    );
}

// ── what is published, and what is structurally absent ────────────────────────────────

#[test]
fn the_real_schema_is_published_not_an_open_object() {
    // A model that cannot see the real schema composes calls the upstream rejects, and cannot tell
    // a schema mistake from a policy refusal. Before forwarding, every tool was published with
    // `additionalProperties: true` and no properties at all.
    let dir = tempdir("schema");
    let stored = stored_open("w-schema", &["selftest.echo"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_upstreams(
                UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
            );

    let tools = endpoint.tools();
    let echo = tools
        .iter()
        .find(|t| t.name == "selftest.echo")
        .expect("echo is published");
    assert_eq!(
        echo.input_schema
            .pointer("/properties/text/type")
            .and_then(Value::as_str),
        Some("string"),
        "the upstream's own schema must survive the proxy: {}",
        echo.input_schema
    );
}

#[test]
fn a_tool_the_warrant_did_not_grant_is_absent_rather_than_denied() {
    // The same structural decision the control endpoint's absent lifecycle tools rest on. The
    // upstream publishes `now`; this warrant does not grant it; under Enforce it must not appear
    // in `tools/list` at all, because a name that is not published cannot be called and a refusal
    // that must be configured can be misconfigured.
    let dir = tempdir("absent");
    let stored = stored_open("w-absent", &["selftest.echo"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_upstreams(
                UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
            );

    let names: Vec<String> = endpoint.tools().into_iter().map(|t| t.name).collect();
    assert!(names.contains(&"selftest.echo".to_string()), "{names:?}");
    assert!(
        !names.contains(&"selftest.now".to_string()),
        "an ungranted tool must not be published: {names:?}"
    );
}

#[test]
fn observe_mode_publishes_everything_because_that_is_what_observing_is_for() {
    // A warrant is authored from what an agent actually reaches for. A tool the agent cannot see
    // is a tool it cannot be observed reaching for, so the enforce-mode absence above would make
    // observe mode unable to do its one job.
    let dir = tempdir("observe");
    // A warrant with no tools is refused at grant time, so this one names a tool no attached
    // server publishes — which is the honest shape of an authoring run anyway.
    let stored = stored_open("w-observe", &["placeholder.tool"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Observe, now)
            .expect("endpoint")
            .with_upstreams(
                UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
            );

    let names: Vec<String> = endpoint.tools().into_iter().map(|t| t.name).collect();
    assert!(names.contains(&"selftest.echo".to_string()), "{names:?}");
    assert!(names.contains(&"selftest.now".to_string()), "{names:?}");
}

#[test]
fn a_granted_tool_no_server_publishes_is_reported_to_the_operator_not_to_the_model() {
    let dir = tempdir("unreachable");
    let stored = stored_open("w-unreachable", &["selftest.echo", "files.read"]);
    let endpoint = agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint")
        .with_upstreams(
            UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
        );

    assert_eq!(endpoint.allowed_but_unreachable(), vec!["files.read"]);
}

#[test]
fn a_staged_effect_needs_no_upstream_and_is_still_published() {
    // Staging is local: the adapter performs it at settle time, from this machine, with
    // credentials the agent never holds. Dropping staged tools because no server publishes them
    // would silently remove the one class of action this product exists to mediate.
    let dir = tempdir("staged");
    let stored = stored_open("w-staged", &["github.create_pr"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_upstreams(
                UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
            );

    let tools = endpoint.tools();
    let staged = tools
        .iter()
        .find(|t| t.name == "github.create_pr")
        .expect("a staged effect is published even with an unrelated upstream attached");
    assert!(
        staged.description.contains("staged"),
        "the sentence a model reads must say the action has NOT happened: {}",
        staged.description
    );

    let result = endpoint.call("github.create_pr", &args(&[("title", json!("t"))]));
    assert!(!result.is_error, "{}", result.text);
    assert!(result.text.contains("Staged as"), "{}", result.text);
    assert_eq!(
        endpoint.forwarding_counts(),
        Some((0, 0)),
        "staging is not forwarding, and the counts must not conflate them"
    );
}

// ── the upstream that is refused ──────────────────────────────────────────────────────

#[test]
fn an_upstream_publishing_lifecycle_tools_is_refused_before_any_call() {
    // The plausible mistake, not a contrived one: "point my agent at the warrantor MCP server"
    // has two answers, and one of them hands the supervised agent the authority to settle its own
    // warrant — the single authority every other line of this design is shaped to withhold.
    let root = tempdir("lifecycle");
    let error = UpstreamSet::start(&[control_spec("warrantor", &root)], timeout())
        .expect_err("the control endpoint must be refused as an upstream");
    let rendered = error.to_string();
    assert!(
        rendered.contains("lifecycle"),
        "the refusal must say why: {rendered}"
    );
    assert!(
        rendered.contains("settle"),
        "and name what it found: {rendered}"
    );
    assert!(
        rendered.contains("--agent"),
        "and point at the endpoint they meant: {rendered}"
    );
}

#[test]
fn a_second_upstream_under_the_same_name_is_not_silently_merged() {
    // Two servers under one name means a warrant granting `x.read` cannot say which server's
    // `read` it authorised. The routing table would simply keep the last one, with no error.
    let first = selftest_spec("selftest");
    let second = selftest_spec("selftest");
    let set = UpstreamSet::start(&[first, second], timeout()).expect("both start");
    // The set itself does not refuse — the CLI does, and that is where the operator is. What the
    // set must not do is pretend two servers are reachable under one prefix.
    assert_eq!(set.len(), 2);
    let published: Vec<String> = set.published_tools().into_iter().map(|t| t.name).collect();
    assert_eq!(
        published.iter().filter(|n| *n == "selftest.echo").count(),
        2,
        "both are published; the routing table can only carry one, which is exactly why the CLI \
         refuses this: {published:?}"
    );
}

// ── failure that is not refusal ───────────────────────────────────────────────────────

#[test]
fn a_transport_failure_is_never_dressed_as_a_refusal() {
    // An agent told "refused" stops asking. An agent told "the server is gone" can reasonably try
    // something else. Rendering the second as the first teaches a model that its warrant is
    // narrower than it is.
    let dir = tempdir("transport");
    let stored = stored_open("w-transport", &["selftest.echo", "ghost.read"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Observe, now)
            .expect("endpoint")
            .with_upstreams(
                UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
            );

    let result = endpoint.call("ghost.read", &args(&[]));
    assert!(result.is_error);
    assert!(
        result.text.contains("transport failure"),
        "it must say which kind of failure this is: {}",
        result.text
    );
    assert!(
        result.text.contains("the warrant did not stop this call"),
        "and say plainly that no bound refused it: {}",
        result.text
    );
    assert_eq!(endpoint.forwarding_counts(), Some((0, 1)));
}

#[test]
fn a_refused_call_never_reaches_the_upstream() {
    // The ordering the whole design rests on: the warrant decides first, and a denial returns
    // before anything is delivered. Asserted through the forwarding counter, which is the only
    // observable that distinguishes "denied" from "denied after it happened".
    let dir = tempdir("refused");
    let stored = stored_open("w-refused", &["selftest.echo"]);
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_upstreams(
                UpstreamSet::start(&[selftest_spec("selftest")], timeout()).expect("attach"),
            );

    let result = endpoint.call("selftest.now", &args(&[]));
    assert!(result.is_error);
    assert!(
        result.text.contains("refused by the warrant"),
        "{}",
        result.text
    );
    assert_eq!(
        endpoint.forwarding_counts(),
        Some((0, 0)),
        "a refused call must not have been delivered"
    );
}

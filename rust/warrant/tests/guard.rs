//! The guard as an observe-only refusal signal.
//!
//! Not one of these opens a socket. `GuardTransport` is injected, exactly as
//! `adapters::github::GitHubTransport` is, so the attach handshake, the classification path, the
//! transport-failure path and the log can all be driven with no daemon running — which is the same
//! machine CI runs on.
//!
//! Four of these tests are the ones the workstream exists to prove:
//!
//! * an absent guard produces no signals and does not fail the run;
//! * a recorded signal carries the model, its digest and every policy knob;
//! * the verdict is unchanged by any guard output;
//! * the verification envelope and the report's bundle digest are byte-identical with and without
//!   a guard log present.
//!
//! The rest exist to stop the surface degrading into "a dead guard looks like a clean run", which
//! is the failure `ml/README.md` names about `--fail-open`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use warrantor_warrant::guard::{
    aggregate_guard_signals, attach, parse_guard_response, read_all_guard_logs, read_guard_log,
    record_guard_signals, GuardConfig, GuardCounters, GuardError, GuardKnobs, GuardMode,
    GuardObservation, GuardOutcome, GuardSession, GuardSink, GuardTransport, GUARD_SIGNAL_FORMAT,
};
use warrantor_warrant::mcp::{Endpoint, ToolResult};
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::proxy::ProxyMode;
use warrantor_warrant::serve::{
    no_adapter, record_refusals, route, HttpRequest, Response, StoreApi,
};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn now() -> u64 {
    NOW
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-guard-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

// ── the stub backend ──────────────────────────────────────────────────────────────────

/// A guard backend that never leaves the process.
///
/// `tags` and `reply` are both `Result`, so the two failure modes this module is most careful
/// about — a backend that cannot say what it is running, and a backend that is not there at all —
/// are configured rather than simulated with a timeout.
struct StubGuard {
    tags: Result<String, String>,
    reply: Result<String, String>,
    posts: usize,
}

impl StubGuard {
    fn answering(reply: &str) -> Self {
        Self {
            tags: Ok(tags_body("guard:test", DIGEST)),
            reply: Ok(format!(
                r#"{{"message":{{"role":"assistant","content":{}}}}}"#,
                serde_json::to_string(reply).expect("encode")
            )),
            posts: 0,
        }
    }

    fn dead() -> Self {
        Self {
            tags: Ok(tags_body("guard:test", DIGEST)),
            reply: Err("connection refused".to_string()),
            posts: 0,
        }
    }
}

impl GuardTransport for StubGuard {
    fn get(&mut self, _path: &str) -> Result<String, String> {
        self.tags.clone()
    }

    fn post_json(&mut self, _path: &str, _body: &str) -> Result<String, String> {
        self.posts += 1;
        self.reply.clone()
    }
}

fn tags_body(name: &str, digest: &str) -> String {
    format!(r#"{{"models":[{{"name":"{name}","model":"{name}","digest":"{digest}"}}]}}"#)
}

fn config(id: &str) -> GuardConfig {
    GuardConfig {
        warrant_id: id.to_string(),
        endpoint: "http://127.0.0.1:11434".to_string(),
        model: "guard:test".to_string(),
        mode: GuardMode::Observe,
        knobs: GuardKnobs::default(),
        max_calls: 8,
    }
}

// ── warrants and the HTTP surface ─────────────────────────────────────────────────────

fn stored_warrant(id: &str) -> StoredWarrant {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string(), "curl".to_string()]
            .into_iter()
            .collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(
        id,
        "fix the auth bug",
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

fn seed(dir: &Path, id: &str) -> StoredWarrant {
    let stored = stored_warrant(id);
    WarrantStore::open(dir)
        .expect("store")
        .save(&stored)
        .expect("save");
    stored
}

fn api(dir: &Path) -> StoreApi {
    StoreApi::new(
        WarrantStore::open(dir).expect("store"),
        dir.to_path_buf(),
        SigningKey::from_bytes(&[1; 32]),
        None,
        no_adapter,
        now,
    )
}

fn get(path: &[&str]) -> HttpRequest {
    HttpRequest::new("GET", path, BTreeMap::new()).with_bearer(TOKEN)
}

fn body(response: &Response) -> Value {
    response.body.clone()
}

/// Drive a handful of tool calls through an agent endpoint, with or without a guard.
fn run_session(dir: &Path, id: &str, guard: Option<Box<dyn GuardSink>>) -> Vec<ToolResult> {
    let stored = seed(dir, id);
    let store = WarrantStore::open(dir).expect("store");
    let mut endpoint = agent_endpoint_for(&stored, store.staged_path(id), ProxyMode::Enforce, now)
        .expect("endpoint");
    if let Some(sink) = guard {
        endpoint = endpoint.with_guard(sink);
    }
    let mut results = Vec::new();
    for (tool, argument) in [
        ("git", "status"),
        ("curl", "https://example.com"),
        // Not in the warrant's tool allowlist: the proxy refuses it, and the guard must not change
        // that answer in either direction.
        ("rm", "-rf /"),
    ] {
        let mut arguments = BTreeMap::new();
        arguments.insert("command".to_string(), Value::String(argument.to_string()));
        results.push(endpoint.call(tool, &arguments));
    }
    if let Some(counters) = endpoint.guard_counters() {
        record_guard_signals(dir, id, &endpoint.guard_signals(), counters, NOW).expect("record");
    }
    results
}

// ── (1) an absent guard writes nothing and changes nothing ────────────────────────────

#[test]
fn an_absent_guard_writes_no_log_and_does_not_fail_the_run() {
    let dir = tempdir("absent");
    let results = run_session(&dir, "wrt_absent", None);

    assert!(
        !dir.join("guard").exists(),
        "an unguarded run must leave no guard directory at all: an empty log and an absent one \
         must not be made to look alike from the disk up"
    );
    let log = read_guard_log(&dir, "wrt_absent");
    assert!(!log.configured());
    assert!(log.signals.is_empty());
    // The run itself is untouched. `rm` is not in the warrant's allowlist, so the tools bound
    // refuses it by name — the guard had no part in that, and there was no guard to have one.
    assert!(
        results[2]
            .text
            .contains("refused by the warrant's tools bound"),
        "rm was refused by the warrant, not by a guard: {}",
        results[2].text
    );
}

#[test]
fn a_guarded_run_returns_byte_identical_results_to_an_unguarded_one() {
    let unguarded = tempdir("identical-none");
    let guarded = tempdir("identical-guard");

    let without = run_session(&unguarded, "wrt_id", None);
    let adapter = attach(
        StubGuard::answering("Safety: Unsafe\nCategories: Violent"),
        config("wrt_id"),
    )
    .expect("attach");
    let with = run_session(&guarded, "wrt_id", Some(Box::new(adapter)));

    // Every call the guard called HARMFUL still returned exactly what it returned without one.
    // This is the workstream's central claim, and it is checked on the bytes rather than argued.
    assert_eq!(without, with);
    let log = read_guard_log(&guarded, "wrt_id");
    assert!(
        log.signals
            .iter()
            .any(|s| s.outcome == GuardOutcome::Harmful),
        "the stub called every call harmful, so the log must show it -- otherwise the equality \
         above would be proving nothing"
    );
}

// ── (2) a dead backend is never a clean run ───────────────────────────────────────────

#[test]
fn a_dead_backend_records_backend_unavailable_and_never_not_harmful() {
    let dir = tempdir("dead");
    let adapter = attach(StubGuard::dead(), config("wrt_dead")).expect("attach");
    run_session(&dir, "wrt_dead", Some(Box::new(adapter)));

    let log = read_guard_log(&dir, "wrt_dead");
    assert!(
        !log.signals.is_empty(),
        "a dead backend still records what it could not do"
    );
    for signal in &log.signals {
        assert_eq!(
            signal.outcome,
            GuardOutcome::BackendUnavailable,
            "a transport failure must be its own outcome; scoring it either way manufactures a \
             verdict no model produced"
        );
    }
    assert!(
        !log.signals
            .iter()
            .any(|s| s.outcome == GuardOutcome::NotHarmful),
        "a dead backend reporting perfect safety is the exact failure ml/README.md warns about"
    );
    let summary = log
        .summaries
        .first()
        .expect("a finished session writes counters");
    assert_eq!(summary.counters.classified, 0);
    assert!(summary.counters.backend_unavailable > 0);

    // And the guidance an operator reads must say so in words, not only in an enum.
    let groups = aggregate_guard_signals(&log.signals);
    assert!(groups
        .iter()
        .all(|g| g.guidance.contains("NOT classified") && g.guidance.contains("no coverage")));
}

// ── (3) and (4) attach refuses rather than producing evidence-free signals ─────────────

#[test]
fn attach_refuses_when_the_backend_cannot_name_the_model() {
    let dir = tempdir("no-digest");
    for tags in [
        // The tag is not there at all.
        Ok(tags_body("something-else", DIGEST)),
        // The tag is there and its digest is not a sha256.
        Ok(tags_body("guard:test", "not-a-digest")),
        // The backend could not be asked.
        Err("connection refused".to_string()),
    ] {
        let transport = StubGuard {
            tags,
            reply: Ok(String::new()),
            posts: 0,
        };
        let error = attach(transport, config("wrt_prov"))
            .err()
            .expect("refused");
        assert!(
            matches!(error, GuardError::ProvenanceUnknown(_)),
            "got {error:?}"
        );
    }
    assert!(
        !dir.join("guard").exists(),
        "a guard that did not attach writes no session record: the log must never claim a guard \
         was watching when none was"
    );
}

#[test]
fn attach_refuses_a_non_loopback_endpoint() {
    for endpoint in [
        "http://guard.example.com:11434",
        "https://api.some-vendor.example/v1",
        "http://10.0.0.4:11434",
        "http://127.0.0.1@evil.example.com/",
    ] {
        let mut settings = config("wrt_exfil");
        settings.endpoint = endpoint.to_string();
        let error = attach(StubGuard::answering("Safety: Safe"), settings)
            .err()
            .expect("refused");
        assert!(
            matches!(error, GuardError::NonLoopbackEndpoint(_)),
            "{endpoint} must be refused: the guard is sent the agent's tool arguments, so an \
             off-box endpoint is an exfiltration channel opened by a flag"
        );
    }
}

// ── (5) provenance travels with every signal ──────────────────────────────────────────

#[test]
fn every_persisted_signal_carries_the_model_the_digest_and_the_knobs() {
    let dir = tempdir("provenance");
    let adapter = attach(
        StubGuard::answering("Safety: Safe\nCategories: Jailbreak"),
        config("wrt_prov"),
    )
    .expect("attach");
    let session: GuardSession = adapter.session_record(NOW);
    warrantor_warrant::guard::record_guard_session(&dir, &session).expect("session");
    run_session(&dir, "wrt_prov", Some(Box::new(adapter)));

    let log = read_guard_log(&dir, "wrt_prov");
    assert!(log.configured());
    assert_eq!(log.unreadable_lines, 0);
    assert!(!log.signals.is_empty());
    let expected = GuardKnobs::default();
    for signal in &log.signals {
        assert_eq!(signal.format, GUARD_SIGNAL_FORMAT);
        assert_eq!(signal.provenance.model, "guard:test");
        assert_eq!(signal.provenance.model_digest, DIGEST);
        assert_eq!(signal.provenance.endpoint, "http://127.0.0.1:11434");
        assert_eq!(signal.provenance.adapter, "warrantor.guard-adapter/1");
        // Knobs, in full. A signal that cannot say how the model was asked is not comparable with
        // the next run's, which is the only reason to record knobs at all.
        assert_eq!(signal.provenance.knobs, expected);
        // The digest, never the content. `<root>/guard/` is served through /v1/.../refusals, which
        // the supervised agent can reach.
        assert!(signal.content_digest.starts_with("sha256:"));
        assert_eq!(signal.content_digest.len(), 71);
        assert_eq!(signal.argument_names, vec!["command".to_string()]);
        let line = serde_json::to_string(signal).expect("encode");
        assert!(
            !line.contains("example.com") && !line.contains("-rf /"),
            "the classified text must never reach the log: {line}"
        );
    }
    // And the knobs serialise as integers and bools, so two runs' lines compare byte for byte.
    let encoded = serde_json::to_value(&expected).expect("encode knobs");
    for (name, value) in encoded.as_object().expect("object") {
        assert!(
            !value.is_f64() || value.as_f64().is_none(),
            "{name} is a float; serde_json float formatting is not stable enough to compare two \
             signal lines across platforms"
        );
    }
}

// ── (6) the ported parser keeps the finding it exists for ─────────────────────────────

#[test]
fn the_parser_agrees_with_the_shared_fixture() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/guard/parse-cases.json");
    let raw = std::fs::read_to_string(&path).expect("the shared parse fixture must exist");
    let document: Value = serde_json::from_str(&raw).expect("fixture json");
    let cases = document
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases");
    assert!(
        cases.len() >= 8,
        "the fixture is the drift guard; do not shrink it"
    );

    for case in cases {
        let name = case.get("name").and_then(Value::as_str).unwrap_or("?");
        let text = case.get("raw").and_then(Value::as_str).expect("raw");
        let gating: BTreeSet<String> = case
            .get("gating_categories")
            .and_then(Value::as_array)
            .expect("gating")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let controversial = case
            .get("controversial_is_harmful")
            .and_then(Value::as_bool)
            .expect("controversial_is_harmful");
        let parsed = parse_guard_response(text, &gating, controversial);
        match case.get("expect") {
            Some(Value::Null) | None => {
                assert!(
                    matches!(parsed, Err(GuardError::Unparseable(_))),
                    "{name}: a reply that is not a verdict must be unparseable, never 'safe'"
                );
            }
            Some(expected) => {
                let verdict = parsed.unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    Some(verdict.is_harmful),
                    expected.get("is_harmful").and_then(Value::as_bool),
                    "{name}"
                );
                assert_eq!(
                    Some(verdict.severity.as_str()),
                    expected.get("severity").and_then(Value::as_str),
                    "{name}"
                );
                assert_eq!(
                    Some(verdict.gated_by_category),
                    expected.get("gated_by_category").and_then(Value::as_bool),
                    "{name}"
                );
                let categories: Vec<String> = expected
                    .get("categories")
                    .and_then(Value::as_array)
                    .expect("categories")
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                assert_eq!(verdict.categories, categories, "{name}");
            }
        }
    }
}

// ── (7) observe cannot deny, for every outcome there is ───────────────────────────────

#[test]
fn observe_yields_no_denial_for_any_outcome_and_enforce_is_not_the_default() {
    assert_eq!(GuardMode::default(), GuardMode::Observe);
    let outcomes = [
        GuardOutcome::Harmful,
        GuardOutcome::NotHarmful,
        GuardOutcome::Unparseable,
        GuardOutcome::BackendUnavailable,
        GuardOutcome::SkippedOverBudget,
    ];
    for outcome in outcomes {
        let observation = GuardObservation {
            outcome,
            mode: GuardMode::Observe,
            tool: "curl".to_string(),
            categories: vec!["jailbreak".to_string()],
        };
        assert_eq!(
            observation.enforcement_denial(),
            None,
            "observe must return None for {}, unconditionally -- the mode decides, never the \
             outcome",
            outcome.word()
        );
    }
    // The enforcement path exists and is reachable only deliberately; and even there, only a
    // positive finding can deny. A dead backend must not be able to block a call either.
    for outcome in outcomes {
        let observation = GuardObservation {
            outcome,
            mode: GuardMode::Enforce,
            tool: "curl".to_string(),
            categories: Vec::new(),
        };
        assert_eq!(
            observation.enforcement_denial().is_some(),
            outcome == GuardOutcome::Harmful,
            "under enforce only a harmful finding may deny; {} may not",
            outcome.word()
        );
    }
}

#[test]
fn a_guard_that_calls_everything_harmful_changes_no_tool_result() {
    let dir = tempdir("verdict");
    let stored = seed(&dir, "wrt_v");
    let store = WarrantStore::open(&dir).expect("store");
    let mut arguments = BTreeMap::new();
    arguments.insert("command".to_string(), Value::String("status".to_string()));

    let bare = agent_endpoint_for(&stored, store.staged_path("wrt_v"), ProxyMode::Enforce, now)
        .expect("endpoint")
        .call("git", &arguments);

    let adapter = attach(
        StubGuard::answering("Safety: Unsafe\nCategories: Jailbreak"),
        config("wrt_v"),
    )
    .expect("attach");
    let guarded = agent_endpoint_for(&stored, store.staged_path("wrt_v"), ProxyMode::Enforce, now)
        .expect("endpoint")
        .with_guard(Box::new(adapter))
        .call("git", &arguments);

    assert_eq!(bare, guarded);
}

// ── the call cap is counted, never silent ─────────────────────────────────────────────

#[test]
fn exhausting_the_call_cap_is_recorded_rather_than_passing_silently() {
    let mut settings = config("wrt_cap");
    settings.max_calls = 1;
    let mut adapter = attach(
        StubGuard::answering("Safety: Safe\nCategories: None"),
        settings,
    )
    .expect("attach");
    for index in 0..3 {
        let mut arguments = BTreeMap::new();
        arguments.insert("command".to_string(), format!("distinct-{index}"));
        adapter.observe("git", &arguments, NOW);
    }
    let counters = adapter.counters();
    assert_eq!(counters.classified, 1);
    assert_eq!(counters.skipped_over_budget, 2);
    let signals = adapter.signals();
    assert_eq!(
        signals
            .iter()
            .filter(|s| s.outcome == GuardOutcome::SkippedOverBudget)
            .count(),
        2,
        "'we stopped looking' has to be in the log, not only in a counter: an operator reads the \
         log"
    );
}

#[test]
fn the_same_call_twice_costs_one_backend_call() {
    let mut adapter = attach(
        StubGuard::answering("Safety: Safe\nCategories: None"),
        config("wrt_dedup"),
    )
    .expect("attach");
    let mut arguments = BTreeMap::new();
    arguments.insert("command".to_string(), "status".to_string());
    adapter.observe("git", &arguments, NOW);
    adapter.observe("git", &arguments, NOW);
    assert_eq!(adapter.counters().classified, 1);
    assert_eq!(adapter.counters().deduplicated, 1);
    let signals = adapter.signals();
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].count, 2);
}

// ── (8), (9), (10) the read surface ───────────────────────────────────────────────────

fn write_guard_log(dir: &Path, id: &str) {
    let adapter = attach(
        StubGuard::answering("Safety: Safe\nCategories: Jailbreak"),
        config(id),
    )
    .expect("attach");
    let session = adapter.session_record(NOW);
    warrantor_warrant::guard::record_guard_session(dir, &session).expect("session");
    let mut adapter = adapter;
    let mut arguments = BTreeMap::new();
    arguments.insert(
        "command".to_string(),
        "curl https://example.com".to_string(),
    );
    adapter.observe("curl", &arguments, NOW);
    record_guard_signals(dir, id, &adapter.signals(), adapter.counters(), NOW).expect("signals");
}

#[test]
fn guard_signals_do_not_move_the_refusal_totals() {
    let dir = tempdir("totals");
    seed(&dir, "wrt_t");
    record_refusals(
        &dir,
        "wrt_t",
        &[&warrantor_warrant::proxy::AuthorityRequest {
            tool: "rm".to_string(),
            bound: "tools".to_string(),
            reason: "not allowed".to_string(),
            count: 2,
        }],
        &[],
        NOW,
    )
    .expect("refusals");

    let mut store = api(&dir);
    let before = body(&route(&mut store, &get(&["v1", "summary", "refusals"])));

    write_guard_log(&dir, "wrt_t");
    let mut store = api(&dir);
    let after = body(&route(&mut store, &get(&["v1", "summary", "refusals"])));

    for field in ["total_occurrences", "groups", "bounds_probably_wrong"] {
        assert_eq!(
            before.pointer(&format!("/data/{field}")),
            after.pointer(&format!("/data/{field}")),
            "{field} is computed from refusals alone. A refusal means the call did NOT happen and \
             a guard signal means it did; merging them would report N refusals for N things that \
             actually occurred."
        );
    }
    assert_eq!(
        after.pointer("/data/guard/configured"),
        Some(&Value::Bool(true))
    );
    assert!(after
        .pointer("/data/guard/groups")
        .and_then(Value::as_array)
        .is_some_and(|groups| !groups.is_empty()));
}

#[test]
fn the_verification_envelope_and_the_bundle_digest_ignore_the_guard_entirely() {
    let dir = tempdir("envelope");
    seed(&dir, "wrt_env");

    let routes: [&[&str]; 3] = [
        &["v1", "warrants", "wrt_env"],
        &["v1", "warrants", "wrt_env", "report"],
        &["v1", "warrants", "wrt_env", "refusals"],
    ];
    let mut store = api(&dir);
    let before: Vec<Value> = routes
        .iter()
        .map(|path| body(&route(&mut store, &get(path))))
        .collect();

    write_guard_log(&dir, "wrt_env");
    let mut store = api(&dir);
    let after: Vec<Value> = routes
        .iter()
        .map(|path| body(&route(&mut store, &get(path))))
        .collect();

    for (index, path) in routes.iter().enumerate() {
        assert_eq!(
            before[index].get("verification"),
            after[index].get("verification"),
            "{path:?}: no classifier score may enter the verification envelope"
        );
        assert_eq!(
            before[index].get("verified"),
            after[index].get("verified"),
            "{path:?}: integrity stays a three-valued Ed25519 answer"
        );
    }
    // And the report bundle itself, byte for byte. Everything a `bundle_digest` covers is in
    // here, so an equal bundle is an equal digest, and a model's opinion has landed in neither.
    assert_eq!(
        before[1].pointer("/data/bundle"),
        after[1].pointer("/data/bundle"),
        "a model's opinion must never land inside a bundle two signatures commit to"
    );
    assert!(
        before[1].pointer("/data/bundle").is_some(),
        "the report route must have answered"
    );
    // The guard object did arrive, so the equalities above are not vacuous.
    assert_eq!(
        before[2].pointer("/data/guard/configured"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        after[2].pointer("/data/guard/configured"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn an_absent_guard_log_says_no_coverage_rather_than_nothing() {
    let dir = tempdir("unconfigured");
    seed(&dir, "wrt_u");
    let mut store = api(&dir);
    let response = body(&route(
        &mut store,
        &get(&["v1", "warrants", "wrt_u", "refusals"]),
    ));

    assert_eq!(
        response.pointer("/data/guard/configured"),
        Some(&Value::Bool(false))
    );
    let note = response
        .pointer("/data/guard/note")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        note.contains("no coverage"),
        "an absent guard must read as an absence of observation, not an absence of findings: {note}"
    );
    assert!(read_all_guard_logs(&dir).signals.is_empty());
}

#[test]
fn a_session_that_never_finished_is_distinguishable_from_one_that_never_started() {
    let dir = tempdir("crashed");
    let adapter =
        attach(StubGuard::answering("Safety: Safe"), config("wrt_crash")).expect("attach");
    // Attach record only: the process died before it could flush signals.
    warrantor_warrant::guard::record_guard_session(&dir, &adapter.session_record(NOW))
        .expect("session");

    let log = read_guard_log(&dir, "wrt_crash");
    assert!(
        log.configured(),
        "a guard WAS attached, and the log has to say so"
    );
    assert!(log.signals.is_empty());
    assert!(
        log.summaries.is_empty(),
        "no end-of-session counters is what distinguishes a crashed run from a clean empty one"
    );
    assert_eq!(log.sessions[0].mode, GuardMode::Observe);
    assert!(log.sessions[0].note.contains("blocked nothing"));
}

#[test]
fn a_corrupt_line_is_counted_rather_than_dropped() {
    let dir = tempdir("corrupt");
    write_guard_log(&dir, "wrt_c");
    let path = dir.join("guard").join("wrt_c.jsonl");
    let mut body = std::fs::read_to_string(&path).expect("read");
    body.push_str("{not json}\n");
    body.push_str("{\"format\":\"warrantor.guard-signal/1\"}\n");
    std::fs::write(&path, body).expect("write");

    let log = read_guard_log(&dir, "wrt_c");
    assert_eq!(
        log.unreadable_lines, 2,
        "a count quietly lower than what is on disk is an answer with no signal that it is short"
    );
}

#[test]
fn counters_default_to_a_session_that_did_nothing() {
    assert_eq!(GuardCounters::default().classified, 0);
    assert_eq!(GuardCounters::default().flagged, 0);
}

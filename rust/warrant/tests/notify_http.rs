//! Notifications from the HTTP surface: the acts taken in a browser are announced too.
//!
//! # The gap this covers
//!
//! `notify.json` was read by the CLI alone. A settle, void or stop performed over HTTP fired
//! nothing, and that was survivable only while the write routes were something nobody used
//! interactively. `/v1/queue` ended that: the console is now the expected place to decide, and it
//! was the one place that went silent. An off-site overseer watching `notify.json` would have seen
//! a machine where warrants stopped being decided on the day people started deciding them.
//!
//! # How the transport stays out of the library
//!
//! The notifier is a plain function pointer, like `performer`. The library decides *when*; the
//! binary owns *how*, because the only transport in this repository is `ureq`-backed and
//! `rust/warrant` carries no HTTP client — a posture worth keeping, so this test injects a
//! recorder rather than a socket.
//!
//! The recorder is a `static`, which a function pointer forces: there is no closure to capture a
//! local into. Every test here therefore takes one lock for its whole body, so two running
//! concurrently cannot read each other's rows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use warrantor_warrant::operators::{ApprovalPolicy, OperatorRegistry};
use warrantor_warrant::serve::{
    handle_scoped, no_adapter, silent_notifier, HttpRequest, SessionToken, StoreApi,
};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
const SESSION: &str = "5e55107ec0de5e55107ec0de5e55107ec0de5e55107ec0de5e55107ec0de5e551";

/// What the injected notifier saw: `(event, warrant_id, detail)`.
static RECORDED: Mutex<Vec<(String, String, serde_json::Value)>> = Mutex::new(Vec::new());
/// Held for the whole of each test, so concurrent tests cannot read each other's rows.
static SERIALISE: Mutex<()> = Mutex::new(());

fn recording_notifier(
    _root: &Path,
    event: &str,
    stored: &StoredWarrant,
    detail: serde_json::Value,
) {
    RECORDED.lock().unwrap_or_else(|e| e.into_inner()).push((
        event.to_string(),
        stored.warrant.claims.id.clone(),
        detail,
    ));
}

fn begin() -> MutexGuard<'static, ()> {
    let guard = SERIALISE.lock().unwrap_or_else(|e| e.into_inner());
    RECORDED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    guard
}

fn recorded() -> Vec<(String, String, serde_json::Value)> {
    RECORDED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn now() -> u64 {
    NOW
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-notify-http-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn store_with_warrant(dir: &Path, id: &str) {
    let store = WarrantStore::open(dir).expect("store");
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["github.create_pr"]
            .into_iter()
            .map(str::to_string)
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
        "decide this from a browser",
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    store
        .create(&StoredWarrant {
            warrant,
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
            staged_chain: None,
        })
        .expect("stored");
}

fn post(path: &[&str]) -> HttpRequest {
    HttpRequest::new("POST", path, BTreeMap::new())
        .with_bearer(SESSION)
        .with_body(&serde_json::json!({}))
}

fn get(path: &[&str]) -> HttpRequest {
    HttpRequest::new("GET", path, BTreeMap::new()).with_bearer(SESSION)
}

fn call(dir: &Path, request: &HttpRequest, notify: bool) -> u16 {
    let store = WarrantStore::open(dir).expect("store");
    let mut api = StoreApi::new(
        store,
        dir.to_path_buf(),
        SigningKey::from_bytes(&[1; 32]),
        Some(SigningKey::from_bytes(&[2; 32])),
        no_adapter,
        now,
    )
    .with_notifier(if notify {
        recording_notifier
    } else {
        silent_notifier
    });
    let registry = OperatorRegistry::load(dir).expect("registry");
    let approvals = ApprovalPolicy::load(dir).expect("policy");
    let token = SessionToken::from_value(SESSION);
    handle_scoped(&mut api, &token, &registry, &approvals, dir, request).status
}

#[test]
fn a_settle_over_http_is_announced() {
    let _lock = begin();
    let dir = tempdir("settle");
    store_with_warrant(&dir, "wrt_1");
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"]), true),
        200
    );

    let rows = recorded();
    assert_eq!(rows.len(), 1, "exactly one announcement: {rows:?}");
    assert_eq!(rows[0].0, "settled");
    assert_eq!(rows[0].1, "wrt_1");
    // The same detail the CLI's settle carries. A receiver must not be able to tell which surface
    // a decision was taken from: the decision is the fact and the surface is not.
    assert_eq!(rows[0].2, serde_json::json!({ "complete": true }));
}

#[test]
fn a_void_over_http_is_announced() {
    let _lock = begin();
    let dir = tempdir("void");
    store_with_warrant(&dir, "wrt_1");
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "void"]), true),
        200
    );

    let rows = recorded();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "voided");
    assert_eq!(
        rows[0].2,
        serde_json::json!({ "staged_effects": "discarded" })
    );
}

#[test]
fn a_refused_act_announces_nothing() {
    let _lock = begin();
    let dir = tempdir("refused");
    store_with_warrant(&dir, "wrt_1");
    // Settled once...
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"]), false),
        200
    );
    RECORDED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    // ...and the second attempt is refused. A notification here would tell an overseer a warrant
    // was settled twice, which is the shape of thing a webhook receiver cannot un-believe.
    let status = call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"]), true);
    assert!(
        !(200..300).contains(&status),
        "the second settle must be refused"
    );
    assert!(
        recorded().is_empty(),
        "a refused act is not an event: {:?}",
        recorded()
    );
}

#[test]
fn a_read_announces_nothing() {
    let _lock = begin();
    let dir = tempdir("read");
    store_with_warrant(&dir, "wrt_1");
    for path in [
        vec!["v1", "warrants"],
        vec!["v1", "queue"],
        vec!["v1", "warrants", "wrt_1"],
        vec!["v1", "warrants", "wrt_1", "custody"],
    ] {
        call(&dir, &get(&path), true);
    }
    assert!(
        recorded().is_empty(),
        "reading is not an event: {:?}",
        recorded()
    );
}

#[test]
fn a_server_with_no_notifier_attached_behaves_exactly_as_it_did() {
    // The compatibility hinge. `silent_notifier` is the default, and the six-argument `new` that
    // every caller predating this constructs must keep working and keep telling nobody.
    let _lock = begin();
    let dir = tempdir("silent");
    store_with_warrant(&dir, "wrt_1");
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "void"]), false),
        200
    );
    assert!(recorded().is_empty());
}

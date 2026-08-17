//! `/v1/queue` through the real HTTP handler: what is waiting, and on whom.
//!
//! The unit tests in `review.rs` cover the blocker arithmetic without a filesystem. What only the
//! handler can show is the three things the arithmetic cannot:
//!
//! 1. that the queue is rendered **per caller** — the same store answers differently to a reviewer
//!    and to a settler, which is the whole reason the route exists rather than a static listing;
//! 2. that it **agrees with the settle gate** — a queue offering an act the gate refuses would be
//!    worse than no queue, because it sends somebody to a 403 with the facts already in hand;
//! 3. that a warrant whose actor log will not read is **listed, not dropped**.
//!
//! Every test drives `handle_scoped` with an in-memory request, the same path `serve_on` takes per
//! connection. No sockets.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use warrantor_warrant::operators::{
    self, ApprovalPolicy, OperatorRegistry, Scope, APPROVALS_FORMAT,
};
use warrantor_warrant::serve::{handle_scoped, no_adapter, HttpRequest, SessionToken, StoreApi};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;
const SESSION: &str = "5e55107ec0de5e55107ec0de5e55107ec0de5e55107ec0de5e55107ec0de5e551";

fn now() -> u64 {
    NOW
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-review-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn store_with_warrant(dir: &Path, id: &str, goal: &str) -> WarrantStore {
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
        goal,
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
    store
}

fn api(dir: &Path) -> StoreApi {
    let store = WarrantStore::open(dir).expect("store");
    StoreApi::new(
        store,
        dir.to_path_buf(),
        SigningKey::from_bytes(&[1; 32]),
        Some(SigningKey::from_bytes(&[2; 32])),
        no_adapter,
        now,
    )
}

fn get(path: &[&str], token: &str) -> HttpRequest {
    HttpRequest::new("GET", path, BTreeMap::new()).with_bearer(token)
}

fn post(path: &[&str], token: &str) -> HttpRequest {
    HttpRequest::new("POST", path, BTreeMap::new())
        .with_bearer(token)
        .with_body(&serde_json::json!({}))
}

fn operator(dir: &Path, name: &str, scopes: &str) -> String {
    let mut registry = OperatorRegistry::load(dir).expect("load");
    let token = registry
        .add(
            name,
            Scope::parse_list(scopes).expect("scopes"),
            "bound out of band, in this test",
            NOW,
        )
        .expect("added");
    registry.save(dir).expect("saved");
    token
}

fn write_policy(dir: &Path, required: usize, settler_may_approve: bool) {
    let policy = ApprovalPolicy {
        format: APPROVALS_FORMAT.to_string(),
        required,
        settler_may_approve,
    };
    std::fs::write(
        operators::approvals_path(dir),
        serde_json::to_vec_pretty(&policy).expect("serialise"),
    )
    .expect("write policy");
}

fn call(dir: &Path, request: &HttpRequest) -> (u16, serde_json::Value) {
    let registry = OperatorRegistry::load(dir).expect("registry");
    let approvals = ApprovalPolicy::load(dir).expect("policy");
    let mut api = api(dir);
    let token = SessionToken::from_value(SESSION);
    let response = handle_scoped(&mut api, &token, &registry, &approvals, dir, request);
    let value: serde_json::Value =
        serde_json::from_str(&response.body.to_string()).expect("a JSON body");
    (response.status, value)
}

fn queue(dir: &Path, token: &str) -> serde_json::Value {
    let (status, value) = call(dir, &get(&["v1", "queue"], token));
    assert_eq!(status, 200, "the queue answered {status}: {value}");
    value.get("data").cloned().expect("a data object")
}

fn entry_for<'a>(data: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    data["waiting"]
        .as_array()
        .expect("waiting is an array")
        .iter()
        .find(|e| e["warrant_id"] == id)
        .unwrap_or_else(|| panic!("{id} is not in the queue: {data}"))
}

fn acts(entry: &serde_json::Value) -> Vec<String> {
    entry["you_can"]
        .as_array()
        .expect("you_can is an array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect()
}

// ── the queue is authenticated like everything else ───────────────────────────────────

#[test]
fn the_queue_needs_a_token() {
    // It names every outstanding warrant, its goal and who is registered to approve it. That is
    // exactly the shape of thing that must not be readable by whoever finds the port.
    let dir = tempdir("auth");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    let (status, _) = call(&dir, &get(&["v1", "queue"], "not-the-token"));
    assert_eq!(status, 401);
}

#[test]
fn the_queue_is_a_get_and_says_so() {
    let dir = tempdir("method");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    let (status, _) = call(&dir, &post(&["v1", "queue"], SESSION));
    assert_eq!(status, 405);
}

// ── what it contains ──────────────────────────────────────────────────────────────────

#[test]
fn an_outstanding_warrant_is_waiting_even_with_no_approval_policy() {
    // The queue's premise: an outstanding warrant nobody looks at is the failure mode, and "no
    // approvals required" is not the same as "no decision owed".
    let dir = tempdir("no-policy");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    let data = queue(&dir, SESSION);
    assert_eq!(data["waiting"].as_array().unwrap().len(), 1);
    assert_eq!(
        entry_for(&data, "wrt_1")["blocker"]["blocker"],
        "awaiting-decision"
    );
}

#[test]
fn a_settled_warrant_leaves_the_queue() {
    let dir = tempdir("settled");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    let (status, _) = call(&dir, &post(&["v1", "warrants", "wrt_1", "void"], SESSION));
    assert_eq!(status, 200);
    let data = queue(&dir, SESSION);
    assert!(
        data["waiting"].as_array().unwrap().is_empty(),
        "a decided warrant is not waiting on anybody: {data}"
    );
}

// ── it is rendered per caller ─────────────────────────────────────────────────────────

#[test]
fn the_same_store_answers_a_reviewer_and_a_settler_differently() {
    // The reason this is a route rather than a static listing. A reviewer handed warrants they
    // hold no scope for stops reading the list, and the list is the only thing between an
    // outstanding warrant and nobody looking at it.
    let dir = tempdir("per-caller");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    write_policy(&dir, 2, false);
    let ana = operator(&dir, "ana", "read,approve");
    let _ben = operator(&dir, "ben", "read,approve");
    let cleo = operator(&dir, "cleo", "read,settle");

    let for_ana = queue(&dir, &ana);
    assert_eq!(acts(entry_for(&for_ana, "wrt_1")), vec!["approve"]);
    assert_eq!(for_ana["waiting_on_you"], 1);

    // cleo can settle, but the approvals are not in. Offering her an act the gate would refuse is
    // worse than offering none.
    let for_cleo = queue(&dir, &cleo);
    assert!(acts(entry_for(&for_cleo, "wrt_1")).is_empty());
    assert_eq!(for_cleo["waiting_on_you"], 0);
}

#[test]
fn the_queue_and_the_settle_gate_agree_at_every_step() {
    // The property that matters most, asserted against the gate itself rather than against a
    // second copy of its rules: whenever the queue offers `settle`, the gate accepts it, and
    // whenever it does not, the gate refuses.
    let dir = tempdir("agreement");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    write_policy(&dir, 2, false);
    let ana = operator(&dir, "ana", "read,approve");
    let ben = operator(&dir, "ben", "read,approve");
    let cleo = operator(&dir, "cleo", "read,settle");

    // Nothing approved: the queue offers cleo nothing, and the gate refuses her.
    assert!(acts(entry_for(&queue(&dir, &cleo), "wrt_1")).is_empty());
    let (refused, _) = call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &cleo));
    assert_eq!(
        refused, 403,
        "the gate must refuse what the queue did not offer"
    );

    // One approval: still short, still refused, still not offered.
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &ana)).0,
        200
    );
    assert!(acts(entry_for(&queue(&dir, &cleo), "wrt_1")).is_empty());
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &cleo)).0,
        403
    );

    // Both approvals: the queue offers it, and the gate takes it.
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &ben)).0,
        200
    );
    let data = queue(&dir, &cleo);
    assert_eq!(
        entry_for(&data, "wrt_1")["blocker"]["blocker"],
        "awaiting-decision"
    );
    assert_eq!(acts(entry_for(&data, "wrt_1")), vec!["settle"]);
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &cleo)).0,
        200,
        "the gate must accept what the queue offered"
    );
}

#[test]
fn the_sole_approver_is_not_offered_a_settle_and_the_gate_confirms_it() {
    // ana approves and also holds settle. With `settler_may_approve: false` the gate refuses her,
    // and the queue predicts that from facts it already has rather than sending her to a 403.
    let dir = tempdir("sole-approver");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    write_policy(&dir, 1, false);
    let ana = operator(&dir, "ana", "read,approve,settle");
    let cleo = operator(&dir, "cleo", "read,settle");

    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &ana)).0,
        200
    );
    assert!(acts(entry_for(&queue(&dir, &ana), "wrt_1")).is_empty());
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &ana)).0,
        403
    );
    // cleo did not approve, so she is the one who can release it — and does.
    assert_eq!(
        acts(entry_for(&queue(&dir, &cleo), "wrt_1")),
        vec!["settle"]
    );
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &cleo)).0,
        200
    );
}

// ── deadlock ──────────────────────────────────────────────────────────────────────────

#[test]
fn a_policy_nobody_can_satisfy_reads_as_deadlocked_rather_than_as_a_wait() {
    let dir = tempdir("deadlock");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    write_policy(&dir, 2, false);
    let ana = operator(&dir, "ana", "read,approve,settle");

    let data = queue(&dir, &ana);
    let entry = entry_for(&data, "wrt_1");
    assert_eq!(entry["blocker"]["blocker"], "deadlocked");
    assert!(
        acts(entry).is_empty(),
        "a deadlocked warrant offers nobody anything"
    );
    assert_eq!(data["counts"]["deadlocked"], 1);
}

#[test]
fn an_anonymous_approval_under_a_two_person_rule_is_reported_as_permanent() {
    // The defect the queue found. The session token records an approval with no operator name;
    // `approval_verdict` then refuses every settle, reads the LOG rather than the registry, and the
    // log is append-only — so no number of named approvals afterwards clears it.
    //
    // Asserted against the gate, so this test fails if either side ever changes alone.
    let dir = tempdir("anonymous-poison");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    write_policy(&dir, 2, false);
    let ana = operator(&dir, "ana", "read,approve");
    let ben = operator(&dir, "ben", "read,approve");
    let cleo = operator(&dir, "cleo", "read,settle");

    // The session token approves: no name attached.
    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "approve"], SESSION)
        )
        .0,
        200
    );
    // Both named operators approve too. Three approvals against a requirement of two.
    for token in [&ana, &ben] {
        assert_eq!(
            call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], token)).0,
            200
        );
    }

    let data = queue(&dir, &cleo);
    assert_eq!(
        entry_for(&data, "wrt_1")["blocker"]["blocker"],
        "deadlocked",
        "three approvals and it can still never be settled: {data}"
    );
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &cleo)).0,
        403,
        "the gate agrees, which is the whole point of reporting it as permanent"
    );
    // Void is the only exit, and it works.
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "void"], &cleo)).0,
        200
    );
}

// ── what it refuses to hide ───────────────────────────────────────────────────────────

#[test]
fn a_warrant_whose_actor_log_will_not_read_is_listed_rather_than_dropped() {
    // A warrant that is outstanding, needs a human, and cannot be described is the most urgent row
    // on the page. Dropping it would make the queue quietly shorter and the store quietly worse.
    let dir = tempdir("undetermined");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    store_with_warrant(&dir, "wrt_2", "bump the dependency");
    let path = operators::actor_log_path(&dir, "wrt_1");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&path, b"this is not a JSON line\n").expect("write");

    let data = queue(&dir, SESSION);
    let undetermined = data["undetermined"].as_array().expect("an array");
    assert_eq!(undetermined.len(), 1, "{data}");
    assert_eq!(undetermined[0]["warrant_id"], "wrt_1");
    // The readable one is unaffected: one bad log does not blind the whole queue.
    assert_eq!(data["waiting"].as_array().unwrap().len(), 1);
    assert_eq!(entry_for(&data, "wrt_2")["state"], "open");
}

#[test]
fn the_queue_says_it_is_not_evidence() {
    // Every derived view in this server carries the same disclaimer, and this one is the most
    // likely to be mistaken for a verdict: it is a list of things a human should act on.
    let dir = tempdir("not-a-verdict");
    store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    let (_, value) = call(&dir, &get(&["v1", "queue"], SESSION));
    assert_eq!(value["verified"], false);
    assert_eq!(value["verification"]["code"], "unsigned_record");
    // `not_attempted` would have said "the request was refused before any record was read" on a
    // 200 that had just read the whole store. It shipped that way on the custody view.
    assert!(
        !value["verification"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("refused"),
        "a successful read must not describe itself as a refusal: {}",
        value["verification"]["reason"]
    );
    assert!(value["data"]["not_a_verdict"]
        .as_str()
        .unwrap_or_default()
        .contains("never that the evidence checks out"));
}

#[test]
fn a_held_warrant_is_waiting_too() {
    // Held is the state a stopped run leaves behind, and it is the one most likely to be forgotten:
    // nobody is watching a run that already ended.
    let dir = tempdir("held");
    let store = store_with_warrant(&dir, "wrt_1", "tidy the changelog");
    let mut stored = store.load("wrt_1").expect("load");
    stored.warrant.state = WarrantState::Held;
    store.save(&stored).expect("save");

    let data = queue(&dir, SESSION);
    assert_eq!(entry_for(&data, "wrt_1")["state"], "held");
}

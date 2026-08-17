//! §2.2 through the real HTTP handler: scopes, and the two-person rule.
//!
//! The unit tests in `operators.rs` cover the registry, the chain and the approval arithmetic. What
//! only the handler can show is that a scope is checked **before** the act rather than after — there
//! is no partial settle, so a 403 that arrived afterwards would be theatre — and that an act's actor
//! is recorded only when the act succeeded.
//!
//! Every test here drives `handle_scoped` with an in-memory request, which is the same path
//! `serve_on` takes per connection. No sockets.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use warrantor_warrant::operators::{
    self, Act, ApprovalPolicy, OperatorRegistry, Scope, APPROVALS_FORMAT,
};

use warrantor_warrant::serve::{
    handle_scoped, no_adapter, HttpRequest, Principal, SessionToken, StoreApi,
};
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
        "warrantor-identity-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// A store holding one open warrant with a staged-effect-free queue.
fn store_with_warrant(dir: &Path, id: &str) -> WarrantStore {
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
        "two-person rule",
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

fn post(path: &[&str], token: &str) -> HttpRequest {
    HttpRequest::new("POST", path, BTreeMap::new())
        .with_bearer(token)
        .with_body(&serde_json::json!({}))
}

fn get(path: &[&str], token: &str) -> HttpRequest {
    HttpRequest::new("GET", path, BTreeMap::new()).with_bearer(token)
}

/// Mint an operator and return its token.
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

fn call(dir: &Path, request: &HttpRequest) -> (u16, String) {
    let registry = OperatorRegistry::load(dir).expect("registry");
    let approvals = ApprovalPolicy::load(dir).expect("policy");
    let mut api = api(dir);
    let token = SessionToken::from_value(SESSION);
    let response = handle_scoped(&mut api, &token, &registry, &approvals, dir, request);
    let body = response.body.to_string();
    (response.status, body)
}

// ── compatibility ─────────────────────────────────────────────────────────────────────

#[test]
fn a_machine_with_no_operators_behaves_exactly_as_it_did_before() {
    // The hinge the whole module rests on. If registering nothing changed anything, this feature
    // would be a migration rather than an addition.
    let dir = tempdir("compat");
    store_with_warrant(&dir, "wrt_1");
    let (status, _) = call(&dir, &post(&["v1", "warrants", "wrt_1", "void"], SESSION));
    assert_eq!(status, 200, "the session token still does everything");

    let (unauth, _) = call(
        &dir,
        &post(&["v1", "warrants", "wrt_1", "void"], "not-the-token"),
    );
    assert_eq!(unauth, 401);
}

#[test]
fn the_session_token_still_works_after_operators_exist() {
    // Otherwise starting a server would lock out the person who started it the moment they
    // registered anybody.
    let dir = tempdir("session-survives");
    store_with_warrant(&dir, "wrt_1");
    let _ = operator(&dir, "ana", "settle");
    let (status, _) = call(&dir, &post(&["v1", "warrants", "wrt_1", "void"], SESSION));
    assert_eq!(status, 200);
}

// ── scopes ────────────────────────────────────────────────────────────────────────────

#[test]
fn a_stop_only_operator_cannot_settle_and_the_refusal_says_which_scope() {
    // The concrete reason `--allow-settle` being all-or-nothing was a real problem: the person you
    // want able to kill a runaway agent at 3am is not necessarily the person you want able to
    // release what it wrote.
    let dir = tempdir("scopes");
    store_with_warrant(&dir, "wrt_1");
    let oncall = operator(&dir, "oncall", "stop");

    let (status, body) = call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &oncall));
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("scope_required"), "{body}");
    assert!(
        body.contains("\\\"settle\\\" scope") || body.contains("settle"),
        "{body}"
    );
    assert!(
        body.contains("oncall"),
        "the refusal must name the principal: {body}"
    );

    // And the warrant is untouched: the scope was checked before the act, not after.
    let store = WarrantStore::open(&dir).expect("store");
    assert_eq!(
        store.load("wrt_1").expect("still there").warrant.state,
        WarrantState::Open,
        "a refused settle must not have happened"
    );
}

#[test]
fn an_approve_only_operator_cannot_settle_and_a_settle_only_one_cannot_approve() {
    // Separation of duties is the entire reason to have an approve scope. If either direction
    // leaked, one person could satisfy a two-person rule alone.
    let dir = tempdir("separation");
    store_with_warrant(&dir, "wrt_1");
    let reviewer = operator(&dir, "reviewer", "approve");
    let releaser = operator(&dir, "releaser", "settle");

    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "settle"], &reviewer)
        )
        .0,
        403
    );
    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "approve"], &releaser)
        )
        .0,
        403
    );
    // Each in their own lane works.
    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "approve"], &reviewer)
        )
        .0,
        200
    );
}

#[test]
fn a_read_only_operator_can_read_and_change_nothing() {
    let dir = tempdir("readonly");
    store_with_warrant(&dir, "wrt_1");
    let viewer = operator(&dir, "viewer", "read");

    let get = get(&["v1", "warrants", "wrt_1"], &viewer);
    assert_eq!(call(&dir, &get).0, 200);
    for verb in ["settle", "void", "stop", "approve"] {
        let (status, body) = call(&dir, &post(&["v1", "warrants", "wrt_1", verb], &viewer));
        assert_eq!(status, 403, "{verb} must be refused: {body}");
    }
}

#[test]
fn a_revoked_operator_is_refused_on_their_next_request_with_no_restart() {
    // The property a credential system needs most. A revocation that requires restarting the server
    // is a revocation nobody performs during an incident — which is the only time it matters.
    let dir = tempdir("revoke");
    store_with_warrant(&dir, "wrt_1");
    let ana = operator(&dir, "ana", "approve");
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &ana)).0,
        200
    );

    let mut registry = OperatorRegistry::load(&dir).expect("load");
    registry.remove("ana").expect("removed");
    registry.save(&dir).expect("saved");

    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &ana)).0,
        401,
        "a revoked token authenticates as nothing"
    );
}

// ── the two-person rule ───────────────────────────────────────────────────────────────

#[test]
fn a_settle_is_refused_until_the_required_approvals_exist() {
    let dir = tempdir("gate");
    store_with_warrant(&dir, "wrt_1");
    write_policy(&dir, 2, false);
    let a1 = operator(&dir, "a1", "approve");
    let a2 = operator(&dir, "a2", "approve");
    let settler = operator(&dir, "settler", "settle");

    let (status, body) = call(
        &dir,
        &post(&["v1", "warrants", "wrt_1", "settle"], &settler),
    );
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("approval_required"), "{body}");

    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &a1)).0,
        200
    );
    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "settle"], &settler)
        )
        .0,
        403,
        "one of two is not two"
    );

    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &a2)).0,
        200
    );
    let (settled, body) = call(
        &dir,
        &post(&["v1", "warrants", "wrt_1", "settle"], &settler),
    );
    assert_eq!(settled, 200, "{body}");
}

#[test]
fn the_settler_cannot_be_their_own_second_approver() {
    let dir = tempdir("self-approve");
    store_with_warrant(&dir, "wrt_1");
    write_policy(&dir, 1, false);
    let both = operator(&dir, "both", "settle,approve");

    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "approve"], &both)).0,
        200
    );
    let (status, body) = call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &both));
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("one person doing both"),
        "the refusal must say what is wrong with it: {body}"
    );
}

#[test]
fn a_void_is_never_gated_on_approvals() {
    // Discarding staged work is the SAFE direction. Requiring review to throw an agent's output
    // away would mean a runaway's staged effects sit queued while approvals are collected.
    let dir = tempdir("void-ungated");
    store_with_warrant(&dir, "wrt_1");
    write_policy(&dir, 2, false);
    let settler = operator(&dir, "settler", "settle");
    let (status, body) = call(&dir, &post(&["v1", "warrants", "wrt_1", "void"], &settler));
    assert_eq!(status, 200, "{body}");
}

// ── the actor log ─────────────────────────────────────────────────────────────────────

#[test]
fn only_acts_that_succeeded_are_recorded() {
    // A register of what happened must not contain attempts that were refused, or "who settled
    // this" has answers in it that are false.
    let dir = tempdir("only-success");
    store_with_warrant(&dir, "wrt_1");
    write_policy(&dir, 1, false);
    let approver = operator(&dir, "approver", "approve");
    let settler = operator(&dir, "settler", "settle");
    let nobody = operator(&dir, "nobody", "read");

    // Refused for scope, and refused for approvals.
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "settle"], &nobody)).0,
        403
    );
    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "settle"], &settler)
        )
        .0,
        403
    );
    assert!(
        operators::read_log(&dir, "wrt_1").expect("read").is_empty(),
        "two refusals must have written no acts"
    );

    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "approve"], &approver)
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &dir,
            &post(&["v1", "warrants", "wrt_1", "settle"], &settler)
        )
        .0,
        200
    );

    let log = operators::read_log(&dir, "wrt_1").expect("read");
    assert_eq!(log.len(), 2, "{log:?}");
    assert_eq!(log[0].act, Act::Approve);
    assert_eq!(log[0].actor.as_deref(), Some("approver"));
    assert_eq!(log[1].act, Act::Settle);
    assert_eq!(log[1].actor.as_deref(), Some("settler"));
    operators::verify_chain(&log).expect("the chain must hold across handler calls");
}

#[test]
fn an_act_under_the_session_token_is_recorded_with_no_name_rather_than_a_placeholder() {
    let dir = tempdir("anon-act");
    store_with_warrant(&dir, "wrt_1");
    assert_eq!(
        call(&dir, &post(&["v1", "warrants", "wrt_1", "void"], SESSION)).0,
        200
    );

    let log = operators::read_log(&dir, "wrt_1").expect("read");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].actor, None, "no name may be invented");
    assert_eq!(log[0].via, "session-token");
}

#[test]
fn a_principal_never_describes_itself_with_a_name_it_does_not_have() {
    assert_eq!(Principal::session().name, None);
    assert!(Principal::session().describe().contains("session token"));
    assert!(Principal::session().allows(Scope::Settle));
}

//! HTTP API tests.
//!
//! Not one of these opens a socket. `serve_conn` is generic over its reader and writer, so the
//! whole parse → authenticate → route → write path is driven by a `Cursor` and a `Vec<u8>`, and
//! `route` is driven with a hand-built request when the transport is not what is under test. That
//! split is deliberate and copied from `tests/mcp.rs`: a socket-loop bug cannot mask an
//! authorization bug, and an authorization bug cannot hide behind a framing test.
//!
//! The load-bearing tests are the first three. Everything else is plumbing; **the token is checked
//! before a route is resolved** is the property this surface rests on, because it is what answers
//! `daemon.rs`'s argument that a loopback port is reachable by every process on the machine
//! including the agent.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use warrantor_warrant::egress::{DenyReason, EgressRefusal};
use warrantor_warrant::proxy::AuthorityRequest;
use warrantor_warrant::serve::{
    aggregate_refusals, bind_warning, default_token_path, handle, no_adapter, read_all_refusals,
    record_refusals, route, serve_conn, status, HttpRequest, Integrity, Liveness, RefusalSignal,
    SessionToken, Shutdown, StoreApi,
};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;
fn now() -> u64 {
    NOW
}

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn token() -> SessionToken {
    SessionToken::from_value(TOKEN)
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-serve-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// A warrant, optionally signed by a key that is NOT this store's trust anchor.
fn warrant_with(id: &str, expires_at: u64, issuer_seed: u8) -> StoredWarrant {
    let issuer = SigningKey::from_bytes(&[issuer_seed; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at,
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
        staged_chain: None,
    }
}

fn seed(dir: &Path, id: &str) -> StoredWarrant {
    let stored = warrant_with(id, NOW + 3600, 1);
    WarrantStore::open(dir)
        .expect("store")
        .save(&stored)
        .expect("save");
    stored
}

fn api(dir: &Path, release_authority: bool) -> StoreApi {
    let store = WarrantStore::open(dir).expect("store");
    StoreApi::new(
        store,
        dir.to_path_buf(),
        SigningKey::from_bytes(&[1; 32]),
        release_authority.then(|| SigningKey::from_bytes(&[2; 32])),
        no_adapter,
        now,
    )
}

fn get(path: &[&str]) -> HttpRequest {
    HttpRequest::new("GET", path, BTreeMap::new()).with_bearer(TOKEN)
}

fn post(path: &[&str], body: &Value) -> HttpRequest {
    HttpRequest::new("POST", path, BTreeMap::new())
        .with_bearer(TOKEN)
        .with_body(body)
}

/// Drive the whole wire path, returning the raw response text.
fn round_trip(api: &mut StoreApi, raw: &str) -> String {
    let mut input = Cursor::new(raw.as_bytes().to_vec());
    let mut output: Vec<u8> = Vec::new();
    serve_conn(api, &token(), &mut input, &mut output).expect("write");
    String::from_utf8(output).expect("utf8")
}

fn body_of(raw: &str) -> Value {
    let (_, body) = raw.split_once("\r\n\r\n").expect("header/body split");
    serde_json::from_str(body).expect("json body")
}

fn code_of(response: &warrantor_warrant::serve::Response) -> String {
    response
        .body
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

// ── THE ordering property ─────────────────────────────────────────────────────────────

/// The load-bearing test. Authentication runs before routing, so an unauthenticated caller cannot
/// use status codes to learn which warrant ids this store holds — or that it holds any.
#[test]
fn a_wrong_token_on_a_nonexistent_id_is_401_and_not_404() {
    let dir = tempdir("auth-order");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_real");

    let real = HttpRequest::new("GET", &["v1", "warrants", "wrt_real"], BTreeMap::new())
        .with_bearer("not-the-token");
    let invented = HttpRequest::new("GET", &["v1", "warrants", "wrt_invented"], BTreeMap::new())
        .with_bearer("not-the-token");

    let a = handle(&mut api, &token(), &real);
    let b = handle(&mut api, &token(), &invented);

    assert_eq!(a.status, status::UNAUTHORIZED);
    assert_eq!(b.status, status::UNAUTHORIZED);
    // Byte-identical, so the pair is indistinguishable to a caller probing for ids.
    assert_eq!(
        a.body, b.body,
        "a real id and an invented one must look the same"
    );
}

#[test]
fn no_token_at_all_is_refused_and_the_body_names_nothing() {
    let dir = tempdir("auth-absent");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_real");

    let bare = HttpRequest::new("GET", &["v1", "warrants"], BTreeMap::new());
    let response = handle(&mut api, &token(), &bare);

    assert_eq!(response.status, status::UNAUTHORIZED);
    let text = response.body.to_string();
    assert!(
        !text.contains("wrt_real"),
        "a denial must not name a warrant"
    );
    assert!(
        !text.contains("warrants"),
        "a denial must not describe the store"
    );
    // Every response carries a verdict, including this one, so a client never branches on whether
    // the field exists.
    assert_eq!(response.body["verified"], Value::Bool(false));
    assert_eq!(response.body["verification"]["integrity"], "unknown");
}

#[test]
fn the_token_comparison_folds_every_byte_and_rejects_a_prefix() {
    let token = token();
    assert!(token.matches(TOKEN));
    assert!(!token.matches(""));
    // A prefix of the real token must not pass, which is what a length-only check would allow.
    assert!(!token.matches(&TOKEN[..TOKEN.len() - 1]));
    let mut wrong = TOKEN.to_string();
    wrong.replace_range(TOKEN.len() - 1.., "0");
    assert_ne!(wrong, TOKEN);
    assert!(!token.matches(&wrong), "one differing byte must fail");
    // Two freshly minted tokens differ, which is the whole point of minting them.
    let one = SessionToken::mint().expect("mint");
    let two = SessionToken::mint().expect("mint");
    assert_ne!(one.as_str(), two.as_str());
    assert_eq!(one.as_str().len(), 64);
}

// ── framing and parsing ───────────────────────────────────────────────────────────────

#[test]
fn a_well_formed_request_produces_exactly_one_response_with_a_matching_length() {
    let dir = tempdir("framing");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_frame");

    let raw = round_trip(
        &mut api,
        &format!(
            "GET /v1/health HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    );

    assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "got: {raw}");
    assert!(raw.contains("connection: close\r\n"));
    assert!(raw.contains("cache-control: no-store\r\n"));
    assert!(raw.contains("x-content-type-options: nosniff\r\n"));
    // No CORS header, ever: one would let any page in the user's browser reach a loopback API
    // that holds settle authority.
    assert!(!raw.to_lowercase().contains("access-control-allow-origin"));

    let (head, body) = raw.split_once("\r\n\r\n").expect("split");
    let declared: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
        .and_then(|v| v.trim().parse().ok())
        .expect("content-length");
    assert_eq!(declared, body.len(), "content-length must match the body");
    // Exactly one status line in the whole stream.
    assert_eq!(raw.matches("HTTP/1.1 ").count(), 1);
}

#[test]
fn any_transfer_encoding_header_is_refused_outright() {
    let dir = tempdir("te");
    let mut api = api(&dir, true);

    for encoding in ["chunked", "identity", "gzip, chunked"] {
        let raw = round_trip(
            &mut api,
            &format!(
                "POST /v1/warrants/wrt_a/void HTTP/1.1\r\nauthorization: Bearer {TOKEN}\r\n\
                 transfer-encoding: {encoding}\r\ncontent-length: 2\r\n\r\n{{}}"
            ),
        );
        assert!(raw.starts_with("HTTP/1.1 400 "), "{encoding}: {raw}");
        assert_eq!(
            body_of(&raw)["error"]["code"],
            "transfer_encoding_refused",
            "Content-Length only: refusing the whole header removes the smuggling class"
        );
    }
}

#[test]
fn oversized_lines_bodies_and_targets_are_each_refused_by_their_own_code() {
    let dir = tempdir("limits");
    let mut api = api(&dir, true);

    let long_target = "a".repeat(warrantor_warrant::serve::MAX_REQUEST_LINE);
    let raw = round_trip(&mut api, &format!("GET /{long_target} HTTP/1.1\r\n\r\n"));
    assert!(raw.starts_with("HTTP/1.1 414 "), "{raw}");

    let mut headers = String::new();
    for index in 0..(warrantor_warrant::serve::MAX_HEADERS + 5) {
        headers.push_str(&format!("x-pad-{index}: padding\r\n"));
    }
    let raw = round_trip(
        &mut api,
        &format!("GET /v1/health HTTP/1.1\r\n{headers}authorization: Bearer {TOKEN}\r\n\r\n"),
    );
    assert!(raw.starts_with("HTTP/1.1 431 "), "{raw}");

    let raw = round_trip(
        &mut api,
        &format!(
            "POST /v1/warrants/wrt_a/stop HTTP/1.1\r\nauthorization: Bearer {TOKEN}\r\n\
             content-type: application/json\r\ncontent-length: {}\r\n\r\n",
            warrantor_warrant::serve::MAX_BODY_BYTES + 1
        ),
    );
    assert!(raw.starts_with("HTTP/1.1 413 "), "{raw}");
}

#[test]
fn a_post_body_that_is_not_json_is_refused_before_it_is_read() {
    let dir = tempdir("media");
    let mut api = api(&dir, true);
    let raw = round_trip(
        &mut api,
        &format!(
            "POST /v1/warrants/wrt_a/stop HTTP/1.1\r\nauthorization: Bearer {TOKEN}\r\n\
             content-type: application/x-www-form-urlencoded\r\ncontent-length: 7\r\n\r\nreason=x"
        ),
    );
    assert!(raw.starts_with("HTTP/1.1 415 "), "{raw}");
    assert_eq!(body_of(&raw)["error"]["code"], "unsupported_media_type");
}

/// `checked_at` says *when this was decided*, so a refusal built before a clock was in scope must
/// not ship a 1970 timestamp on the one field whose whole job is the time.
#[test]
fn refusals_from_the_framing_and_routing_layers_still_carry_the_clock() {
    let dir = tempdir("stamped");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_t");

    // Refused during framing, before any route or Api call.
    let raw = round_trip(&mut api, "GET /v1/health HTTP/9.9\r\n\r\n");
    assert!(raw.starts_with("HTTP/1.1 505 "), "{raw}");
    assert_eq!(body_of(&raw)["verification"]["checked_at"], NOW);

    // Refused during routing, before the Api answers.
    let wrong_method = route(
        &mut api,
        &HttpRequest::new(
            "POST",
            &["v1", "warrants", "wrt_t", "report"],
            BTreeMap::new(),
        )
        .with_bearer(TOKEN),
    );
    assert_eq!(wrong_method.body["verification"]["checked_at"], NOW);

    let unknown = route(&mut api, &get(&["v1", "receipts"]));
    assert_eq!(unknown.body["verification"]["checked_at"], NOW);
}

/// The path never reaches the filesystem un-validated, and there is no decoding step to be tricked.
#[test]
fn traversal_shaped_targets_are_refused_before_the_store_is_touched() {
    let dir = tempdir("traversal");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_real");

    for target in [
        "/v1/warrants/%2e%2e%2fkeys",
        "/v1/warrants/../keys/issuer.key",
        "/v1/warrants/wrt_../report",
        "/v1/warrants/..%2F..%2Fetc",
        "/v1/warrants/wrt_a%00",
    ] {
        let raw = round_trip(
            &mut api,
            &format!("GET {target} HTTP/1.1\r\nauthorization: Bearer {TOKEN}\r\n\r\n"),
        );
        assert!(
            raw.starts_with("HTTP/1.1 400 "),
            "{target} should be refused as malformed, got: {raw}"
        );
    }

    // And an id that is well-formed but not warrant-shaped is refused too, with its own code.
    let response = route(&mut api, &get(&["v1", "warrants", "issuer.key"]));
    assert_eq!(response.status, status::BAD_REQUEST);
    assert_eq!(code_of(&response), "malformed_warrant_id");
}

#[test]
fn a_known_route_reached_with_the_wrong_method_is_405_with_allow() {
    let dir = tempdir("methods");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_m");

    let response = route(
        &mut api,
        &HttpRequest::new(
            "POST",
            &["v1", "warrants", "wrt_m", "report"],
            BTreeMap::new(),
        )
        .with_bearer(TOKEN),
    );
    assert_eq!(response.status, status::METHOD_NOT_ALLOWED);
    assert_eq!(code_of(&response), "method_not_allowed");

    let response = route(
        &mut api,
        &HttpRequest::new(
            "GET",
            &["v1", "warrants", "wrt_m", "settle"],
            BTreeMap::new(),
        )
        .with_bearer(TOKEN),
    );
    assert_eq!(response.status, status::METHOD_NOT_ALLOWED);
}

/// There is no `grant` over HTTP, and the absence is structural: no route resolves to one.
#[test]
fn nothing_on_this_surface_mints_authority() {
    let dir = tempdir("no-grant");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_g");

    for path in [
        vec!["v1", "warrants", "wrt_g", "grant"],
        vec!["v1", "grant"],
        vec!["v1", "warrants", "wrt_g", "delegate"],
        vec!["v1", "warrants", "wrt_g", "bounds"],
    ] {
        let response = route(
            &mut api,
            &HttpRequest::new("POST", &path, BTreeMap::new()).with_bearer(TOKEN),
        );
        assert_eq!(
            response.status,
            status::NOT_FOUND,
            "{path:?} must not be a route: grant holds the issuer key"
        );
    }
    // Creating a warrant by POSTing the collection is not a thing either.
    let response = route(
        &mut api,
        &HttpRequest::new("POST", &["v1", "warrants"], BTreeMap::new()).with_bearer(TOKEN),
    );
    assert_eq!(response.status, status::METHOD_NOT_ALLOWED);
}

#[test]
fn an_unrecognised_filter_is_refused_rather_than_ignored() {
    let dir = tempdir("filters");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_f");

    let mut query = BTreeMap::new();
    query.insert("status".to_string(), "open".to_string());
    let response = route(
        &mut api,
        &HttpRequest::new("GET", &["v1", "warrants"], query).with_bearer(TOKEN),
    );
    assert_eq!(response.status, status::BAD_REQUEST);
    assert_eq!(code_of(&response), "malformed_query");

    let mut query = BTreeMap::new();
    query.insert("since".to_string(), "yesterday".to_string());
    let response = route(
        &mut api,
        &HttpRequest::new("GET", &["v1", "warrants"], query).with_bearer(TOKEN),
    );
    assert_eq!(response.status, status::BAD_REQUEST);

    // The filters that do exist work, and filtering to nothing is not an error.
    let mut query = BTreeMap::new();
    query.insert("state".to_string(), "settled".to_string());
    let response = route(
        &mut api,
        &HttpRequest::new("GET", &["v1", "warrants"], query).with_bearer(TOKEN),
    );
    assert_eq!(response.status, status::OK);
    assert_eq!(response.body["data"]["count"], 0);
}

// ── the verification envelope ─────────────────────────────────────────────────────────

#[test]
fn every_read_route_carries_a_server_computed_verdict() {
    let dir = tempdir("verdicts");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_v");

    let routes: Vec<Vec<&str>> = vec![
        vec!["v1", "health"],
        vec!["v1", "warrants"],
        vec!["v1", "warrants", "wrt_v"],
        vec!["v1", "warrants", "wrt_v", "report"],
        vec!["v1", "warrants", "wrt_v", "effects"],
        vec!["v1", "warrants", "wrt_v", "refusals"],
        vec!["v1", "warrants", "wrt_v", "evidence"],
        vec!["v1", "summary", "refusals"],
        vec!["v1", "summary", "daily"],
    ];
    for path in routes {
        let response = route(&mut api, &get(&path));
        assert_eq!(response.status, status::OK, "{path:?}: {}", response.body);
        let verification = &response.body["verification"];
        assert!(
            verification.is_object(),
            "{path:?} must carry a verification verdict"
        );
        assert!(response.body["verified"].is_boolean(), "{path:?}");
        for field in ["integrity", "liveness", "checked_at", "reason"] {
            assert!(
                !verification[field].is_null(),
                "{path:?} is missing {field}"
            );
        }
        // Three-valued, never collapsed to a boolean pair.
        assert!(
            matches!(
                verification["integrity"].as_str(),
                Some("ok" | "failed" | "unknown")
            ),
            "{path:?}: {verification}"
        );
    }
}

#[test]
fn a_report_verifies_and_the_verdict_is_the_servers_own() {
    let dir = tempdir("report");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_r");

    let response = route(&mut api, &get(&["v1", "warrants", "wrt_r", "report"]));
    assert_eq!(response.status, status::OK, "{}", response.body);
    assert_eq!(response.body["verified"], Value::Bool(true));
    assert_eq!(response.body["verification"]["integrity"], "ok");
    assert_eq!(response.body["verification"]["liveness"], "live");
    assert_eq!(response.body["verification"]["checked_at"], NOW);
    assert!(response.body["verification"]["digest"].is_string());
    assert!(response.body["verification"]["signed_by"].is_string());
    // The bundle is present and is the same object every other surface renders.
    assert_eq!(response.body["data"]["bundle"]["warrant_id"], "wrt_r");
    assert!(response.body["data"]["bundle"]["limitations"]
        .as_array()
        .is_some_and(|l| !l.is_empty()));
    // The evidence route carries the whole export, so a third party can re-verify it elsewhere.
    let evidence = route(&mut api, &get(&["v1", "warrants", "wrt_r", "evidence"]));
    assert!(evidence.body["data"]["export"]["notary_receipt"].is_object());
    assert!(evidence.body["data"]["export"]["evidence_receipt"].is_object());
}

/// Intact-but-stale and corrupt want opposite responses from whoever is reading, so they are two
/// fields and never one.
#[test]
fn an_expired_report_is_expired_not_tampered() {
    let dir = tempdir("expired");
    let stored = warrant_with("wrt_old", NOW - 10, 1);
    WarrantStore::open(&dir)
        .expect("store")
        .save(&stored)
        .expect("save");
    let mut api = api(&dir, true);

    let response = route(&mut api, &get(&["v1", "warrants", "wrt_old", "report"]));
    assert_eq!(response.status, status::OK);
    assert_eq!(
        response.body["verification"]["integrity"], "ok",
        "a lapsed deadline is not tampering"
    );
    assert_eq!(response.body["verification"]["liveness"], "expired");
    assert_eq!(
        response.body["verified"],
        Value::Bool(true),
        "an archived report must not rot into 'does not verify'"
    );
}

/// A record that fails verification is the single most important thing to put in front of a human,
/// so it is served and marked rather than hidden behind a 500.
#[test]
fn a_warrant_signed_by_another_key_is_served_marked_rather_than_hidden() {
    let dir = tempdir("tampered");
    let stored = warrant_with("wrt_bad", NOW + 3600, 9);
    WarrantStore::open(&dir)
        .expect("store")
        .save(&stored)
        .expect("save");
    let mut api = api(&dir, true);

    let response = route(&mut api, &get(&["v1", "warrants", "wrt_bad"]));
    assert_eq!(response.status, status::OK, "not hidden behind an error");
    assert_eq!(response.body["verified"], Value::Bool(false));
    assert_eq!(response.body["verification"]["integrity"], "failed");
    assert_eq!(response.body["verification"]["code"], "signature_invalid");
    // The key a broken record CLAIMS is not reported: a forged file must not put a
    // trusted-looking key in front of a reader.
    assert!(response.body["verification"]["signed_by"].is_null());
    // The listing agrees, per entry and in the aggregate.
    let listing = route(&mut api, &get(&["v1", "warrants"]));
    assert_eq!(listing.body["verification"]["integrity"], "failed");
    assert_eq!(
        listing.body["data"]["warrants"][0]["verified"],
        Value::Bool(false)
    );
}

/// Reads fail open and marked. The three acts fail closed.
#[test]
fn the_three_acts_refuse_a_warrant_whose_signature_does_not_verify() {
    let dir = tempdir("failclosed");
    let stored = warrant_with("wrt_bad", NOW + 3600, 9);
    WarrantStore::open(&dir)
        .expect("store")
        .save(&stored)
        .expect("save");
    let mut api = api(&dir, true);

    for act in ["settle", "void", "stop"] {
        let response = route(
            &mut api,
            &post(&["v1", "warrants", "wrt_bad", act], &serde_json::json!({})),
        );
        assert_eq!(
            response.status,
            status::FORBIDDEN,
            "{act} must refuse an unattested warrant"
        );
        assert_eq!(code_of(&response), "integrity_failed");
    }
    // And it is still Open: nothing was performed.
    let after = WarrantStore::open(&dir)
        .expect("store")
        .load("wrt_bad")
        .expect("load");
    assert_eq!(after.warrant.state, WarrantState::Open);
}

// ── the three acts ────────────────────────────────────────────────────────────────────

#[test]
fn a_server_without_release_authority_refuses_settle_and_void_by_name_but_still_stops() {
    let dir = tempdir("no-settle");
    let mut api = api(&dir, false);
    seed(&dir, "wrt_ns");

    for act in ["settle", "void"] {
        let response = route(
            &mut api,
            &post(&["v1", "warrants", "wrt_ns", act], &serde_json::json!({})),
        );
        assert_eq!(response.status, status::FORBIDDEN);
        assert_eq!(code_of(&response), "settle_authority_absent");
    }
    // Stop needs only the issuer key -- it releases nothing -- so it is still reachable.
    let response = route(
        &mut api,
        &post(
            &["v1", "warrants", "wrt_ns", "stop"],
            &serde_json::json!({ "reason": "the console said so" }),
        ),
    );
    assert_ne!(code_of(&response), "settle_authority_absent");
    assert!(
        response.status == status::OK || response.status == status::CONFLICT,
        "stop returns its record either way, got {}: {}",
        response.status,
        response.body
    );
    let held = WarrantStore::open(&dir)
        .expect("store")
        .load("wrt_ns")
        .expect("load");
    assert_eq!(
        held.warrant.state,
        WarrantState::Held,
        "stop holds the work rather than discarding it"
    );
}

#[test]
fn settling_twice_is_a_conflict_rather_than_a_second_settle() {
    let dir = tempdir("settle");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_s");

    let first = route(
        &mut api,
        &post(
            &["v1", "warrants", "wrt_s", "settle"],
            &serde_json::json!({}),
        ),
    );
    assert_eq!(first.status, status::OK, "{}", first.body);
    assert_eq!(first.body["data"]["state"], "settled");
    assert_eq!(first.body["data"]["complete"], Value::Bool(true));

    let second = route(
        &mut api,
        &post(
            &["v1", "warrants", "wrt_s", "settle"],
            &serde_json::json!({}),
        ),
    );
    assert_eq!(second.status, status::CONFLICT);
    assert_eq!(code_of(&second), "wrong_state");

    // A void after a settle is refused for the same reason.
    let voided = route(
        &mut api,
        &post(&["v1", "warrants", "wrt_s", "void"], &serde_json::json!({})),
    );
    assert_eq!(voided.status, status::CONFLICT);
}

#[test]
fn a_malformed_field_on_a_mutating_route_is_refused_rather_than_defaulted() {
    let dir = tempdir("fields");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_x");

    let response = route(
        &mut api,
        &post(
            &["v1", "warrants", "wrt_x", "settle"],
            &serde_json::json!({ "commit": 17 }),
        ),
    );
    assert_eq!(response.status, status::BAD_REQUEST);
    assert_eq!(code_of(&response), "malformed_field");
    // Nothing happened.
    let after = WarrantStore::open(&dir)
        .expect("store")
        .load("wrt_x")
        .expect("load");
    assert_eq!(after.warrant.state, WarrantState::Open);
}

// ── refusals: the tuning signal ───────────────────────────────────────────────────────

fn tool_refusal(tool: &str, count: u32) -> AuthorityRequest {
    AuthorityRequest {
        tool: tool.to_string(),
        bound: "tools".to_string(),
        reason: format!("{tool} is not in this warrant's tool allowlist"),
        count,
    }
}

fn egress_refusal(tool: &str, destination: &str, count: u32) -> EgressRefusal {
    EgressRefusal {
        tool: tool.to_string(),
        argument: "url".to_string(),
        destination: destination.to_string(),
        capability: format!("net.egress:{destination}"),
        reason: DenyReason::NotInCatalog,
        count,
    }
}

/// The refusal-review habit as an API: the aggregate is what tells an operator whether the bound
/// was wrong or the agent was, and a per-run view cannot.
#[test]
fn refusals_aggregate_across_warrants_into_a_tuning_signal() {
    let dir = tempdir("refusals");
    let mut api = api(&dir, true);

    // curl: refused repeatedly, in four different runs. rm: once, in one run.
    for (index, count) in [(1u8, 8u32), (2, 6), (3, 5), (4, 4)] {
        let id = format!("wrt_run{index}");
        seed(&dir, &id);
        record_refusals(&dir, &id, &[&tool_refusal("curl", count)], &[], NOW).expect("record");
    }
    seed(&dir, "wrt_solo");
    record_refusals(&dir, "wrt_solo", &[&tool_refusal("rm", 1)], &[], NOW).expect("record");

    let response = route(&mut api, &get(&["v1", "summary", "refusals"]));
    assert_eq!(response.status, status::OK);
    let groups = response.body["data"]["groups"].as_array().expect("groups");

    let curl = groups
        .iter()
        .find(|g| g["subject"] == "curl")
        .expect("curl group");
    assert_eq!(curl["occurrences"], 23, "8+6+5+4 across four warrants");
    assert_eq!(curl["warrants"], 4);
    assert_eq!(curl["signal"], "bounds_probably_wrong");
    assert!(
        curl["guidance"]
            .as_str()
            .is_some_and(|g| g.contains("23 times across 4 warrants")),
        "the guidance must state the number an operator acts on: {}",
        curl["guidance"]
    );

    let rm = groups
        .iter()
        .find(|g| g["subject"] == "rm")
        .expect("rm group");
    assert_eq!(rm["occurrences"], 1);
    assert_eq!(rm["signal"], "isolated");
    // Loudest first, so a console renders the same order every time.
    assert_eq!(groups[0]["subject"], "curl");
    // The verdict says plainly that this log is unsigned, which is the honest claim to make.
    assert_eq!(response.body["verification"]["integrity"], "unknown");
    assert_eq!(response.body["verification"]["code"], "unsigned_record");

    // Per-warrant, the same records with the same grouping.
    let one = route(&mut api, &get(&["v1", "warrants", "wrt_solo", "refusals"]));
    assert_eq!(one.status, status::OK);
    assert_eq!(
        one.body["data"]["records"]
            .as_array()
            .expect("records")
            .len(),
        1
    );
}

/// A GET with a query string attached.
fn get_with(path: &[&str], query: &[(&str, &str)]) -> HttpRequest {
    let map: BTreeMap<String, String> = query
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    HttpRequest::new("GET", path, map).with_bearer(TOKEN)
}

/// The defect this window exists to close: the route answered 200 to a filter it never applied.
///
/// `request.query` was read at exactly one place — inside `list_filter`, reached only from
/// `Target::List` — so `/v1/summary/refusals?since=X` returned the ALL-TIME aggregate. A console
/// rendering that under a month heading is the `?status=open silently returning every warrant`
/// defect wearing a nicer font, on the surface whose whole job is not to overstate what it knows.
#[test]
fn the_summary_window_filters_before_it_aggregates() {
    let dir = tempdir("summary-window");
    let mut api = api(&dir, true);

    let january = 1_767_225_600; // 2026-01-01T00:00:00Z
    let february = 1_769_904_000; // 2026-02-01T00:00:00Z
    let march = 1_772_323_200; // 2026-03-01T00:00:00Z

    // Enough of the same wall, in enough runs, to earn `bounds_probably_wrong` — but only if all
    // of it is counted. Half of it is in January and half in February.
    for (index, at) in [(1u8, january), (2, january), (3, february), (4, february)] {
        let id = format!("wrt_w{index}");
        seed(&dir, &id);
        record_refusals(&dir, &id, &[&tool_refusal("curl", 6)], &[], at).expect("record");
    }

    let all_time = route(&mut api, &get(&["v1", "summary", "refusals"]));
    assert_eq!(all_time.body["data"]["total_occurrences"], 24);
    assert_eq!(
        all_time.body["data"]["groups"][0]["signal"],
        "bounds_probably_wrong"
    );

    let jan = route(
        &mut api,
        &get_with(
            &["v1", "summary", "refusals"],
            &[
                ("since", &january.to_string()),
                ("until", &february.to_string()),
            ],
        ),
    );
    assert_eq!(jan.status, status::OK);
    assert_eq!(
        jan.body["data"]["total_occurrences"], 12,
        "a window that answered 24 here would be the all-time aggregate under a month heading"
    );
    assert_eq!(
        jan.body["data"]["window"]["records_in_window"], 2,
        "two records fall in January; the other two ended in February"
    );
    assert_eq!(jan.body["data"]["window"]["records_all_time"], 4);
    assert_eq!(jan.body["data"]["window"]["since"], january);
    assert_eq!(jan.body["data"]["window"]["until"], february);
    // The verdict is re-read for the window rather than inherited from the all-time set. Two
    // warrants is still spread, so this one stays loud — but it is loud on evidence the reader is
    // actually being shown.
    assert_eq!(jan.body["data"]["groups"][0]["warrants"], 2);
    assert!(
        jan.body["data"]["groups"][0]["guidance"]
            .as_str()
            .is_some_and(|g| g.contains("12 times across 2 warrants")),
        "the guidance has to state the number an operator acts on, for THIS window: {}",
        jan.body["data"]["groups"][0]["guidance"]
    );

    // A month in which nothing was recorded is an empty aggregate, not the all-time one.
    let mar = route(
        &mut api,
        &get_with(
            &["v1", "summary", "refusals"],
            &[("since", &march.to_string())],
        ),
    );
    assert_eq!(mar.body["data"]["total_occurrences"], 0);
    assert_eq!(
        mar.body["data"]["groups"].as_array().expect("groups").len(),
        0
    );
    assert!(
        mar.body["data"]["window"]["caveat"]
            .as_str()
            .is_some_and(|c| c.contains("SESSION ENDED")),
        "a windowed answer must carry the reason its boundary is not the boundary of a call"
    );
}

/// A window the API cannot apply must not be a window the API accepts.
#[test]
fn the_summary_route_refuses_a_query_it_cannot_honour() {
    let dir = tempdir("summary-query");
    let mut api = api(&dir, true);

    let refusals: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("an unknown key", vec![("month", "2026-08")]),
        ("a key that is nearly right", vec![("state", "open")]),
        ("a since that is not a number", vec![("since", "august")]),
        ("a negative since", vec![("since", "-1")]),
        (
            "an inverted window",
            vec![("since", "200"), ("until", "100")],
        ),
        ("an empty window", vec![("since", "100"), ("until", "100")]),
    ];
    for (why, query) in refusals {
        let response = route(&mut api, &get_with(&["v1", "summary", "refusals"], &query));
        assert_eq!(
            response.status,
            status::BAD_REQUEST,
            "{why} must be refused rather than ignored"
        );
        assert_eq!(code_of(&response), "malformed_query", "{why}");
    }

    // And the honest window still works.
    let ok = route(
        &mut api,
        &get_with(
            &["v1", "summary", "refusals"],
            &[("since", "100"), ("until", "200")],
        ),
    );
    assert_eq!(ok.status, status::OK);
}

/// The other ten routes had no query parser at all, which is the same failure one level quieter.
///
/// `GET /v1/warrants/{id}?state=settled` answered 200 with the warrant, which reads as though the
/// parameter meant something. It never did. This is a behaviour change to `/v1` and the right one:
/// the alternative is a surface where whether a filter is honoured depends on which route was hit.
#[test]
fn a_route_with_no_filters_refuses_a_query_rather_than_ignoring_it() {
    let dir = tempdir("no-query");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_q");

    let routes: [&[&str]; 5] = [
        &["v1", "health"],
        &["v1", "warrants", "wrt_q"],
        &["v1", "warrants", "wrt_q", "report"],
        &["v1", "warrants", "wrt_q", "refusals"],
        &["v1", "summary", "daily"],
    ];
    for path in routes {
        let ignored = route(&mut api, &get_with(path, &[("state", "settled")]));
        assert_eq!(
            ignored.status,
            status::BAD_REQUEST,
            "{path:?} accepted a filter it does not have"
        );
        assert_eq!(code_of(&ignored), "malformed_query", "{path:?}");
        // Unchanged without one.
        assert_eq!(route(&mut api, &get(path)).status, status::OK, "{path:?}");
    }
}

/// The proxy books an egress denial twice. Counting both would double every egress number.
#[test]
fn an_egress_denial_is_recorded_once_and_keeps_its_destination() {
    let dir = tempdir("egress-refusals");

    let authority = AuthorityRequest {
        tool: "http.get".to_string(),
        bound: "egress_hosts".to_string(),
        reason: "egress to evil.example is refused".to_string(),
        count: 3,
    };
    let written = record_refusals(
        &dir,
        "wrt_e",
        &[&authority],
        &[&egress_refusal("http.get", "evil.example", 3)],
        NOW,
    )
    .expect("record");
    assert_eq!(written, 1, "the egress_hosts authority request is dropped");

    let log = read_all_refusals(&dir);
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.unreadable_lines, 0);
    let groups = aggregate_refusals(&log.records);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].subject, "evil.example");
    assert_eq!(groups[0].occurrences, 3);
    assert_eq!(groups[0].signal, RefusalSignal::Isolated);

    // A torn or garbage line is counted, not silently dropped.
    let path = dir.join("refusals").join("wrt_e.jsonl");
    let mut body = std::fs::read_to_string(&path).expect("read");
    body.push_str("{\"format\":\"warrantor.refu\n");
    std::fs::write(&path, body).expect("write");
    let log = read_all_refusals(&dir);
    assert_eq!(log.records.len(), 1);
    assert_eq!(
        log.unreadable_lines, 1,
        "a short count must carry its own signal"
    );
}

// ── honesty of the wire ───────────────────────────────────────────────────────────────

#[test]
fn no_error_body_carries_a_filesystem_path_or_an_internal_error_string() {
    let dir = tempdir("no-paths");
    let mut api = api(&dir, false);
    seed(&dir, "wrt_p");
    let root = dir.display().to_string();

    let failures = vec![
        route(&mut api, &get(&["v1", "warrants", "wrt_missing"])),
        route(&mut api, &get(&["v1", "nope"])),
        route(&mut api, &get(&["v1", "warrants", "not-an-id"])),
        route(
            &mut api,
            &post(
                &["v1", "warrants", "wrt_p", "settle"],
                &serde_json::json!({}),
            ),
        ),
        handle(
            &mut api,
            &token(),
            &HttpRequest::new("GET", &["v1", "warrants"], BTreeMap::new()),
        ),
    ];
    for response in &failures {
        let text = response.body.to_string();
        assert!(
            !text.contains(&root),
            "an error body leaked the store root: {text}"
        );
        assert!(
            !text.contains(".warrantor") && !text.contains("issuer.key"),
            "an error body leaked store layout: {text}"
        );
        assert!(
            response.body.pointer("/error/code").is_some(),
            "every failure needs a stable machine code: {text}"
        );
        assert!(response.body["verification"].is_object());
    }
}

#[test]
fn unreadable_warrant_files_are_counted_rather_than_silently_dropped() {
    let dir = tempdir("unreadable");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_good");
    std::fs::write(dir.join("warrants").join("wrt_corrupt.json"), b"{ not json")
        .expect("write corrupt");

    let response = route(&mut api, &get(&["v1", "warrants"]));
    assert_eq!(response.status, status::OK);
    assert_eq!(response.body["data"]["count"], 1);
    assert_eq!(
        response.body["data"]["unreadable_records"], 1,
        "a listing shorter than the directory must say so"
    );
    assert!(response.body["verification"]["reason"]
        .as_str()
        .is_some_and(|r| r.contains("could not be parsed")));

    let daily = route(&mut api, &get(&["v1", "summary", "daily"]));
    assert_eq!(daily.body["data"]["unreadable_records"], 1);
    assert_eq!(
        daily.body["data"]["needs_decision"]
            .as_array()
            .expect("array")
            .len(),
        1
    );
}

/// The warning is the only thing standing between an operator and an unintended exposure, so its
/// wording is tested rather than trusted.
#[test]
fn the_non_loopback_warning_names_what_became_reachable_and_never_implies_tls() {
    let root = Path::new("/home/dev/.warrantor");

    assert!(
        bind_warning("127.0.0.1:8787".parse().expect("addr"), root, true).is_none(),
        "loopback needs no warning"
    );
    assert!(bind_warning("[::1]:8787".parse().expect("addr"), root, true).is_none());

    let warning = bind_warning("0.0.0.0:8787".parse().expect("addr"), root, true)
        .expect("a non-loopback bind must warn");
    assert!(warning.contains("NOT loopback"));
    assert!(warning.contains("0.0.0.0:8787"));
    assert!(warning.contains("settle, void and stop are reachable"));
    assert!(
        warning.contains("no TLS"),
        "it must not imply confidentiality"
    );
    assert!(warning.contains("in the clear"));

    let read_only =
        bind_warning("0.0.0.0:8787".parse().expect("addr"), root, false).expect("warning");
    assert!(read_only.contains("settle and void refuse"));
    assert!(read_only.contains("stop is reachable"));
}

#[test]
fn the_verdict_types_stay_three_valued() {
    // A compile-time guard as much as a runtime one: collapsing either of these to a boolean is
    // how "unknown" starts being rendered as "failed".
    assert_ne!(Integrity::Unknown, Integrity::Failed);
    assert_ne!(Integrity::Unknown, Integrity::Ok);
    assert_ne!(Liveness::Unknown, Liveness::Expired);
    assert_ne!(Liveness::Unknown, Liveness::Live);
}

// ── the CLI verb's two side effects: a token on disk, and a way to stop ────────────────

#[test]
fn the_token_file_lands_under_the_store_root_and_holds_exactly_the_token() {
    let dir = tempdir("token-default");
    let minted = SessionToken::mint().expect("mint");

    let path = minted.write_to(&dir).expect("write");

    assert_eq!(
        path,
        default_token_path(&dir),
        "the printed path and the written path must be the same path"
    );
    assert!(path.starts_with(&dir), "the token belongs to its own store");
    let written = std::fs::read_to_string(&path).expect("read back");
    assert_eq!(written, minted.as_str());
    // No trailing newline. `$(cat token)` is how this is used, and a newline that survives into an
    // Authorization header is a 401 nobody can explain.
    assert!(!written.ends_with('\n'));
    assert!(SessionToken::from_value(written).matches(minted.as_str()));
}

/// The permission is the whole point of writing it to a file rather than only printing it.
#[cfg(unix)]
#[test]
fn on_unix_the_token_is_owner_only_inside_an_owner_only_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir("token-mode");
    let path = SessionToken::mint()
        .expect("mint")
        .write_to(&dir)
        .expect("write");

    let file_mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600, "another local user must not read it");
    let dir_mode = std::fs::metadata(path.parent().expect("parent"))
        .expect("stat dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "nor list the directory holding it");
}

#[test]
fn a_second_run_leaves_no_tail_of_the_first_runs_token() {
    let dir = tempdir("token-truncate");
    let path = default_token_path(&dir);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    // A longer previous value, as a run under a future format could leave.
    std::fs::write(&path, "x".repeat(200)).expect("seed");

    let minted = SessionToken::mint().expect("mint");
    minted.write_to(&dir).expect("write");

    let written = std::fs::read_to_string(&path).expect("read back");
    assert_eq!(
        written,
        minted.as_str(),
        "a rewrite must truncate, not overwrite a prefix"
    );
}

#[test]
fn a_named_token_file_is_written_where_it_was_named() {
    let dir = tempdir("token-named");
    let path = dir.join("somewhere-else.token");
    let minted = SessionToken::mint().expect("mint");

    minted.write_to_file(&path).expect("write");

    assert_eq!(
        std::fs::read_to_string(&path).expect("read back"),
        minted.as_str()
    );
    assert!(
        !default_token_path(&dir).exists(),
        "naming a path must not also write the default one"
    );
}

/// `--token-file` into a directory that is not there is a refusal, and the refusal happens before
/// anything is created. A server that mkdir'd a tree to park a secret in would be making a decision
/// about where secrets live that belongs to the operator.
#[test]
fn a_named_token_file_in_a_missing_directory_is_refused_and_creates_nothing() {
    let dir = tempdir("token-missing-dir");
    let missing = dir.join("not-created").join("deeper");
    let path = missing.join("token");

    let refusal = SessionToken::mint()
        .expect("mint")
        .write_to_file(&path)
        .expect_err("a missing directory must refuse");

    assert!(refusal.to_string().contains("does not exist"), "{refusal}");
    assert!(!missing.exists(), "nothing may be created on the way out");
    assert!(!path.exists());
}

#[test]
fn a_shutdown_is_not_asked_for_until_it_is_asked_for_and_every_clone_sees_it() {
    let shutdown = Shutdown::new();
    assert!(
        !shutdown.stopping(),
        "a fresh server must not start out stopping"
    );

    // The accept loop holds one handle and the caller another; they are the same request.
    let watcher = shutdown.clone();
    assert!(!watcher.stopping());
    shutdown.stop();
    assert!(watcher.stopping(), "a clone must see the stop");
    assert!(shutdown.stopping(), "and it must stay stopped");
}

// ── the round trip a console actually makes ───────────────────────────────────────────

/// One warrant, over the wire, along the path a console walks: list it, open it, read its report.
/// Every hop carries a server-computed verdict, and the id survives all three unchanged.
#[test]
fn a_warrant_round_trips_over_the_wire_from_list_to_detail_to_report() {
    let dir = tempdir("round-trip");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_trip");

    let listing = body_of(&round_trip(
        &mut api,
        &format!(
            "GET /v1/warrants HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    ));
    assert_eq!(listing["data"]["count"], 1);
    let id = listing["data"]["warrants"][0]["id"]
        .as_str()
        .expect("an id in the listing")
        .to_string();
    assert_eq!(id, "wrt_trip");
    // A listing carries no host layout: has_worktree, not a path.
    assert!(listing["data"]["warrants"][0]["worktree"].is_null());

    let detail = body_of(&round_trip(
        &mut api,
        &format!(
            "GET /v1/warrants/{id} HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer \
             {TOKEN}\r\n\r\n"
        ),
    ));
    assert_eq!(detail["data"]["id"], "wrt_trip");
    assert_eq!(detail["data"]["state"], "open");
    assert_eq!(detail["verified"], Value::Bool(true));

    let report = body_of(&round_trip(
        &mut api,
        &format!(
            "GET /v1/warrants/{id}/report HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer \
             {TOKEN}\r\n\r\n"
        ),
    ));
    assert_eq!(report["data"]["bundle"]["warrant_id"], "wrt_trip");
    assert_eq!(report["verification"]["integrity"], "ok");
    // The client is handed the verdict; it is never asked to compute one.
    assert_eq!(report["verified"], Value::Bool(true));
}

/// A route nobody wrote is a 404 that says nothing about the store behind it.
#[test]
fn an_unknown_route_is_404_and_describes_nothing() {
    let dir = tempdir("unknown-route");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_u");

    for path in [
        vec!["v1", "nope"],
        vec!["v1"],
        vec!["v2", "warrants"],
        vec!["v1", "warrants", "wrt_u", "nope"],
        vec!["v1", "summary", "nope"],
        vec!["v1", "warrants", "wrt_u", "report", "extra"],
    ] {
        let response = route(&mut api, &get(&path));
        assert_eq!(
            response.status,
            status::NOT_FOUND,
            "{path:?} must not route"
        );
        assert_eq!(code_of(&response), "no_such_route", "{path:?}");
        let text = response.body.to_string();
        assert!(
            !text.contains("wrt_u"),
            "a 404 must not confirm an id: {text}"
        );
        // Even a 404 carries the envelope, so a client never branches on whether it exists.
        assert!(response.body["verification"].is_object(), "{path:?}");
    }

    // The same target over the whole wire path, so the framing layer agrees with the router.
    let raw = round_trip(
        &mut api,
        &format!(
            "GET /v1/nope HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    );
    assert!(raw.starts_with("HTTP/1.1 404 "), "{raw}");
}

/// The three acts a human must make are each reachable, on a server that holds release authority.
/// This is the counterpart to the fail-closed tests: those prove refusal, this proves the door is
/// actually there.
#[test]
fn settle_void_and_stop_are_each_reachable_and_each_moves_the_warrant() {
    let dir = tempdir("three-acts");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_a");
    seed(&dir, "wrt_b");
    seed(&dir, "wrt_c");

    // A commit message on a warrant with no worktree is refused, not quietly dropped: the caller
    // asked for something this warrant cannot do, and answering 200 would say it was done.
    let asked_to_commit = route(
        &mut api,
        &post(
            &["v1", "warrants", "wrt_a", "settle"],
            &serde_json::json!({ "commit": "the console settled it" }),
        ),
    );
    assert_eq!(asked_to_commit.status, status::CONFLICT);
    assert_eq!(code_of(&asked_to_commit), "no_worktree");

    let settled = route(
        &mut api,
        &post(
            &["v1", "warrants", "wrt_a", "settle"],
            &serde_json::json!({}),
        ),
    );
    assert_eq!(settled.status, status::OK, "{}", settled.body);
    assert_eq!(settled.body["data"]["state"], "settled");

    let voided = route(
        &mut api,
        &post(&["v1", "warrants", "wrt_b", "void"], &serde_json::json!({})),
    );
    assert_eq!(voided.status, status::OK, "{}", voided.body);
    assert_eq!(voided.body["data"]["state"], "void");

    let stopped = route(
        &mut api,
        &post(
            &["v1", "warrants", "wrt_c", "stop"],
            &serde_json::json!({ "reason": "the operator said stop" }),
        ),
    );
    assert!(
        stopped.status == status::OK || stopped.status == status::CONFLICT,
        "stop returns its record either way, got {}: {}",
        stopped.status,
        stopped.body
    );

    // The store is the record, not the response: read it back through a fresh handle.
    let store = WarrantStore::open(&dir).expect("store");
    assert_eq!(
        store.load("wrt_a").expect("load").warrant.state,
        WarrantState::Settled
    );
    assert_eq!(
        store.load("wrt_b").expect("load").warrant.state,
        WarrantState::Void
    );
    assert_eq!(
        store.load("wrt_c").expect("load").warrant.state,
        WarrantState::Held,
        "stop holds the work for a decision rather than discarding it"
    );
}

//! The console assets, and the boundary they are allowed to cross.
//!
//! `serve.rs` answers `/v1` with a 401 *before* it resolves a route, so an unauthenticated caller
//! cannot tell a real warrant id from an invented one. Serving a browser console punches one hole
//! in that: a browser cannot put an `Authorization` header on the navigation that loads a page, so
//! three paths have to answer without a token or the console can never be opened.
//!
//! These tests exist to hold that hole to exactly three paths and exactly three fixed byte
//! strings. The load-bearing one is
//! [`serving_the_console_does_not_make_the_api_reachable_without_a_token`] — everything else here
//! is detail, but that one is the property the whole surface rests on, and it is the one a future
//! change to `console_asset` would break first.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

use ed25519_dalek::SigningKey;

use warrantor_warrant::serve::{
    handle, no_adapter, serve_conn, status, HttpRequest, SessionToken, StoreApi,
};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

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
        "warrantor-console-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
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

fn seed(dir: &Path, id: &str, task: &str) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(
        id,
        task,
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    WarrantStore::open(dir)
        .expect("store")
        .save(&StoredWarrant {
            warrant,
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
        })
        .expect("save");
}

/// A request with no `Authorization` header at all — what a browser sends on navigation.
fn anonymous(method: &str, path: &[&str]) -> HttpRequest {
    HttpRequest::new(method, path, BTreeMap::new())
}

fn wire(api: &mut StoreApi, raw: &str) -> String {
    let mut input = Cursor::new(raw.as_bytes().to_vec());
    let mut output: Vec<u8> = Vec::new();
    serve_conn(api, &token(), &mut input, &mut output).expect("write");
    String::from_utf8(output).expect("utf8")
}

fn headers_of(raw: &str) -> String {
    raw.split_once("\r\n\r\n")
        .map(|(head, _)| head.to_ascii_lowercase())
        .expect("header/body split")
}

fn body_of(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").expect("header/body split").1
}

// ── THE property ──────────────────────────────────────────────────────────────────────

/// The load-bearing test.
///
/// Three console paths answer without a token. Nothing else may. If a future refactor makes
/// `console_asset` match too eagerly — a wildcard, a prefix test, a fallthrough to `index.html`
/// for unknown paths — this fails, and it fails on the exact request an attacker would send.
#[test]
fn serving_the_console_does_not_make_the_api_reachable_without_a_token() {
    let dir = tempdir("boundary");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_real", "fix the auth bug");

    for path in [
        vec!["v1", "health"],
        vec!["v1", "warrants"],
        vec!["v1", "warrants", "wrt_real"],
        vec!["v1", "warrants", "wrt_real", "report"],
        vec!["v1", "warrants", "wrt_real", "settle"],
        vec!["v1", "summary", "daily"],
    ] {
        let response = handle(&mut api, &token(), &anonymous("GET", &path));
        assert_eq!(
            response.status,
            status::UNAUTHORIZED,
            "/{} must still refuse an anonymous caller",
            path.join("/")
        );
    }
}

/// The console must not become a way to read a warrant id out of an unauthenticated response.
#[test]
fn an_unknown_path_is_not_quietly_answered_with_the_console() {
    let dir = tempdir("unknown");
    let mut api = api(&dir, false);

    // A single-segment path that is not one of the three assets. If this returned the document,
    // `console_asset` would be a catch-all and the 401 boundary would be a fiction.
    let response = handle(&mut api, &token(), &anonymous("GET", &["dashboard"]));
    assert_eq!(response.status, status::UNAUTHORIZED);
}

// ── the assets themselves ─────────────────────────────────────────────────────────────

#[test]
fn the_console_document_is_served_to_a_caller_with_no_token() {
    let dir = tempdir("document");
    let mut api = api(&dir, false);

    let raw = wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    let headers = headers_of(&raw);

    assert!(raw.starts_with("HTTP/1.1 200 OK"), "got: {raw:.60}");
    assert!(
        headers.contains("content-type: text/html; charset=utf-8"),
        "the document must be served as html, not as json: {headers}"
    );
    assert!(body_of(&raw).contains("<title>Warrantor</title>"));
}

#[test]
fn each_asset_is_served_as_its_own_type() {
    let dir = tempdir("types");
    let mut api = api(&dir, false);

    for (path, expected) in [
        ("/console.css", "content-type: text/css; charset=utf-8"),
        (
            "/console.js",
            "content-type: text/javascript; charset=utf-8",
        ),
    ] {
        let raw = wire(
            &mut api,
            &format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n"),
        );
        assert!(raw.starts_with("HTTP/1.1 200 OK"), "{path}: {raw:.60}");
        assert!(
            headers_of(&raw).contains(expected),
            "{path} should be {expected}"
        );
    }
}

/// The policy is the reason serving an unauthenticated document is safe.
///
/// `connect-src 'self'` is the one that matters: the console holds a token to an API that can hold
/// settle authority, so what must be impossible is not script execution but *exfiltration*. A
/// script with nowhere to send the token cannot leak it.
#[test]
fn console_assets_carry_the_policy_that_keeps_a_token_from_leaving() {
    let dir = tempdir("policy");
    let mut api = api(&dir, true);

    let headers = headers_of(&wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n"));

    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ] {
        assert!(
            headers.contains(directive),
            "the console policy must carry {directive}: {headers}"
        );
    }
    assert!(headers.contains("x-frame-options: deny"));
    assert!(headers.contains("referrer-policy: no-referrer"));
    // Inherited from the shared writer, and worth pinning here too: a sniffed content type would
    // undo the type declarations above.
    assert!(headers.contains("x-content-type-options: nosniff"));
    // No CORS header, ever. One would let any page in the user's browser reach this API.
    assert!(
        !headers.contains("access-control-allow-origin"),
        "the console must not be granted a CORS header: {headers}"
    );
}

/// The claim in `console_asset`'s doc comment, tested rather than asserted.
///
/// The assets are fixed byte strings compiled into the binary, so they cannot carry a store path,
/// a warrant id or a token. Two servers on different roots — one holding a warrant, one empty —
/// must answer byte-identically. If someone later templates the store path or a warrant count into
/// the document, this fails, and serving it unauthenticated stops being safe.
#[test]
fn the_console_is_byte_identical_across_stores_because_it_carries_no_store_data() {
    let populated_dir = tempdir("populated");
    let empty_dir = tempdir("empty");
    seed(
        &populated_dir,
        "wrt_secret",
        "a task name that must never reach an anonymous response",
    );

    let mut populated = api(&populated_dir, true);
    let mut empty = api(&empty_dir, false);

    for path in ["/", "/console.css", "/console.js"] {
        let request = format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        let from_populated = wire(&mut populated, &request);
        let from_empty = wire(&mut empty, &request);
        assert_eq!(
            from_populated, from_empty,
            "{path} differed between two stores, so it is carrying store data"
        );
        assert!(!from_populated.contains("wrt_secret"));
        assert!(!from_populated.contains(&populated_dir.display().to_string()));
        assert!(!from_populated.contains(TOKEN));
    }
}

#[test]
fn a_non_get_on_a_console_path_is_refused_with_the_method_it_wanted() {
    let dir = tempdir("method");
    let mut api = api(&dir, true);

    let response = handle(&mut api, &token(), &anonymous("POST", &[]));
    assert_eq!(response.status, status::METHOD_NOT_ALLOWED);

    let raw = wire(
        &mut api,
        "POST /console.js HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
    );
    assert!(headers_of(&raw).contains("allow: get"));
}

/// `/index.html` is the same document as `/`, because a browser that was handed the one will
/// sometimes ask for the other.
#[test]
fn index_html_and_the_root_are_the_same_document() {
    let dir = tempdir("alias");
    let mut api = api(&dir, false);

    let root = wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    let named = wire(
        &mut api,
        "GET /index.html HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(root, named);
}

/// A token that *is* presented on an asset request changes nothing: the assets are public, and a
/// caller holding a token still gets the same bytes rather than a privileged variant.
#[test]
fn presenting_a_token_does_not_produce_a_different_console() {
    let dir = tempdir("same");
    let mut api = api(&dir, true);

    let anonymous_body = wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    let authenticated = wire(
        &mut api,
        &format!("GET / HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: Bearer {TOKEN}\r\n\r\n"),
    );
    assert_eq!(anonymous_body, authenticated);
}

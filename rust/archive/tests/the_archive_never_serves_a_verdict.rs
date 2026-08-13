//! The structural guard on rule 2: **the backend is a relay, never an authority.**
//!
//! The way this rule gets broken is not by someone deciding to break it. It is by reusing
//! [`warrantor_warrant::serve::Response`], whose `json` constructor puts `"verified": true` on every
//! body. On the local agent that field is correct — the verdict is computed in Rust on the
//! operator's own machine, from their own store. On a remote archive the identical field is a
//! verdict computed by a machine the audited party may control, and a console that renders
//! `verified` renders it without knowing the difference.
//!
//! So this file walks the body of **every route** and asserts that no key named `verified` or
//! `verification` appears anywhere in it, at any depth. It is a test about a field name because the
//! field name is the guardrail: nobody puts a green tick next to a key called `not_a_verdict`.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use warrantor_archive::device::{self, DEVICE_SCHEME};
use warrantor_archive::http::{self, ArchiveResponse};
use warrantor_archive::store::{Device, MemoryStore};
use warrantor_warrant::serve::{status, HttpRequest};

const NOW: u64 = 1_786_000_000;
const DEVICE: &str = "dev_00112233445566778899aabbccddeeff";

fn device_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn store_with_a_device() -> MemoryStore {
    let mut store = MemoryStore::new();
    store.enrol_without_a_code(Device {
        id: DEVICE.to_string(),
        label: "Ana's laptop".to_string(),
        public_key: hex::encode(device_key().verifying_key().to_bytes()),
        enrolled_at: NOW,
        revoked_at: None,
    });
    store
}

/// Build a request and sign it as an enrolled device would.
///
/// `nonce` is a parameter rather than generated, so a test that needs two requests can make them
/// distinct on purpose and the replay test can make them identical on purpose.
fn signed(method: &str, segments: &[&str], body: &[u8], nonce: &str) -> HttpRequest {
    let path = format!("/{}", segments.join("/"));
    let header = device::sign_request(&device_key(), method, &path, DEVICE, nonce, NOW, body);
    let mut request = HttpRequest::new(method, segments, BTreeMap::new());
    request.authorization = Some(header);
    request.body = body.to_vec();
    request
}

/// Every key name that appears anywhere in a JSON value, at any depth.
fn all_keys(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                out.push(key.clone());
                all_keys(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                all_keys(item, out);
            }
        }
        _ => {}
    }
}

/// The assertion, written once so every route gets exactly the same one.
fn assert_carries_no_verdict(label: &str, response: &ArchiveResponse) {
    if response.raw.is_some() {
        // A stored artifact is returned verbatim. Its contents are the submitter's, not the
        // archive's, so a `verified` key inside somebody's evidence file is not the archive
        // speaking — and rewriting those bytes to remove one would break the digest.
        return;
    }
    let mut keys = Vec::new();
    all_keys(&response.body, &mut keys);
    for forbidden in ["verified", "verification"] {
        assert!(
            !keys.iter().any(|k| k == forbidden),
            "{label} carries a {forbidden:?} key. That field is a server-computed verdict, and \
             this server is a relay: a viewer would render it as an answer about evidence the \
             archive did not produce and cannot check authoritatively. Use `not_a_verdict`."
        );
    }
    assert!(
        keys.iter().any(|k| k == "not_a_verdict"),
        "{label} carries no not_a_verdict block. Every answer must say what the archive's opinion \
         is worth, which is nothing."
    );
}

#[test]
fn no_route_serves_a_field_a_client_could_render_as_a_verdict() {
    let mut store = store_with_a_device();

    // Health, which is answered before authentication.
    let health = http::handle(
        &mut store,
        &HttpRequest::new("GET", &["v1", "health"], BTreeMap::new()),
        NOW,
    );
    assert_eq!(health.status, status::OK);
    assert_carries_no_verdict("GET /v1/health", &health);

    // Submit, with a body that is not real evidence — the refusal path.
    let refused = http::handle(
        &mut store,
        &signed("POST", &["v1", "evidence"], b"{}", "n1"),
        NOW,
    );
    assert_eq!(refused.status, status::BAD_REQUEST);
    assert_carries_no_verdict("POST /v1/evidence (refused)", &refused);

    // Listing.
    let listing = http::handle(
        &mut store,
        &signed(
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "n2",
        ),
        NOW,
    );
    assert_eq!(listing.status, status::OK);
    assert_carries_no_verdict("GET /v1/warrants/{id}/evidence", &listing);

    // Fetch, missing.
    let missing = http::handle(
        &mut store,
        &signed("GET", &["v1", "evidence", &"a".repeat(64)], b"", "n3"),
        NOW,
    );
    assert_eq!(missing.status, status::NOT_FOUND);
    assert_carries_no_verdict("GET /v1/evidence/{digest} (missing)", &missing);

    // Enrolment, refused.
    let enrol_body = br#"{"code":"nope","public_key":"00"}"#;
    let mut enrol = HttpRequest::new("POST", &["v1", "devices", "enrol"], BTreeMap::new());
    enrol.body = enrol_body.to_vec();
    let enrolled = http::handle(&mut store, &enrol, NOW);
    assert_carries_no_verdict("POST /v1/devices/enrol", &enrolled);

    // An unknown route, and an unauthenticated one.
    let unknown = http::handle(
        &mut store,
        &HttpRequest::new("GET", &["v1", "settle"], BTreeMap::new()),
        NOW,
    );
    assert_eq!(unknown.status, status::NOT_FOUND);
    assert_carries_no_verdict("an unknown route", &unknown);

    let anonymous = http::handle(
        &mut store,
        &HttpRequest::new(
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            BTreeMap::new(),
        ),
        NOW,
    );
    assert_eq!(anonymous.status, status::UNAUTHORIZED);
    assert_carries_no_verdict("an unauthenticated read", &anonymous);
}

/// An artifact whose ingest check FAILED is still stored, still listed and still returned verbatim.
///
/// This is rule 5 in its most consequential form. A tampered file is the single most important
/// thing to be able to put in front of a human, so an archive that refused to hold one would be
/// destroying the evidence that it existed. The archive's job is to keep it and mark it — never to
/// suppress it, and never to fix it.
#[test]
fn an_artifact_whose_ingest_check_failed_is_still_held_and_returned_byte_for_byte() {
    let mut store = store_with_a_device();

    // A real report export with one byte of the goal changed after signing: it parses, so the
    // verifier runs, and it fails on the digest. That is `failed`, not `unknown`.
    let tampered = tampered_report_bytes();

    let response = http::handle(
        &mut store,
        &signed("POST", &["v1", "evidence"], &tampered, "n1"),
        NOW,
    );
    assert_eq!(
        response.status,
        status::OK,
        "a submission whose signatures do not check out is still filed: refusing it would delete \
         the evidence of tampering"
    );
    let not_a_verdict = response
        .body
        .get("not_a_verdict")
        .expect("every answer carries one");
    assert_eq!(
        not_a_verdict.get("ingest_check").and_then(Value::as_str),
        Some("failed"),
        "the door ran the check and it did not hold, so the word is `failed`"
    );

    let digest = response
        .body
        .get("data")
        .and_then(|d| d.get("digest"))
        .and_then(Value::as_str)
        .expect("a filed artifact reports its digest")
        .to_string();

    let fetched = http::handle(
        &mut store,
        &signed("GET", &["v1", "evidence", &digest], b"", "n2"),
        NOW,
    );
    assert_eq!(fetched.status, status::OK);
    let (_, bytes) = fetched.raw.expect("an artifact is returned as raw bytes");
    assert_eq!(
        bytes, tampered,
        "a failed artifact is returned byte for byte, so a human can see exactly what arrived"
    );
}

/// `unknown` and `failed` are different claims and one is never rendered as the other.
///
/// A body that declares a format this build knows but does not parse as it is `unknown`: no
/// verifier ran, so nothing established that its signatures are wrong. Calling that `failed` would
/// be an accusation the archive did not earn.
#[test]
fn a_check_that_could_not_run_is_unknown_and_never_failed() {
    use warrantor_archive::artifact::{ingest, IngestCheck};
    use warrantor_warrant::report::REPORT_EXPORT_FORMAT;

    let body = serde_json::json!({
        "format": REPORT_EXPORT_FORMAT,
        "bundle_digest": "not even close to a report",
    });
    let error = ingest(serde_json::to_vec(&body).expect("encode"))
        .expect_err("a report export with no warrant id has nothing to be filed under");
    // It is refused at the door for want of a warrant id, and the reason names the shape of the
    // file rather than accusing it of a bad signature.
    let message = error.to_string();
    assert!(
        !message.contains("signature"),
        "an unparseable file must not be described as a signature failure: {message}"
    );

    // The same shape, but with enough structure to carry a warrant id. Refusing it at the door is
    // honest and so is filing it as `Unknown`; the one outcome that must never happen is `Failed`,
    // because no verifier ran and nothing established that its signatures are wrong.
    if let Ok(ingested) = ingest(unparseable_but_identifiable_bytes()) {
        assert!(
            matches!(ingested.check, IngestCheck::Unknown { .. }),
            "a file that could not be parsed into its declared shape is `unknown`, never `failed`"
        );
    }
}

// ── fixtures ──────────────────────────────────────────────────────────────────────────

fn tampered_report_bytes() -> Vec<u8> {
    use std::collections::BTreeSet;
    use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
    use warrantor_warrant::store::StoredWarrant;
    use warrantor_warrant::{report, SideEffectClass, Warrant, WarrantBounds, WarrantState};

    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["github.create_pr".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: Some(500),
        delegation_depth: 3,
    };
    let mut warrant = Warrant::grant(
        "wrt_archive",
        "fix the auth token refresh bug",
        "spiffe://muveraai.com/agent/alpha",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    warrant.state = WarrantState::Open;
    let stored = StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
    };
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "warrantor-archive-verdict-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let queue = StagingQueue::open(dir.join("q.jsonl"), "wrt_archive", EffectRegistry::github())
        .expect("open queue");
    let mut signed = report::build(&stored, Ok(&queue), &issuer.verifying_key(), NOW)
        .sign(&issuer, "issuer")
        .expect("sign");
    // The tamper: edited after signing, so the digest no longer covers it.
    signed.bundle.goal = "ship it without review".to_string();
    serde_json::to_vec(&signed).expect("encode")
}

/// A body that declares the stop format and carries a warrant id, but is not a stop record.
fn unparseable_but_identifiable_bytes() -> Vec<u8> {
    use warrantor_warrant::stop::STOP_EXPORT_FORMAT;
    serde_json::to_vec(&serde_json::json!({
        "format": STOP_EXPORT_FORMAT,
        "record": { "warrant_id": "wrt_archive" },
    }))
    .expect("encode")
}

/// The scheme token is part of the wire contract, so a rename is a breaking change and gets a test.
#[test]
fn the_device_scheme_token_is_pinned() {
    assert_eq!(DEVICE_SCHEME, "Warrantor-Device");
}

//! Device pairing: single-use codes, replay refusal, and the attribution that a bearer token
//! cannot provide.
//!
//! The last test in this file is the one the workstream is judged on:
//! `two_devices_submitting_produce_two_distinguishable_submitters`. W1 delivery gap 2.2 says the
//! audit trail "cannot say which human settled a warrant — only that someone holding the token
//! did". That is a property of a single unscoped bearer token, and no amount of logging fixes it.
//! Here two devices file two artifacts and the archive records two different names against them.
//!
//! It is worth being exact about what that closes, because over-claiming it would get gap 2.2
//! marked done when it is half done: this attributes **submission** and **read**. It does not
//! attribute the settle, which happens on a laptop under the local agent's settle key and may never
//! reach this server at all.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use warrantor_archive::device::{
    self, DeviceError, EnrolmentCode, ENROLMENT_CODE_LIFETIME_SECONDS, FRESHNESS_WINDOW_SECONDS,
};
use warrantor_archive::http;
use warrantor_archive::store::{
    ArchiveStore, Device, EnrolError, ListFilter, MemoryStore, NonceOutcome,
};
use warrantor_warrant::serve::{status, HttpRequest};

const NOW: u64 = 1_786_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn enrolled(store: &mut MemoryStore, id: &str, label: &str, seed: u8) {
    store.enrol_without_a_code(Device {
        id: id.to_string(),
        label: label.to_string(),
        public_key: hex::encode(key(seed).verifying_key().to_bytes()),
        enrolled_at: NOW,
        revoked_at: None,
    });
}

fn request(
    signer: &SigningKey,
    device_id: &str,
    method: &str,
    segments: &[&str],
    body: &[u8],
    nonce: &str,
    timestamp: u64,
) -> HttpRequest {
    let path = format!("/{}", segments.join("/"));
    let header = device::sign_request(signer, method, &path, device_id, nonce, timestamp, body);
    let mut request = HttpRequest::new(method, segments, BTreeMap::new());
    request.authorization = Some(header);
    request.body = body.to_vec();
    request
}

// ── enrolment codes ───────────────────────────────────────────────────────────────────

/// A code is single-use under a race: of two devices claiming one code, exactly one wins.
///
/// Sequential here rather than threaded, because the property under test is that the claim and the
/// write are **one operation**, and a sequential second attempt exercises exactly the state a loser
/// in a real race would find. The Postgres implementation gets the same property from a conditional
/// `UPDATE ... RETURNING` inside a transaction; the `#[ignore]`d database test is where that is
/// exercised for real.
#[test]
fn one_enrolment_code_enrols_exactly_one_device() {
    let mut store = MemoryStore::new();
    let code = EnrolmentCode::mint().expect("mint");
    store
        .create_enrolment_code(
            code.digest(),
            "Ana's laptop",
            NOW,
            NOW + ENROLMENT_CODE_LIFETIME_SECONDS,
        )
        .expect("create");

    let first = store
        .enrol_device(
            code.digest(),
            "dev_1111",
            &hex::encode(key(1).verifying_key().to_bytes()),
            NOW,
        )
        .expect("the first device claims the code");
    assert_eq!(first.label, "Ana's laptop", "the label follows the code");

    let second = store.enrol_device(
        code.digest(),
        "dev_2222",
        &hex::encode(key(2).verifying_key().to_bytes()),
        NOW,
    );
    assert_eq!(
        second.expect_err("the second device must be refused"),
        EnrolError::CodeNotUsable
    );
    assert!(
        store.device("dev_2222").expect("read").is_none(),
        "a refused enrolment must leave no device behind"
    );
}

/// An expired code is refused, and refused with the same message as an unknown one.
///
/// One message for unknown, expired and already-claimed on purpose: distinguishing them tells
/// someone holding a guessed code whether they guessed a real one, which is a free oracle in
/// exchange for a marginally better error message.
#[test]
fn an_expired_code_is_refused_and_indistinguishable_from_an_unknown_one() {
    let mut store = MemoryStore::new();
    let code = EnrolmentCode::mint().expect("mint");
    store
        .create_enrolment_code(code.digest(), "Ana's laptop", NOW, NOW + 60)
        .expect("create");

    let expired = store.enrol_device(
        code.digest(),
        "dev_1111",
        &hex::encode(key(1).verifying_key().to_bytes()),
        NOW + 61,
    );
    let unknown = store.enrol_device(
        &EnrolmentCode::digest_of("a code that was never minted"),
        "dev_1111",
        &hex::encode(key(1).verifying_key().to_bytes()),
        NOW,
    );
    assert_eq!(
        expired.expect_err("expired").to_string(),
        unknown.expect_err("unknown").to_string(),
        "unknown, expired and already-claimed must be one refusal: three would be an oracle"
    );
}

/// Only the digest of a code is ever stored.
#[test]
fn the_code_itself_is_never_stored() {
    let code = EnrolmentCode::mint().expect("mint");
    assert_ne!(code.code(), code.digest());
    assert_eq!(
        code.digest(),
        EnrolmentCode::digest_of(code.code()),
        "the digest a device's presented code hashes to must match the one that was stored"
    );
    assert_eq!(code.digest().len(), 64, "SHA-256 hex");
    assert!(
        !code.digest().contains(code.code()),
        "the stored value must not contain the plaintext"
    );
}

// ── request signing ───────────────────────────────────────────────────────────────────

/// A replayed nonce is refused, and the first use is not.
#[test]
fn a_replayed_nonce_is_refused() {
    let mut store = MemoryStore::new();
    enrolled(&mut store, "dev_1111", "Ana's laptop", 1);

    let first = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_1111",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-one",
            NOW,
        ),
        NOW,
    );
    assert_eq!(first.status, status::OK);

    // The identical request again — which is exactly what an eavesdropper with no TLS would resend.
    let replayed = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_1111",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-one",
            NOW,
        ),
        NOW,
    );
    assert_eq!(replayed.status, status::UNAUTHORIZED);
    assert_eq!(
        replayed
            .body
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str),
        Some("replayed_nonce"),
        "a replay is named as one, because an operator debugging it needs to know which refusal \
         this is"
    );
}

/// A signature over one body does not authorise a different body.
///
/// The attack this stops: capture a valid submission, swap the evidence for something else, and
/// resend. The body digest is inside the signed descriptor, so the swap invalidates the signature.
#[test]
fn a_signature_over_a_different_body_is_refused() {
    let mut store = MemoryStore::new();
    enrolled(&mut store, "dev_1111", "Ana's laptop", 1);

    // Signed over one body...
    let mut tampered = request(
        &key(1),
        "dev_1111",
        "POST",
        &["v1", "evidence"],
        br#"{"format":"warrantor.report-export/1"}"#,
        "nonce-one",
        NOW,
    );
    // ...and sent with another.
    tampered.body = br#"{"format":"warrantor.report-export/1","tampered":true}"#.to_vec();

    let response = http::handle(&mut store, &tampered, NOW);
    assert_eq!(
        response.status,
        status::UNAUTHORIZED,
        "swapping the body after signing must invalidate the signature"
    );
    assert_eq!(
        store.len(),
        0,
        "and nothing may be filed off a request that failed authentication"
    );
}

/// A signature over one route does not authorise another.
#[test]
fn a_signature_cannot_be_lifted_onto_a_different_route() {
    let mut store = MemoryStore::new();
    enrolled(&mut store, "dev_1111", "Ana's laptop", 1);

    let header = device::sign_request(
        &key(1),
        "GET",
        "/v1/warrants/wrt_archive/evidence",
        "dev_1111",
        "nonce-one",
        NOW,
        b"",
    );
    // The same credential presented against a different path.
    let mut lifted = HttpRequest::new("GET", &["v1", "evidence", &"a".repeat(64)], BTreeMap::new());
    lifted.authorization = Some(header);

    let response = http::handle(&mut store, &lifted, NOW);
    assert_eq!(response.status, status::UNAUTHORIZED);
}

/// A stale request is refused, in both directions, and does not burn a nonce.
///
/// The second half matters: if a stale request consumed its nonce, an attacker replaying captured
/// old traffic could burn the nonces a victim's client is about to use. Freshness is checked before
/// the nonce is spent, so a refused request leaves the replay store untouched.
#[test]
fn a_stale_request_is_refused_in_both_directions_and_burns_no_nonce() {
    let mut store = MemoryStore::new();
    enrolled(&mut store, "dev_1111", "Ana's laptop", 1);

    let too_old = NOW - FRESHNESS_WINDOW_SECONDS - 1;
    let past = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_1111",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-one",
            too_old,
        ),
        NOW,
    );
    assert_eq!(past.status, status::UNAUTHORIZED);

    // A timestamp far in the FUTURE is refused too. A window that only bounded the past would
    // accept a request that becomes valid later, which is a replay that has not happened yet.
    let future = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_1111",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-two",
            NOW + FRESHNESS_WINDOW_SECONDS + 1,
        ),
        NOW,
    );
    assert_eq!(future.status, status::UNAUTHORIZED);

    // Neither refusal consumed its nonce, so the honest client can still use it.
    assert_eq!(
        store
            .remember_nonce("dev_1111", "nonce-one", NOW)
            .expect("nonce"),
        NonceOutcome::Fresh,
        "a request refused for staleness must not have spent its nonce"
    );
}

/// A revoked device is refused, and its past submissions keep their attribution.
#[test]
fn a_revoked_device_is_refused_but_its_history_keeps_its_name() {
    let mut store = MemoryStore::new();
    enrolled(&mut store, "dev_1111", "Ana's laptop", 1);

    assert!(store.revoke_device("dev_1111", NOW + 10).expect("revoke"));
    let response = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_1111",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-one",
            NOW + 20,
        ),
        NOW + 20,
    );
    assert_eq!(response.status, status::UNAUTHORIZED);
    assert_eq!(
        response
            .body
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str),
        Some("device_revoked")
    );

    // The row survives revocation. Deleting it would silently anonymise everything that device ever
    // filed, which is the opposite of what an audit trail is for.
    let device = store
        .device("dev_1111")
        .expect("read")
        .expect("a revoked device is kept, not deleted");
    assert_eq!(device.label, "Ana's laptop");
    assert_eq!(device.revoked_at, Some(NOW + 10));
}

/// An unknown device and a bad signature give the same refusal.
///
/// Otherwise the route is an oracle for which device ids exist.
#[test]
fn an_unknown_device_and_a_bad_signature_are_indistinguishable() {
    let mut store = MemoryStore::new();
    enrolled(&mut store, "dev_1111", "Ana's laptop", 1);

    let unknown = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_9999",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-one",
            NOW,
        ),
        NOW,
    );
    // The right device id, signed with the wrong key.
    let wrong_key = http::handle(
        &mut store,
        &request(
            &key(2),
            "dev_1111",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-two",
            NOW,
        ),
        NOW,
    );
    assert_eq!(unknown.status, wrong_key.status);
    assert_eq!(unknown.body, wrong_key.body);
}

/// A malformed credential is refused before anything is looked up.
#[test]
fn a_malformed_credential_is_refused() {
    for header in [
        None,
        Some("Bearer deadbeef"),
        Some("Warrantor-Device"),
        Some("Warrantor-Device dev_1111.notanumber.nonce.aabb"),
        Some("Warrantor-Device dev_1111.100.nonce"),
        Some("Warrantor-Device ../../etc/passwd.100.nonce.aabb"),
    ] {
        assert!(
            device::parse_credential(header).is_err(),
            "{header:?} must not parse as a device credential"
        );
    }
}

// ── the attribution test ──────────────────────────────────────────────────────────────

/// Two devices submit; the archive records two distinguishable names.
///
/// This is what a single unscoped bearer token structurally cannot do, and it is the whole reason
/// device pairing exists rather than a second shared secret.
#[test]
fn two_devices_submitting_produce_two_distinguishable_submitters() {
    let mut store = MemoryStore::new();
    enrolled(&mut store, "dev_1111", "Ana's laptop", 1);
    enrolled(&mut store, "dev_2222", "Ben's workstation", 2);

    let ana_filed = export_bytes("wrt_archive", "fix the auth token refresh bug");
    let ben_filed = export_bytes("wrt_archive", "fix the auth token refresh bug, take two");

    let ana = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_1111",
            "POST",
            &["v1", "evidence"],
            &ana_filed,
            "ana-1",
            NOW,
        ),
        NOW,
    );
    assert_eq!(ana.status, status::OK);

    let ben = http::handle(
        &mut store,
        &request(
            &key(2),
            "dev_2222",
            "POST",
            &["v1", "evidence"],
            &ben_filed,
            "ben-1",
            NOW + 60,
        ),
        NOW + 60,
    );
    assert_eq!(ben.status, status::OK);

    let rows = store
        .list_artifacts(&ListFilter {
            warrant_id: Some("wrt_archive".to_string()),
            kind: None,
        })
        .expect("list");
    assert_eq!(rows.len(), 2);
    let submitters: Vec<&str> = rows
        .iter()
        .map(|r| r.submitted_by_device.as_str())
        .collect();
    assert!(
        submitters.contains(&"dev_1111") && submitters.contains(&"dev_2222"),
        "each artifact must name the device that filed it, not a shared principal: {submitters:?}"
    );
    assert_ne!(
        rows[0].submitted_by_device, rows[1].submitted_by_device,
        "two people filing two artifacts must be two names in the trail"
    );

    // And the name resolves to a human-readable label, which is what an audit view shows.
    let ana_device = store.device("dev_1111").expect("read").expect("enrolled");
    assert_eq!(ana_device.label, "Ana's laptop");
}

/// The device signature scheme carries no private key to the archive, ever.
///
/// A shape test on the enrolment route: what a device sends is a public key, and what the archive
/// stores is a public key. If a future change ever accepted a private key "for convenience", the
/// archive would hold the ability to impersonate every device that enrolled.
#[test]
fn enrolment_accepts_a_public_key_and_the_archive_stores_only_that() {
    let mut store = MemoryStore::new();
    let code = EnrolmentCode::mint().expect("mint");
    store
        .create_enrolment_code(
            code.digest(),
            "Ana's laptop",
            NOW,
            NOW + ENROLMENT_CODE_LIFETIME_SECONDS,
        )
        .expect("create");

    let signing = key(5);
    let public = hex::encode(signing.verifying_key().to_bytes());
    let body = serde_json::json!({ "code": code.code(), "public_key": public });
    let mut enrol = HttpRequest::new("POST", &["v1", "devices", "enrol"], BTreeMap::new());
    enrol.body = serde_json::to_vec(&body).expect("encode");

    let response = http::handle(&mut store, &enrol, NOW);
    assert_eq!(response.status, status::OK, "{:?}", response.body);
    let device_id = response
        .body
        .get("data")
        .and_then(|d| d.get("device_id"))
        .and_then(Value::as_str)
        .expect("a device id")
        .to_string();

    let stored = store.device(&device_id).expect("read").expect("enrolled");
    assert_eq!(stored.public_key, public);
    let private = hex::encode(signing.to_bytes());
    assert_ne!(
        stored.public_key, private,
        "the archive must hold the public half and never the private one"
    );

    // The freshly enrolled device can immediately sign a request.
    let signed = request(
        &signing,
        &device_id,
        "GET",
        &["v1", "warrants", "wrt_archive", "evidence"],
        b"",
        "first-request",
        NOW,
    );
    assert_eq!(http::handle(&mut store, &signed, NOW).status, status::OK);
}

/// A signature the archive cannot check is a refusal, not a panic.
#[test]
fn a_device_with_an_unparseable_stored_key_is_a_refusal() {
    let mut store = MemoryStore::new();
    store.enrol_without_a_code(Device {
        id: "dev_1111".to_string(),
        label: "corrupted".to_string(),
        public_key: "not hex".to_string(),
        enrolled_at: NOW,
        revoked_at: None,
    });
    let response = http::handle(
        &mut store,
        &request(
            &key(1),
            "dev_1111",
            "GET",
            &["v1", "warrants", "wrt_archive", "evidence"],
            b"",
            "nonce-one",
            NOW,
        ),
        NOW,
    );
    assert_eq!(response.status, status::UNAUTHORIZED);
    assert_eq!(
        device::parse_public_key("not hex").expect_err("refused"),
        DeviceError::BadSignature,
        "a device whose stored key cannot be parsed cannot have signed anything, and the caller is \
         told about their request rather than about this archive's rows"
    );
}

// ── fixtures ──────────────────────────────────────────────────────────────────────────

fn export_bytes(id: &str, goal: &str) -> Vec<u8> {
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
        id,
        goal,
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
        "warrantor-archive-pairing-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let queue =
        StagingQueue::open(dir.join("q.jsonl"), id, EffectRegistry::github()).expect("open queue");
    let signed = report::build(&stored, Ok(&queue), &issuer.verifying_key(), NOW)
        .sign(&issuer, "issuer")
        .expect("sign");
    serde_json::to_vec_pretty(&signed).expect("encode")
}

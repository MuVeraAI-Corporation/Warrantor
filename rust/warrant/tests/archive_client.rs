//! What the archive client refuses, and how it says so.
//!
//! Every case here is a failure path, because the success path is checked where it can be checked
//! honestly — `rust/archive/tests/push_client_interop.rs` drives this same client against the real
//! server in one process. What that file cannot exercise is a server behaving in ways the real one
//! never does: answering with something that is not JSON, going away mid-pipeline, or returning a
//! 200 over an artifact whose signatures do not check out.
//!
//! **This file imports no `warrantor_archive` type, and must not.** The dependency edge runs
//! archive → warrant and never the reverse: `warrantor-archive` pulls `postgres` and therefore
//! tokio, and a test dependency is still a dependency. The response bodies below are written out by
//! hand from the wire format for exactly that reason, which has a second benefit — it checks that
//! the client parses the documented shape rather than one a shared constructor happened to produce.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde_json::json;

use warrantor_warrant::archive_client::{
    self, ArchiveAnswer, ArchiveClientError, ArchiveConfig, ArchiveTransport,
    ARCHIVE_CONFIG_FORMAT, ARCHIVE_RESPONSE_FORMAT,
};
use warrantor_warrant::report::sha256_hex;

const NOW: u64 = 1_786_000_000;
const DEVICE: &str = "dev_00112233445566778899aabbccddeeff";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-archive-client-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn config() -> ArchiveConfig {
    ArchiveConfig {
        format: ARCHIVE_CONFIG_FORMAT.to_string(),
        url: "http://127.0.0.1:8788".to_string(),
        device_id: DEVICE.to_string(),
        device_public_key: hex::encode(key().verifying_key().to_bytes()),
        label: "Ana's laptop".to_string(),
        enrolled_at: NOW,
    }
}

/// Whatever the test says the archive said. Records what it was asked, so a test can assert that a
/// refusal happened *before* anything went on the wire.
struct Canned {
    answers: Vec<Result<ArchiveAnswer, String>>,
    asked: Vec<(String, String)>,
}

impl Canned {
    fn saying(answers: Vec<Result<ArchiveAnswer, String>>) -> Self {
        Self {
            answers,
            asked: Vec::new(),
        }
    }

    fn ok(body: serde_json::Value) -> Self {
        Self::saying(vec![Ok(ArchiveAnswer {
            status: 200,
            body: serde_json::to_vec(&body).expect("encode"),
        })])
    }

    fn refusing(status: u16, code: &str, message: &str) -> Self {
        Self::ok_body(
            status,
            json!({
                "format": ARCHIVE_RESPONSE_FORMAT,
                "error": { "code": code, "message": message },
                "not_a_verdict": {
                    "ingest_check": "unknown",
                    "reason": "nothing was checked",
                    "verify_locally": "verify locally",
                },
            }),
        )
    }

    fn ok_body(status: u16, body: serde_json::Value) -> Self {
        Self::saying(vec![Ok(ArchiveAnswer {
            status,
            body: serde_json::to_vec(&body).expect("encode"),
        })])
    }
}

impl ArchiveTransport for Canned {
    fn send(
        &mut self,
        method: &str,
        path: &str,
        _authorization: Option<&str>,
        _body: &[u8],
    ) -> Result<ArchiveAnswer, String> {
        self.asked.push((method.to_string(), path.to_string()));
        if self.answers.is_empty() {
            return Err("this test scripted no answer for that request".to_string());
        }
        self.answers.remove(0)
    }
}

/// A well-formed filing answer for `bytes`, with the door's note set to whatever the test wants.
fn filed_body(bytes: &[u8], already_held: bool, check: &str, reason: &str) -> serde_json::Value {
    json!({
        "format": ARCHIVE_RESPONSE_FORMAT,
        "data": {
            "digest": sha256_hex(bytes),
            "kind": "report",
            "warrant_id": "wrt_test",
            "already_held": already_held,
            "submitted_by_device": DEVICE,
            "submitted_at": NOW,
        },
        "not_a_verdict": {
            "ingest_check": check,
            "reason": reason,
            "verify_locally": "verify locally with `warrantor verify <file> --issuer <hex>`",
        },
    })
}

// ── being unpaired is its own answer ──────────────────────────────────────────────────

/// An unpaired machine is told it is unpaired, and told what to type.
///
/// The alternative shape — inventing a URL, or minting a device key on demand — produces a request
/// that fails at the far end with a message about signatures, sending the operator to look at
/// cryptography when their problem is that they never enrolled.
#[test]
fn an_unpaired_machine_refuses_and_says_how_to_pair() {
    let root = tempdir("unpaired");

    let error = ArchiveConfig::load(&root).expect_err("there is no pairing record");

    assert!(
        matches!(&error, ArchiveClientError::NotConfigured(_)),
        "{error}"
    );
    let message = error.to_string();
    assert!(
        message.contains("warrantor archive enrol")
            && message.contains("warrantor-archive enrol --label"),
        "the refusal names both halves of pairing: {message}"
    );
}

/// A pairing record from a future format is refused rather than read field by field.
#[test]
fn a_pairing_record_in_an_unknown_format_is_refused() {
    let root = tempdir("future-format");
    let mut config = config();
    config.format = "warrantor.archive-pairing/2".to_string();
    config.save(&root).expect("save");

    let error = ArchiveConfig::load(&root).expect_err("an unknown format is not guessed at");

    assert!(matches!(&error, ArchiveClientError::Config(_)), "{error}");
    assert!(error.to_string().contains("archive-pairing/2"), "{error}");
}

/// A record naming something that is not a device id is refused before anything is signed under it.
#[test]
fn a_pairing_record_naming_a_bad_device_is_refused() {
    let root = tempdir("bad-device");
    let mut config = config();
    config.device_id = "laptop".to_string();
    config.save(&root).expect("save");

    let error = ArchiveConfig::load(&root).expect_err("that is not a device id");
    assert!(matches!(&error, ArchiveClientError::Config(_)), "{error}");
}

/// A pairing record round-trips, so `enrol` writes something `push` can read.
#[test]
fn a_pairing_record_written_by_enrol_is_readable_by_push() {
    let root = tempdir("roundtrip");
    let written = config().save(&root).expect("save");
    assert!(written.ends_with("archive.json"));
    assert_eq!(ArchiveConfig::load(&root).expect("load"), config());
}

/// A record that does not say which key it was written for is refused rather than trusted.
///
/// The field is what makes the device id and the key on disk one credential instead of two facts
/// that happen to sit in the same directory. A record without it would have to be taken on faith.
#[test]
fn a_pairing_record_without_a_public_key_is_refused() {
    let root = tempdir("no-public-key");
    let mut config = config();
    config.device_public_key = "not-a-key".to_string();
    config.save(&root).expect("save");

    let error = ArchiveConfig::load(&root).expect_err("that is not a public key");
    assert!(matches!(&error, ArchiveClientError::Config(_)), "{error}");
    assert!(error.to_string().contains("64 hex characters"), "{error}");
}

/// The key on disk is checked against the record BEFORE anything is signed, and the refusal names
/// the pairing rather than blaming the signature.
///
/// This is the shape a half-finished enrolment leaves behind, and the shape a `device.key` copied
/// from another machine's backup leaves behind. Both sign perfectly well; both are refused by the
/// archive with a message about signatures, which sends the operator hunting a crypto problem.
#[test]
fn a_device_key_that_is_not_the_enrolled_one_is_refused_as_a_pairing_problem() {
    let config = config();
    let stranger = SigningKey::from_bytes(&[9; 32]);
    let path = PathBuf::from("/warrantor/keys/device.key");

    config
        .check_key(&key(), &path)
        .expect("the enrolled key is accepted");
    let error = config
        .check_key(&stranger, &path)
        .expect_err("a key this pairing was not written for");

    assert!(
        matches!(&error, ArchiveClientError::DeviceKeyMismatch(mismatch)
            if mismatch.device_id == DEVICE),
        "{error}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&hex::encode(stranger.verifying_key().to_bytes()))
            && message.contains(&config.device_public_key),
        "the refusal names both keys, so the operator can tell which one is the stranger: {message}"
    );
    assert!(
        message.contains("not a signature problem"),
        "the refusal says what kind of problem this is not: {message}"
    );
}

/// "No pairing" and "a pairing record I cannot read" are different answers, and the second one is
/// never flattened into the first.
///
/// Flattening them is precisely what would let a second enrolment run silently over a device that
/// is still active at the archive.
#[test]
fn an_unreadable_pairing_record_is_not_reported_as_never_paired() {
    let absent = tempdir("read-if-present-absent");
    assert_eq!(
        ArchiveConfig::read_if_present(&absent).expect("absence is not an error"),
        None
    );

    let root = tempdir("read-if-present-broken");
    std::fs::write(ArchiveConfig::path(&root), b"{ this is not json").expect("write");
    let error = ArchiveConfig::read_if_present(&root)
        .expect_err("a record that exists and cannot be read is not an absent record");
    assert!(matches!(&error, ArchiveClientError::Config(_)), "{error}");
}

/// A URL this client will not sign a request to is refused, with the reason.
#[test]
fn a_url_that_is_not_an_archive_url_is_refused() {
    for bad in ["127.0.0.1:8788", "file:///tmp/archive", "ftp://host"] {
        let error = archive_client::check_url(bad).expect_err("not an archive URL");
        assert!(
            matches!(&error, ArchiveClientError::Config(_)),
            "{bad}: {error}"
        );
    }
    // A trailing slash is refused too: the path is appended verbatim and is inside the signature,
    // so `…8788//v1/evidence` would be signed and sent and refused with a message about keys.
    assert!(archive_client::check_url("http://127.0.0.1:8788/").is_err());
    archive_client::check_url("http://127.0.0.1:8788").expect("a bare base URL is fine");
    archive_client::check_url("https://archive.example.com").expect("https too");
}

// ── refusals from the archive, in the archive's own words ─────────────────────────────

/// A clock problem is reported as a clock problem, with the archive's own sentence.
#[test]
fn a_stale_request_is_reported_as_clock_skew_and_not_as_a_key_problem() {
    let mut archive = Canned::refusing(
        401,
        "stale_request",
        "this request is timestamped 1786000000 and the archive's clock reads 1786000900; the \
         accepted window is 300 seconds either way",
    );

    let error = archive_client::push(&mut archive, &config(), &key(), b"{}", NOW)
        .expect_err("a stale request is refused");

    let ArchiveClientError::Refused {
        status,
        code,
        message,
    } = &error
    else {
        panic!("expected the archive's refusal: {error}");
    };
    assert_eq!(*status, 401);
    assert_eq!(code, "stale_request");
    assert!(
        message.contains("1786000900"),
        "the archive's own message is carried verbatim, clocks and all: {message}"
    );
}

/// A revoked device is told so, and it is not collapsed into a generic failure.
#[test]
fn a_revoked_device_is_named_as_revoked() {
    let mut archive = Canned::refusing(
        401,
        "device_revoked",
        "this device was revoked and can no longer submit or read",
    );

    let error = archive_client::push(&mut archive, &config(), &key(), b"{}", NOW)
        .expect_err("a revoked device is refused");

    assert!(
        matches!(&error, ArchiveClientError::Refused { code, .. } if code == "device_revoked"),
        "{error}"
    );
}

/// A file over the archive's cap surfaces the archive's own 413, not "the request failed".
#[test]
fn an_oversized_body_surfaces_the_archives_own_message() {
    let mut archive = Canned::refusing(
        413,
        "payload_too_large",
        "this archive accepts a body of at most 4194304 bytes",
    );

    let error =
        archive_client::push(&mut archive, &config(), &key(), b"{}", NOW).expect_err("refused");

    assert!(
        matches!(&error, ArchiveClientError::Refused { status, code, .. }
            if *status == 413 && code == "payload_too_large"),
        "{error}"
    );
}

/// A store that cannot be written says nothing was filed, and the client repeats it.
#[test]
fn an_unavailable_store_is_reported_as_nothing_filed() {
    let mut archive = Canned::refusing(
        503,
        "store_unavailable",
        "the archive could not write to its store, so nothing was filed. Retry: this submission is \
         idempotent on its digest, so a retry cannot create a duplicate.",
    );

    let error =
        archive_client::push(&mut archive, &config(), &key(), b"{}", NOW).expect_err("refused");

    assert!(
        error.to_string().contains("nothing was filed"),
        "the operator is told the state of the world, not just a status: {error}"
    );
}

/// An unusable enrolment code is one refusal, and the client does not embellish it.
#[test]
fn an_unusable_enrolment_code_is_refused() {
    let mut archive = Canned::refusing(
        403,
        "code_not_usable",
        "that enrolment code is not usable: it is unknown, expired, or already claimed.",
    );

    let error = archive_client::enrol(
        &mut archive,
        "http://127.0.0.1:8788",
        "deadbeef",
        &key().verifying_key(),
    )
    .expect_err("refused");

    assert!(
        matches!(&error, ArchiveClientError::Refused { status, code, .. }
            if *status == 403 && code == "code_not_usable"),
        "{error}"
    );
}

// ── answers this client will not read ─────────────────────────────────────────────────

/// Something that is not JSON at all — a proxy's error page, say — is not silently swallowed.
#[test]
fn a_body_that_is_not_json_is_refused_rather_than_assumed() {
    let mut archive = Canned::saying(vec![Ok(ArchiveAnswer {
        status: 200,
        body: b"<html>502 Bad Gateway</html>".to_vec(),
    })]);

    let error =
        archive_client::push(&mut archive, &config(), &key(), b"{}", NOW).expect_err("refused");

    let ArchiveClientError::Unreadable { reason, .. } = &error else {
        panic!("expected an unreadable answer: {error}");
    };
    assert!(reason.contains("not JSON"), "{reason}");
    assert!(
        error.to_string().contains("Nothing is assumed"),
        "the message says outright that the state of the submission is unknown: {error}"
    );
}

/// A response envelope from a format this build does not speak is refused, not field-picked.
#[test]
fn a_response_in_an_unknown_format_is_refused() {
    let mut archive = Canned::ok(json!({
        "format": "warrantor.archive-response/2",
        "data": { "digest": sha256_hex(b"{}") },
    }));

    let error =
        archive_client::push(&mut archive, &config(), &key(), b"{}", NOW).expect_err("refused");

    assert!(
        matches!(&error, ArchiveClientError::Unreadable { reason, .. }
            if reason.contains("archive-response/2")),
        "{error}"
    );
}

/// A 200 missing a field this client needs is a refusal, never a default.
#[test]
fn a_success_missing_a_field_is_refused_rather_than_defaulted() {
    let mut archive = Canned::ok(json!({
        "format": ARCHIVE_RESPONSE_FORMAT,
        "data": {
            "digest": sha256_hex(b"{}"),
            "kind": "report",
            "warrant_id": "wrt_test",
            // already_held omitted: defaulting it to false would report a re-file as a new one.
            "submitted_by_device": DEVICE,
            "submitted_at": NOW,
        },
        "not_a_verdict": { "ingest_check": "ok", "reason": "", "verify_locally": "…" },
    }));

    let error =
        archive_client::push(&mut archive, &config(), &key(), b"{}", NOW).expect_err("refused");

    assert!(
        matches!(&error, ArchiveClientError::Unreadable { reason, .. }
            if reason.contains("already_held")),
        "{error}"
    );
}

/// No answer at all names the archive that did not answer.
#[test]
fn a_transport_failure_names_the_archive() {
    let mut archive = Canned::saying(vec![Err("connection refused".to_string())]);

    let error =
        archive_client::push(&mut archive, &config(), &key(), b"{}", NOW).expect_err("refused");

    assert!(
        matches!(&error, ArchiveClientError::Transport { url, .. } if url == "http://127.0.0.1:8788"),
        "{error}"
    );
}

// ── the two things that must never be reported as success ─────────────────────────────

/// A digest the archive did not compute from these bytes fails the push, at runtime.
///
/// The answer is otherwise perfect: 200, every field present and well-typed. This is the case a
/// test-only assertion would have missed in production, which is why the check lives inside
/// `push` rather than in a test of it.
#[test]
fn a_digest_that_does_not_name_the_bytes_sent_fails_the_push() {
    let bytes = br#"{"format":"warrantor.report-export/1"}"#;
    let mut archive = Canned::ok(filed_body(b"different bytes entirely", false, "ok", ""));

    let error = archive_client::push(&mut archive, &config(), &key(), bytes, NOW)
        .expect_err("a 200 under the wrong address is not a filing");

    let ArchiveClientError::DigestDisagreement {
        expected, returned, ..
    } = &error
    else {
        panic!("expected a digest disagreement: {error}");
    };
    assert_eq!(expected, &sha256_hex(bytes));
    assert_eq!(returned, &sha256_hex(b"different bytes entirely"));
    assert!(
        error
            .to_string()
            .contains("refusing to report this as filed"),
        "{error}"
    );
}

/// An artifact whose signatures do not check out is HELD, and the failure is carried, not hidden.
///
/// Custody and validity are different claims. The archive deliberately stores a tampered file —
/// refusing would destroy the evidence that it arrived — so `push` succeeds and the door's note
/// comes back saying `failed`. What must never happen is the reverse of either: the filing
/// reported as a verification, or the failure quietly dropped because the HTTP status was 200.
#[test]
fn a_filing_whose_ingest_check_failed_is_carried_verbatim_and_is_not_a_verification() {
    let bytes = br#"{"format":"warrantor.report-export/1"}"#;
    let mut archive = Canned::ok(filed_body(
        bytes,
        false,
        "failed",
        "the bundle digest does not match its contents",
    ));

    let filed = archive_client::push(&mut archive, &config(), &key(), bytes, NOW)
        .expect("the archive holds it, so the filing succeeded");

    assert_eq!(filed.ingest_check, "failed");
    assert_eq!(
        filed.ingest_reason, "the bundle digest does not match its contents",
        "the verifier's own sentence is carried, not paraphrased"
    );
    assert!(
        !filed.verify_locally.is_empty(),
        "and the sentence about where a real answer comes from travels with it"
    );
}

/// Filing the same bytes again reads as already filed, not as an error.
#[test]
fn already_held_reads_as_already_filed() {
    let bytes = br#"{"format":"warrantor.report-export/1"}"#;
    let mut archive = Canned::ok(filed_body(bytes, true, "ok", ""));

    let filed = archive_client::push(&mut archive, &config(), &key(), bytes, NOW)
        .expect("a retry is not a failure");

    assert!(filed.already_held);
    assert_eq!(filed.digest, sha256_hex(bytes));
}

// ── refusals that happen before anything is sent ──────────────────────────────────────

/// An empty file is refused here, not filed and then puzzled over.
#[test]
fn an_empty_file_is_never_filed() {
    let mut archive = Canned::saying(Vec::new());

    let error =
        archive_client::push(&mut archive, &config(), &key(), b"", NOW).expect_err("refused");

    assert!(matches!(&error, ArchiveClientError::Config(_)), "{error}");
    assert!(archive.asked.is_empty(), "nothing was sent");
}

/// Something that is not an artifact address is refused before a request is signed.
#[test]
fn a_fetch_of_something_that_is_not_a_digest_sends_nothing() {
    let mut archive = Canned::saying(Vec::new());

    let error = archive_client::fetch(&mut archive, &config(), &key(), "report.json", NOW)
        .expect_err("refused");

    assert!(matches!(&error, ArchiveClientError::Config(_)), "{error}");
    assert!(archive.asked.is_empty(), "nothing was sent");
}

/// A fetch asks for exactly the path it signed, and asks with GET.
#[test]
fn a_fetch_addresses_the_artifact_by_digest() {
    let digest = sha256_hex(b"whatever");
    let mut archive = Canned::saying(vec![Ok(ArchiveAnswer {
        status: 200,
        body: b"whatever".to_vec(),
    })]);

    let back =
        archive_client::fetch(&mut archive, &config(), &key(), &digest, NOW).expect("fetched");

    assert_eq!(back, b"whatever");
    assert_eq!(
        archive.asked,
        [("GET".to_string(), format!("/v1/evidence/{digest}"))]
    );
}

/// Two pushes never reuse a nonce. The archive refuses a repeat permanently, so a client that
/// derived one from a counter or a clock would eventually lock itself out of filing anything.
#[test]
fn every_request_carries_a_fresh_nonce() {
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        assert!(
            seen.insert(archive_client::mint_nonce().expect("the system CSPRNG")),
            "a nonce repeated"
        );
    }
}

// ── listing what was filed ────────────────────────────────────────────────────────────

/// A listing row, in the wire shape the archive actually sends. Written by hand, not built from a
/// shared struct, so the test pins the client to the documented format.
fn held_row(digest: &str, kind: &str, at: u64, check: &str) -> serde_json::Value {
    json!({
        "digest": digest,
        "kind": kind,
        "warrant_id": "wrt_test",
        "submitted_at": at,
        "submitted_by_device": DEVICE,
        "ingest_check": check,
    })
}

/// A well-formed listing answer, `artifacts` set to whatever the test wants.
fn holdings_body(artifacts: serde_json::Value) -> serde_json::Value {
    json!({
        "format": ARCHIVE_RESPONSE_FORMAT,
        "data": {
            "warrant_id": "wrt_test",
            "artifacts": artifacts,
            "kinds_held": ["report", "stop", "ledger"],
        },
        "not_a_verdict": {
            "ingest_check": "unknown",
            "reason": "a listing reads no artifact body, so no signature was checked for these rows.",
            "verify_locally": "verify locally with `warrantor verify <file> --issuer <hex>`",
        },
    })
}

/// A list asks for exactly the warrant it was given, with GET, and the rows come back in the
/// archive's order as plain facts — including a door's note of `failed`, carried verbatim rather
/// than tidied into a pass.
#[test]
fn a_list_addresses_one_warrant_and_carries_the_rows_verbatim() {
    let older = held_row(&"1".repeat(64), "report", NOW, "ok");
    let newer = held_row(&"2".repeat(64), "stop", NOW + 1, "failed");
    let mut archive = Canned::ok(holdings_body(json!([newer, older])));

    let holdings = archive_client::list(&mut archive, &config(), &key(), "wrt_test", NOW)
        .expect("a well-formed listing is read");

    assert_eq!(
        archive.asked,
        [(
            "GET".to_string(),
            "/v1/warrants/wrt_test/evidence".to_string()
        )]
    );
    assert_eq!(holdings.warrant_id, "wrt_test");
    assert_eq!(
        holdings.artifacts.len(),
        2,
        "the rows arrive in the order sent"
    );
    assert_eq!(holdings.artifacts[0].digest, "2".repeat(64));
    assert_eq!(holdings.artifacts[0].kind, "stop");
    assert_eq!(holdings.artifacts[0].warrant_id, "wrt_test");
    assert_eq!(holdings.artifacts[0].submitted_at, NOW + 1);
    assert_eq!(holdings.artifacts[0].submitted_by_device, DEVICE);
    assert_eq!(
        holdings.artifacts[0].ingest_check, "failed",
        "a failed door's note is a fact about the filing, not something to soften"
    );
    assert!(
        !holdings.verify_locally.is_empty(),
        "the archive's own sentence about where a real answer comes from travels with the listing"
    );
}

/// An empty listing is a real answer — this archive holds nothing about that warrant — and it is
/// returned as one. The archive says "nothing" with a 200 and an empty array, on purpose.
#[test]
fn an_empty_listing_is_an_answer_not_a_failure() {
    let mut archive = Canned::ok(holdings_body(json!([])));

    let holdings = archive_client::list(&mut archive, &config(), &key(), "wrt_test", NOW)
        .expect("empty is what the archive said, and it said it with a 200");

    assert_eq!(holdings.warrant_id, "wrt_test");
    assert!(
        holdings.artifacts.is_empty(),
        "and it stays empty rather than growing a defaulted row"
    );
}

/// A listing that comes back about a warrant other than the one asked about is refused, at
/// runtime. The echo check is the listing's analogue of `push`'s digest check: an answer about a
/// different warrant is not an answer to the question, and returning it would send the operator
/// to `fetch` under someone else's evidence.
#[test]
fn a_listing_about_a_different_warrant_than_the_one_asked_is_refused() {
    let mut body = holdings_body(json!([]));
    *body.pointer_mut("/data/warrant_id").unwrap() = json!("wrt_somebody_elses");
    let mut archive = Canned::ok(body);

    let error = archive_client::list(&mut archive, &config(), &key(), "wrt_test", NOW)
        .expect_err("an answer about a different warrant is not an answer");

    assert!(
        matches!(&error, ArchiveClientError::Unreadable { reason, .. }
            if reason.contains("wrt_somebody_elses") && reason.contains("wrt_test")),
        "{error}"
    );
}

/// A store the archive cannot read is a refusal, and that refusal is what keeps "nothing held"
/// honest. Collapsing the 503 into an empty listing would make a broken archive indistinguishable
/// from an empty one — the exact pair this archive keeps apart on its side of the wire.
#[test]
fn a_store_the_archive_cannot_read_is_a_refusal_not_an_empty_listing() {
    let mut archive = Canned::refusing(
        503,
        "store_unavailable",
        "the archive could not read its store, so this listing was not produced. An empty list \
         would have been indistinguishable from an archive that holds nothing.",
    );

    let error = archive_client::list(&mut archive, &config(), &key(), "wrt_test", NOW)
        .expect_err("an unreadable store is not an empty one");

    assert!(
        matches!(&error, ArchiveClientError::Refused { status, code, .. }
            if *status == 503 && code == "store_unavailable"),
        "{error}"
    );
}

/// A 200 with no `artifacts` array is refused rather than read as empty. "The archive holds
/// nothing" and "the archive said something this client cannot parse" are different claims, and a
/// default of `vec![]` would erase the difference exactly where it matters most.
#[test]
fn a_listing_without_an_artifacts_array_is_refused_rather_than_assumed_empty() {
    let mut archive = Canned::ok(json!({
        "format": ARCHIVE_RESPONSE_FORMAT,
        "data": { "warrant_id": "wrt_test" },
        "not_a_verdict": { "ingest_check": "unknown", "reason": "", "verify_locally": "…" },
    }));

    let error = archive_client::list(&mut archive, &config(), &key(), "wrt_test", NOW)
        .expect_err("a missing field is not an empty answer");

    assert!(
        matches!(&error, ArchiveClientError::Unreadable { reason, .. }
            if reason.contains("artifacts")),
        "{error}"
    );
}

/// A row missing one field is refused rather than defaulted. `ingest_check` especially: defaulting
/// it to `ok` would turn a row the door flagged into one the CLI renders as clean, which is the
/// one transformation this client must never perform.
#[test]
fn a_row_missing_its_ingest_check_is_refused_rather_than_defaulted_to_ok() {
    let row = json!({
        "digest": "1".repeat(64),
        "kind": "report",
        "warrant_id": "wrt_test",
        "submitted_at": NOW,
        "submitted_by_device": DEVICE,
        // ingest_check omitted.
    });
    let mut archive = Canned::ok(holdings_body(json!([row])));

    let error = archive_client::list(&mut archive, &config(), &key(), "wrt_test", NOW)
        .expect_err("refused");

    assert!(
        matches!(&error, ArchiveClientError::Unreadable { reason, .. }
            if reason.contains("ingest_check")),
        "{error}"
    );
}

/// A 200 that carries no `not_a_verdict` block is refused, with a reason naming the block — not
/// read as a listing whose `verify_locally` happens to be absent. That block is where the archive
/// says what a listing is worth; an answer without it is not the archive's answer.
#[test]
fn a_listing_without_a_not_a_verdict_block_is_refused() {
    let mut archive = Canned::ok(json!({
        "format": ARCHIVE_RESPONSE_FORMAT,
        "data": { "warrant_id": "wrt_test", "artifacts": [] },
    }));

    let error = archive_client::list(&mut archive, &config(), &key(), "wrt_test", NOW)
        .expect_err("refused");

    assert!(
        matches!(&error, ArchiveClientError::Unreadable { reason, .. }
            if reason.contains("not_a_verdict")),
        "{error}"
    );
}

/// A warrant id with a path separator, or none at all, is refused before anything is signed — the
/// path is inside the signature, so `../` in a warrant id would otherwise be signed and sent.
#[test]
fn a_list_of_something_that_is_not_a_warrant_id_sends_nothing() {
    let mut archive = Canned::saying(Vec::new());

    for bad in ["", "wrt_../keys"] {
        let error = archive_client::list(&mut archive, &config(), &key(), bad, NOW)
            .expect_err("refused before the wire");
        assert!(
            matches!(&error, ArchiveClientError::Config(_)),
            "{bad:?}: {error}"
        );
    }
    assert!(archive.asked.is_empty(), "nothing was sent");
}

// ── the CLI verb ──────────────────────────────────────────────────────────────────────

/// Run `warrantor archive <args...>` against a store rooted in `home`.
fn run_archive(home: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .arg("archive")
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor archive");
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), both)
}

/// `warrantor archive list` with no warrant id is a usage error, and it is the pairing that is
/// asked about second — a machine that never enrolled still gets the usage error, not a lecture
/// about keys.
#[test]
fn archive_list_without_an_id_is_a_usage_error() {
    let home = tempdir("list-no-id");

    let (success, output) = run_archive(&home, &["list"]);

    assert!(!success, "{output}");
    assert!(output.contains("usage: warrantor archive list"), "{output}");
}

/// An unknown archive verb names all four, so an operator who guesses can see `list` exists.
#[test]
fn an_unknown_archive_verb_names_all_four() {
    let home = tempdir("unknown-verb");

    let (success, output) = run_archive(&home, &["retrieve"]);

    assert!(!success, "{output}");
    assert!(output.contains("enrol, push, fetch, list"), "{output}");
}

/// The synopsis names the list verb. A synopsis that has drifted from the dispatch is how a verb
/// ships unreachable — listed in the match, absent from the help an operator actually reads.
#[test]
fn the_synopsis_names_the_list_verb() {
    let home = tempdir("usage");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .expect("run warrantor with no arguments");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(output.contains("list <warrant-id>"), "{output}");
}

// ── enrolling twice ───────────────────────────────────────────────────────────────────
//
// These drive the real binary, because what is being tested is an ordering: the refusal has to
// happen before a key is minted and before anything goes on the wire, and only the command knows
// that order. The archive URL below points at a port nothing is listening on — if a test here ever
// reaches the network it will hang or fail loudly rather than pass by accident.

/// `warrantor archive enrol` on an already-paired machine refuses, names the device that is still
/// active at the archive, and changes nothing on disk.
///
/// Silently re-enrolling is the failure this exists to prevent: it mints a SECOND device id at the
/// archive with the first row left active, and overwrites the only local record of the first id —
/// and `warrantor-archive revoke` takes a device id. The natural way to get there is the ordinary
/// way, a mistyped URL and a re-run.
#[test]
fn enrolling_over_an_existing_pairing_is_refused_and_touches_nothing() {
    let home = tempdir("enrol-twice");
    let root = home.join(".warrantor");
    std::fs::create_dir_all(root.join("keys")).expect("keys dir");
    config().save(&root).expect("an existing pairing");
    std::fs::write(root.join("keys/device.key"), key().to_bytes()).expect("an existing key");

    let (success, output) = run_enrol(&home, &["--url", "http://127.0.0.1:9", "--code", "abc"]);

    assert!(
        !success,
        "enrol exited 0 over an existing pairing: {output}"
    );
    assert!(
        output.contains(DEVICE) && output.contains("warrantor-archive revoke --device"),
        "the refusal names the device that would have been orphaned, and how to withdraw it: \
         {output}"
    );
    assert!(
        output.contains("--replace"),
        "the refusal says how to proceed on purpose: {output}"
    );
    assert_eq!(
        ArchiveConfig::load(&root).expect("the pairing record is untouched"),
        config()
    );
    assert_eq!(
        std::fs::read(root.join("keys/device.key")).expect("the key is untouched"),
        key().to_bytes(),
        "a refused enrolment must not have replaced the device key"
    );
}

/// A pairing record that exists and cannot be parsed is still a pairing: refused, not treated as an
/// unpaired machine.
#[test]
fn enrolling_over_an_unreadable_pairing_record_is_refused_too() {
    let home = tempdir("enrol-over-junk");
    let root = home.join(".warrantor");
    std::fs::create_dir_all(&root).expect("root");
    std::fs::write(ArchiveConfig::path(&root), b"{ half a record").expect("write");

    let (success, output) = run_enrol(&home, &["--url", "http://127.0.0.1:9", "--code", "abc"]);

    assert!(!success, "enrol exited 0 over a broken record: {output}");
    assert!(
        output.contains("already paired") && output.contains("cannot read it"),
        "the refusal says which of the two problems this is: {output}"
    );
}

/// `--url` and `--code` are still checked before the pairing state is, so a machine that was never
/// paired gets the usage error it deserves rather than a lecture about revocation.
#[test]
fn an_unpaired_machine_enrolling_without_a_code_gets_the_usage_error() {
    let home = tempdir("enrol-no-code");

    let (success, output) = run_enrol(&home, &["--url", "http://127.0.0.1:9"]);

    assert!(!success, "{output}");
    assert!(output.contains("--code is required"), "{output}");
    assert!(
        !home.join(".warrantor/keys/device.key").exists(),
        "no key is minted for an enrolment that never happened: {output}"
    );
}

/// Run `warrantor archive enrol <args>` against a store rooted in `home`.
fn run_enrol(home: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .arg("archive")
        .arg("enrol")
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor archive enrol");
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), both)
}

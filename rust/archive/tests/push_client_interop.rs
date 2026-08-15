//! The client and the server, checked against each other in one process.
//!
//! This crate is the only place that can hold this test: it is the only crate permitted to depend
//! on both halves. The client lives in `warrantor_warrant::archive_client` because the dependency
//! edge runs archive → warrant and must never invert; the server lives here; and until this file
//! existed nothing anywhere had ever checked that the two agree about what a device signature
//! covers.
//!
//! It is not a mock. [`LoopbackArchive`] is a real [`ArchiveTransport`] whose `send` builds an
//! [`HttpRequest`] and calls the real [`http::handle`] against a real [`MemoryStore`], so a request
//! travels the whole path — descriptor, DSSE PAE, Ed25519, credential parsing, freshness, nonce
//! store, ingest, response encoding, response parsing — with only the socket missing. What the
//! socket adds is framing, and framing is `serve.rs`'s and is tested there.
//!
//! The sabotage cases matter more than the happy one. A client that signed nothing at all would
//! still pass a test that only ever asserted 200 against a server that never checked.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use warrantor_archive::device::{self, FRESHNESS_WINDOW_SECONDS};
use warrantor_archive::http;
use warrantor_archive::store::{ArchiveStore, Device, MemoryStore};
use warrantor_warrant::archive_client::{
    self, ArchiveAnswer, ArchiveClientError, ArchiveConfig, ArchiveTransport, ARCHIVE_CONFIG_FORMAT,
};
use warrantor_warrant::report::{build, sha256_hex, SignedReport};
use warrantor_warrant::serve::{status, HttpRequest};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;
const DEVICE: &str = "dev_00112233445566778899aabbccddeeff";

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn settle_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn device_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-archive-interop-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// A real, issuer-signed report export: the bytes an operator would actually file.
fn evidence(dir: &std::path::Path) -> Vec<u8> {
    evidence_at(dir, NOW)
}

/// The same export built at a different moment, so it hashes differently: a warrant accumulates
/// one filing per distinct artifact, and distinct bytes are the only way to make two.
fn evidence_at(dir: &std::path::Path, at: u64) -> Vec<u8> {
    let mut warrant = Warrant::grant(
        "wrt_interop",
        "fix the auth token refresh bug",
        "spiffe://muveraai.com/agent/alpha",
        WarrantBounds {
            tools: ["github.create_pr".to_string()].into_iter().collect(),
            write_paths: ["src/**".to_string()].into_iter().collect(),
            egress_hosts: Default::default(),
            staged_classes: [SideEffectClass::Write].into_iter().collect(),
            expires_at: NOW + 3600,
            budget_cents_observed: Some(500),
            delegation_depth: 3,
        },
        at,
        &settle_key().verifying_key(),
        &issuer(),
    )
    .expect("grant");
    warrant.state = WarrantState::Open;
    let stored = StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        // No mark: this fixture is about the push path, and a warrant granted before the witness
        // existed carries `None` too. `open_witnessed` checks nothing when it is absent rather
        // than inventing a verdict, so the interop assertions are unaffected either way.
        staged_chain: None,
    };
    let queue = StagingQueue::open(dir.join("q.jsonl"), "wrt_interop", EffectRegistry::github())
        .expect("open queue");
    let signed: SignedReport = build(&stored, Ok(&queue), &issuer().verifying_key(), at)
        .sign(&issuer(), "issuer")
        .expect("sign");
    // `to_vec_pretty`, exactly as `warrantor report --export` writes it. The bytes are the artifact;
    // re-encoding them any other way here would test a file nobody has.
    serde_json::to_vec_pretty(&signed).expect("encode")
}

/// What a hostile or broken archive does to the request or the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sabotage {
    /// Behave.
    None,
    /// Change one byte of the body after the client signed it.
    MutateBody,
    /// Route a fetch at an artifact address other than the one the client signed for.
    ///
    /// Another *digest* rather than another *route*: the archive resolves the method before it
    /// authenticates, so pointing a POST at a GET-only route answers 405 and never reaches the
    /// signature. Two addresses on the same route is the case that actually exercises whether the
    /// path the client signed is the path the server checked.
    SwapPath,
    /// File the artifact honestly, then answer with a different digest.
    LieAboutTheDigest,
    /// Serve bytes other than the ones the requested digest names.
    ServeOtherBytes,
}

/// The real server, reachable without a socket.
struct LoopbackArchive {
    store: MemoryStore,
    /// The archive's own clock. Separate from the client's, so clock skew is testable.
    now: u64,
    sabotage: Sabotage,
    /// Every path the server actually saw, for assertions about what was signed.
    seen: Vec<String>,
}

impl LoopbackArchive {
    fn new() -> Self {
        let mut store = MemoryStore::new();
        store.enrol_without_a_code(Device {
            id: DEVICE.to_string(),
            label: "Ana's laptop".to_string(),
            public_key: hex::encode(device_key().verifying_key().to_bytes()),
            enrolled_at: NOW,
            revoked_at: None,
        });
        Self {
            store,
            now: NOW,
            sabotage: Sabotage::None,
            seen: Vec::new(),
        }
    }
}

impl ArchiveTransport for LoopbackArchive {
    fn send(
        &mut self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<ArchiveAnswer, String> {
        self.seen.push(path.to_string());
        let routed = if self.sabotage == Sabotage::SwapPath {
            format!("/v1/evidence/{}", "a".repeat(64))
        } else {
            path.to_string()
        };
        let segments: Vec<&str> = routed.split('/').filter(|s| !s.is_empty()).collect();
        let mut request = HttpRequest::new(method, &segments, BTreeMap::new());
        request.authorization = authorization.map(str::to_string);
        request.body = if self.sabotage == Sabotage::MutateBody {
            let mut mutated = body.to_vec();
            if let Some(first) = mutated.first_mut() {
                *first = first.wrapping_add(1);
            }
            mutated
        } else {
            body.to_vec()
        };
        let response = http::handle(&mut self.store, &request, self.now);
        let body = match response.raw {
            Some((_, bytes)) => match self.sabotage {
                Sabotage::ServeOtherBytes => {
                    b"{\"format\":\"not the artifact you asked for\"}".to_vec()
                }
                _ => bytes,
            },
            None => {
                let mut value = response.body;
                if self.sabotage == Sabotage::LieAboutTheDigest {
                    if let Some(digest) = value.pointer_mut("/data/digest") {
                        *digest = Value::String("0".repeat(64));
                    }
                }
                serde_json::to_vec(&value).expect("encode response")
            }
        };
        Ok(ArchiveAnswer {
            status: response.status,
            body,
        })
    }
}

fn config() -> ArchiveConfig {
    ArchiveConfig {
        format: ARCHIVE_CONFIG_FORMAT.to_string(),
        url: "http://127.0.0.1:8788".to_string(),
        device_id: DEVICE.to_string(),
        // Derived from `device_key()` rather than written as a literal, because every call below
        // signs with that key and `check_key` compares the two. A hardcoded hex here would be a
        // second place to update whenever the fixture key changes, and getting it wrong would fail
        // as a pairing mismatch inside tests that are about something else entirely.
        device_public_key: hex::encode(device_key().verifying_key().to_bytes()),
        label: "Ana's laptop".to_string(),
        enrolled_at: NOW,
    }
}

// ── the loop that did not exist ───────────────────────────────────────────────────────

/// The whole point of the change: a client files evidence and the archive names the device.
///
/// Before this, `submitted_by_device` had never held anything but a literal a test wrote itself,
/// because nothing outside this crate could produce a `Warrantor-Device` header at all.
#[test]
fn a_client_files_evidence_and_the_archive_attributes_it_to_the_device() {
    let dir = tempdir("push");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();

    let filed = archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW)
        .expect("a signed submission is accepted");

    assert_eq!(
        filed.digest,
        sha256_hex(&bytes),
        "the address names the bytes"
    );
    assert_eq!(filed.kind, "report");
    assert_eq!(filed.warrant_id, "wrt_interop");
    assert!(!filed.already_held);
    assert_eq!(
        filed.submitted_by_device, DEVICE,
        "the filing is attributed to the enrolled device, not to 'someone with the token'"
    );
    assert_eq!(
        filed.ingest_check, "ok",
        "a genuine issuer-signed export passes the door's hygiene check"
    );
    assert!(
        !filed.verify_locally.is_empty(),
        "the archive's own sentence about what its opinion is worth is carried to the client"
    );
    assert_eq!(archive.seen, ["/v1/evidence"]);
}

/// The bytes come back out byte for byte, and reading is authenticated too.
///
/// `GET /v1/evidence/{sha256}` needs a device signature exactly as the submission did, so this half
/// of the loop was as unreachable as the other half. A `curl` cannot do it.
#[test]
fn what_was_filed_can_be_fetched_back_verbatim() {
    let dir = tempdir("fetch");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    let filed =
        archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW).expect("filed");

    let back = archive_client::fetch(&mut archive, &config(), &device_key(), &filed.digest, NOW)
        .expect("an enrolled device can read what it filed");

    assert_eq!(
        back, bytes,
        "the archive returns what it was given, byte for byte"
    );
    // And the returned bytes still verify with no archive in the call graph.
    let received: SignedReport = serde_json::from_slice(&back).expect("decode");
    warrantor_warrant::report::verify_export_signed_by(&received, &issuer().verifying_key())
        .expect("verification happens at the client, against an anchor it pinned");
}

/// Filing the same bytes twice is idempotent, and says so rather than failing.
#[test]
fn filing_the_same_evidence_twice_reports_already_held() {
    let dir = tempdir("idempotent");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();

    let first =
        archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW).expect("filed");
    let second = archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW + 1)
        .expect("a retry is not an error");

    assert!(!first.already_held);
    assert!(second.already_held);
    assert_eq!(first.digest, second.digest);
    assert_eq!(archive.store.len(), 1);
}

// ── enumerating what was filed ────────────────────────────────────────────────────────

/// The loop the listing verb exists to close: file evidence, enumerate it by warrant, and the
/// digest the listing prints is the address that fetches the bytes back.
///
/// `push` prints a digest exactly once and `fetch` takes a digest, not a warrant id — so an
/// operator whose scrollback is gone could not even find out what they filed. This checks the
/// three verbs agree with each other and with the store: the row names the filing, the digest
/// names the bytes, and fetching that digest returns them.
#[test]
fn what_was_filed_can_be_listed_and_the_listing_fetches() {
    let dir = tempdir("list");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    let filed =
        archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW).expect("filed");

    let holdings = archive_client::list(
        &mut archive,
        &config(),
        &device_key(),
        "wrt_interop",
        NOW + 1,
    )
    .expect("an enrolled device can enumerate what it filed");

    assert_eq!(holdings.warrant_id, "wrt_interop");
    assert_eq!(holdings.artifacts.len(), 1);
    let row = &holdings.artifacts[0];
    assert_eq!(row.digest, filed.digest, "the row names the filing");
    assert_eq!(row.digest, sha256_hex(&bytes), "the digest names the bytes");
    assert_eq!(row.kind, "report");
    assert_eq!(row.warrant_id, "wrt_interop");
    assert_eq!(row.submitted_by_device, DEVICE);
    assert_eq!(row.ingest_check, "ok");
    assert!(
        !holdings.verify_locally.is_empty(),
        "the archive's own sentence about what a listing is worth travels with it"
    );
    assert!(
        archive
            .seen
            .contains(&"/v1/warrants/wrt_interop/evidence".to_string()),
        "the listing went to the route the client signed for"
    );

    let back = archive_client::fetch(&mut archive, &config(), &device_key(), &row.digest, NOW + 2)
        .expect("the digest a listing prints is the address fetch takes");
    assert_eq!(back, bytes, "and it addresses the bytes that were filed");
}

/// A warrant nothing was ever filed for lists as empty — a 200, not a refusal — and the client
/// carries it as an answer rather than an error. The archive keeps "nothing held" and "store
/// unreadable" apart on its side of the wire (it answers the second with `store_unavailable`
/// rather than an empty list); the client keeps them apart on its, and both halves are checked.
#[test]
fn a_warrant_with_nothing_filed_lists_as_empty() {
    let mut archive = LoopbackArchive::new();

    let holdings = archive_client::list(
        &mut archive,
        &config(),
        &device_key(),
        "wrt_never_filed",
        NOW,
    )
    .expect("empty is an answer, not a failure");

    assert_eq!(holdings.warrant_id, "wrt_never_filed");
    assert!(
        holdings.artifacts.is_empty(),
        "the archive said it holds nothing, and nothing is what arrived"
    );
}

/// A listing is newest first, so the top row is the latest filing — the one an operator reaching
/// for the listing is most likely after. Two distinct artifacts for one warrant, filed in order,
/// listed reversed.
#[test]
fn a_listing_is_newest_first() {
    let dir = tempdir("newest-first");
    let earlier = evidence_at(&dir, NOW);
    let later = evidence_at(&dir, NOW + 1);
    assert_ne!(
        sha256_hex(&earlier),
        sha256_hex(&later),
        "the fixture must make two artifacts, not one idempotent re-file"
    );
    let mut archive = LoopbackArchive::new();
    let first =
        archive_client::push(&mut archive, &config(), &device_key(), &earlier, NOW).expect("filed");
    // The archive stamps `submitted_at` from its OWN clock, not from the client's signature
    // timestamp — a client could otherwise set its filing time to anything it liked. Advancing the
    // archive between the two filings is what makes their stamps differ.
    archive.now = NOW + 1;
    let second = archive_client::push(&mut archive, &config(), &device_key(), &later, NOW + 1)
        .expect("filed");

    let holdings = archive_client::list(
        &mut archive,
        &config(),
        &device_key(),
        "wrt_interop",
        NOW + 2,
    )
    .expect("listed");

    assert_eq!(holdings.artifacts.len(), 2);
    assert_eq!(
        holdings.artifacts[0].digest, second.digest,
        "the later filing is listed first"
    );
    assert_eq!(holdings.artifacts[0].submitted_at, NOW + 1);
    assert_eq!(holdings.artifacts[1].digest, first.digest);
    assert_eq!(holdings.artifacts[1].submitted_at, NOW);
}

// ── what must be refused ──────────────────────────────────────────────────────────────

/// A body changed after signing is refused. This is what the body digest in the descriptor is for.
#[test]
fn a_body_mutated_after_signing_is_refused() {
    let dir = tempdir("mutated");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    archive.sabotage = Sabotage::MutateBody;

    let error = archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW)
        .expect_err("a signature must not cover bytes other than the ones that arrived");

    assert!(
        matches!(
            &error,
            ArchiveClientError::Refused { status, code, .. }
                if *status == status::UNAUTHORIZED && code == "unauthorized"
        ),
        "{error}"
    );
    assert!(archive.store.is_empty(), "nothing was filed");
}

/// A signature taken over one artifact address cannot be presented at another.
///
/// The client asks for the digest it filed; the archive routes the request at a different one. The
/// path is inside the descriptor, so the signature no longer checks out and the read is refused —
/// which is what stops a captured read of a public artifact from becoming a read of any artifact.
#[test]
fn a_signature_cannot_be_lifted_onto_another_artifact_address() {
    let dir = tempdir("swapped");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    let filed =
        archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW).expect("filed");
    archive.sabotage = Sabotage::SwapPath;

    let error = archive_client::fetch(&mut archive, &config(), &device_key(), &filed.digest, NOW)
        .expect_err("the path is inside the descriptor");

    assert!(
        matches!(&error, ArchiveClientError::Refused { code, .. } if code == "unauthorized"),
        "{error}"
    );
}

/// Clock skew past the window is refused, and it is refused *as clock skew*.
///
/// The distinction is the test. An operator told only "authentication failed" goes hunting a key
/// problem; `stale_request` names both clocks and ends the search in a minute.
#[test]
fn a_clock_outside_the_window_is_refused_as_a_clock_problem() {
    let dir = tempdir("stale");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();

    let client_clock = NOW - FRESHNESS_WINDOW_SECONDS - 1;
    let error = archive_client::push(&mut archive, &config(), &device_key(), &bytes, client_clock)
        .expect_err("a request from outside the window is refused");

    let ArchiveClientError::Refused {
        status,
        code,
        message,
    } = &error
    else {
        panic!("expected the archive's own refusal: {error}");
    };
    assert_eq!(*status, status::UNAUTHORIZED);
    assert_eq!(code, "stale_request");
    assert!(
        message.contains(&client_clock.to_string()) && message.contains(&NOW.to_string()),
        "the message names both clocks: {message}"
    );
}

/// One nonce, twice, is refused permanently — and the client never mints the same one anyway.
///
/// Driven through `sign_request` rather than through `push`, because `push` mints its nonce from
/// the system CSPRNG and cannot be made to repeat one. That is the property being relied on; this
/// test is what the reliance rests on.
#[test]
fn a_replayed_nonce_is_refused() {
    let dir = tempdir("replay");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    let nonce = "a_fixed_nonce";

    for expected_ok in [true, false] {
        let header = device::sign_request(
            &device_key(),
            "POST",
            "/v1/evidence",
            DEVICE,
            nonce,
            NOW,
            &bytes,
        );
        let mut request = HttpRequest::new("POST", &["v1", "evidence"], BTreeMap::new());
        request.authorization = Some(header);
        request.body = bytes.clone();
        let response = http::handle(&mut archive.store, &request, NOW);
        if expected_ok {
            assert_eq!(response.status, status::OK);
        } else {
            assert_eq!(response.status, status::UNAUTHORIZED);
            assert_eq!(
                response.body.pointer("/error/code").and_then(Value::as_str),
                Some("replayed_nonce")
            );
        }
    }
}

/// An archive that names a digest other than the one the bytes hash to is refused, at runtime.
///
/// This is the silent-wrong the whole client is shaped around. The archive filed something; it
/// answered 200; every field is present and well-typed. Only the address disagrees — and a
/// content-addressed archive whose address does not name the bytes is not holding the operator's
/// file. Reporting that as "filed" would put a digest in a pipeline log that fetches back a
/// different artifact, and both would verify against their own signatures.
#[test]
fn an_archive_that_names_a_different_digest_is_refused_rather_than_reported_as_filed() {
    let dir = tempdir("lying-digest");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    archive.sabotage = Sabotage::LieAboutTheDigest;

    let error = archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW)
        .expect_err("a 200 is not enough: the address must name the bytes that were sent");

    let ArchiveClientError::DigestDisagreement {
        expected, returned, ..
    } = &error
    else {
        panic!("expected a digest disagreement, got: {error}");
    };
    assert_eq!(expected, &sha256_hex(&bytes));
    assert_eq!(returned, &"0".repeat(64));
}

/// An archive that serves bytes other than the ones asked for is refused, at runtime.
#[test]
fn an_archive_that_serves_the_wrong_bytes_is_refused() {
    let dir = tempdir("wrong-bytes");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    let filed =
        archive_client::push(&mut archive, &config(), &device_key(), &bytes, NOW).expect("filed");
    archive.sabotage = Sabotage::ServeOtherBytes;

    let error = archive_client::fetch(&mut archive, &config(), &device_key(), &filed.digest, NOW)
        .expect_err("a fetch by digest must check the digest it got back");

    assert!(
        matches!(&error, ArchiveClientError::DigestDisagreement { .. }),
        "{error}"
    );
}

/// A device the archive never enrolled cannot file anything, however well-formed its signature is.
#[test]
fn an_unenrolled_device_is_refused() {
    let dir = tempdir("stranger");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    let mut stranger = config();
    stranger.device_id = "dev_ffffffffffffffffffffffffffffffff".to_string();

    let error = archive_client::push(&mut archive, &stranger, &device_key(), &bytes, NOW)
        .expect_err("an unknown device is refused");

    assert!(
        matches!(&error, ArchiveClientError::Refused { code, .. } if code == "unauthorized"),
        "{error}"
    );
}

// ── enrolment ─────────────────────────────────────────────────────────────────────────

/// The client claims a real one-time code and gets a usable identity back.
#[test]
fn the_client_enrols_against_a_one_time_code_and_can_then_file() {
    let dir = tempdir("enrol");
    let bytes = evidence(&dir);
    let mut archive = LoopbackArchive::new();
    let code = device::EnrolmentCode::mint().expect("mint");
    archive
        .store
        .create_enrolment_code(code.digest(), "Bo's laptop", NOW, NOW + 900)
        .expect("record the code");

    let fresh = SigningKey::from_bytes(&[42; 32]);
    let enrolled = archive_client::enrol(
        &mut archive,
        "http://127.0.0.1:8788",
        code.code(),
        &fresh.verifying_key(),
    )
    .expect("a fresh code enrols");

    assert_eq!(enrolled.label, "Bo's laptop");
    assert!(warrantor_warrant::archive_client::is_device_id(
        &enrolled.device_id
    ));

    // The identity is immediately usable: the whole loop, from a code to a filed artifact.
    let mut paired = config();
    paired.device_id = enrolled.device_id.clone();
    let filed = archive_client::push(&mut archive, &paired, &fresh, &bytes, NOW).expect("filed");
    assert_eq!(filed.submitted_by_device, enrolled.device_id);

    // And the code is single-use: the same code cannot enrol a second device.
    let second = archive_client::enrol(
        &mut archive,
        "http://127.0.0.1:8788",
        code.code(),
        &SigningKey::from_bytes(&[43; 32]).verifying_key(),
    )
    .expect_err("a claimed code is spent");
    assert!(
        matches!(&second, ArchiveClientError::Refused { code, .. } if code == "code_not_usable"),
        "{second}"
    );
}

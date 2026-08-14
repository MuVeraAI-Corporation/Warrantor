//! The two tests this whole workstream exists to pass.
//!
//! W1's rule for every backend stage: **it ships only if a client can still verify without it.**
//! That test is what keeps a relay from quietly becoming an authority, so it is written here as
//! executable code rather than as a paragraph in an RFC.
//!
//! Two cases:
//!
//! * `a_client_verifies_an_exported_bundle_with_no_archive_in_the_process` — the positive one. No
//!   store, no HTTP, no socket, no archive type anywhere in the call graph.
//! * `a_malicious_archive_cannot_make_a_tampered_bundle_verify` — the negative one, with a hostile
//!   store that tries four attacks.
//!
//! # The fourth attack is the one that mattered
//!
//! Three of the four attacks fail against [`verify_export`] alone, because they leave the bundle
//! digest or a receipt binding inconsistent. The fourth does not: an archive holding **any**
//! Ed25519 keypair can fabricate a bundle and sign both receipts with it, producing a file that is
//! fully self-consistent. `verify_export` is anchor-free by construction — each receipt carries its
//! own public key — so that forgery passes it, and before this workstream `warrantor verify` merely
//! *printed* the key it had just failed to check against anything.
//!
//! That is why [`verify_export_signed_by`] had to be added before this crate could honestly ship,
//! and why attack four is asserted in **both** directions below: the unanchored check must pass and
//! the anchored one must fail. A future refactor that drops the anchor comparison fails here on the
//! first assertion, not on a subtle one.

use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};

use warrantor_warrant::report::{
    self, build, verify_export, verify_export_signed_by, ReportError, SignedReport,
};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-archive-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// The real issuer. In production this key lives on the operator's machine and never leaves it.
fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

/// A key the archive holds. Deliberately a *valid* Ed25519 key: the attack this file is about is
/// not "a broken signature", it is "a perfectly good signature by the wrong signer".
fn archive_key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn settle_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn bounds() -> WarrantBounds {
    WarrantBounds {
        tools: ["github.create_pr".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: Some(500),
        delegation_depth: 3,
    }
}

fn stored_as(id: &str, goal: &str) -> StoredWarrant {
    let mut warrant = Warrant::grant(
        id,
        goal,
        "spiffe://muveraai.com/agent/alpha",
        bounds(),
        NOW,
        &settle_key().verifying_key(),
        &issuer(),
    )
    .expect("grant");
    warrant.state = WarrantState::Open;
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

fn stored() -> StoredWarrant {
    stored_as("wrt_archive", "fix the auth token refresh bug")
}

/// A genuine, issuer-signed export of one warrant.
///
/// Takes the warrant rather than building a fixed one, because the graft attack below needs two
/// exports that genuinely differ: two identical bundles swapped for each other is not an attack,
/// and a test that "detected" it would be detecting nothing.
fn genuine_export_of(dir: &std::path::Path, stored: &StoredWarrant) -> SignedReport {
    let queue = StagingQueue::open(
        dir.join("q.jsonl"),
        &stored.warrant.claims.id,
        EffectRegistry::github(),
    )
    .expect("open queue");
    build(stored, Ok(&queue), &issuer().verifying_key(), NOW)
        .sign(&issuer(), "issuer")
        .expect("sign")
}

fn genuine_export(dir: &std::path::Path) -> SignedReport {
    genuine_export_of(dir, &stored())
}

// ── (a) the positive case ─────────────────────────────────────────────────────────────

/// A third party checks an exported bundle with nothing but the file and the issuer's key.
///
/// The point of this test is what it does **not** import. There is no `ArchiveStore`, no
/// `MemoryStore`, no HTTP request, no socket and no `warrantor_archive` type anywhere in the call
/// graph — this file is deliberately the one place in the crate's test suite where the archive is
/// absent, because "a client can verify without the archive" is only proven by a verification that
/// could not have touched it.
#[test]
fn a_client_verifies_an_exported_bundle_with_no_archive_in_the_process() {
    let dir = tempdir("no-archive");
    let export = genuine_export(&dir);

    // Serialised and re-read, so this is the file a third party would actually receive rather than
    // an in-memory value that never crossed a boundary.
    let bytes = serde_json::to_vec(&export).expect("encode");
    let received: SignedReport = serde_json::from_slice(&bytes).expect("decode");

    verify_export(&received).expect("a genuine export verifies with nothing but the file");
    verify_export_signed_by(&received, &issuer().verifying_key())
        .expect("and it verifies against the real issuer's key");
}

/// The same file, pinned to a key that is not the issuer's, is refused.
///
/// Without this, `verify_export_signed_by` could be implemented as `verify_export` and the test
/// above would still pass.
#[test]
fn the_anchored_check_refuses_a_genuine_bundle_pinned_to_the_wrong_key() {
    let dir = tempdir("wrong-anchor");
    let export = genuine_export(&dir);

    let error = verify_export_signed_by(&export, &archive_key().verifying_key())
        .expect_err("a genuine bundle must not verify against a key that did not sign it");
    assert!(
        matches!(error, ReportError::Binding(_)),
        "a key mismatch is a binding failure, not a digest or signature failure: {error}"
    );
}

// ── (b) the negative case ─────────────────────────────────────────────────────────────

/// A store that serves whatever it was told to serve.
///
/// Not an `ArchiveStore` implementation on purpose: the attacks below are about what a client does
/// with bytes it received, and routing them through the real store trait would test the store
/// rather than the client. This is the shortest thing that can stand in for "a server that returns
/// the bytes it feels like returning".
struct MaliciousArchive {
    serves: Vec<u8>,
}

impl MaliciousArchive {
    fn serving(bytes: Vec<u8>) -> Self {
        Self { serves: bytes }
    }

    /// What a client gets when it fetches. The client then verifies locally — which is the whole
    /// design — so this is the last point at which the attacker has any influence.
    fn fetch(&self) -> SignedReport {
        serde_json::from_slice(&self.serves).expect("the attacker serves parseable JSON")
    }
}

#[test]
fn a_malicious_archive_cannot_make_a_tampered_bundle_verify() {
    let dir = tempdir("malicious");
    let genuine = genuine_export(&dir);
    let anchor = issuer().verifying_key();

    // ── attack 1: flip a byte in the bundle ───────────────────────────────────────────
    //
    // The crudest edit: change the warrant's stated goal so the file describes different work. The
    // receipts still commit to the old bundle's digest.
    let mut tampered = genuine.clone();
    tampered.bundle.goal = "ship the thing without review".to_string();
    let attack = MaliciousArchive::serving(serde_json::to_vec(&tampered).expect("encode"));
    let error = verify_export(&attack.fetch()).expect_err("a tampered bundle must not verify");
    assert!(
        matches!(error, ReportError::Digest { .. }),
        "editing the bundle must fail on the digest: {error}"
    );

    // ── attack 2: delete a limitation ─────────────────────────────────────────────────
    //
    // The most tempting edit for an audited party, and the most dangerous: the limitations are
    // exactly the sentences that stop a reader hearing more than was said. Removing one has to be
    // as detectable as forging the verdict, and it is — it is the same digest.
    let mut trimmed = genuine.clone();
    assert!(
        !trimmed.bundle.limitations.is_empty(),
        "the fixture must carry limitations or this attack tests nothing"
    );
    trimmed.bundle.limitations.remove(0);
    let attack = MaliciousArchive::serving(serde_json::to_vec(&trimmed).expect("encode"));
    let error = verify_export(&attack.fetch())
        .expect_err("a bundle with a limitation removed must not verify");
    assert!(
        matches!(error, ReportError::Digest { .. }),
        "removing a limitation must fail on the digest: {error}"
    );

    // ── attack 3: lift a valid receipt onto a different bundle ────────────────────────
    //
    // The receipts here are genuine and verify on their own. They simply do not describe the bundle
    // they have been attached to, which is what the binding checks are for.
    let other_dir = tempdir("malicious-other");
    let other = genuine_export_of(
        &other_dir,
        &stored_as("wrt_other", "a different warrant entirely"),
    );
    assert_ne!(
        other.bundle_digest, genuine.bundle_digest,
        "the two exports must genuinely differ, or this attack swaps a bundle for itself"
    );
    let mut grafted = genuine.clone();
    grafted.bundle = other.bundle.clone();
    let attack = MaliciousArchive::serving(serde_json::to_vec(&grafted).expect("encode"));
    let error = verify_export(&attack.fetch())
        .expect_err("receipts lifted onto another bundle must not verify");
    assert!(
        matches!(error, ReportError::Digest { .. } | ReportError::Binding(_)),
        "a grafted receipt must fail on the digest or a binding: {error}"
    );

    // ── attack 4: re-sign a fabricated bundle end to end ──────────────────────────────
    //
    // The one that matters, and the only one that was not detectable before this workstream. The
    // archive builds a bundle saying whatever it likes and signs BOTH receipts with a key it holds.
    // Nothing is inconsistent: the digest covers the fabricated bundle, both receipts verify
    // against the key they carry, and they share that key.
    let mut fabricated_store = stored();
    fabricated_store.warrant = Warrant::grant(
        "wrt_archive",
        "a goal the agent never had",
        "spiffe://muveraai.com/agent/alpha",
        bounds(),
        NOW,
        &settle_key().verifying_key(),
        // Signed by the ARCHIVE's key, so the fabricated warrant is internally consistent too.
        &archive_key(),
    )
    .expect("grant");
    let queue = StagingQueue::open(
        tempdir("fabricated").join("q.jsonl"),
        "wrt_archive",
        EffectRegistry::github(),
    )
    .expect("open queue");
    let forged = build(
        &fabricated_store,
        Ok(&queue),
        &archive_key().verifying_key(),
        NOW,
    )
    .sign(&archive_key(), "archive")
    .expect("the archive can sign whatever it likes");

    let attack = MaliciousArchive::serving(serde_json::to_vec(&forged).expect("encode"));
    let received = attack.fetch();

    // Direction one: the unanchored check PASSES. This assertion is the reason the anchored check
    // exists, and a refactor that quietly made `verify_export` anchor-aware would fail here rather
    // than leave a hole nobody noticed.
    verify_export(&received).expect(
        "a fabricated bundle signed end to end by one key IS self-consistent — that is precisely \
         why an anchor is required, and why `warrantor verify` without --issuer says so",
    );

    // Direction two: the anchored check REFUSES. This is the assertion that carries the product
    // claim "a compromised archive cannot make a tampered bundle verify".
    let error = verify_export_signed_by(&received, &anchor).expect_err(
        "a bundle signed by the archive's own key must not verify against the pinned issuer",
    );
    assert!(
        matches!(error, ReportError::Binding(_)),
        "an archive-signed forgery must fail as a key binding: {error}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&hex::encode(anchor.to_bytes())),
        "the refusal must name the key the reader pinned, so they can tell a wrong-signer from a \
         tampered file: {message}"
    );
}

/// The archive's stored bytes are the client's bytes, and the digest is the whole coupling.
///
/// This is the property that makes every assertion above meaningful. If the archive returned
/// re-serialised JSON — even a faithful round trip through `serde_json` — the bytes a client
/// verifies would be bytes the archive chose, and "the archive returns what it was given" would be
/// a claim with no test behind it.
#[test]
fn the_archive_returns_the_bytes_it_was_given_and_the_digest_proves_it() {
    use warrantor_archive::artifact::ingest;
    use warrantor_archive::sha256_hex;
    use warrantor_archive::store::{ArchiveStore, MemoryStore};

    let dir = tempdir("verbatim");
    let export = genuine_export(&dir);
    // `to_vec_pretty` on purpose: this is what `warrantor report --export` writes, and pretty JSON
    // is exactly the shape a re-serialising archive would silently reformat.
    let filed = serde_json::to_vec_pretty(&export).expect("encode");

    let ingested = ingest(filed.clone()).expect("a genuine export is accepted at the door");
    let mut store = MemoryStore::new();
    store.enrol_without_a_code(warrantor_archive::store::Device {
        id: "dev_abc".to_string(),
        label: "Ana's laptop".to_string(),
        public_key: hex::encode([0u8; 32]),
        enrolled_at: NOW,
        revoked_at: None,
    });
    store
        .put_artifact(&ingested, "dev_abc", NOW)
        .expect("filed");

    let read_back = store
        .get_artifact(&ingested.digest)
        .expect("read")
        .expect("held");
    assert_eq!(
        read_back.bytes, filed,
        "the archive must return the submitted bytes verbatim, byte for byte"
    );
    assert_eq!(
        sha256_hex(&read_back.bytes),
        ingested.digest,
        "the digest must be over the bytes as filed"
    );

    // And the round trip still verifies, anchored, off the archive.
    let received: SignedReport = serde_json::from_slice(&read_back.bytes).expect("decode");
    verify_export_signed_by(&received, &issuer().verifying_key())
        .expect("an artifact that came out of the archive still verifies against the real issuer");
}

/// Every artifact `warrantor verify` reads is one this archive holds, and vice versa.
///
/// A drift test rather than a behaviour test. If a fourth export format is added to the CLI and not
/// here, the archive silently refuses evidence a user was told to file; if one is added here and
/// not to the CLI, the archive holds files nothing can read.
#[test]
fn the_archive_holds_exactly_the_three_formats_warrantor_verify_reads() {
    use warrantor_archive::artifact::ArtifactKind;
    use warrantor_warrant::{spend, stop};

    assert_eq!(
        ArtifactKind::Report.format(),
        report::REPORT_EXPORT_FORMAT,
        "the archive and the CLI must agree on what a report export is"
    );
    assert_eq!(ArtifactKind::Stop.format(), stop::STOP_EXPORT_FORMAT);
    assert_eq!(ArtifactKind::Ledger.format(), spend::LEDGER_EXPORT_FORMAT);
    assert_eq!(
        ArtifactKind::from_format("warrantor.something-else/1"),
        None,
        "an unknown format is a refusal at the door, never a stored blob"
    );
}

/// Unused-import guard for the fixture helpers above; keeps clippy honest about `BTreeMap`.
#[test]
fn fixtures_are_self_consistent() {
    let empty: BTreeMap<String, String> = BTreeMap::new();
    assert!(empty.is_empty());
    assert_eq!(stored().warrant.claims.id, "wrt_archive");
}

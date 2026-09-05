//! A8 — the evidence-integrity adversary against the only recorder that exists.
//!
//! Strategy A8 of the suite registered in `rust/warrant/tests/invariants/adversary/mod.rs`. It lives
//! here rather than there because the dependency edge runs **archive -> warrant, never the reverse**:
//! `rust/archive/Cargo.toml` declares `warrantor-warrant` as a path dependency, so a mirror
//! `[dev-dependencies]` on warrant would create a package cycle and, worse, hide an edge from
//! `tools/ci/wiring_census.py` — whose lines 28-29 exclude dev-dependencies from the census by
//! design. The shared `harness` module is a test-target module and is unreachable from another
//! crate, so this test carries its controls inline, in the same two-sided shape and with the same
//! message wording.
//!
//! # What A8 adds that `append_only.rs` does not already assert
//!
//! `append_only.rs::resubmitting_identical_bytes_is_idempotent_and_never_rewrites_the_first_submitter`
//! already establishes that a resubmission keeps the first submitter's attribution. Re-running that
//! with the word "adversary" in the test name would be a second copy of an existing assertion.
//!
//! A8 attacks the composition instead: `artifact::ingest` calls `report::verify_export`, which is
//! **anchor-free by construction**, so the archive's door asks "is this file internally consistent?"
//! and never "was this signed by an issuer anyone trusts?". An adversary holding a keypair it
//! generated itself can therefore manufacture an export, file it first, and own the custody record
//! on it. Both halves are asserted: the archive is right to refuse to rewrite the attribution, and
//! `submitted_by_device` therefore means *who filed this*, never *who produced this*.

use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;

use warrantor_archive::artifact::{ingest, Ingested};
use warrantor_archive::store::{ArchiveStore, Device, MemoryStore, PutOutcome};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{report, SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;

/// The key an honest operator's warrantor signs with.
fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

/// A key the adversary generated inside its own workload. Nobody has ever pinned it.
fn adversary_key() -> SigningKey {
    SigningKey::from_bytes(&[99; 32])
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-adversary-custody-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// An export over `id`, signed end to end by `signer`. With the issuer's key this is genuine
/// evidence; with the adversary's it is a fabrication that is nonetheless self-consistent.
fn export_bytes_signed_by(id: &str, goal: &str, signer: &SigningKey) -> Vec<u8> {
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
        signer,
    )
    .expect("grant");
    warrant.state = WarrantState::Open;
    let stored = StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    };
    let dir = tempdir(id);
    let queue =
        StagingQueue::open(dir.join("q.jsonl"), id, EffectRegistry::github()).expect("open queue");
    let signed = report::build(&stored, Ok(&queue), &signer.verifying_key(), NOW)
        .sign(signer, "issuer")
        .expect("sign");
    serde_json::to_vec_pretty(&signed).expect("encode")
}

fn ingested_signed_by(id: &str, goal: &str, signer: &SigningKey) -> Ingested {
    ingest(export_bytes_signed_by(id, goal, signer)).expect("the door accepts it")
}

fn store_with_devices(ids: &[&str]) -> MemoryStore {
    let mut store = MemoryStore::new();
    for (index, id) in ids.iter().enumerate() {
        store.enrol_without_a_code(Device {
            id: (*id).to_string(),
            label: format!("device {index}"),
            public_key: hex::encode([index as u8; 32]),
            enrolled_at: NOW,
            revoked_at: None,
        });
    }
    store
}

/// A8 — the adversary files evidence it manufactured itself, and owns the attribution on it.
#[test]
fn a8_a_first_filer_owns_the_attribution_and_the_door_never_asked_whose_key_signed_it() {
    let mut store = store_with_devices(&["dev_adversary", "dev_operator"]);

    // The control, first: a genuine export, signed by the operator's issuer key, is accepted. If
    // the door refused everything, the acceptance below would prove nothing about the key.
    let genuine = ingested_signed_by(
        "wrt_a8_genuine",
        "fix the auth token refresh bug",
        &issuer_key(),
    );
    assert_eq!(
        store
            .put_artifact(&genuine, "dev_operator", NOW)
            .expect("the genuine export is filed"),
        PutOutcome::Stored,
        "the honest filing must be accepted, or this test measures an error path"
    );

    // The attack: an export signed end to end by a key the adversary generated in its own workload.
    // `artifact::ingest` calls `report::verify_export`, which answers "has this changed since
    // signing" and never "whose key was that", so the door accepts it.
    let fabricated = ingested_signed_by(
        "wrt_a8_forged",
        "a goal the agent never pursued",
        &adversary_key(),
    );
    assert_eq!(
        store
            .put_artifact(&fabricated, "dev_adversary", NOW + 30)
            .expect("the fabricated export is filed too"),
        PutOutcome::Stored,
        "RECORDED, not fixed: the archive's door is anchor-free, so a self-consistent fabrication \
         enters custody exactly as genuine evidence does. Pinning an issuer is the reader's job \
         (report::verify_export_signed_by), and the archive deliberately is not a trust root."
    );

    // The adversary now files the operator's own bytes first, ahead of the operator.
    let contested = ingested_signed_by("wrt_a8_race", "who filed this first", &issuer_key());
    assert_eq!(
        store
            .put_artifact(&contested, "dev_adversary", NOW + 60)
            .expect("filed"),
        PutOutcome::Stored
    );
    // The control for the attribution half: the operator's identical bytes must be ACCEPTED, or
    // the assertion below would be about an error rather than about attribution.
    assert_eq!(
        store
            .put_artifact(&contested, "dev_operator", NOW + 120)
            .expect("filed again"),
        PutOutcome::AlreadyHeld,
        "the honest second filing must be accepted, or this test measures an error path"
    );

    let held = store
        .get_artifact(&contested.digest)
        .expect("read")
        .expect("held");
    assert_eq!(
        held.submitted_by_device, "dev_adversary",
        "RECORDED, not fixed: whoever files first owns the attribution on a digest. The archive is \
         right to refuse to rewrite it -- that is append-only -- and a reader must therefore treat \
         submitted_by_device as 'who filed this', never as 'who produced this'."
    );
    assert_eq!(
        held.bytes, contested.bytes,
        "and the bytes are the ones that were filed: the refusal to rewrite is what makes the \
         attribution residual tolerable rather than fatal"
    );
}

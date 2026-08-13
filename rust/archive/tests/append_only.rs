//! Append-only, and the retention default that grants nothing.
//!
//! Two of these tests are about behaviour and one is about *shape*. The shape one matters most:
//! `the_store_trait_offers_no_way_to_update_or_delete_an_artifact` is a source-level assertion,
//! because append-only stops being a guarantee the moment a convenience method exists, however
//! carefully guarded its call sites are.
//!
//! What is tested here and what is not: the trait and [`MemoryStore`] are exercised in full; the
//! schema's own two enforcement mechanisms — a `BEFORE UPDATE OR DELETE` trigger and a runtime role
//! with no UPDATE grant — are not, because CI has no Postgres. The `#[ignore]`d test at the bottom
//! names the compose command that runs them against a real database.

use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;

use warrantor_archive::artifact::{ingest, ArtifactKind, Ingested};
use warrantor_archive::store::{
    ArchiveStore, Device, ListFilter, MemoryStore, PutOutcome, RetentionPolicy,
};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{report, SideEffectClass, Warrant, WarrantBounds, WarrantState};

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

fn export_bytes(id: &str, goal: &str) -> Vec<u8> {
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
    let dir = tempdir("append");
    let queue =
        StagingQueue::open(dir.join("q.jsonl"), id, EffectRegistry::github()).expect("open queue");
    let signed = report::build(&stored, Ok(&queue), &issuer.verifying_key(), NOW)
        .sign(&issuer, "issuer")
        .expect("sign");
    serde_json::to_vec_pretty(&signed).expect("encode")
}

fn ingested(id: &str, goal: &str) -> Ingested {
    ingest(export_bytes(id, goal)).expect("a genuine export is accepted at the door")
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

/// Filing identical bytes twice is normal, is idempotent, and overwrites nothing.
///
/// Two people filing the same evidence is the ordinary case — an operator and a CI job both push
/// the same export — and an archive that errored on the second would teach them to stop filing.
/// What it must not do is *overwrite*, because the first submitter's name is the attribution.
#[test]
fn resubmitting_identical_bytes_is_idempotent_and_never_rewrites_the_first_submitter() {
    let mut store = store_with_devices(&["dev_aaaa", "dev_bbbb"]);
    let artifact = ingested("wrt_archive", "fix the auth token refresh bug");

    let first = store
        .put_artifact(&artifact, "dev_aaaa", NOW)
        .expect("filed");
    assert_eq!(first, PutOutcome::Stored);

    let second = store
        .put_artifact(&artifact, "dev_bbbb", NOW + 60)
        .expect("filed again");
    assert_eq!(
        second,
        PutOutcome::AlreadyHeld,
        "identical bytes are already held: not an error, and not a second row"
    );
    assert_eq!(
        store.len(),
        1,
        "a resubmission must not create a second row"
    );

    let held = store
        .get_artifact(&artifact.digest)
        .expect("read")
        .expect("held");
    assert_eq!(
        held.submitted_by_device, "dev_aaaa",
        "the first submitter keeps the attribution; a resubmission must not rewrite who filed it"
    );
    assert_eq!(
        held.submitted_at, NOW,
        "and must not rewrite when it was filed"
    );
}

/// Different bytes about the same warrant are a second artifact, not a replacement.
#[test]
fn different_bytes_under_one_warrant_create_a_second_artifact() {
    let mut store = store_with_devices(&["dev_aaaa"]);
    // Two exports of the same warrant that genuinely differ. Same warrant id, different goal, so
    // the digests differ and both belong to `wrt_archive`.
    let first = ingested("wrt_archive", "fix the auth token refresh bug");
    let second = ingested("wrt_archive", "fix the auth token refresh bug, take two");
    assert_ne!(
        first.digest, second.digest,
        "the fixtures must differ or this test asserts nothing"
    );

    store.put_artifact(&first, "dev_aaaa", NOW).expect("filed");
    store
        .put_artifact(&second, "dev_aaaa", NOW + 60)
        .expect("filed");
    assert_eq!(store.len(), 2);

    let listing = store
        .list_artifacts(&ListFilter {
            warrant_id: Some("wrt_archive".to_string()),
            kind: None,
        })
        .expect("list");
    assert_eq!(
        listing.len(),
        2,
        "both are held, and neither replaced the other"
    );
    assert_eq!(
        listing[0].digest, second.digest,
        "listings are newest first, so the later submission leads"
    );

    // The earlier one is still fetchable, unchanged. This is the whole of what custody means.
    let earlier = store
        .get_artifact(&first.digest)
        .expect("read")
        .expect("still held");
    assert_eq!(earlier.bytes, first.bytes);
}

/// The trait has no mutation on it, and that is not an accident of what has been needed so far.
///
/// A source-level assertion because there is no runtime way to test the absence of a method. If
/// someone adds `fn update_artifact` or `fn delete_artifact` to satisfy a caller, this test tells
/// them, at the point of the change, that they are removing the product claim rather than adding a
/// convenience.
#[test]
fn the_store_trait_offers_no_way_to_update_or_delete_an_artifact() {
    let source = include_str!("../src/store.rs");
    // Only the trait declaration block: `MemoryStore` legitimately mutates devices and nonces.
    let trait_body = source
        .split("pub trait ArchiveStore {")
        .nth(1)
        .expect("the trait must exist")
        .split("\n}")
        .next()
        .expect("the trait must be closed");
    for forbidden in [
        "fn update_artifact",
        "fn delete_artifact",
        "fn remove_artifact",
        "fn prune_artifacts",
        "fn overwrite",
    ] {
        assert!(
            !trait_body.contains(forbidden),
            "ArchiveStore declares {forbidden}. Append-only is the custody claim: an artifact that \
             can be revised is not evidence, it is a record of what the archive currently says. If \
             a correction is needed, file it as a new artifact — the first one stays."
        );
    }
}

/// Retention is implemented and **defaulted off**, and an absent window authorises nothing.
///
/// This is the absent-limit rule at its most dangerous point. The obvious implementation —
/// "delete anything older than the window" with a window that defaults to zero or NULL — deletes
/// everything, immediately, because an absent limit was read as a limit of zero. Both halves are
/// required here: deletion enabled AND a non-zero window.
#[test]
fn retention_defaults_to_no_deletion_authority_at_all() {
    let mut store = MemoryStore::new();

    for kind in [
        ArtifactKind::Report,
        ArtifactKind::Stop,
        ArtifactKind::Ledger,
    ] {
        let policy = store.retention_policy(kind).expect("policy");
        assert!(
            !policy.enabled,
            "{} retention must ship disabled",
            kind.word()
        );
        assert!(
            !policy.deletes_anything(),
            "{} must grant no deletion authority by default",
            kind.word()
        );
    }

    // An absent window, with deletion explicitly enabled, STILL authorises nothing. This is the
    // case that would otherwise be read as "delete everything older than nothing".
    store.set_retention(
        ArtifactKind::Report,
        RetentionPolicy {
            enabled: true,
            window_seconds: None,
        },
    );
    assert!(
        !store
            .retention_policy(ArtifactKind::Report)
            .expect("policy")
            .deletes_anything(),
        "an enabled policy with no window has granted authority over nothing — an absent limit \
         means NONE, never unlimited and never immediate"
    );

    // A zero window is the same claim written differently.
    store.set_retention(
        ArtifactKind::Report,
        RetentionPolicy {
            enabled: true,
            window_seconds: Some(0),
        },
    );
    assert!(
        !store
            .retention_policy(ArtifactKind::Report)
            .expect("policy")
            .deletes_anything(),
        "a zero window is an absent window, not an instruction to delete everything"
    );

    // Only an explicit enable plus an explicit non-zero window authorises anything.
    store.set_retention(
        ArtifactKind::Report,
        RetentionPolicy {
            enabled: true,
            window_seconds: Some(86_400 * 365 * 7),
        },
    );
    assert!(store
        .retention_policy(ArtifactKind::Report)
        .expect("policy")
        .deletes_anything());
}

/// The migration carries both enforcement mechanisms, and neither has quietly gone away.
///
/// A text assertion over the SQL, because the two things that make append-only real in production
/// are a trigger and the *absence* of a grant, and neither can be exercised without a database. If
/// someone adds `GRANT UPDATE ... ON artifact` while fixing something else, this fails.
#[test]
fn the_migration_enforces_append_only_twice_and_grants_no_write_back() {
    let sql = include_str!("../migrations/0001_initial.sql");
    assert!(
        sql.contains("BEFORE UPDATE OR DELETE ON artifact"),
        "the trigger is enforcement 1 of 2 and must survive"
    );
    assert!(
        sql.contains("GRANT INSERT, SELECT ON artifact TO archive_runtime"),
        "the runtime role's grant on artifact must stay INSERT, SELECT and nothing else"
    );
    // Scoped to GRANT statements only. A naive `sql.contains("DELETE ON artifact")` also matches
    // the trigger's own `BEFORE UPDATE OR DELETE ON artifact` line, which is the mechanism rather
    // than a hole — and a test that fires on its own defence is a test people delete.
    let grants: Vec<&str> = sql
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("GRANT "))
        .collect();
    for grant in &grants {
        let touches_artifact = grant.contains(" ON artifact ");
        if !touches_artifact {
            continue;
        }
        for forbidden in ["UPDATE", "DELETE", "ALL"] {
            assert!(
                !grant.contains(forbidden),
                "this grant hands {forbidden} on the artifact table to somebody: {grant:?}. The \
                 artifact table is the one custody is about, and a role that can rewrite it makes \
                 the archive an editor of evidence rather than a keeper of it."
            );
        }
    }
    assert!(
        sql.contains("enabled        BOOLEAN NOT NULL DEFAULT FALSE"),
        "retention must default off as an explicit column, not be inferred from a NULL window"
    );
}

/// Round-tripping through the schema's own trigger and grants. Needs a real database.
///
/// Run it with:
///
/// ```text
/// docker compose -f deploy/evidence-archive/docker-compose.yml up -d
/// WARRANTOR_ARCHIVE_DATABASE_URL=postgres://archive_runtime@127.0.0.1:5433/warrantor_archive \
///   cargo test -p warrantor-archive -- --ignored
/// ```
///
/// `#[ignore]`d rather than skipped on a missing variable, so a run that was meant to exercise the
/// database reports "0 passed" loudly instead of quietly passing having tested nothing.
#[test]
#[ignore = "needs Postgres: docker compose -f deploy/evidence-archive/docker-compose.yml up -d"]
fn the_database_itself_refuses_an_update_to_a_filed_artifact() {
    use warrantor_archive::postgres::PostgresStore;

    let url = std::env::var("WARRANTOR_ARCHIVE_DATABASE_URL")
        .expect("set WARRANTOR_ARCHIVE_DATABASE_URL to run the database tests");
    let store = PostgresStore::connect(&url).expect("connect");
    store.migrate().expect("migrate");

    let mut client = postgres::Client::connect(&url, postgres::NoTls).expect("second connection");
    let refused = client.execute(
        "UPDATE artifact SET warrant_id = 'wrt_rewritten' WHERE TRUE",
        &[],
    );
    assert!(
        refused.is_err(),
        "the database itself must refuse an UPDATE on artifact, whatever the connecting role was \
         granted — the trigger is the half a misconfigured grant cannot undo"
    );
}

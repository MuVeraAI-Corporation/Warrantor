//! Append-only, and the retention default that grants nothing.
//!
//! Two of these tests are about behaviour and one is about *shape*. The shape one matters most:
//! `the_store_trait_offers_no_way_to_update_or_delete_an_artifact` is a source-level assertion,
//! because append-only stops being a guarantee the moment a convenience method exists, however
//! carefully guarded its call sites are.
//!
//! What is tested here and what is not: the trait and [`MemoryStore`] are exercised in full; the
//! schema's own two enforcement mechanisms — a `BEFORE UPDATE OR DELETE` trigger and a runtime role
//! with no UPDATE grant — need a real database, because CI has no Postgres. The two `#[ignore]`d
//! tests at the bottom cover one mechanism each, and they are separate on purpose: a single test
//! that connected as one role could not tell "the trigger refused" from "the role was never granted
//! UPDATE", which is precisely how the earlier version of this file claimed to cover a trigger it
//! never fired.

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

/// The docs and the code agree on how many database tests exist.
///
/// A count, because the specific way this branch went wrong was arithmetic. RFC W2 §Testing said
/// "the two that need a database are `#[ignore]`d", `src/store.rs` said "the tests that genuinely
/// need a database" (plural), `device_pairing.rs` pointed at "the `#[ignore]`d database test" for
/// the enrolment-code race, and exactly one existed — about something else entirely. A reviewer
/// running the documented command got "1 passed" and read it as coverage of a race nothing had ever
/// executed. **A test that is counted and does not exist is worse than a missing one.**
///
/// Update this number and the prose together, in `docs/rfcs/W2-evidence-archive.md`, `src/store.rs`,
/// this file's module doc and `deploy/evidence-archive/README.md`, or leave both alone.
///
/// **A new test file must be added to `files` below.** The list is hardcoded because `include_str!`
/// takes a literal, and a file missing from it is a file this counter silently stopped covering —
/// which is the same "a check that stopped checking" shape the counter itself was written against.
#[test]
fn the_ignored_database_tests_are_the_number_the_docs_claim() {
    const EXPECTED: usize = 3;
    // Built at run time rather than written as a literal: this file is one of the files being
    // scanned, and a literal `#[ignore` in the needle would count itself.
    let attribute = format!("#{}", "[ignore");
    let files = [
        ("append_only.rs", include_str!("append_only.rs")),
        ("device_pairing.rs", include_str!("device_pairing.rs")),
        (
            "push_client_interop.rs",
            include_str!("push_client_interop.rs"),
        ),
        (
            "the_archive_never_serves_a_verdict.rs",
            include_str!("the_archive_never_serves_a_verdict.rs"),
        ),
        (
            "verification_does_not_depend_on_the_archive.rs",
            include_str!("verification_does_not_depend_on_the_archive.rs"),
        ),
    ];
    // Attribute lines only. Prose mentions of the attribute live in `//!` and `///` comments, and
    // counting those is how a doc paragraph would silently satisfy this test.
    let mut found = Vec::new();
    for (name, source) in files {
        for line in source.lines() {
            if line.trim_start().starts_with(&attribute) {
                found.push(name);
            }
        }
    }
    assert_eq!(
        found.len(),
        EXPECTED,
        "the crate has {} #[ignore]d database tests ({found:?}) and the docs claim {EXPECTED}. \
         `make archive-test` runs what is here, not what is written down.",
        found.len()
    );
}

/// The RFC's threat model names no mitigation this crate does not perform.
///
/// One row said "constant-time comparison" among the shipped mitigations for a stolen enrolment
/// code. There was a constant-time `digests_match` in `src/lib.rs` and nothing ever called it: the
/// comparison that actually decides is a `BTreeMap::get` in the memory store and a
/// `WHERE code_sha256 = $1` index lookup in Postgres, neither of which is constant-time and neither
/// of which can route through a helper without becoming a full scan. A threat-model row that names a
/// control the code does not apply is the kind of claim an auditor checks, and that one did not
/// survive `grep`, so the function is gone and the row is corrected downward.
///
/// If a constant-time comparison is ever genuinely wired in, add its call site to `PERFORMS_ONE`
/// and the claim may come back — together, in one change.
#[test]
fn the_threat_model_names_no_mitigation_this_crate_does_not_implement() {
    const PERFORMS_ONE: [&str; 2] = ["digests_match(", "ct_eq("];
    let rfc = include_str!("../../../docs/rfcs/W2-evidence-archive.md");
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/device.rs"),
        include_str!("../src/store.rs"),
        include_str!("../src/postgres.rs"),
        include_str!("../src/http.rs"),
    ];
    let claimed = rfc.contains("constant-time");
    // A **call site**, not a definition and not a comment. That distinction is the whole test: the
    // constant-time helper this row described did exist, as a public function nobody called, and it
    // satisfied every reader who checked by grepping for the name.
    let implemented = sources.iter().any(|source| {
        source.lines().any(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//")
                || trimmed.starts_with("fn ")
                || trimmed.starts_with("pub fn ")
            {
                return false;
            }
            PERFORMS_ONE.iter().any(|call| line.contains(call))
        })
    });
    assert!(
        !claimed || implemented,
        "RFC W2 claims a constant-time comparison as a shipped mitigation and no call site exists \
         in this crate. Either wire one in or drop the claim: a mitigation that is documented and \
         not applied is worse than one that is neither, because it stops anyone looking."
    );
}

/// Enforcement 1 of 2: the trigger, fired on a row that is really there.
///
/// The earlier version of this test could not fail. It issued `UPDATE artifact SET … WHERE TRUE`
/// against a table it had never inserted into, and `artifact_append_only` is a `FOR EACH ROW`
/// trigger — a row-level trigger does not fire when the statement matches zero rows. Connected as
/// the owner it therefore returned `Ok(0)`; connected as `archive_runtime` the assertion was
/// satisfied by the *missing UPDATE grant*, which is the other mechanism entirely. Either way,
/// nothing had ever demonstrated that the trigger fires.
///
/// So this one files a real artifact first, connects as the **owner** — the role that *does* hold
/// UPDATE and DELETE — and requires the refusal to carry the trigger's own message. A permission
/// denial would say `permission denied for table artifact` and would fail this test, which is the
/// point: "the trigger refused" and "the role was never granted UPDATE" must be distinguishable.
///
/// ```text
/// make archive-up
/// WARRANTOR_ARCHIVE_DATABASE_URL=postgres://archive_admin:$POSTGRES_PASSWORD@127.0.0.1:5433/warrantor_archive \
///   make archive-test
/// ```
///
/// `#[ignore]`d rather than skipped on a missing variable, so a run that was meant to exercise the
/// database reports "0 passed" loudly instead of quietly passing having tested nothing.
#[test]
#[ignore = "needs Postgres and the archive_admin URL: make archive-up, then make archive-test"]
fn the_database_itself_refuses_an_update_to_a_filed_artifact() {
    use warrantor_archive::postgres::PostgresStore;

    let url = std::env::var("WARRANTOR_ARCHIVE_DATABASE_URL").expect(
        "set WARRANTOR_ARCHIVE_DATABASE_URL to the archive_admin URL — the owner, deliberately: \
         this test proves the trigger refuses a role that HAS the UPDATE grant",
    );
    let mut store = PostgresStore::connect(&url).expect("connect");
    store.migrate().expect("migrate");

    let mut client = postgres::Client::connect(&url, postgres::NoTls).expect("second connection");

    // A device to hang the attribution on, and an artifact to update. Both idempotent, because
    // nothing in this test may delete a row: these tests run under the same append-only rules the
    // product claims, and a test that cleaned up after itself would need the grant it is denying.
    let artifact = ingested("wrt_archive", "fix the auth token refresh bug");
    let device_id = format!("dev_{}", &artifact.digest[..24]);
    client
        .execute(
            "INSERT INTO device (id, label, public_key, enrolled_at)
             VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
            &[
                &device_id,
                &"append-only test",
                &hex::encode([7u8; 32]),
                &(NOW as i64),
            ],
        )
        .expect("enrol a device to attribute the artifact to");
    store
        .put_artifact(&artifact, &device_id, NOW)
        .expect("file the artifact");
    let filed = store
        .get_artifact(&artifact.digest)
        .expect("read")
        .expect("the artifact must be present, or the trigger has nothing to refuse");

    for statement in [
        "UPDATE artifact SET warrant_id = 'wrt_rewritten' WHERE digest = $1",
        "DELETE FROM artifact WHERE digest = $1",
    ] {
        let error = client
            .execute(statement, &[&artifact.digest])
            .expect_err(&format!(
                "the database itself must refuse `{statement}` on a row that exists, whatever the \
                 connecting role was granted — the trigger is the half a misconfigured grant \
                 cannot undo"
            ));
        let db = error
            .as_db_error()
            .expect("a database refusal, not a client-side error");
        assert!(
            db.message().contains("append-only"),
            "the refusal must come from `artifact_is_append_only`, not from a missing grant — \
             otherwise this test cannot tell the two enforcement mechanisms apart: {}",
            db.message()
        );
    }

    let after = store
        .get_artifact(&artifact.digest)
        .expect("read")
        .expect("still held");
    assert_eq!(after.warrant_id, filed.warrant_id, "and nothing changed");
    assert_eq!(after.bytes, artifact.bytes);
}

/// Enforcement 2 of 2: the runtime role has no UPDATE or DELETE grant on `artifact`.
///
/// Separate from the trigger test and connected as a different role, because one connection cannot
/// prove two mechanisms. Here the refusal must be `42501 insufficient_privilege` — read from the
/// SQLSTATE rather than the message text, for the reason `postgres.rs::is_unique_violation` gives:
/// a message is localised and version-dependent, and a check that stopped matching after an upgrade
/// would fail open.
///
/// Needs the password the README has the operator set out of band:
///
/// ```text
/// WARRANTOR_ARCHIVE_RUNTIME_DATABASE_URL=postgres://archive_runtime:$ARCHIVE_RUNTIME_PASSWORD@127.0.0.1:5433/warrantor_archive
/// ```
#[test]
#[ignore = "needs Postgres and the archive_runtime URL: make archive-up, then make archive-test"]
fn the_runtime_role_holds_no_update_or_delete_grant_on_artifact() {
    use postgres::error::SqlState;

    let url = std::env::var("WARRANTOR_ARCHIVE_RUNTIME_DATABASE_URL").expect(
        "set WARRANTOR_ARCHIVE_RUNTIME_DATABASE_URL to the archive_runtime URL, with the password \
         the README has you ALTER ROLE in — this test is about that role's grants",
    );
    let mut client = postgres::Client::connect(&url, postgres::NoTls).expect("connect as runtime");

    // First prove the connection works and the role can do its job, so a failure below is a denied
    // privilege rather than a broken URL. A dead guard is no signal, never an all-clear.
    client
        .query("SELECT count(*) FROM artifact", &[])
        .expect("archive_runtime must hold SELECT on artifact, or this test proves nothing");

    for statement in [
        "UPDATE artifact SET warrant_id = 'wrt_rewritten' WHERE TRUE",
        "DELETE FROM artifact WHERE TRUE",
    ] {
        let error = client.execute(statement, &[]).expect_err(&format!(
            "archive_runtime must not be able to run `{statement}`: the absent UPDATE/DELETE grant \
             is enforcement 2 of 2, and the server connects as this role"
        ));
        assert_eq!(
            error.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "the refusal must be a privilege denial (42501). Anything else means the grant is \
             there and only the trigger is stopping this: {error}"
        );
    }
}

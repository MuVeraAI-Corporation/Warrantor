//! The Postgres-backed [`ArchiveStore`], and the migrator that creates its schema.
//!
//! # Parameterised queries only
//!
//! Every value reaches the database through `$1`, `$2` … . There is no format string anywhere near
//! a query and no identifier interpolation, so SQL injection is impossible by construction rather
//! than by escaping. The two places a caller-supplied value could plausibly be spliced — a digest
//! and a device id — are also validated before they reach here, so the defence is doubled for the
//! same reason the schema enforces append-only twice.
//!
//! # One mutex, not a pool
//!
//! A `Mutex<Client>`, mirroring the answer [`warrantor_warrant::serve`] gives for its store, and
//! with the same honest caveat: it serialises requests **in this process** and cannot serialise
//! against another process holding the same database. That is the right trade for a service whose
//! busiest client is a human pressing refresh, and it is not claimed to be more. Reaching for a
//! pool crate would add a dependency to buy concurrency this workload does not have.
//!
//! A poisoned mutex is recovered rather than re-panicked. The workspace release profile is
//! `panic = "abort"`, so a panicking handler takes the whole server down — every Postgres error
//! here becomes a [`StoreError`], never a panic, and there is no `unwrap`, `expect` or index in any
//! path below.
//!
//! # No digest arithmetic in SQL
//!
//! Nothing here computes or compares a digest. The digest is computed once in Rust at ingest and
//! stored beside the bytes. A generated column or a `CHECK (digest = encode(sha256(bytes),'hex'))`
//! would be a second implementation of the rule that says which bytes are which artifact, in a
//! language nobody on this project audits, and two implementations can disagree.

use std::sync::{Mutex, MutexGuard};

use postgres::error::SqlState;
use postgres::{Client, NoTls, Row};

use crate::artifact::{ArtifactKind, IngestCheck, Ingested};
use crate::store::{
    ArchiveStore, ArtifactSummary, Device, EnrolError, ListFilter, NonceOutcome, PutOutcome,
    RetentionPolicy, StoreError, StoredArtifact,
};

/// The migrations this build ships, in application order.
///
/// Embedded with `include_str!` rather than read off the disk at run time, so the binary in a
/// container carries its own schema and cannot be pointed at a different one by an environment
/// variable. The version string is the file name; `schema_migrations` records what has run.
pub const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_initial",
    include_str!("../migrations/0001_initial.sql"),
)];

/// An [`ArchiveStore`] over a single synchronous Postgres connection.
pub struct PostgresStore {
    client: Mutex<Client>,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connection string is not printed, ever. It carries a password, and a Debug impl is
        // the easiest way for one to reach a log line nobody meant to write.
        f.write_str("PostgresStore { client: <postgres connection> }")
    }
}

impl PostgresStore {
    /// Connect.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`] when the database will not accept a connection.
    pub fn connect(database_url: &str) -> Result<Self, StoreError> {
        // NoTls because in the shipped deployment the archive and Postgres share a compose network
        // and never cross a machine boundary. Splitting them across hosts means putting TLS on this
        // connection, and the README says so rather than leaving it to be discovered.
        let client = Client::connect(database_url, NoTls).map_err(unavailable)?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    /// Apply every migration that has not run, each inside its own transaction.
    ///
    /// A migration and its `schema_migrations` row commit together, so a crash halfway cannot leave
    /// a schema that is half-applied and recorded as done.
    ///
    /// # Errors
    /// [`StoreError`] when a migration cannot be applied.
    pub fn migrate(&self) -> Result<Vec<String>, StoreError> {
        let mut client = self.lock();
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                     version TEXT PRIMARY KEY,
                     applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                 )",
            )
            .map_err(unavailable)?;
        let mut applied = Vec::new();
        for (version, sql) in MIGRATIONS {
            let already = client
                .query_opt(
                    "SELECT version FROM schema_migrations WHERE version = $1",
                    &[version],
                )
                .map_err(unavailable)?;
            if already.is_some() {
                continue;
            }
            let mut transaction = client.transaction().map_err(unavailable)?;
            transaction.batch_execute(sql).map_err(unavailable)?;
            transaction
                .execute(
                    "INSERT INTO schema_migrations (version) VALUES ($1)",
                    &[version],
                )
                .map_err(unavailable)?;
            transaction.commit().map_err(unavailable)?;
            applied.push((*version).to_string());
        }
        Ok(applied)
    }

    /// Take the connection, recovering from poison rather than re-panicking.
    ///
    /// With `panic = "abort"` a poisoned lock cannot arise in release, because the first panic takes
    /// the process. In a debug build it can, and unwrapping would turn one failed request into a
    /// panic in every thread that followed it.
    fn lock(&self) -> MutexGuard<'_, Client> {
        match self.client.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Every Postgres error becomes a refusal, never a panic.
fn unavailable(error: postgres::Error) -> StoreError {
    StoreError::Unavailable(error.to_string())
}

/// Is this the unique-violation that means "already there"?
///
/// Read from the SQLSTATE rather than by matching on the message text: a message is localised and
/// version-dependent, and a replay check that stopped working after a Postgres upgrade would fail
/// open.
fn is_unique_violation(error: &postgres::Error) -> bool {
    error
        .code()
        .is_some_and(|code| *code == SqlState::UNIQUE_VIOLATION)
}

fn artifact_from_row(row: &Row) -> Result<StoredArtifact, StoreError> {
    let kind_word: String = row.try_get("kind").map_err(unreadable)?;
    let kind = ArtifactKind::from_word(&kind_word)
        .ok_or_else(|| StoreError::Unreadable(format!("unknown artifact kind {kind_word:?}")))?;
    let check_word: String = row.try_get("ingest_check").map_err(unreadable)?;
    let reason: String = row.try_get("ingest_check_reason").map_err(unreadable)?;
    let check = match check_word.as_str() {
        "ok" => IngestCheck::Ok,
        "failed" => IngestCheck::Failed { reason },
        // Anything this build does not recognise reads as `Unknown`, never as `Failed`. A word
        // written by a newer build must not be rendered to a human as an accusation.
        _ => IngestCheck::Unknown { reason },
    };
    Ok(StoredArtifact {
        digest: row.try_get("digest").map_err(unreadable)?,
        kind,
        warrant_id: row.try_get("warrant_id").map_err(unreadable)?,
        subject: row.try_get("subject").map_err(unreadable)?,
        submitted_at: row.try_get::<_, i64>("submitted_at").map_err(unreadable)? as u64,
        submitted_by_device: row.try_get("submitted_by_device").map_err(unreadable)?,
        check,
        bytes: row.try_get("bytes").map_err(unreadable)?,
    })
}

fn unreadable(error: postgres::Error) -> StoreError {
    StoreError::Unreadable(error.to_string())
}

/// Epoch seconds are `u64` in this crate and `BIGINT` in Postgres, which is signed.
///
/// Saturating rather than wrapping: a clock value past `i64::MAX` is a broken clock, and the right
/// answer to a broken clock is a timestamp that is obviously wrong in the same direction, not one
/// that silently becomes negative and sorts before every real row.
fn to_bigint(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl ArchiveStore for PostgresStore {
    fn put_artifact(
        &mut self,
        ingested: &Ingested,
        submitted_by_device: &str,
        submitted_at: u64,
    ) -> Result<PutOutcome, StoreError> {
        let mut client = self.lock();
        // ON CONFLICT DO NOTHING is the idempotence, and it is also the only safe form here: the
        // table has no UPDATE grant and a BEFORE UPDATE trigger, so `DO UPDATE` would raise rather
        // than overwrite. That is the schema refusing to let this method quietly become a mutation.
        let written = client
            .execute(
                "INSERT INTO artifact (
                     digest, kind, warrant_id, subject, submitted_at, submitted_by_device,
                     ingest_check, ingest_check_reason, bytes
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (digest) DO NOTHING",
                &[
                    &ingested.digest,
                    &ingested.kind.word(),
                    &ingested.warrant_id,
                    &ingested.subject,
                    &to_bigint(submitted_at),
                    &submitted_by_device,
                    &ingested.check.word(),
                    &ingested.check.reason(),
                    &ingested.bytes,
                ],
            )
            .map_err(unavailable)?;
        Ok(if written == 0 {
            PutOutcome::AlreadyHeld
        } else {
            PutOutcome::Stored
        })
    }

    fn get_artifact(&self, digest: &str) -> Result<Option<StoredArtifact>, StoreError> {
        let mut client = self.lock();
        let row = client
            .query_opt(
                "SELECT digest, kind, warrant_id, subject, submitted_at, submitted_by_device,
                        ingest_check, ingest_check_reason, bytes
                   FROM artifact WHERE digest = $1",
                &[&digest],
            )
            .map_err(unavailable)?;
        row.as_ref().map(artifact_from_row).transpose()
    }

    fn list_artifacts(&self, filter: &ListFilter) -> Result<Vec<ArtifactSummary>, StoreError> {
        let mut client = self.lock();
        // One statement with NULL-tolerant predicates rather than a query assembled from strings.
        // A `WHERE` clause built by concatenation is exactly the shape that eventually takes a
        // caller's value, and there is no version of this filter worth that risk.
        let warrant_id = filter.warrant_id.clone();
        let kind = filter.kind.map(|k| k.word().to_string());
        let rows = client
            .query(
                "SELECT digest, kind, warrant_id, submitted_at, submitted_by_device, ingest_check
                   FROM artifact
                  WHERE ($1::text IS NULL OR warrant_id = $1)
                    AND ($2::text IS NULL OR kind = $2)
                  ORDER BY submitted_at DESC, digest ASC",
                &[&warrant_id, &kind],
            )
            .map_err(unavailable)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let kind_word: String = row.try_get("kind").map_err(unreadable)?;
            let kind = ArtifactKind::from_word(&kind_word).ok_or_else(|| {
                StoreError::Unreadable(format!("unknown artifact kind {kind_word:?}"))
            })?;
            out.push(ArtifactSummary {
                digest: row.try_get("digest").map_err(unreadable)?,
                kind,
                warrant_id: row.try_get("warrant_id").map_err(unreadable)?,
                submitted_at: row.try_get::<_, i64>("submitted_at").map_err(unreadable)? as u64,
                submitted_by_device: row.try_get("submitted_by_device").map_err(unreadable)?,
                ingest_check: row.try_get("ingest_check").map_err(unreadable)?,
            });
        }
        Ok(out)
    }

    fn create_enrolment_code(
        &mut self,
        code_digest: &str,
        label: &str,
        created_at: u64,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let mut client = self.lock();
        client
            .execute(
                "INSERT INTO enrolment_code (code_sha256, label, created_at, expires_at)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &code_digest,
                    &label,
                    &to_bigint(created_at),
                    &to_bigint(expires_at),
                ],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    fn enrol_device(
        &mut self,
        code_digest: &str,
        device_id: &str,
        public_key: &str,
        now: u64,
    ) -> Result<Device, EnrolError> {
        let mut client = self.lock();
        let mut transaction = client.transaction().map_err(unavailable)?;

        // The whole single-use property is this one statement. The `consumed_at IS NULL` predicate
        // is evaluated by the row lock the UPDATE takes, so of two devices racing on one code
        // exactly one gets a row back and the other gets none -- there is no window between a check
        // and a write for the second one to slip through.
        //
        // `consumed_by_device` is deliberately NOT set here, and that is a bug fix rather than a
        // style choice. It is `TEXT REFERENCES device(id)`, the constraint is NOT DEFERRABLE, and a
        // NOT DEFERRABLE foreign key is checked at the end of the *statement* -- so naming a device
        // row that this transaction has not inserted yet raised a foreign-key violation and every
        // enrolment against a real database failed. Nothing caught it because this path had no test
        // at any level; the `#[ignore]`d one in `tests/device_pairing.rs` is now that test.
        let claimed = transaction
            .query_opt(
                "UPDATE enrolment_code
                    SET consumed_at = $2
                  WHERE code_sha256 = $1 AND consumed_at IS NULL AND expires_at > $2
              RETURNING label",
                &[&code_digest, &to_bigint(now)],
            )
            .map_err(unavailable)?;
        let Some(row) = claimed else {
            return Err(EnrolError::CodeNotUsable);
        };
        let label: String = row.try_get("label").map_err(unreadable)?;

        transaction
            .execute(
                "INSERT INTO device (id, label, public_key, enrolled_at) VALUES ($1, $2, $3, $4)",
                &[&device_id, &label, &public_key, &to_bigint(now)],
            )
            .map_err(unavailable)?;
        // Bookkeeping, once the referent exists. It is not part of the claim -- `consumed_at` above
        // is what makes the code single-use, and this statement's WHERE clause cannot un-claim it.
        // If this fails the whole transaction rolls back, so a code is never left consumed by a
        // device that was never enrolled.
        transaction
            .execute(
                "UPDATE enrolment_code SET consumed_by_device = $2 WHERE code_sha256 = $1",
                &[&code_digest, &device_id],
            )
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;

        Ok(Device {
            id: device_id.to_string(),
            label,
            public_key: public_key.to_string(),
            enrolled_at: now,
            revoked_at: None,
        })
    }

    fn device(&self, id: &str) -> Result<Option<Device>, StoreError> {
        let mut client = self.lock();
        let row = client
            .query_opt(
                "SELECT id, label, public_key, enrolled_at, revoked_at FROM device WHERE id = $1",
                &[&id],
            )
            .map_err(unavailable)?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(Device {
            id: row.try_get("id").map_err(unreadable)?,
            label: row.try_get("label").map_err(unreadable)?,
            public_key: row.try_get("public_key").map_err(unreadable)?,
            enrolled_at: row.try_get::<_, i64>("enrolled_at").map_err(unreadable)? as u64,
            revoked_at: row
                .try_get::<_, Option<i64>>("revoked_at")
                .map_err(unreadable)?
                .map(|v| v as u64),
        }))
    }

    fn revoke_device(&mut self, id: &str, at: u64) -> Result<bool, StoreError> {
        let mut client = self.lock();
        let updated = client
            .execute(
                "UPDATE device SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
                &[&id, &to_bigint(at)],
            )
            .map_err(unavailable)?;
        Ok(updated > 0)
    }

    fn remember_nonce(
        &mut self,
        device_id: &str,
        nonce: &str,
        at: u64,
    ) -> Result<NonceOutcome, StoreError> {
        let mut client = self.lock();
        // The unique index decides, not a prior SELECT. A check-then-insert has a window in which
        // two concurrent replays of the same nonce both pass the check, which is exactly the
        // request an attacker sends twice.
        match client.execute(
            "INSERT INTO seen_nonce (device_id, nonce, seen_at) VALUES ($1, $2, $3)",
            &[&device_id, &nonce, &to_bigint(at)],
        ) {
            Ok(_) => Ok(NonceOutcome::Fresh),
            Err(e) if is_unique_violation(&e) => Ok(NonceOutcome::Replay),
            Err(e) => Err(unavailable(e)),
        }
    }

    fn retention_policy(&self, kind: ArtifactKind) -> Result<RetentionPolicy, StoreError> {
        let mut client = self.lock();
        let row = client
            .query_opt(
                "SELECT enabled, window_seconds FROM retention_policy WHERE kind = $1",
                &[&kind.word()],
            )
            .map_err(unavailable)?;
        // A missing row is `default()`, which grants NO deletion authority. It is emphatically not
        // "no policy recorded, so anything goes": an absent limit means none.
        let Some(row) = row else {
            return Ok(RetentionPolicy::default());
        };
        Ok(RetentionPolicy {
            enabled: row.try_get("enabled").map_err(unreadable)?,
            window_seconds: row
                .try_get::<_, Option<i64>>("window_seconds")
                .map_err(unreadable)?
                .and_then(|v| u64::try_from(v).ok()),
        })
    }
}

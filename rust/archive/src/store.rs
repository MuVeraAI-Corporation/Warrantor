//! The storage seam, and an in-memory implementation of it.
//!
//! A trait for the same reason [`warrantor_warrant::serve::Api`] is one: it keeps [`crate::http`]
//! free of any database knowledge, so a transport bug cannot hide behind a storage stub and a
//! storage bug cannot hide behind a transport test.
//!
//! It also settles a practical problem. CI runs `cargo test --workspace --all-targets` with no
//! Postgres anywhere, so without this seam either the tests cannot run or the CI job grows a
//! service container. Every unit and integration test in this crate runs against [`MemoryStore`];
//! the tests that genuinely need a database are `#[ignore]`d and name the compose command that runs
//! them.
//!
//! # What "append-only" means at this seam
//!
//! There is no `update` method and no `delete` method, in the trait or on either implementation.
//! That is the shape of the guarantee, not a coincidence of what has been needed so far: a caller
//! cannot ask for a mutation that does not exist. [`ArchiveStore::put_artifact`] is idempotent on
//! the digest — re-submitting identical bytes reports [`PutOutcome::AlreadyHeld`] and is never an
//! error and never an overwrite — because two people filing the same evidence is normal and
//! rejecting the second one would teach them to stop filing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::{ArtifactKind, IngestCheck, Ingested};

/// Everything that can go wrong in a store.
///
/// Deliberately coarse: [`crate::http`] turns every variant into the same refusal, because the shape
/// of a database error is a description of this machine and the wire never learns about this
/// machine.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    /// The backing store could not be reached or would not answer.
    #[error("the archive store is unavailable: {0}")]
    Unavailable(String),
    /// A row was read but could not be understood.
    #[error("the archive store holds a row this build cannot read: {0}")]
    Unreadable(String),
}

/// What happened to a submitted artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// These bytes were not held before and now are.
    Stored,
    /// Byte-identical content was already held. Nothing was written and nothing was overwritten.
    AlreadyHeld,
}

/// One artifact, as the archive holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifact {
    /// SHA-256 hex of `bytes`.
    pub digest: String,
    /// Which of the three files this is.
    pub kind: ArtifactKind,
    /// The warrant it is about.
    pub warrant_id: String,
    /// The subject the file names, when it carries one.
    pub subject: Option<String>,
    /// When it was filed, epoch seconds.
    pub submitted_at: u64,
    /// The device that filed it. **This is the attribution**, and it is why device pairing exists.
    pub submitted_by_device: String,
    /// The door's note at ingest. Not a verdict, and never re-run on read: it records what was
    /// found at the door, and re-deriving it here would make the archive an ongoing opinion-holder
    /// about evidence it merely keeps.
    pub check: IngestCheck,
    /// The submitted bytes, verbatim.
    pub bytes: Vec<u8>,
}

/// One row of a listing. Carries no bytes, because a list of fifty report bundles is a response
/// nobody asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSummary {
    /// SHA-256 hex, which is also how the artifact is fetched.
    pub digest: String,
    /// Which of the three files this is.
    pub kind: ArtifactKind,
    /// The warrant it is about.
    pub warrant_id: String,
    /// When it was filed.
    pub submitted_at: u64,
    /// The device that filed it.
    pub submitted_by_device: String,
    /// The door's note, as a stable word.
    pub ingest_check: String,
}

/// Which artifacts a listing should include.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilter {
    /// Only artifacts about this warrant.
    pub warrant_id: Option<String>,
    /// Only this kind.
    pub kind: Option<ArtifactKind>,
}

/// An enrolled device: a public key, a human label, and whether it still counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Opaque identifier, minted at enrolment.
    pub id: String,
    /// What the operator called it — "Ana's laptop". This is the string an audit trail shows a
    /// human, so it is required rather than optional.
    pub label: String,
    /// Hex Ed25519 verifying key. The archive holds only public key material.
    pub public_key: String,
    /// When it was enrolled, epoch seconds.
    pub enrolled_at: u64,
    /// When it was revoked, if it was. A revoked device is kept, not deleted: its past submissions
    /// still need a name attached to them.
    pub revoked_at: Option<u64>,
}

impl Device {
    /// Is this device currently allowed to sign a request?
    #[must_use]
    pub fn active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Whether a presented nonce had been seen before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceOutcome {
    /// First sight. The request may proceed.
    Fresh,
    /// Seen before under this device. A replay, and refused.
    Replay,
}

/// Why an enrolment attempt did not produce a device.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrolError {
    /// No such code, it expired, or it was already used. **One error for all three on purpose**:
    /// distinguishing them tells an attacker holding a guessed code whether they guessed a real
    /// one.
    #[error("that enrolment code is not usable: it is unknown, expired, or already claimed")]
    CodeNotUsable,
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The retention window for one kind of artifact.
///
/// # The absent-limit rule, encoded rather than commented
///
/// `enabled` is a separate boolean and defaults to **false**. It is not derived from
/// `window_seconds`, because a NULL or zero window is exactly the value that gets misread: an
/// absent limit means *no deletion authority was granted*, never "delete everything older than
/// nothing" and never "retain forever by accident". With `enabled` false, [`RetentionPolicy::
/// deletes_anything`] is false whatever the window says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Whether any deletion authority has been granted at all. Default false.
    pub enabled: bool,
    /// How long artifacts are kept, when deletion is enabled. `None` means no window was set.
    pub window_seconds: Option<u64>,
}

// Written out rather than derived, and clippy is told so on purpose. `#[derive(Default)]` produces
// the identical values, and it produces them invisibly: a reader checking whether this archive
// ships with deletion authority would have to know Rust's per-type defaults to answer. The default
// for a retention policy is the absent-limit rule, and the rule is worth being able to read.
#[allow(clippy::derivable_impls)]
impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            // No deletion authority has been granted. Not "unlimited", and not "immediate".
            enabled: false,
            // And no window, which on its own still grants nothing — see `deletes_anything`.
            window_seconds: None,
        }
    }
}

impl RetentionPolicy {
    /// Does this policy authorise deleting anything at all?
    ///
    /// False unless deletion was explicitly enabled **and** a non-zero window was set. Both halves
    /// are required: an enabled policy with no window has granted authority over nothing.
    #[must_use]
    pub fn deletes_anything(&self) -> bool {
        self.enabled && self.window_seconds.is_some_and(|w| w > 0)
    }
}

/// Everything the HTTP layer is allowed to ask of storage.
///
/// Note what is absent: no update, no delete, no "correct this row". The append-only claim is a
/// property of this trait's shape before it is a property of any implementation.
pub trait ArchiveStore {
    /// File an artifact. Idempotent on the digest.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be written.
    fn put_artifact(
        &mut self,
        ingested: &Ingested,
        submitted_by_device: &str,
        submitted_at: u64,
    ) -> Result<PutOutcome, StoreError>;

    /// Fetch one artifact by digest, bytes included.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be read.
    fn get_artifact(&self, digest: &str) -> Result<Option<StoredArtifact>, StoreError>;

    /// List artifacts, newest first.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be read.
    fn list_artifacts(&self, filter: &ListFilter) -> Result<Vec<ArtifactSummary>, StoreError>;

    /// Record a one-time enrolment code by its digest. The code itself is never stored.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be written.
    fn create_enrolment_code(
        &mut self,
        code_digest: &str,
        label: &str,
        created_at: u64,
        expires_at: u64,
    ) -> Result<(), StoreError>;

    /// Claim a code and enrol a device, atomically.
    ///
    /// One method rather than a check followed by a write, so "a code is single-use" is a property
    /// of one operation rather than of a window between two. The Postgres implementation is a
    /// single `UPDATE ... WHERE consumed_at IS NULL ... RETURNING` inside a transaction; two racing
    /// devices cannot both claim one code.
    ///
    /// # Errors
    /// [`EnrolError::CodeNotUsable`] when the code is unknown, expired or already claimed.
    fn enrol_device(
        &mut self,
        code_digest: &str,
        device_id: &str,
        public_key: &str,
        now: u64,
    ) -> Result<Device, EnrolError>;

    /// Look up an enrolled device.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be read.
    fn device(&self, id: &str) -> Result<Option<Device>, StoreError>;

    /// Revoke a device. Returns false when there was no such active device.
    ///
    /// Revocation is not a delete: the row stays, so past submissions keep their attribution.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be written.
    fn revoke_device(&mut self, id: &str, at: u64) -> Result<bool, StoreError>;

    /// Record a nonce against a device, reporting whether it had been seen.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be written.
    fn remember_nonce(
        &mut self,
        device_id: &str,
        nonce: &str,
        at: u64,
    ) -> Result<NonceOutcome, StoreError>;

    /// The retention policy for one kind. Defaults to [`RetentionPolicy::default`], which grants
    /// no deletion authority.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be read.
    fn retention_policy(&self, kind: ArtifactKind) -> Result<RetentionPolicy, StoreError>;
}

// ── the in-memory store ───────────────────────────────────────────────────────────────

/// An [`ArchiveStore`] in a `BTreeMap`. The one every test runs against.
///
/// Real enough to test the properties that matter — idempotence on digest, single-use codes,
/// replayed nonces, revocation — because those are decided in this crate rather than by Postgres.
/// What it deliberately cannot test is the schema's own append-only enforcement (a trigger and a
/// grant), which is why `migrations/0001_initial.sql` carries both and why the compose file exists.
#[derive(Debug, Default)]
pub struct MemoryStore {
    artifacts: BTreeMap<String, StoredArtifact>,
    /// Insertion order, so "newest first" is a real ordering rather than digest order.
    order: Vec<String>,
    devices: BTreeMap<String, Device>,
    codes: BTreeMap<String, EnrolmentRow>,
    seen_nonces: BTreeMap<(String, String), u64>,
    retention: BTreeMap<ArtifactKind, RetentionPolicy>,
}

#[derive(Debug, Clone)]
struct EnrolmentRow {
    label: String,
    expires_at: u64,
    consumed_at: Option<u64>,
}

impl MemoryStore {
    /// An empty archive.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrol a device directly, bypassing the one-time code.
    ///
    /// For tests and for the first device on a fresh archive, which has no operator session to mint
    /// a code from. Named `_without_a_code` rather than something neutral so a call site in a
    /// handler is visible on sight — the pairing flow exists precisely so this is not how devices
    /// normally arrive.
    pub fn enrol_without_a_code(&mut self, device: Device) {
        self.devices.insert(device.id.clone(), device);
    }

    /// Set a retention policy, for the tests that assert the default grants nothing.
    pub fn set_retention(&mut self, kind: ArtifactKind, policy: RetentionPolicy) {
        self.retention.insert(kind, policy);
    }

    /// How many artifacts are held. Tests use it to assert that nothing was overwritten.
    #[must_use]
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Is the archive empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }
}

impl ArchiveStore for MemoryStore {
    fn put_artifact(
        &mut self,
        ingested: &Ingested,
        submitted_by_device: &str,
        submitted_at: u64,
    ) -> Result<PutOutcome, StoreError> {
        if self.artifacts.contains_key(&ingested.digest) {
            // Deliberately not touching the existing row. The digest is over the bytes, so an
            // identical digest means identical bytes; there is nothing to update, and updating the
            // submitter would rewrite the attribution of the person who actually filed it first.
            return Ok(PutOutcome::AlreadyHeld);
        }
        self.artifacts.insert(
            ingested.digest.clone(),
            StoredArtifact {
                digest: ingested.digest.clone(),
                kind: ingested.kind,
                warrant_id: ingested.warrant_id.clone(),
                subject: ingested.subject.clone(),
                submitted_at,
                submitted_by_device: submitted_by_device.to_string(),
                check: ingested.check.clone(),
                bytes: ingested.bytes.clone(),
            },
        );
        self.order.push(ingested.digest.clone());
        Ok(PutOutcome::Stored)
    }

    fn get_artifact(&self, digest: &str) -> Result<Option<StoredArtifact>, StoreError> {
        Ok(self.artifacts.get(digest).cloned())
    }

    fn list_artifacts(&self, filter: &ListFilter) -> Result<Vec<ArtifactSummary>, StoreError> {
        let mut out = Vec::new();
        for digest in self.order.iter().rev() {
            let Some(artifact) = self.artifacts.get(digest) else {
                continue;
            };
            if filter
                .warrant_id
                .as_ref()
                .is_some_and(|id| id != &artifact.warrant_id)
            {
                continue;
            }
            if filter.kind.is_some_and(|kind| kind != artifact.kind) {
                continue;
            }
            out.push(ArtifactSummary {
                digest: artifact.digest.clone(),
                kind: artifact.kind,
                warrant_id: artifact.warrant_id.clone(),
                submitted_at: artifact.submitted_at,
                submitted_by_device: artifact.submitted_by_device.clone(),
                ingest_check: artifact.check.word().to_string(),
            });
        }
        Ok(out)
    }

    fn create_enrolment_code(
        &mut self,
        code_digest: &str,
        label: &str,
        _created_at: u64,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        self.codes.insert(
            code_digest.to_string(),
            EnrolmentRow {
                label: label.to_string(),
                expires_at,
                consumed_at: None,
            },
        );
        Ok(())
    }

    fn enrol_device(
        &mut self,
        code_digest: &str,
        device_id: &str,
        public_key: &str,
        now: u64,
    ) -> Result<Device, EnrolError> {
        // The claim and the write happen under one `&mut self`, which is what makes this atomic
        // here. In Postgres the same atomicity is a transaction plus a conditional UPDATE; neither
        // is a lock held across a network round trip.
        let row = self
            .codes
            .get_mut(code_digest)
            .ok_or(EnrolError::CodeNotUsable)?;
        if row.consumed_at.is_some() || row.expires_at <= now {
            return Err(EnrolError::CodeNotUsable);
        }
        row.consumed_at = Some(now);
        let device = Device {
            id: device_id.to_string(),
            label: row.label.clone(),
            public_key: public_key.to_string(),
            enrolled_at: now,
            revoked_at: None,
        };
        self.devices.insert(device.id.clone(), device.clone());
        Ok(device)
    }

    fn device(&self, id: &str) -> Result<Option<Device>, StoreError> {
        Ok(self.devices.get(id).cloned())
    }

    fn revoke_device(&mut self, id: &str, at: u64) -> Result<bool, StoreError> {
        match self.devices.get_mut(id) {
            Some(device) if device.revoked_at.is_none() => {
                device.revoked_at = Some(at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn remember_nonce(
        &mut self,
        device_id: &str,
        nonce: &str,
        at: u64,
    ) -> Result<NonceOutcome, StoreError> {
        let key = (device_id.to_string(), nonce.to_string());
        if self.seen_nonces.contains_key(&key) {
            return Ok(NonceOutcome::Replay);
        }
        self.seen_nonces.insert(key, at);
        Ok(NonceOutcome::Fresh)
    }

    fn retention_policy(&self, kind: ArtifactKind) -> Result<RetentionPolicy, StoreError> {
        Ok(self.retention.get(&kind).copied().unwrap_or_default())
    }
}

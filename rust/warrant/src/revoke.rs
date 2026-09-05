//! The local revocation source for the notary's Identity gate (invariant I-05).
//!
//! # What this is, and what it is not
//!
//! [`warrantor_notary::VerdictContext::revoked_svids`] is a `Vec<String>` the caller supplies, and
//! until this module existed the product's one caller ([`crate::report::build_observed`]) supplied
//! an empty one — so gate 2 asked whether a subject appeared in an empty set, and the answer was
//! always no. This module supplies it, in exactly the shape
//! [`crate::stop::StopStore::contained_scopes`] supplies the containment gate: a local file, read at
//! adjudication time, needing no service.
//!
//! The journal format is [`warrantor_credential_vault::persist`]'s — an append-only JSONL log,
//! `fsync`'d before a mutation is acknowledged, replayed at open, auditable with `cat`. Reusing it
//! rather than inventing a second one is the whole point of the dependency edge: the credential
//! half of I-05 already had a durable revocation log, and the identity half had none.
//!
//! # Tiers, stated plainly
//!
//! The **refusal** is Tier B, a chokepoint ([`crate::BoundStrength::Mediated`]):
//! `warrantor_notary::verdict` returns `Deny { gate: Identity }` at the moment an action is
//! adjudicated, and that is a specific line of code refusing a specific request. It is not an
//! operating-system bound. An agent that never asks for a verdict is never refused; nothing here
//! terminates a process, closes a socket, drops a connection, or invalidates a bearer token held
//! anywhere else.
//!
//! The **propagation** claim is Tier C, observed ([`crate::BoundStrength::Observed`]). Nothing in
//! this build delivers a revocation record to a second process or a second machine, so the latency
//! measured here is this process's own.
//!
//! # No new trust root
//!
//! The journal is a file under one warrant store's root, appended by an operator and read by the
//! adjudications that go through THAT STORE. The unit is the store, not the machine: `--root` is
//! accepted on every command, so one machine can hold several stores and each has its own journal.
//! It establishes two things:
//!
//! - every verdict THIS process computes against THIS store after `sync_all` returns denies at gate
//!   Identity for that subject; and
//! - non-revocation at any past epoch is provable from the log alone, because revocation is monotone
//!   and every record carries the epoch second at which it became durable.
//!
//! It establishes nothing about any other store — including a second store on the same machine under
//! a different `--root`, where the same subject reads as unrevoked — nothing about any other machine,
//! nothing about a credential a third party already holds, and nothing about a session already open.
//! It is not a directory, not a CA, and not an authority anyone else consults.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use warrantor_credential_vault::{JournalOp, JournalRecord, RevocationJournal};

use crate::{WarrantError, IDENTITY_REVOCATION_SLA};

/// The journal file, under the warrant store root. Named for what it holds, not for who writes it.
pub const REVOCATION_JOURNAL: &str = "revocations.jsonl";

/// The wire format of [`evidence/revocation-latency.json`](../../../evidence/revocation-latency.json).
pub const LATENCY_EVIDENCE_FORMAT: &str = "warrantor.revocation-latency/1";

/// Anything that can answer "which subjects are revoked".
///
/// A trait rather than a concrete type so the latency measurement can be exercised against a
/// deliberately slow source, and the SLA can be *seen* to break. A bound that cannot be observed
/// breaking is not measured; it is asserted.
pub trait RevocationSource {
    /// The revoked subjects, in the shape the notary's context wants them.
    fn revoked_svids(&self) -> Vec<String>;
}

/// A revocation, as recorded.
///
/// `sequence` is the record's index in the append-only journal — the "release consistency" half of
/// the bound, which a wall clock cannot express: two revocations one nanosecond apart are still
/// ordered, and a reader with only the file can say which came first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    /// The subject revoked.
    pub svid: String,
    /// Epoch seconds at which the record became durable.
    pub recorded_at: u64,
    /// The record's position in the append-only journal, counted from zero.
    pub sequence: u64,
    /// Monotonic instant at which `sync_all` returned.
    ///
    /// Private, and not serialized: an `Instant` is only meaningful against this process's clock,
    /// and pretending otherwise is exactly how a local measurement gets reported as a fleet one.
    durable_at: Instant,
    /// How many verdicts this process had computed when the record became durable. The baseline
    /// for `adjudications_between`.
    adjudications_at_durability: u64,
}

/// One propagation measurement, in the two units the bound is stated in.
///
/// Every field except `sla_nanos` is **computed from a real read**. Nothing here accepts a verdict
/// about itself: `within_sla` is derived from `elapsed_nanos` and `propagated`, never supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationLatency {
    /// Wall-clock nanoseconds spent getting the answer.
    ///
    /// For [`RevocationStore::latency`] this runs from the moment the record became durable to the
    /// moment a read of the journal returned it. For [`measure`] it is the cost of one call to
    /// [`RevocationSource::revoked_svids`].
    pub elapsed_nanos: u128,
    /// How many verdicts this process computed in that window.
    ///
    /// Counted, not assumed — see [`crate::report::adjudications_computed`], and
    /// `tests/revocation.rs::adjudications_between_counts_verdicts_rather_than_assuming_zero`, which
    /// fails if the counter stops counting.
    ///
    /// **What a positive number does and does not mean.** Until 2026-09-05 this doc said a positive
    /// number "means an action was adjudicated against a revocation set that was already stale". It
    /// does not, and no code here establishes that: every adjudication in the window re-reads the
    /// journal through [`crate::report::RevocationSection::from_store`], so a verdict computed inside
    /// it sees the record. What the number says is exactly what it counts — how many verdicts this
    /// process computed between durability and the read being timed. That is worth publishing because
    /// wall-clock alone is gameable by a fast disk, and because a build that later adjudicated from a
    /// cached set would need this number to notice; it is not, by itself, evidence that anything was
    /// adjudicated stale.
    pub adjudications_between: u64,
    /// The stated bound, from [`IDENTITY_REVOCATION_SLA`].
    pub sla_nanos: u128,
    /// Whether the revocation actually reached the reader.
    ///
    /// A source that never answers with the subject has not propagated at all, and a latency for a
    /// revocation that never arrived would be a number describing nothing. `false` here forces
    /// `within_sla` to `false` however small `elapsed_nanos` is.
    pub propagated: bool,
    /// Whether the measurement is inside the bound. Computed, never supplied.
    pub within_sla: bool,
}

/// Time one source's answer.
///
/// The measurement is of the *read*: how long this process took to learn what is revoked. It is not
/// a measurement of delivery to anywhere else, and there is nowhere else in this build.
#[must_use]
pub fn measure<S: RevocationSource + ?Sized>(source: &S) -> RevocationLatency {
    let started = Instant::now();
    let revoked = source.revoked_svids();
    let elapsed = started.elapsed();
    latency_from(elapsed, 0, !revoked.is_empty())
}

fn latency_from(
    elapsed: Duration,
    adjudications_between: u64,
    propagated: bool,
) -> RevocationLatency {
    let elapsed_nanos = elapsed.as_nanos();
    let sla_nanos = IDENTITY_REVOCATION_SLA.as_nanos();
    RevocationLatency {
        elapsed_nanos,
        adjudications_between,
        sla_nanos,
        propagated,
        within_sla: propagated && elapsed_nanos <= sla_nanos,
    }
}

/// The append-only, `fsync`-per-write revocation list for one warrant store.
///
/// Holds a path rather than an open file handle, so two readers never contend and a `revoke`
/// re-opens, appends, `fsync`s and closes. The journal is small by construction — one line per
/// revocation, and revocation is monotone.
#[derive(Debug, Clone)]
pub struct RevocationStore {
    path: PathBuf,
}

impl RevocationStore {
    /// Open (or create) the revocation journal under a warrant store root.
    ///
    /// The journal is replayed here, which is what makes this **fail-closed**: an unreadable or
    /// foreign journal is an error, never an empty set. [`crate::stop::StopStore::is_stopped`]
    /// makes the same call for the same reason — there, unknown resolves to *contained*; here,
    /// unknown resolves to an error rather than to "nothing is revoked", because a caller that
    /// silently received an empty set would adjudicate as though no subject had ever been revoked.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the journal cannot be created or replayed, or if it holds a
    /// record this store did not write. This file has exactly one operation — [`JournalOp::Revoked`]
    /// — and an `Issued` or `RevokedAll` line would mean the credential vault's own journal had
    /// been pointed at this path; expanding `RevokedAll` needs an issued-credential set that does
    /// not exist here, so guessing would under-revoke.
    pub fn open(root: &Path) -> Result<Self, WarrantError> {
        let path = root.join(REVOCATION_JOURNAL);
        let records = replay(&path)?;
        for (index, record) in records.iter().enumerate() {
            if record.op != JournalOp::Revoked {
                return Err(WarrantError::Encode(format!(
                    "revocation journal {} line {} carries op {:?}; this journal holds only \
                     `revoked` records and cannot expand any other op without an issued-credential \
                     set, so it refuses rather than under-revoking",
                    path.display(),
                    index + 1,
                    record.op,
                )));
            }
        }
        Ok(Self { path })
    }

    /// The journal this store reads and appends to. Exposed so a report can name the file a reader
    /// should go and look at, rather than asserting the set came from somewhere.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.path
    }

    /// Record a revocation, durably, and return what was recorded.
    ///
    /// The [`Instant`] in the returned record is taken **after** the journal's append returns, which
    /// is after its `sync_all`. Measuring from before the write would charge the SLA for the disk
    /// and then report that the disk was fast.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] for an empty subject — the notary's Identity gate already denies an
    /// empty SVID, so a blank record would be an unreadable line that changed nothing.
    /// [`WarrantError::Encode`] if the append or its `fsync` failed, in which case the revocation is
    /// **not** durable and the caller has been told so.
    pub fn revoke(&mut self, svid: &str) -> Result<RevocationRecord, WarrantError> {
        if svid.trim().is_empty() {
            return Err(WarrantError::Invalid(
                "a revocation needs a subject; the Identity gate already denies an empty SVID"
                    .to_string(),
            ));
        }
        let (mut journal, existing) =
            RevocationJournal::open(&self.path).map_err(|e| journal_error(&self.path, &e))?;
        let line = JournalRecord::now(JournalOp::Revoked, svid);
        journal
            .append(&line)
            .map_err(|e| journal_error(&self.path, &e))?;
        // After `append` returned, which is after its `sync_all`.
        let durable_at = Instant::now();
        Ok(RevocationRecord {
            svid: svid.to_string(),
            recorded_at: line.at,
            sequence: existing.len() as u64,
            durable_at,
            adjudications_at_durability: crate::report::adjudications_computed(),
        })
    }

    /// Every record in the journal, in order.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the journal cannot be replayed.
    pub fn records(&self) -> Result<Vec<JournalRecord>, WarrantError> {
        replay(&self.path)
    }

    /// Was this subject revoked at or before `epoch`?
    ///
    /// The past-epoch clause, answerable from the log alone: revocation is monotone, so a record's
    /// `at` is the first moment the subject was revoked and every later moment inherits it. A reader
    /// holding only this file can therefore demonstrate **non**-revocation at a past epoch, which is
    /// the harder direction and the one an auditor asks for.
    ///
    /// A journal that cannot be read answers `true`, fail-closed: "I cannot show this subject was
    /// unrevoked then" must never render as "it was unrevoked then".
    #[must_use]
    pub fn was_revoked_at(&self, svid: &str, epoch: u64) -> bool {
        match replay(&self.path) {
            Ok(records) => records
                .iter()
                .any(|r| r.op == JournalOp::Revoked && r.jti == svid && r.at <= epoch),
            Err(_) => true,
        }
    }

    /// Measure the propagation of one revocation to this process's adjudication point.
    ///
    /// Performs the read a verdict would perform, then reports how long it took from durability and
    /// how many verdicts this process computed in between. If the read does not find the subject the
    /// revocation has not propagated at all, and `within_sla` is `false` regardless of the elapsed
    /// time.
    #[must_use]
    pub fn latency(&self, record: &RevocationRecord) -> RevocationLatency {
        let revoked = self.revoked_svids();
        let elapsed = record.durable_at.elapsed();
        let propagated = revoked.iter().any(|s| s == &record.svid);
        let between = crate::report::adjudications_computed()
            .saturating_sub(record.adjudications_at_durability);
        latency_from(elapsed, between, propagated)
    }
}

impl RevocationSource for RevocationStore {
    /// Replay, keep the revocations, dedupe. Monotone, so there is no un-revoke case.
    ///
    /// An unreadable journal returns the empty set **and** is reported: [`RevocationStore::open`]
    /// already refused such a file, so reaching this arm means the file changed underneath a store
    /// that had validated it. Returning everything-revoked instead is not available — the set of
    /// subjects is not known here — so the honest handling is an empty set plus a limitation line
    /// saying the source was unreadable, which [`crate::report::RevocationSection`] carries.
    fn revoked_svids(&self) -> Vec<String> {
        let Ok(records) = replay(&self.path) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for record in records {
            if record.op == JournalOp::Revoked && !out.contains(&record.jti) {
                out.push(record.jti);
            }
        }
        out
    }
}

fn replay(path: &Path) -> Result<Vec<JournalRecord>, WarrantError> {
    RevocationJournal::read_all(path).map_err(|e| journal_error(path, &e))
}

fn journal_error(
    path: &Path,
    source: &warrantor_credential_vault::CredentialError,
) -> WarrantError {
    WarrantError::Encode(format!("revocation journal {}: {source}", path.display()))
}

// ── the published measurement ─────────────────────────────────────────────────────────

/// One decision point, and whether it consults the revocation set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPoint {
    /// What the point is called in the product.
    pub name: String,
    /// Where in this repository the decision is made.
    pub call_site: String,
    /// Whether that decision reads the revocation set.
    pub consults_revocation: bool,
    /// Why not, when it does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The two numbers the bound is stated in, and where each is written as code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatedSla {
    /// The identity half, seconds.
    pub identity_seconds: u64,
    /// The credential half, seconds.
    pub credential_seconds: u64,
    /// Where the identity number comes from.
    pub identity_source: String,
    /// Where the credential number comes from.
    pub credential_source: String,
}

/// The published record for `evidence/revocation-latency.json`.
///
/// The point of publishing an `enforcement_points` count alongside
/// `enforcement_points_consulting_revocation` is that "latency distributions per enforcement point"
/// would otherwise read as though every point had one. Two exist here and one of them consults the
/// revocation set; saying so is the difference between a measurement and a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyEvidence {
    /// Wire format.
    pub format: String,
    /// The date the record was written.
    pub recorded: String,
    /// The stated bound and its two sources.
    pub sla: StatedSla,
    /// How many decision points exist in this build.
    pub enforcement_points: usize,
    /// How many of them read the revocation set.
    pub enforcement_points_consulting_revocation: usize,
    /// Each point, named.
    pub points: Vec<EnforcementPoint>,
    /// What a reader must not conclude from the numbers above.
    pub not_covered: Vec<String>,
}

/// The measurement record, as the product states it.
///
/// This is the single definition; `evidence/revocation-latency.json` is generated from it and
/// `tests/revocation_latency.rs` refuses a build in which the file and this function disagree. A
/// rendered number that is not gated against its record is a number that drifts.
#[must_use]
pub fn latency_evidence() -> LatencyEvidence {
    let points = vec![
        EnforcementPoint {
            name: "notary identity gate".to_string(),
            call_site: "rust/warrant/src/report.rs::build_observed".to_string(),
            consults_revocation: true,
            note: None,
        },
        EnforcementPoint {
            name: "egress broker".to_string(),
            call_site: "rust/egress/src/lib.rs::decide".to_string(),
            consults_revocation: false,
            note: Some(
                "egress::decide takes a request and a destination catalog and no revocation \
                 input at all; this task does not give it one (Task 7.7)"
                    .to_string(),
            ),
        },
    ];
    let consulting = points.iter().filter(|p| p.consults_revocation).count();
    LatencyEvidence {
        format: LATENCY_EVIDENCE_FORMAT.to_string(),
        recorded: "2026-09-05".to_string(),
        sla: StatedSla {
            identity_seconds: IDENTITY_REVOCATION_SLA.as_secs(),
            credential_seconds: warrantor_credential_vault::REVOKE_BUDGET.as_secs(),
            identity_source: "warrantor_warrant::IDENTITY_REVOCATION_SLA".to_string(),
            credential_source: "warrantor_credential_vault::REVOKE_BUDGET".to_string(),
        },
        enforcement_points: points.len(),
        enforcement_points_consulting_revocation: consulting,
        points,
        not_covered: vec![
            "does not propagate to any other machine or any other process: no fan-out, no broker \
             and no replica set is linked, so every latency here is this process's own"
                .to_string(),
            "does not recall a credential already used; revocation bounds future use only"
                .to_string(),
            "does not reach a copy of the credential held by a third party".to_string(),
            "does not close a session already open, terminate a process, or drop a socket"
                .to_string(),
            "does not bind an agent that never asks for a verdict: the refusal is a chokepoint, \
             not an operating-system bound"
                .to_string(),
            "does not reach a second store on the SAME machine: the journal is a file under one \
             store root, `--root` is accepted on every command, and a report built against a \
             different root reads a different file"
                .to_string(),
            "does not bind a revoked string to an issued identity: `grant --subject` and \
             `revoke --svid` both accept arbitrary strings and this build mints no SVID document, \
             so the default subject is a constant, not an issued SVID, until Task 3.1 lands"
                .to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "warrantor-revoke-unit-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("scratch");
        path
    }

    #[test]
    fn a_revocation_round_trips_through_the_journal() {
        let root = scratch("round-trip");
        let mut store = RevocationStore::open(&root).expect("open");
        assert!(
            store.revoked_svids().is_empty(),
            "a fresh store must start empty, or every later assertion is meaningless"
        );
        let record = store.revoke("spiffe://example/agent/a").expect("revoke");
        assert_eq!(record.sequence, 0);
        assert_eq!(store.revoked_svids(), vec!["spiffe://example/agent/a"]);
    }

    /// Mirrors the credential half's `revocation_survives_an_actual_restart_ax40`: a store that
    /// forgets on restart has an unbounded effective latency, whatever a wall clock said.
    #[test]
    fn a_revocation_survives_dropping_and_reopening_the_store() {
        let root = scratch("restart");
        {
            let mut store = RevocationStore::open(&root).expect("open");
            store.revoke("spiffe://example/agent/b").expect("revoke");
        }
        let reopened = RevocationStore::open(&root).expect("reopen");
        assert_eq!(
            reopened.revoked_svids(),
            vec!["spiffe://example/agent/b"],
            "the journal is on disk and `fsync`'d; a reopen that lost it would mean the bound \
             lasted exactly as long as the process"
        );
    }

    /// The past-epoch pair. A store that answers "revoked" for every epoch is useless as a proof of
    /// NON-revocation, so the negative direction is asserted explicitly.
    #[test]
    fn was_revoked_at_is_false_before_the_record_and_true_after() {
        let root = scratch("past-epoch");
        let mut store = RevocationStore::open(&root).expect("open");
        let record = store.revoke("spiffe://example/agent/c").expect("revoke");

        assert!(
            store.was_revoked_at("spiffe://example/agent/c", record.recorded_at),
            "at the recorded epoch the subject is revoked"
        );
        assert!(
            store.was_revoked_at("spiffe://example/agent/c", record.recorded_at + 3600),
            "revocation is monotone, so every later epoch inherits it"
        );
        assert!(
            !store.was_revoked_at(
                "spiffe://example/agent/c",
                record.recorded_at.saturating_sub(1)
            ),
            "one second before the record, the log proves the subject was NOT revoked. Without \
             this direction the function is a constant."
        );
        assert!(
            !store.was_revoked_at("spiffe://example/agent/never", record.recorded_at + 3600),
            "a subject the log never names was never revoked"
        );
    }

    #[test]
    fn a_foreign_journal_is_refused_rather_than_read_as_empty() {
        let root = scratch("foreign");
        let path = root.join(REVOCATION_JOURNAL);
        let (mut journal, _) = RevocationJournal::open(&path).expect("open journal");
        journal
            .append(&JournalRecord::now(JournalOp::RevokedAll, ""))
            .expect("append");
        drop(journal);

        let err = RevocationStore::open(&root).expect_err("a foreign op must refuse");
        let text = err.to_string();
        assert!(
            text.contains("revoked_all") || text.contains("RevokedAll"),
            "the refusal must name the op it could not expand: {text}"
        );
    }

    #[test]
    fn an_unreadable_journal_is_refused_at_open() {
        let root = scratch("corrupt");
        std::fs::write(
            root.join(REVOCATION_JOURNAL),
            "{not json at all}\n{also not}\n",
        )
        .expect("write");
        let err = RevocationStore::open(&root).expect_err("a corrupt journal must refuse");
        assert!(
            err.to_string().contains("revocation journal"),
            "the error must name the file: {err}"
        );
    }

    #[test]
    fn revoking_an_empty_subject_is_refused() {
        let root = scratch("empty-subject");
        let mut store = RevocationStore::open(&root).expect("open");
        assert!(store.revoke("   ").is_err());
        assert!(
            store.revoked_svids().is_empty(),
            "a refused revocation must not have written a line"
        );
    }

    #[test]
    fn a_measured_latency_never_reports_a_source_that_did_not_answer_as_inside_the_sla() {
        struct Silent;
        impl RevocationSource for Silent {
            fn revoked_svids(&self) -> Vec<String> {
                Vec::new()
            }
        }
        let measured = measure(&Silent);
        assert!(!measured.propagated);
        assert!(
            !measured.within_sla,
            "a revocation that never arrived took no time to not arrive; reporting that as \
             inside the bound is how an unmeasured bound looks measured"
        );
    }

    #[test]
    fn the_evidence_record_counts_its_own_points() {
        let record = latency_evidence();
        assert_eq!(record.enforcement_points, record.points.len());
        assert_eq!(
            record.enforcement_points_consulting_revocation,
            record
                .points
                .iter()
                .filter(|p| p.consults_revocation)
                .count(),
            "the summary count must be derived from the list, not typed beside it"
        );
        assert_eq!(record.sla.identity_seconds, 5);
        assert_eq!(record.sla.credential_seconds, 1);
    }
}

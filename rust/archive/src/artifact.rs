//! What is accepted at the door, and the three-valued answer the door records about it.
//!
//! Ingest does two things and refuses to do a third. It decides whether a submission is one of the
//! three evidence files this archive holds — dispatched on the declared `format`, the same
//! three-way match `warrantor verify` makes — and it runs the existing verifier over it as hygiene.
//! It does not decide anything a reader should believe.
//!
//! # Why the bytes are stored verbatim
//!
//! The submitted bytes are kept exactly as received and returned exactly as stored. Not a parsed
//! value that gets re-serialised on the way out: re-serialisation is a *mutation the archive
//! performs on evidence*, and even a faithful round trip through `serde_json` is the archive
//! choosing the bytes. "The archive returns what it was given" is the only claim that makes the
//! malicious-archive test meaningful, and it is only true if nothing here rewrites a byte.
//!
//! The digest is SHA-256 of those bytes, computed once, here, in Rust. Not in SQL, not in a
//! generated column, not in a `CHECK` constraint — a digest computed a second way in a second
//! language is a second implementation of the rule that says which bytes are which artifact.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use warrantor_warrant::serve::is_warrant_id;
use warrantor_warrant::{report, spend, stop};

use crate::sha256_hex;

/// The three evidence files this archive holds.
///
/// Exactly the three `warrantor verify` reads. Dispatch is on the declared `format` string and
/// never on whether a struct happens to deserialise: a report bundle and a stop record are
/// different claims, and guessing between them by shape is how one gets checked with the other's
/// rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// `warrantor.report-export/1`.
    Report,
    /// `warrantor.stop-export/1`.
    Stop,
    /// `warrantor.spend-export/1`. The kind is called `ledger` and the format string says `spend`;
    /// the two names differ and the format string is the one on the wire. Written out because this
    /// doc is what somebody hand-building a submission reads, and a format the door does not
    /// recognise is refused outright.
    Ledger,
}

impl ArtifactKind {
    /// The declared `format` value this kind is recognised by.
    #[must_use]
    pub fn format(self) -> &'static str {
        match self {
            Self::Report => report::REPORT_EXPORT_FORMAT,
            Self::Stop => stop::STOP_EXPORT_FORMAT,
            Self::Ledger => spend::LEDGER_EXPORT_FORMAT,
        }
    }

    /// The stable word this kind is stored and served under.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Stop => "stop",
            Self::Ledger => "ledger",
        }
    }

    /// Every kind this build holds. One list, so a fourth format cannot be added to the parser and
    /// forgotten by the lister.
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::Report, Self::Stop, Self::Ledger]
    }

    /// Recognise a declared format. `None` is a refusal, never a stored blob.
    #[must_use]
    pub fn from_format(format: &str) -> Option<Self> {
        // An exact match against an exhaustive list, never a `starts_with`: a format this build does
        // not understand must be refused at the door, because storing it would mean holding a file
        // the archive cannot say anything true about while a reader assumes it could.
        Self::all().into_iter().find(|kind| format == kind.format())
    }

    /// Recover a kind from its stored word.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Self::all().into_iter().find(|kind| word == kind.word())
    }
}

/// What the door found when it checked the signatures.
///
/// **Three-valued, and the three are never collapsed.** This mirrors
/// [`warrantor_warrant::serve::Integrity`] deliberately: [`IngestCheck::Unknown`] means the check
/// could not run, [`IngestCheck::Failed`] means it ran and the signatures do not hold, and reporting
/// the first as the second would turn "we could not tell" into an accusation.
///
/// None of these is a verdict. It is the door's own note about why it accepted or refused a
/// submission, and [`crate::http`] serves it under a field named `not_a_verdict` so it cannot be
/// mistaken for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum IngestCheck {
    /// The existing verifier ran and passed.
    Ok,
    /// The existing verifier ran and refused, with its own sentence.
    Failed {
        /// Verbatim from the verifier that refused. Not reworded here — the verifier's message
        /// names the first check that failed, and a paraphrase would lose that.
        reason: String,
    },
    /// The check could not be run at all.
    Unknown {
        /// Why the check could not run.
        reason: String,
    },
}

impl IngestCheck {
    /// The stable word for the wire and for storage.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed { .. } => "failed",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// The sentence behind the word, empty on a pass.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Ok => "",
            Self::Failed { reason } | Self::Unknown { reason } => reason,
        }
    }
}

/// A submission that got past the door: the bytes, what they are, and what the door thought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingested {
    /// SHA-256 hex of `bytes`, exactly as received.
    pub digest: String,
    /// Which of the three files this is.
    pub kind: ArtifactKind,
    /// The warrant it is about, read out of the file.
    pub warrant_id: String,
    /// The subject the warrant names, when the file carries one.
    pub subject: Option<String>,
    /// The submitted bytes, verbatim. Never re-serialised.
    pub bytes: Vec<u8>,
    /// The door's own note. Not a verdict.
    pub check: IngestCheck,
}

/// Why a submission was refused at the door.
///
/// A refusal is not a stored blob. Everything here is a statement that this is not one of the three
/// files the archive holds — never a statement that the evidence is bad, which is what
/// [`IngestCheck::Failed`] is for and which is *stored*, because a tampered file is the single most
/// important thing to be able to put in front of a human.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IngestError {
    /// The body is not JSON.
    #[error("this submission is not JSON, so it is not a warrantor evidence file")]
    NotJson,
    /// The body is JSON but declares no format.
    #[error("this submission has no `format` field, so it is not a warrantor evidence file")]
    NoFormat,
    /// The declared format is not one of the three.
    #[error(
        "this submission declares format {found:?}. This archive holds {report}, {stop} and \
         {ledger}, and stores nothing else."
    )]
    UnknownFormat {
        /// What the file said.
        found: String,
        /// The report export format.
        report: &'static str,
        /// The stop export format.
        stop: &'static str,
        /// The ledger export format.
        ledger: &'static str,
    },
    /// The file is the right kind but carries no warrant id, so nothing could file it.
    #[error("this {kind} declares no warrant id, so there is nothing to file it under")]
    NoWarrantId {
        /// Which kind of file was missing an id.
        kind: &'static str,
    },
}

/// Accept a submission, or refuse it at the door.
///
/// The verification step calls the existing verifier and **nothing else**: no hand-rolled digest
/// comparison, no re-serialisation, no second opinion. A file whose check fails is still
/// [`Ok`](Result::Ok) here and still stored — refusing to hold a tampered file would delete the
/// evidence that it was tampered with.
///
/// A file that declares one of the three formats and will not parse into it is *also* stored, when
/// it names the warrant it is about, and its check is [`IngestCheck::Unknown`]: no verifier ran, so
/// nothing established that its signatures are wrong, and recording that as `failed` would be an
/// accusation the archive did not earn.
///
/// # Errors
/// [`IngestError`] when the submission is not one of the three evidence files at all.
pub fn ingest(bytes: Vec<u8>) -> Result<Ingested, IngestError> {
    let declared: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| IngestError::NotJson)?;
    let format = declared
        .get("format")
        .and_then(serde_json::Value::as_str)
        .ok_or(IngestError::NoFormat)?;
    let kind = ArtifactKind::from_format(format).ok_or_else(|| IngestError::UnknownFormat {
        found: format.to_string(),
        report: report::REPORT_EXPORT_FORMAT,
        stop: stop::STOP_EXPORT_FORMAT,
        ledger: spend::LEDGER_EXPORT_FORMAT,
    })?;

    let (warrant_id, subject, check) = match kind {
        ArtifactKind::Report => check_report(&bytes),
        ArtifactKind::Stop => check_stop(&bytes),
        ArtifactKind::Ledger => check_ledger(&bytes),
    };
    // `warrant_id` is `None` only on the parse-failure arms, which are also the only arms that
    // produce `Unknown`. Falling straight through to `NoWarrantId` here is what made
    // `IngestCheck::Unknown` unreachable from this function: every body that would have been
    // recorded as `unknown` was refused at the door instead, so the three-valued check promised by
    // the RFC, by the schema's `CHECK (ingest_check IN ('ok','failed','unknown'))` and by the
    // `not_a_verdict` wire contract had two reachable values. A body that names the warrant it is
    // about can be filed under it even when this build cannot parse it — which is exactly the
    // version-skew case worth keeping rather than dropping on the floor.
    let warrant_id = match warrant_id {
        Some(id) => id,
        None => filing_key_from_unparsed(&bytes, kind)
            .ok_or(IngestError::NoWarrantId { kind: kind.word() })?,
    };

    Ok(Ingested {
        digest: sha256_hex(&bytes),
        kind,
        warrant_id,
        subject,
        bytes,
        check,
    })
}

/// The unparseable case, written once so all three arms say the same thing about it.
///
/// A body that declares a format this build knows but will not deserialise into that shape is
/// `Unknown`, not `Failed`: the verifier never ran, so nothing established that the signatures are
/// wrong, and saying they are would be an accusation the archive did not earn.
fn unparseable(kind: &str, error: &impl std::fmt::Display) -> IngestCheck {
    IngestCheck::Unknown {
        reason: format!(
            "this declares itself a warrantor {kind} export but does not parse as one, so no \
             signature check was performed: {error}"
        ),
    }
}

/// The filing key of a body that declares a known format and will not parse into it.
///
/// One string, read out of the raw JSON at the place that kind carries its warrant id. It is a
/// **filing key and nothing else**: no signature is checked here and none can be, which is why the
/// caller's [`IngestCheck`] stays [`IngestCheck::Unknown`]. Reading an id is not a second verifier —
/// it is the same thing the parsed path does, minus the shape it could not have.
///
/// The id is validated with the same [`is_warrant_id`] the router applies to a path segment. This
/// value came out of a body that did not typecheck and is on its way to a query parameter and to a
/// listing filter, so it is validated rather than sanitised: a hostile string is refused, never
/// transformed into a different string that is then used.
fn filing_key_from_unparsed(bytes: &[u8], kind: ArtifactKind) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    // Where each of the three exports carries its warrant id. Written as a match on the same
    // exhaustive enum the parser dispatches on, so a fourth format cannot be added to one and
    // forgotten by the other.
    let holder = match kind {
        ArtifactKind::Report => "bundle",
        ArtifactKind::Stop => "record",
        ArtifactKind::Ledger => "ledger",
    };
    let id = value.get(holder)?.get("warrant_id")?.as_str()?;
    is_warrant_id(id).then(|| id.to_string())
}

fn check_report(bytes: &[u8]) -> (Option<String>, Option<String>, IngestCheck) {
    match serde_json::from_slice::<report::SignedReport>(bytes) {
        Err(e) => (None, None, unparseable("report", &e)),
        Ok(signed) => {
            // The time-free verifier, on purpose and for the same reason `warrantor verify` uses
            // it: an archived report is a record of a past evaluation and must not become
            // unverifiable because a deadline went by, or the archive rots into a shelf of files
            // that all read "does NOT verify".
            let check = match report::verify_export(&signed) {
                Ok(()) => IngestCheck::Ok,
                Err(e) => IngestCheck::Failed {
                    reason: e.to_string(),
                },
            };
            (
                Some(signed.bundle.warrant_id.clone()),
                Some(signed.bundle.subject.clone()),
                check,
            )
        }
    }
}

fn check_stop(bytes: &[u8]) -> (Option<String>, Option<String>, IngestCheck) {
    match serde_json::from_slice::<stop::SignedStop>(bytes) {
        Err(e) => (None, None, unparseable("stop record", &e)),
        Ok(signed) => {
            let check = match stop::verify_stop(&signed) {
                Ok(()) => IngestCheck::Ok,
                Err(e) => IngestCheck::Failed {
                    reason: e.to_string(),
                },
            };
            (Some(signed.record.warrant_id.clone()), None, check)
        }
    }
}

fn check_ledger(bytes: &[u8]) -> (Option<String>, Option<String>, IngestCheck) {
    match serde_json::from_slice::<spend::SignedSpend>(bytes) {
        Err(e) => (None, None, unparseable("spend ledger", &e)),
        Ok(signed) => {
            let check = match spend::verify_spend(&signed) {
                Ok(()) => IngestCheck::Ok,
                Err(e) => IngestCheck::Failed {
                    reason: e.to_string(),
                },
            };
            (
                Some(signed.ledger.warrant_id.clone()),
                Some(signed.ledger.subject.clone()),
                check,
            )
        }
    }
}

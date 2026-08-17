//! What this machine holds, and what deleting each part of it would cost.
//!
//! # Why an inventory comes before a retention policy
//!
//! The buyer question — "what do you keep, where, for how long, and what happens when you delete
//! it" — has four parts, and until now Warrantor could answer none of them. `warrantor list`
//! reports id, state and goal for the `warrants/` directory; the other ten locations in the store
//! had no command that named them at all, and the module comment describing the layout listed two.
//!
//! So this module answers the first three parts and refuses to pretend about the fourth. **Nothing
//! here deletes anything, and no retention window can be configured, because nothing would enforce
//! one.** A `retention.json` that an operator could fill in while no deletion job existed would be
//! worse than the absence it replaces: it would read as a policy in force. [`Holdings`] says, on
//! every class, that no deletion authority exists in this build — see [`RETENTION_STATEMENT`].
//!
//! # The classification is the part that matters
//!
//! Deleting a file in this store is not uniformly "losing data". Three of these locations decide
//! verdicts by their own existence, and removing one *flips a verdict* rather than emptying a
//! field:
//!
//! - `stops/<id>.json` — [`crate::stop::StopStore::is_stopped`] is file existence, read
//!   fail-closed (`try_exists().unwrap_or(true)`). Delete the record and `contained_scopes` comes
//!   back empty, so the notary's containment gate goes from deny to pass and the next report reads
//!   as authorised.
//! - `spend/<id>.json` — [`crate::spend::SpendStore::load`] treats `NotFound` as a fresh ledger, so
//!   a deleted ledger is indistinguishable from one that never spent anything and a spent budget is
//!   restored to zero.
//! - `daemons/<id>.done.json` — [`crate::daemon::DaemonState`] reconciles a missing completion
//!   record as "open and nothing is supervising it" rather than "finished, exit 0". Noisy rather
//!   than dangerous, but still a changed verdict.
//!
//! And `staged/<id>.jsonl` is the one whose deletion used to be *silent*, which is what
//! [`crate::staging::StagedChainMark`] now closes.
//!
//! Against those, `logs/<id>.log` is the class most worth a retention window and the one with no
//! integrity consequence at all: raw agent stdout and stderr, in no evidence bundle, unsigned, and
//! the most likely of all of them to hold source, prompts and secrets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::store::WarrantStore;
use crate::{WarrantError, WarrantState, DEFAULT_CLI_SUBJECT, DEFAULT_MCP_SUBJECT};

/// What this build will delete on a schedule: nothing.
///
/// Printed on every class rather than once at the bottom, because "no retention configured" read
/// once at the top of a long listing is the kind of thing an operator carries into the wrong
/// conclusion about the line they are actually looking at.
pub const RETENTION_STATEMENT: &str =
    "no deletion authority exists in this build; nothing here is ever removed by warrantor";

/// What deleting a class of artifact actually costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeletionEffect {
    /// Removing it changes an answer rather than losing one: a gate flips, a ledger resets, a
    /// finished run reads as unsupervised.
    FlipsAVerdict,
    /// Removing it destroys evidence nothing else holds, and the loss is detectable.
    LosesEvidence,
    /// Removing it destroys evidence nothing else holds, and until recently nothing would have
    /// noticed. Kept as its own answer because "silent" is the property that makes a class
    /// dangerous to prune first.
    LosesEvidenceSilently,
    /// Removing it costs nothing any signed artifact depends on. This is where a retention window
    /// belongs first, and it is also the class most likely to contain secrets.
    NoIntegrityConsequence,
    /// Removing it breaks the installation rather than its evidence.
    BreaksTheInstallation,
}

impl DeletionEffect {
    /// One word for a table column.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::FlipsAVerdict => "FLIPS-VERDICT",
            Self::LosesEvidence => "LOSES-EVIDENCE",
            Self::LosesEvidenceSilently => "LOSES-EVIDENCE",
            Self::NoIntegrityConsequence => "NO-CONSEQUENCE",
            Self::BreaksTheInstallation => "BREAKS-INSTALL",
        }
    }
}

/// Every location the store writes to, as a value rather than as prose in a module comment.
///
/// The list lives here so `warrantor holdings` enumerates the store from one place. The layout
/// comment in [`crate::store`] was written when there were two directories and was wrong by nine
/// before anybody asked what the store held; an inventory built from a doc comment would go the
/// same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArtifactClass {
    /// `warrants/<id>.json`
    Warrants,
    /// `staged/<id>.jsonl`
    Staged,
    /// `witness/<id>.jsonl`
    Witness,
    /// `stops/<id>.json`
    Stops,
    /// `spend/<id>.json`
    Spend,
    /// `daemons/<id>[.done].json`
    Daemons,
    /// `logs/<id>.log`
    Logs,
    /// `refusals/<id>.jsonl`
    Refusals,
    /// `guard/<id>.jsonl`
    Guard,
    /// `keys/{issuer,settle}.key`
    Keys,
    /// `serve/{token,open.html}`
    Serve,
    /// `run/<id>.sock`
    Run,
    /// `backends.json`
    Backends,
    /// `exports/<id>.settle-report.json`
    Exports,
    /// `archive/pending.jsonl`
    PendingFilings,
    /// `trusted/issuers.json`
    TrustedIssuers,
    /// `notify.json`, `notify/pending.jsonl`
    Notifications,
    /// `actors/<id>.jsonl`
    Actors,
    /// `runs/<id>.jsonl`
    Runs,
    /// `reviews/<id>.json`
    Reviews,
}

/// Every class, in the order an operator should read them: evidence first, machinery last.
pub const ALL_CLASSES: [ArtifactClass; 20] = [
    ArtifactClass::Warrants,
    ArtifactClass::Staged,
    ArtifactClass::Witness,
    ArtifactClass::Stops,
    ArtifactClass::Spend,
    ArtifactClass::Refusals,
    ArtifactClass::Guard,
    ArtifactClass::Actors,
    ArtifactClass::Runs,
    ArtifactClass::Exports,
    ArtifactClass::PendingFilings,
    ArtifactClass::TrustedIssuers,
    ArtifactClass::Notifications,
    ArtifactClass::Reviews,
    ArtifactClass::Daemons,
    ArtifactClass::Logs,
    ArtifactClass::Keys,
    ArtifactClass::Serve,
    ArtifactClass::Run,
    ArtifactClass::Backends,
];

impl ArtifactClass {
    /// Short name, as it appears in a listing.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Warrants => "warrants",
            Self::Staged => "staged",
            Self::Witness => "witness",
            Self::Stops => "stops",
            Self::Spend => "spend",
            Self::Daemons => "daemons",
            Self::Logs => "logs",
            Self::Actors => "actors",
            Self::Runs => "runs",
            Self::Reviews => "reviews",
            Self::Refusals => "refusals",
            Self::Guard => "guard",
            Self::Keys => "keys",
            Self::Serve => "serve",
            Self::Run => "run",
            Self::Backends => "backends.json",
            Self::Exports => "exports",
            Self::PendingFilings => "archive-queue",
            Self::TrustedIssuers => "trusted-issuers",
            Self::Notifications => "notifications",
        }
    }

    /// Where it lives, relative to the store root.
    #[must_use]
    pub fn location(self) -> &'static str {
        match self {
            Self::Warrants => "warrants/<id>.json",
            Self::Staged => "staged/<id>.jsonl",
            Self::Witness => "witness/<id>.jsonl",
            Self::Stops => "stops/<id>.json",
            Self::Spend => "spend/<id>.json",
            Self::Daemons => "daemons/<id>[.done].json",
            Self::Logs => "logs/<id>.log",
            Self::Actors => "actors/<id>.jsonl",
            Self::Runs => "runs/<id>.jsonl",
            Self::Reviews => "reviews/<id>.json",
            Self::Refusals => "refusals/<id>.jsonl",
            Self::Guard => "guard/<id>.jsonl",
            Self::Keys => "keys/*.key",
            Self::Serve => "serve/{token,open.html}",
            Self::Run => "run/<id>.sock",
            Self::Backends => "backends.json",
            Self::Exports => "exports/<id>.settle-report.json",
            Self::PendingFilings => "archive/pending.jsonl",
            Self::TrustedIssuers => "trusted/issuers.json",
            Self::Notifications => "notify/pending.jsonl (config: notify.json at the root)",
        }
    }

    /// The directory (or file) to scan, under `root`.
    #[must_use]
    pub fn path_under(self, root: &Path) -> PathBuf {
        match self {
            Self::Warrants => root.join("warrants"),
            Self::Staged => root.join("staged"),
            Self::Witness => root.join("witness"),
            Self::Stops => root.join("stops"),
            Self::Spend => root.join("spend"),
            Self::Daemons => root.join("daemons"),
            Self::Logs => root.join("logs"),
            Self::Actors => root.join("actors"),
            Self::Runs => root.join("runs"),
            Self::Reviews => root.join("reviews"),
            Self::Refusals => root.join("refusals"),
            Self::Guard => root.join("guard"),
            Self::Keys => root.join("keys"),
            Self::Serve => root.join("serve"),
            Self::Run => root.join("run"),
            Self::Backends => root.join("backends.json"),
            Self::Exports => root.join("exports"),
            Self::PendingFilings => root.join("archive").join("pending.jsonl"),
            Self::TrustedIssuers => root.join("trusted").join("issuers.json"),
            Self::Notifications => root.join("notify"),
        }
    }

    /// What it holds, in one sentence an operator can act on.
    #[must_use]
    pub fn contains(self) -> &'static str {
        match self {
            Self::Warrants => {
                "the signed warrant -- and, alongside the signature rather than under it, its \
                 lifecycle state, its worktree, and the chain mark taken at grant"
            }
            Self::Staged => "every outward-facing effect an agent queued and did not perform",
            Self::Actors => "who settled, voided, stopped or approved each warrant -- hash-chained, and the only place a name is attached to a decision",
            Self::Runs => "when each supervised session started, and whether anything was watching it. The `guard: null` lines are the only positive record that a session ran unwatched",
            Self::Reviews => "which blocker was last announced for each warrant, so a repeated check does not repeatedly notify. Bookkeeping, not evidence",
            Self::Witness => {
                "how far each warrant's staged-effect chain reached, recorded outside the log it                  describes"
            }
            Self::Stops => "signed stop records: what a stop terminated and what it did not",
            Self::Spend => "the signed observed-spend ledger the budget bound is checked against",
            Self::Daemons => "supervisor registration and completion for each run",
            Self::Logs => {
                "the agent's raw stdout and stderr -- source, prompts and anything it printed"
            }
            Self::Refusals => "what a bound refused, with the verbatim arguments and destinations",
            Self::Guard => "guard-model session records and per-call signals",
            Self::Exports => {
                "the final report exports that automatic filing wrote, one per settled warrant"
            }
            Self::PendingFilings => {
                "filings that failed and are queued to retry at the next settle"
            }
            Self::TrustedIssuers => {
                "the names this machine pins to issuer keys, with when and why each was trusted"
            }
            Self::Notifications => {
                "notifications that failed and are queued to retry. The webhook config that \
                 caused them is notify.json at the store root: named by this class, and not \
                 part of its file count"
            }
            Self::Keys => "the issuer and settle signing keys",
            Self::Serve => "the read API's bearer token and the browser shim that opens it",
            Self::Run => "a socket path recorded for each daemon",
            Self::Backends => "the local price table used for spend routing",
        }
    }

    /// Is what it holds signed?
    #[must_use]
    pub fn signed(self) -> bool {
        matches!(
            self,
            Self::Warrants | Self::Stops | Self::Spend | Self::Exports
        )
    }

    /// Is what it holds hash-chained?
    #[must_use]
    pub fn chained(self) -> bool {
        matches!(self, Self::Staged)
    }

    /// What deleting it costs.
    #[must_use]
    pub fn deletion_effect(self) -> DeletionEffect {
        match self {
            Self::Warrants | Self::Stops | Self::Spend | Self::Daemons => {
                DeletionEffect::FlipsAVerdict
            }
            Self::Staged => DeletionEffect::LosesEvidenceSilently,
            Self::Witness => DeletionEffect::LosesEvidence,
            Self::Refusals | Self::Guard => DeletionEffect::LosesEvidence,
            Self::Exports => DeletionEffect::LosesEvidence,
            Self::PendingFilings | Self::TrustedIssuers => DeletionEffect::FlipsAVerdict,
            Self::Notifications => DeletionEffect::LosesEvidenceSilently,
            Self::Logs => DeletionEffect::NoIntegrityConsequence,
            // Removing an act loses the only record of WHO settled a warrant. The chain makes the
            // removal detectable to somebody holding a later head, which is not the same as
            // preventing it -- see `operators` for why that is stated as the weaker guarantee it is.
            Self::Actors => DeletionEffect::LosesEvidence,
            // Removing a run record makes an UNGUARDED run indistinguishable from a run that never
            // happened, which is the exact confusion `runs` was written to end. A store missing
            // these reads as better supervised than it was.
            Self::Runs => DeletionEffect::LosesEvidence,
            // The one genuinely disposable class added since `holdings` was written: a review
            // marker records that a notification went out, and losing it costs a DUPLICATE
            // notification. Nothing downstream of it is a verdict, and nothing is lost that was
            // not also derivable.
            Self::Reviews => DeletionEffect::NoIntegrityConsequence,
            Self::Keys | Self::Serve | Self::Run | Self::Backends => {
                DeletionEffect::BreaksTheInstallation
            }
        }
    }

    /// Why the effect above is what it is — the sentence that stops a reader pruning the wrong
    /// class first.
    #[must_use]
    pub fn deletion_note(self) -> &'static str {
        match self {
            Self::Warrants => {
                "the warrant is the record everything else is keyed to; without it the store cannot \
                 answer for the run at all"
            }
            Self::Staged => {
                "the log is created lazily, so its absence used to read as an empty queue -- zero \
                 staged effects, signed into a bundle. The chain witness now makes a removal a \
                 refusal instead"
            }
            Self::Witness => {
                "it is what makes a deleted staged log detectable rather than silent; delete both \
                 and the pair is back to the absence the witness exists to close"
            }
            Self::Actors => "the chain makes a removal DETECTABLE to somebody holding a later head, which is not the same as preventing it -- and a reader with no earlier copy cannot tell",
            Self::Runs => "an unguarded run and a run that never happened become the same observation again, which is precisely the confusion this class was added to end",
            Self::Reviews => "the next check re-announces whatever is still waiting. A duplicate notification is the whole cost, and a duplicate is something a human can see and dismiss",
            Self::Stops => {
                "containment is decided by this file existing: remove it and the notary's gate goes \
                 from deny to pass"
            }
            Self::Spend => {
                "a missing ledger is read as one that never spent, so removing it restores a spent \
                 budget to zero"
            }
            Self::Daemons => {
                "a missing completion record reconciles as 'open and unsupervised' rather than \
                 'finished, exit 0'"
            }
            Self::Refusals => {
                "the store-wide refusal summary is computed from these; pruning them makes a bound \
                 that is genuinely wrong stop looking wrong"
            }
            Self::Guard => {
                "the only record of what a classifier thought about calls that actually happened"
            }
            Self::Logs => {
                "in no evidence bundle and referenced by nothing -- which is exactly why it is the \
                 class most worth a retention window and the one most likely to hold secrets"
            }
            Self::Keys => "deleting the issuer key orphans every signature this store has made",
            Self::Serve => "regenerated on the next start; deleting it invalidates a live session",
            Self::Run => {
                "a path recorded in a daemon record. Nothing binds it -- there is no listener on \
                 this socket in this build"
            }
            Self::Backends => "the price table an operator wrote; nothing else holds a copy",
            Self::Exports => {
                "the archive holds a copy when the filing succeeded, so the loss there is a local \
                 duplicate. When the filing is still queued it is the only copy of those bytes, \
                 and the queue entry pointing at it can no longer retry"
            }
            Self::PendingFilings => {
                "the exports it points at stay on disk, but nothing retries them and nothing \
                 complains that they were never filed -- a failed filing becomes a permanent one, \
                 silently"
            }
            Self::TrustedIssuers => {
                "every `verify --issuer <name>` flips from a verdict to a refusal, and the only \
                 road back is re-pinning -- the one operation that could put a DIFFERENT key \
                 under the same name. Verdicts already given stand; the ability to re-obtain \
                 them does not"
            }
            Self::Notifications => {
                "notifications stop firing, or stop retrying, and nothing complains in either \
                 direction -- an operator who asked to be told silently stops being told. \
                 Deleting the queue alone abandons undelivered notifications it still names"
            }
        }
    }
}

/// What one class holds, counted rather than estimated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassHoldings {
    /// The class.
    pub class: ArtifactClass,
    /// Does the location exist on disk at all?
    pub present: bool,
    /// Files counted.
    pub files: usize,
    /// Total bytes.
    pub bytes: u64,
    /// Oldest modification time seen, epoch seconds.
    pub oldest: Option<u64>,
    /// Newest modification time seen, epoch seconds.
    pub newest: Option<u64>,
    /// Files whose metadata could not be read, or (for `warrants/`) whose contents would not
    /// parse.
    ///
    /// Counted separately and never folded into `files`, for the reason
    /// [`WarrantStore::list_counting_unreadable`] gives: an answer of "we hold fourteen" computed
    /// by silently dropping three is worse than one that says it could not read three.
    pub unreadable: usize,
}

/// The one thing about the store an inventory cannot honestly answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectHoldings {
    /// Warrants per recorded subject, most first.
    pub by_subject: Vec<(String, usize)>,
    /// How many of those carry a subject Warrantor assigned because nobody named one.
    pub default_subjects: usize,
}

/// Worktrees, which live in each repository rather than in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeHoldings {
    /// Worktree paths recorded on warrants that still exist on disk.
    pub on_disk: usize,
    /// Of those, how many belong to a warrant that has been settled.
    ///
    /// `settle` does not remove a worktree — only `void` does — so these accumulate in every
    /// repository a warrant was ever granted against, and no command reports them.
    pub settled: usize,
    /// Recorded worktrees that are no longer on disk.
    pub missing: usize,
}

/// Everything this machine holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holdings {
    /// The store root scanned.
    pub root: PathBuf,
    /// When the scan ran, epoch seconds.
    pub generated_at: u64,
    /// Per class.
    pub classes: Vec<ClassHoldings>,
    /// Warrants per lifecycle state.
    pub by_state: BTreeMap<String, usize>,
    /// Who the warrants say they are for.
    pub subjects: SubjectHoldings,
    /// Worktrees outside the store.
    pub worktrees: WorktreeHoldings,
    /// Warrants carrying no staged-chain witness.
    ///
    /// For these, a deleted staged log still reads as an empty queue — the pre-witness behaviour.
    /// Reported because "we cannot prove it for this many" is the honest form of the answer.
    pub unwitnessed_chains: usize,
    /// The prune policy in force, when one exists. Absent means no deletion authority: storage
    /// grows without bound, and every class line says so rather than implying a window.
    #[serde(default)]
    pub retention: Option<PrunePolicy>,
    /// Set when a `retention.json` exists and cannot be read: the operator wrote a window and it
    /// is enforcing nothing, which must be said on the listing rather than making the listing
    /// fail — an inventory that refuses to render leaves the operator with less than one that
    /// renders with a complaint.
    #[serde(default)]
    pub retention_error: Option<String>,
}

/// Count what the store holds. Reads only; nothing here writes or deletes.
///
/// # Errors
/// [`WarrantError::Encode`] only if the `warrants/` directory itself cannot be read — every other
/// location that cannot be read is reported as unreadable rather than aborting the inventory. An
/// inventory that refuses because one directory is missing is an inventory nobody can run on the
/// machine that most needs it.
pub fn holdings(store: &WarrantStore, now: u64) -> Result<Holdings, WarrantError> {
    let root = store.root().to_path_buf();
    let (warrants, unparseable) = store.list_counting_unreadable()?;
    // The prune policy is read here rather than at render time so the rendered answer and the
    // API answer agree. A policy that exists but will not parse is carried as an error on the
    // answer rather than failing it: the operator with a broken window configured must read a
    // listing that says so, and a listing that refuses to render says nothing at all.
    let (retention, retention_error) = match PrunePolicy::load(&root) {
        Ok(policy) => (policy, None),
        Err(e) => (None, Some(e)),
    };

    let classes = ALL_CLASSES
        .into_iter()
        .map(|class| {
            let mut counted = count_class(class, &root);
            if class == ArtifactClass::Warrants {
                counted.unreadable = counted.unreadable.saturating_add(unparseable);
                // A warrant file that will not parse was counted as a file above; it is not one of
                // the warrants this store can answer for, so it does not stay in both columns.
                counted.files = counted.files.saturating_sub(unparseable);
            }
            counted
        })
        .collect();

    let mut by_state: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_subject: BTreeMap<String, usize> = BTreeMap::new();
    let mut default_subjects = 0usize;
    let mut unwitnessed_chains = 0usize;
    let mut worktrees = WorktreeHoldings {
        on_disk: 0,
        settled: 0,
        missing: 0,
    };

    for stored in &warrants {
        *by_state
            .entry(format!("{:?}", stored.warrant.state).to_lowercase())
            .or_default() += 1;
        let subject = stored.warrant.claims.subject.clone();
        if subject == DEFAULT_CLI_SUBJECT || subject == DEFAULT_MCP_SUBJECT {
            default_subjects += 1;
        }
        *by_subject.entry(subject).or_default() += 1;
        if stored.staged_chain.is_none() {
            unwitnessed_chains += 1;
        }
        if let Some(path) = &stored.worktree {
            if path.exists() {
                worktrees.on_disk += 1;
                if stored.warrant.state == WarrantState::Settled {
                    worktrees.settled += 1;
                }
            } else {
                worktrees.missing += 1;
            }
        }
    }

    let mut subjects: Vec<(String, usize)> = by_subject.into_iter().collect();
    subjects.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    Ok(Holdings {
        root,
        generated_at: now,
        classes,
        by_state,
        subjects: SubjectHoldings {
            by_subject: subjects,
            default_subjects,
        },
        worktrees,
        unwitnessed_chains,
        retention,
        retention_error,
    })
}

/// Count one location. A directory that does not exist is `present: false` with zero files, which
/// is a different statement from "exists and is empty" and is rendered as one.
fn count_class(class: ArtifactClass, root: &Path) -> ClassHoldings {
    let path = class.path_under(root);
    let mut out = ClassHoldings {
        class,
        present: path.exists(),
        files: 0,
        bytes: 0,
        oldest: None,
        newest: None,
        unreadable: 0,
    };
    if !out.present {
        return out;
    }
    if path.is_file() {
        record_file(&path, &mut out);
        return out;
    }
    let Ok(entries) = std::fs::read_dir(&path) else {
        // The location exists and cannot be read. That is one unreadable thing, not zero files.
        out.unreadable = 1;
        return out;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            continue;
        }
        record_file(&child, &mut out);
    }
    out
}

fn record_file(path: &Path, out: &mut ClassHoldings) {
    let Ok(meta) = std::fs::metadata(path) else {
        out.unreadable = out.unreadable.saturating_add(1);
        return;
    };
    out.files = out.files.saturating_add(1);
    out.bytes = out.bytes.saturating_add(meta.len());
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let Some(modified) = modified else {
        // The file is there and its age is not knowable. Counted, and the age left as unknown
        // rather than defaulted to now -- a defaulted timestamp is what a retention window would
        // later be measured against.
        out.unreadable = out.unreadable.saturating_add(1);
        return;
    };
    out.oldest = Some(out.oldest.map_or(modified, |o: u64| o.min(modified)));
    out.newest = Some(out.newest.map_or(modified, |n: u64| n.max(modified)));
}

/// Render the inventory the way `warrantor holdings` prints it.
#[must_use]
pub fn render_cli(holdings: &Holdings) -> String {
    let mut lines = vec![
        format!("STORE  {}", holdings.root.display()),
        String::new(),
        format!(
            "── WHAT THIS MACHINE HOLDS ── ({})",
            match (&holdings.retention, &holdings.retention_error) {
                (_, Some(error)) => format!(
                    "retention.json exists and cannot be read: {error} — it enforces nothing"
                ),
                (Some(policy), None) => policy.sentence(),
                (None, None) => RETENTION_STATEMENT.to_string(),
            }
        ),
        String::new(),
        format!(
            "{:<14}{:<26}{:>7}{:>12}{:>10}{:>12}  {}",
            "CLASS", "LOCATION", "FILES", "BYTES", "OLDEST", "UNREADABLE", "DELETING IT"
        ),
    ];
    for class in &holdings.classes {
        lines.push(format!(
            "{:<14}{:<26}{:>7}{:>12}{:>10}{:>12}  {}",
            class.class.name(),
            class.class.location(),
            if class.present {
                class.files.to_string()
            } else {
                "-".to_string()
            },
            if class.present {
                class.bytes.to_string()
            } else {
                "-".to_string()
            },
            class
                .oldest
                .map_or_else(|| "-".to_string(), |t| age(holdings.generated_at, t)),
            class.unreadable,
            class.class.deletion_effect().word(),
        ));
    }

    lines.push(String::new());
    lines.push("── WHAT EACH ONE IS ──".to_string());
    for class in &holdings.classes {
        lines.push(String::new());
        lines.push(format!(
            "  {} — {}",
            class.class.name(),
            class.class.contains()
        ));
        lines.push(format!(
            "    integrity : {}{}",
            if class.class.signed() {
                "signed"
            } else {
                "unsigned"
            },
            if class.class.chained() {
                ", hash-chained"
            } else {
                ""
            }
        ));
        lines.push(format!(
            "    deleting  : {} — {}",
            class.class.deletion_effect().word(),
            class.class.deletion_note()
        ));
        lines.push(format!(
            "    retention : {}",
            retention_line(
                class.class,
                holdings.retention.as_ref(),
                holdings.retention_error.as_deref()
            )
        ));
        if !class.present {
            lines.push(
                "    on disk   : this location has never been created on this machine".to_string(),
            );
        }
        if class.unreadable > 0 {
            lines.push(format!(
                "    UNKNOWN   : {} file(s) here could not be read, and are NOT included in the \
                 count above",
                class.unreadable
            ));
        }
    }

    lines.push(String::new());
    lines.push("── WARRANTS ──".to_string());
    if holdings.by_state.is_empty() {
        lines.push("  none".to_string());
    }
    for (state, count) in &holdings.by_state {
        lines.push(format!("  {count:>5}  {state}"));
    }
    lines.push(format!(
        "  {:>5}  carry no staged-chain witness — for these, a deleted staged log still reads as \
         an empty queue",
        holdings.unwitnessed_chains
    ));

    lines.push(String::new());
    lines.push("── WORKTREES (outside this store, in each repository) ──".to_string());
    lines.push(format!(
        "  {:>5}  still on disk, of which {} belong to settled warrants",
        holdings.worktrees.on_disk, holdings.worktrees.settled
    ));
    lines.push(format!(
        "  {:>5}  recorded but no longer on disk",
        holdings.worktrees.missing
    ));
    lines.push(
        "  `void` removes a worktree; `settle` does not. Settled worktrees accumulate in every \
         repository."
            .to_string(),
    );

    lines.push(String::new());
    lines.push("── WHO IT IS FOR ──".to_string());
    for (subject, count) in &holdings.subjects.by_subject {
        lines.push(format!("  {count:>5}  {subject}"));
    }
    if holdings.subjects.by_subject.is_empty() {
        lines.push("  none".to_string());
    }
    lines.push(format!(
        "  {} of these carry a subject Warrantor assigned because the grant named none.",
        holdings.subjects.default_subjects
    ));
    lines.push(
        "  A subject is what the grant recorded, not an authenticated identity: `warrantor grant \
         --subject` writes whatever it is given, and the MCP grant path takes no subject at all. \
         Where the count above is concentrated on a default, this breakdown is not a per-person \
         answer and must not be read as one."
            .to_string(),
    );

    lines.push(String::new());
    lines.push("── WHAT THIS DOES NOT SAY ──".to_string());
    lines.push(
        "  Nothing here is deleted on a schedule: there is no retention window to configure, \
         because no deletion job exists to enforce one."
            .to_string(),
    );
    lines.push(
        "  Ages are file modification times, which a copy or a restore rewrites. They are not \
         evidence of when anything happened."
            .to_string(),
    );

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// A human age, coarse on purpose: the question is "how old is the oldest thing here", not a
/// duration anybody should compute with.
fn age(now: u64, then: u64) -> String {
    let seconds = now.saturating_sub(then);
    match seconds {
        0..=59 => "now".to_string(),
        60..=3599 => format!("{}m", seconds / 60),
        3600..=86_399 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

// ── pruning: the deletion authority this build does have ──────────────────────────────
//
// For the whole of Wave-1 the honest sentence was RETENTION_STATEMENT: no deletion authority
// existed, so no window was offered — a retention setting an operator could fill in while
// nothing enforced it would have read as a policy in force. That was true because nothing could
// delete. This section is the authority, and it is shaped so the sentence can stay honest in the
// other direction:
//
// * The policy mirrors the archive's `retention_policy` table exactly — `enabled` separate from
//   `window_seconds`, deleting anything only when both say so — so the two halves of this
//   platform answer the absent-limit question the same way, and neither can drift into "a number
//   that means nothing".
// * **The gate is in the code, not the config.** There is no per-class setting, on purpose:
//   this job deletes only classes whose `DeletionEffect` is `NoIntegrityConsequence` — today,
//   `logs/`. Everything a verdict, an answer or a piece of evidence depends on is refused by
//   construction, and the refusal is printed per class with the reason, so an operator reads
//   what is NOT being deleted as easily as what is.
// * Extending the gate to a class that carries evidence (first candidate: `staged/`) requires
//   writing the chain witness forward into a tombstone at deletion time — a removed log must
//   read as a refusal, not as an empty queue. That is recorded in W1-delivery-gaps §3.4 and is
//   the one hard prerequisite for widening this.

/// The format line of the prune policy.
pub const PRUNE_POLICY_FORMAT: &str = "warrantor.retention/1";

/// The local prune policy, hand-written by the operator at `<root>/retention.json`.
///
/// The shape is the archive's `retention_policy` — `enabled` and `window_seconds` are separate,
/// and neither alone deletes anything — because "the absent-limit rule" should not mean two
/// different shapes on two halves of one platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunePolicy {
    /// Always [`PRUNE_POLICY_FORMAT`].
    pub format: String,
    /// Whether deletion is permitted at all. `false` means the window is recorded but enforces
    /// nothing, which is sometimes exactly what an operator wants to be able to say.
    pub enabled: bool,
    /// How old a file must be before it is prunable, seconds.
    pub window_seconds: u64,
}

impl PrunePolicy {
    /// Where the policy lives under a store root.
    #[must_use]
    pub fn path(root: &Path) -> PathBuf {
        root.join("retention.json")
    }

    /// Read the policy.
    ///
    /// An absent file is `None` — no policy, no deletion authority, and every caller says so
    /// rather than implying a default window. A file that exists and will not parse, or declares
    /// a future format, is an error: an operator who wrote a window and is silently not getting
    /// it enforced has been told something false by omission.
    ///
    /// # Errors
    /// [`String`] naming the file and the reason.
    pub fn load(root: &Path) -> Result<Option<Self>, String> {
        let path = Self::path(root);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(None);
        };
        let policy: PrunePolicy = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} cannot be read: {e}", path.display()))?;
        if policy.format != PRUNE_POLICY_FORMAT {
            return Err(format!(
                "{} declares format {:?}, and this build reads only {PRUNE_POLICY_FORMAT}. \
                 Nothing is guessed at across formats.",
                path.display(),
                policy.format
            ));
        }
        Ok(Some(policy))
    }

    /// Does this policy, on its own, delete anything? The archive's rule: enabled AND a window.
    #[must_use]
    pub fn deletes_anything(&self) -> bool {
        self.enabled && self.window_seconds > 0
    }

    /// One human sentence about what this policy is worth, for the holdings header.
    #[must_use]
    pub fn sentence(&self) -> String {
        if !self.deletes_anything() {
            return format!(
                "prune policy present but {} — it deletes nothing",
                if self.enabled {
                    "its window is zero"
                } else {
                    "not enabled"
                }
            );
        }
        format!(
            "prune policy: enabled, window {} — `warrantor prune` deletes only \
             NO-CONSEQUENCE classes this old; everything else is refused by the job itself",
            age(self.window_seconds, 0)
        )
    }
}

/// May this job ever delete this class? The gate is the deletion effect, not the config.
#[must_use]
pub fn prunable(class: ArtifactClass) -> bool {
    class.deletion_effect() == DeletionEffect::NoIntegrityConsequence
}

/// What the prune job plans to do to one class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassPrune {
    /// The class.
    pub class: ArtifactClass,
    /// Files old enough to delete under the policy.
    pub files: Vec<PathBuf>,
    /// Their total bytes.
    pub bytes: u64,
    /// Why this class is refused, when it is. Printed, never swallowed: an operator reading a
    /// prune report is exactly the person who needs to see what is NOT going.
    pub refused: Option<&'static str>,
}

/// A full prune plan: what would go, and what is refused and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    /// Per class, in `ALL_CLASSES` order.
    pub classes: Vec<ClassPrune>,
    /// Whether the plan deletes anything at all.
    pub deletes_anything: bool,
}

/// Plan a prune. Nothing is deleted here; the plan is what `--apply` acts on and what a dry run
/// prints, and building it never touches a file's contents — only its metadata.
///
/// # Errors
/// [`String`] when a class's files cannot be listed at all.
pub fn plan_prune(root: &Path, policy: &PrunePolicy, now: u64) -> Result<PruneReport, String> {
    let cutoff = now.saturating_sub(policy.window_seconds);
    let mut classes = Vec::new();
    for class in ALL_CLASSES {
        if !prunable(class) {
            classes.push(ClassPrune {
                class,
                files: Vec::new(),
                bytes: 0,
                refused: Some(class.deletion_note()),
            });
            continue;
        }
        let mut files = Vec::new();
        let mut bytes = 0u64;
        for path in list_files(class.path_under(root))? {
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or(u64::MAX);
            if modified < cutoff {
                files.push(path);
                bytes = bytes.saturating_add(metadata.len());
            }
        }
        classes.push(ClassPrune {
            class,
            bytes,
            files,
            refused: None,
        });
    }
    let deletes_anything = classes.iter().any(|entry| !entry.files.is_empty());
    Ok(PruneReport {
        classes,
        deletes_anything,
    })
}

/// Apply a plan: delete the files it names, and report every one that would not go.
///
/// A file that cannot be removed is reported and the apply continues — a stuck file is a fact
/// about that file, not a reason to abandon the rest — but the caller exits non-zero when any
/// deletion failed, because "pruned" that left things behind is a success line this command
/// refuses to print.
///
/// # Errors
/// [`String`] naming each file that could not be removed.
pub fn apply_prune(report: &PruneReport) -> Result<u64, String> {
    let mut removed = 0u64;
    let mut failures = Vec::new();
    for entry in &report.classes {
        for path in &entry.files {
            match std::fs::remove_file(path) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(e) => failures.push(format!("{}: {e}", path.display())),
            }
        }
    }
    if failures.is_empty() {
        return Ok(removed);
    }
    Err(failures.join("\n"))
}

/// List the files directly under a path (or the single file the path names). Flat on purpose:
/// every class this build can prune is a flat directory, and a recursive walk would silently
/// promise more than the plan verified.
fn list_files(path: PathBuf) -> Result<Vec<PathBuf>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    if path.is_file() {
        return Ok(vec![path]);
    }
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&path).map_err(|e| format!("list {}: {e}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("list {}: {e}", path.display()))?;
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// The per-class retention line, which now depends on the policy in force.
///
/// With no policy, every class carries [`RETENTION_STATEMENT`] — the old truth, still true.
/// With one, prunable classes state their window and the command that enforces it, and every
/// other class says it is never removed and what deleting it would cost. An operator reading
/// either listing knows exactly which sentence they are under.
#[must_use]
pub fn retention_line(
    class: ArtifactClass,
    policy: Option<&PrunePolicy>,
    error: Option<&str>,
) -> String {
    if let Some(error) = error {
        return format!(
            "retention.json is BROKEN ({error}) — no deletion is happening under a policy \
             nobody can read"
        );
    }
    match policy {
        None => RETENTION_STATEMENT.to_string(),
        Some(policy) if !policy.deletes_anything() => RETENTION_STATEMENT.to_string(),
        Some(policy) if prunable(class) => format!(
            "removable by `warrantor prune --apply` once older than {}",
            age(policy.window_seconds, 0)
        ),
        Some(_) => format!(
            "never removed by warrantor — deleting it {}",
            class.deletion_effect().word().to_lowercase()
        ),
    }
}

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
}

/// Every class, in the order an operator should read them: evidence first, machinery last.
pub const ALL_CLASSES: [ArtifactClass; 12] = [
    ArtifactClass::Warrants,
    ArtifactClass::Staged,
    ArtifactClass::Stops,
    ArtifactClass::Spend,
    ArtifactClass::Refusals,
    ArtifactClass::Guard,
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
            Self::Stops => "stops",
            Self::Spend => "spend",
            Self::Daemons => "daemons",
            Self::Logs => "logs",
            Self::Refusals => "refusals",
            Self::Guard => "guard",
            Self::Keys => "keys",
            Self::Serve => "serve",
            Self::Run => "run",
            Self::Backends => "backends.json",
        }
    }

    /// Where it lives, relative to the store root.
    #[must_use]
    pub fn location(self) -> &'static str {
        match self {
            Self::Warrants => "warrants/<id>.json",
            Self::Staged => "staged/<id>.jsonl",
            Self::Stops => "stops/<id>.json",
            Self::Spend => "spend/<id>.json",
            Self::Daemons => "daemons/<id>[.done].json",
            Self::Logs => "logs/<id>.log",
            Self::Refusals => "refusals/<id>.jsonl",
            Self::Guard => "guard/<id>.jsonl",
            Self::Keys => "keys/*.key",
            Self::Serve => "serve/{token,open.html}",
            Self::Run => "run/<id>.sock",
            Self::Backends => "backends.json",
        }
    }

    /// The directory (or file) to scan, under `root`.
    #[must_use]
    pub fn path_under(self, root: &Path) -> PathBuf {
        match self {
            Self::Warrants => root.join("warrants"),
            Self::Staged => root.join("staged"),
            Self::Stops => root.join("stops"),
            Self::Spend => root.join("spend"),
            Self::Daemons => root.join("daemons"),
            Self::Logs => root.join("logs"),
            Self::Refusals => root.join("refusals"),
            Self::Guard => root.join("guard"),
            Self::Keys => root.join("keys"),
            Self::Serve => root.join("serve"),
            Self::Run => root.join("run"),
            Self::Backends => root.join("backends.json"),
        }
    }

    /// What it holds, in one sentence an operator can act on.
    #[must_use]
    pub fn contains(self) -> &'static str {
        match self {
            Self::Warrants => {
                "the signed warrant, its lifecycle state, its worktree, and the witness of its \
                 staged chain"
            }
            Self::Staged => "every outward-facing effect an agent queued and did not perform",
            Self::Stops => "signed stop records: what a stop terminated and what it did not",
            Self::Spend => "the signed observed-spend ledger the budget bound is checked against",
            Self::Daemons => "supervisor registration and completion for each run",
            Self::Logs => {
                "the agent's raw stdout and stderr -- source, prompts and anything it printed"
            }
            Self::Refusals => "what a bound refused, with the verbatim arguments and destinations",
            Self::Guard => "guard-model session records and per-call signals",
            Self::Keys => "the issuer and settle signing keys",
            Self::Serve => "the read API's bearer token and the browser shim that opens it",
            Self::Run => "a socket path recorded for each daemon",
            Self::Backends => "the local price table used for spend routing",
        }
    }

    /// Is what it holds signed?
    #[must_use]
    pub fn signed(self) -> bool {
        matches!(self, Self::Warrants | Self::Stops | Self::Spend)
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
            Self::Refusals | Self::Guard => DeletionEffect::LosesEvidence,
            Self::Logs => DeletionEffect::NoIntegrityConsequence,
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
                 staged effects, signed into a bundle. The chain witness in the warrant record now \
                 makes a removal a refusal instead"
            }
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
        format!("── WHAT THIS MACHINE HOLDS ── ({RETENTION_STATEMENT})"),
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
        lines.push(format!("    retention : {RETENTION_STATEMENT}"));
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

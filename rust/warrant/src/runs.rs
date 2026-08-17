//! When a supervised session started, and whether anything was watching it.
//!
//! # The question this exists to answer
//!
//! `docs/W1-delivery-gaps.md` §4.3 ends on a gap the refusals view could not close: it "does not
//! yet count warrants that ran with **no guard attached at all**", because doing so "needs a
//! per-warrant *run* timestamp, and the only one the store holds is `claims.issued_at`, which is
//! when the warrant was granted."
//!
//! That is the whole difficulty, and it is sharper than a missing timestamp. The guard writes its
//! attach record at the start of a guarded session — so a guarded run is visible, and an
//! **unguarded run leaves nothing behind at all**. Absence of a guard record is therefore
//! indistinguishable from absence of a run, and the two mean opposite things: one is a session
//! nobody watched, the other is a session that never happened. Counting the first requires a record
//! written whether or not a guard is present, which is what this module is.
//!
//! # Why it is a separate record and not a field on the guard log
//!
//! Because that would be the same conflation the guard block already refuses. A guard record is a
//! *model's opinion about a call*; a run record is *the fact that a session started*. Writing the
//! second inside the first would mean the log of what a classifier thought also carried the
//! authoritative count of runs — and every reader would then have to know that some lines in a
//! guard log are not about the guard.
//!
//! The join between them is the guard's own session id, carried here in [`RunRecord::guard`]. One
//! id, two logs, and neither pretends to be the other.
//!
//! # What it deliberately does not record
//!
//! No tool names, no arguments, no paths, no agent command line. A run record is four facts —
//! which warrant, when, in what proxy mode, and whether a guard was attached — because the moment
//! it carries more it becomes another thing that must be reasoned about before a store can be
//! copied off a machine.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The wire format of a run record.
pub const RUN_FORMAT: &str = "warrantor.run/1";

/// The sentence every run record carries about what it is not.
pub const RUN_NOTE: &str = "This records that a supervised session STARTED. It is not evidence \
                            that the agent did anything, that any bound held, or that the session \
                            finished -- a crashed run leaves this record exactly as a clean one \
                            does. It exists so that a session nobody watched can be told apart \
                            from a session that never happened.";

/// One supervised session, recorded at its start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    /// Wire format.
    pub format: String,
    /// The warrant this session ran under.
    pub warrant_id: String,
    /// This run's own id.
    pub run_id: String,
    /// When the session started, epoch seconds.
    ///
    /// The timestamp §4.3 needed. It is the start of the *session*, not the grant of the warrant:
    /// one warrant can be run many times, and `claims.issued_at` answers a different question.
    pub at: u64,
    /// The proxy mode: `enforce` or `observe`.
    pub mode: String,
    /// The guard session attached to this run, or `None` when nothing was watching.
    ///
    /// `None` is the whole point of the module. It is a positive record of an unwatched run, which
    /// is a fact no absence could establish.
    pub guard: Option<String>,
    /// How many upstream MCP servers were attached.
    ///
    /// Recorded as a count and never as names: a server name can carry a hostname or a path, and
    /// this record is meant to be safe to hand to somebody counting runs.
    pub upstreams: usize,
    /// What this record is not.
    pub note: String,
}

/// Where a warrant's run log lives.
#[must_use]
pub fn log_path(root: &Path, warrant_id: &str) -> PathBuf {
    root.join("runs").join(format!("{warrant_id}.jsonl"))
}

/// Mint a run id.
///
/// # Errors
/// A sentence when the system CSPRNG refuses. The caller treats that as "do not record", never as
/// "record with a placeholder id": two runs sharing an id would make the count this module exists
/// to produce quietly wrong, and a run recorded under a fabricated identity is worse than a run
/// not recorded — the first is a false statement, the second is a known gap.
pub fn new_run_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| {
        format!("the system CSPRNG refused ({e}), so this run could not be given an id")
    })?;
    Ok(format!("run_{}", hex::encode(bytes)))
}

/// Append one run record.
///
/// # Errors
/// A sentence on I/O failure. The caller decides whether that is fatal; in `warrantor mcp` it is
/// not — refusing to start a supervised session because a bookkeeping file would not open would
/// turn an observability feature into an outage.
pub fn record(root: &Path, entry: &RunRecord) -> Result<(), String> {
    let path = log_path(root, &entry.warrant_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let line =
        serde_json::to_string(entry).map_err(|e| format!("cannot serialise a run record: {e}"))?;
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("cannot append to {}: {e}", path.display()))?;
    file.flush()
        .map_err(|e| format!("cannot flush {}: {e}", path.display()))
}

/// Every run record in a store, and how many lines would not parse.
///
/// # Why unreadable lines are counted rather than skipped
///
/// The same rule the guard log and the actor log follow. A count computed over a readable prefix,
/// reported as though it were the whole, is how "no unguarded runs happened" gets said about a log
/// whose second half is corrupt. The number is carried alongside every total this produces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunLog {
    /// The records, in the order read.
    pub records: Vec<RunRecord>,
    /// Lines that exist and would not parse.
    pub unreadable_lines: usize,
}

impl RunLog {
    /// The subset of this log inside a half-open window `[since, until)`.
    ///
    /// A run is a point rather than an interval here — it is stamped at its start — so windowing
    /// is a straight comparison, unlike the guard log where an attach record and its counters can
    /// fall on opposite sides of a boundary.
    ///
    /// `unreadable_lines` is carried through unchanged and is deliberately **all-time**: an
    /// unparseable line has no timestamp, so it cannot be placed in or out of a window, and
    /// dropping it would let a window silently claim completeness it does not have.
    #[must_use]
    pub fn within(&self, since: Option<u64>, until: Option<u64>) -> Self {
        Self {
            records: self
                .records
                .iter()
                .filter(|r| since.is_none_or(|s| r.at >= s) && until.is_none_or(|u| r.at < u))
                .cloned()
                .collect(),
            unreadable_lines: self.unreadable_lines,
        }
    }

    /// How many runs, how many had a guard, and how many had none.
    #[must_use]
    pub fn tally(&self) -> RunTally {
        let guarded = self.records.iter().filter(|r| r.guard.is_some()).count();
        RunTally {
            total: self.records.len(),
            guarded,
            unguarded: self.records.len() - guarded,
            warrants: self
                .records
                .iter()
                .map(|r| r.warrant_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            unreadable_lines: self.unreadable_lines,
        }
    }
}

/// The counts a summary renders.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTally {
    /// Supervised sessions started in the window.
    pub total: usize,
    /// Of those, how many had a guard attached.
    pub guarded: usize,
    /// Of those, how many had nothing watching them.
    ///
    /// **The number §4.3 could not produce.** It is not "runs the guard missed things in" — an
    /// unguarded run has no signal at all, so nothing is known about what happened in it beyond
    /// what the bounds refused.
    pub unguarded: usize,
    /// How many distinct warrants those runs belong to.
    pub warrants: usize,
    /// Run-log lines that would not parse. All-time; see [`RunLog::within`].
    pub unreadable_lines: usize,
}

/// Read one warrant's run log.
///
/// A missing file is an empty log: a warrant that has never been run is the ordinary case and not
/// an error.
#[must_use]
pub fn read_for(root: &Path, warrant_id: &str) -> RunLog {
    let path = log_path(root, warrant_id);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return RunLog::default();
    };
    let mut log = RunLog::default();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RunRecord>(line) {
            Ok(record) => log.records.push(record),
            Err(_) => log.unreadable_lines += 1,
        }
    }
    log
}

/// Read every run log in a store.
///
/// A `runs/` directory that cannot be listed reads as an empty log with no unreadable lines, which
/// is the one place this module cannot tell "nothing ran" from "cannot say". Every caller that
/// reports a total is expected to sit beside a store-level unreadable count that would already be
/// non-zero in that situation.
#[must_use]
pub fn read_all(root: &Path) -> RunLog {
    let mut log = RunLog::default();
    let Ok(entries) = std::fs::read_dir(root.join("runs")) else {
        return log;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    // Sorted so two runs of the same command produce the same order, which is what makes a
    // difference between two summaries mean something.
    paths.sort();
    for path in paths {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let one = read_for(root, stem);
        log.records.extend(one.records);
        log.unreadable_lines += one.unreadable_lines;
    }
    log.records.sort_by_key(|r| r.at);
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(warrant: &str, at: u64, guard: Option<&str>) -> RunRecord {
        RunRecord {
            format: RUN_FORMAT.to_string(),
            warrant_id: warrant.to_string(),
            run_id: format!("run_{at}"),
            at,
            mode: "enforce".to_string(),
            guard: guard.map(str::to_string),
            upstreams: 0,
            note: RUN_NOTE.to_string(),
        }
    }

    fn dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wt-runs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("tempdir");
        path
    }

    #[test]
    fn an_unguarded_run_is_a_positive_record_and_not_an_absence() {
        // The whole reason the module exists. Before it, a run with no guard wrote nothing, so
        // "nobody was watching" and "nothing ran" were the same observation.
        let root = dir("unguarded");
        record(&root, &run("wrt_a", 10, None)).expect("record");
        record(&root, &run("wrt_a", 20, Some("gsn_1"))).expect("record");

        let tally = read_all(&root).tally();
        assert_eq!(tally.total, 2);
        assert_eq!(tally.guarded, 1);
        assert_eq!(tally.unguarded, 1);
        assert_eq!(tally.warrants, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_warrant_that_never_ran_reads_as_an_empty_log_rather_than_an_error() {
        let root = dir("never");
        assert_eq!(read_for(&root, "wrt_missing"), RunLog::default());
        assert_eq!(read_all(&root).tally(), RunTally::default());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_line_that_will_not_parse_is_counted_and_never_dropped() {
        // A total computed over a readable prefix and reported as the whole is how "no unguarded
        // runs happened" gets said about a log whose second half is corrupt.
        let root = dir("corrupt");
        record(&root, &run("wrt_a", 10, None)).expect("record");
        let path = log_path(&root, "wrt_a");
        let mut existing = std::fs::read_to_string(&path).expect("read");
        existing.push_str("{ this will not parse\n");
        std::fs::write(&path, existing).expect("write");

        let tally = read_all(&root).tally();
        assert_eq!(tally.total, 1);
        assert_eq!(tally.unreadable_lines, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_window_selects_on_the_run_start_and_carries_the_unreadable_count_through() {
        let log = RunLog {
            records: vec![
                run("wrt_a", 10, None),
                run("wrt_a", 20, Some("gsn_1")),
                run("wrt_b", 30, None),
            ],
            unreadable_lines: 4,
        };
        let inside = log.within(Some(15), Some(30));
        assert_eq!(inside.records.len(), 1, "[15, 30) holds only the run at 20");
        assert_eq!(inside.tally().guarded, 1);
        assert_eq!(inside.tally().unguarded, 0);
        // All-time, and deliberately so: an unparseable line has no timestamp, so it can be placed
        // neither inside the window nor outside it, and dropping it would let the window claim a
        // completeness it does not have.
        assert_eq!(inside.unreadable_lines, 4);
    }

    #[test]
    fn an_open_sided_window_means_open_and_not_empty() {
        let log = RunLog {
            records: vec![run("wrt_a", 10, None), run("wrt_a", 90, None)],
            unreadable_lines: 0,
        };
        assert_eq!(log.within(None, None).records.len(), 2);
        assert_eq!(log.within(Some(50), None).records.len(), 1);
        assert_eq!(log.within(None, Some(50)).records.len(), 1);
    }

    #[test]
    fn run_ids_are_distinct() {
        // Two runs sharing an id would make the count this module exists to produce quietly wrong.
        let a = new_run_id().expect("id");
        let b = new_run_id().expect("id");
        assert_ne!(a, b);
        assert!(a.starts_with("run_"), "{a}");
        assert_eq!(a.len(), 4 + 32);
    }

    #[test]
    fn records_from_every_warrant_are_read_and_ordered_by_time() {
        let root = dir("many");
        record(&root, &run("wrt_b", 30, None)).expect("record");
        record(&root, &run("wrt_a", 10, Some("gsn_1"))).expect("record");
        record(&root, &run("wrt_c", 20, None)).expect("record");

        let log = read_all(&root);
        assert_eq!(
            log.records.iter().map(|r| r.at).collect::<Vec<_>>(),
            vec![10, 20, 30],
            "a stable order is what makes a difference between two summaries mean something"
        );
        assert_eq!(log.tally().warrants, 3);
        let _ = std::fs::remove_dir_all(&root);
    }
}

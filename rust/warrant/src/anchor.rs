//! Time anchoring, without adding a trust root.
//!
//! # The problem, stated precisely
//!
//! Every signed artifact this system produces carries a timestamp read from the machine's own
//! clock. The signature covers that timestamp, so it cannot be edited afterwards — and it was never
//! *checked* in the first place. An operator who sets the clock back and then exports a report
//! produces a correctly-signed artifact claiming to be older than it is. Nothing in the evidence
//! detects it, because from the signature's point of view nothing is wrong: the bytes say what they
//! said when they were signed.
//!
//! That matters here more than it would elsewhere. The whole product is "an agent's actions carry a
//! verifiable receipt", and *when* is half of what a receipt asserts. A receipt whose time can be
//! chosen after the fact is a receipt whose ordering relative to an incident can be chosen too.
//!
//! # Why the obvious fix is refused
//!
//! The standard answer is a third-party time-stamping authority — RFC 3161, or a public ledger. Both
//! work and both are **new trust roots**, and this codebase has already declined one for exactly
//! this reason: [`crate::trust`] refuses to fetch issuer keys over a network because *"a directory
//! that hands them out is a new trust root, and this design does not add one."* Contacting a TSA on
//! every export would make every piece of evidence depend on somebody else's availability and
//! somebody else's key, decided by whoever configured a URL.
//!
//! # What this does instead, and exactly what it buys
//!
//! An append-only, hash-chained **local time ledger**. Every signed artifact's digest is appended
//! with the clock reading at the moment it was signed, and each entry carries the previous entry's
//! digest.
//!
//! What that genuinely establishes:
//!
//! * **Relative order is provable.** If A precedes B in the chain, A was signed before B — whatever
//!   timestamps the two artifacts carry. Ordering no longer depends on trusting either clock
//!   reading.
//! * **A clock that went backwards is visible.** The ledger's own timestamps must be
//!   non-decreasing; [`verify`] reports the first place they are not, naming both readings. A
//!   backdated export shows up as a *later* chain position holding an *earlier* time.
//! * **Rewriting history is detectable.** Editing or removing an entry breaks every digest after
//!   it, so anyone holding a later head — a colleague, a ticket, a commit message — can detect it.
//!
//! What it does **not** establish, and this is said in every rendering rather than left to be
//! inferred: **it proves nothing about absolute time to anybody who does not already have a copy of
//! an earlier head.** A machine that has always lied about the clock produces a perfectly consistent
//! ledger of lies.
//!
//! # The bridge to real time, which is a human step
//!
//! The head digest is 32 bytes of hex, and it is publishable. An operator who pastes it into a
//! commit message, a ticket, a signed email or a chat channel has bound everything in the ledger up
//! to that moment to a time *somebody else* can attest to — because the containing system has its
//! own clock and its own record. That is a genuine anchor to external time, obtained without this
//! program contacting anything, and `anchor show` prints the head for precisely that use.
//!
//! It is deliberately manual. Automating a publication target would mean this program choosing whose
//! clock to trust, which is the decision being avoided.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::report::sha256_hex;

/// The wire format of one ledger line.
pub const ANCHOR_FORMAT: &str = "warrantor.anchor/1";

/// What kind of artifact was anchored.
///
/// Recorded so a reader can tell what a digest refers to without holding the artifact. A ledger of
/// bare digests is a ledger nobody can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anchored {
    /// An exported evidence report.
    Report,
    /// An exported stop record.
    Stop,
    /// An exported spend ledger.
    Spend,
    /// A settle report written by the automatic-filing path.
    SettleReport,
}

impl Anchored {
    /// The word it is written as.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Stop => "stop",
            Self::Spend => "spend",
            Self::SettleReport => "settle-report",
        }
    }
}

/// One entry in the time ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorEntry {
    /// Wire format.
    pub format: String,
    /// The warrant the artifact belongs to.
    pub warrant_id: String,
    /// What kind of artifact it is.
    pub kind: Anchored,
    /// SHA-256 of the artifact's bytes, hex. The artifact itself is never copied here.
    pub artifact_digest: String,
    /// The clock reading when it was anchored.
    pub at: u64,
    /// The previous entry's digest, or the empty string for the first.
    pub prev: String,
    /// This entry's digest, over every field above.
    pub digest: String,
}

impl AnchorEntry {
    fn compute_digest(
        warrant_id: &str,
        kind: Anchored,
        artifact_digest: &str,
        at: u64,
        prev: &str,
    ) -> String {
        // Unit-separated, for the same reason the actor log is: without a separator that cannot
        // occur in a field, two different entries can share a pre-image.
        let pre_image = format!(
            "{ANCHOR_FORMAT}\u{1f}{warrant_id}\u{1f}{}\u{1f}{artifact_digest}\u{1f}{at}\u{1f}{prev}",
            kind.word()
        );
        sha256_hex(pre_image.as_bytes())
    }
}

/// Where the ledger lives.
///
/// One ledger per store, not one per warrant. The whole value is cross-artifact ordering: a
/// per-warrant chain could not establish that warrant A's report was signed before warrant B's,
/// which is the question an incident actually asks.
#[must_use]
pub fn ledger_path(root: &Path) -> PathBuf {
    root.join("anchor").join("ledger.jsonl")
}

/// Read the ledger.
///
/// # Errors
/// A sentence when a line will not parse. A partially-readable ledger is reported rather than
/// silently truncated to its readable prefix: a prefix is a chain that appears intact and is short,
/// which is exactly what a deletion looks like.
pub fn read(root: &Path) -> Result<Vec<AnchorEntry>, String> {
    let path = ledger_path(root);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut entries = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AnchorEntry = serde_json::from_str(line).map_err(|e| {
            format!(
                "{}: line {} will not parse ({e}). A readable prefix of a hash chain is \
                 indistinguishable from a chain somebody truncated, so this is refused rather than \
                 partially accepted.",
                path.display(),
                index + 1
            )
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Append one artifact to the ledger.
///
/// # Errors
/// A sentence on I/O failure, or when the existing ledger cannot be read — appending to a ledger
/// whose tail is unknown would start a second chain on top of a gap.
pub fn append(
    root: &Path,
    warrant_id: &str,
    kind: Anchored,
    artifact_bytes: &[u8],
    at: u64,
) -> Result<AnchorEntry, String> {
    let path = ledger_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let existing = read(root)?;
    let prev = existing
        .last()
        .map(|e| e.digest.clone())
        .unwrap_or_default();
    let artifact_digest = sha256_hex(artifact_bytes);
    let digest = AnchorEntry::compute_digest(warrant_id, kind, &artifact_digest, at, &prev);
    let entry = AnchorEntry {
        format: ANCHOR_FORMAT.to_string(),
        warrant_id: warrant_id.to_string(),
        kind,
        artifact_digest,
        at,
        prev,
        digest,
    };
    let line =
        serde_json::to_string(&entry).map_err(|e| format!("cannot serialise an anchor: {e}"))?;
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("cannot append to {}: {e}", path.display()))?;
    // Flushed before returning. An anchor still in a buffer when the process dies is an artifact
    // whose position in the chain does not exist, which is worse than never having anchored it:
    // the next append then chains over a hole nobody knows about.
    file.sync_all()
        .map_err(|e| format!("cannot flush {}: {e}", path.display()))?;
    Ok(entry)
}

/// What is wrong with a ledger, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorFault {
    /// An entry does not follow the one before it.
    ChainBroken {
        /// 1-based line number.
        line: usize,
        /// What it names as its predecessor.
        names: String,
        /// What the predecessor actually hashes to.
        actual: String,
    },
    /// An entry's own contents do not hash to the digest it carries.
    Edited {
        /// 1-based line number.
        line: usize,
    },
    /// The clock went backwards between two entries.
    ///
    /// **Not** a break in the chain: the chain is intact and the clock is not. Kept as a separate
    /// fault because the remedies are entirely different — a broken chain means somebody edited the
    /// file, and a backwards clock means the machine's time cannot be trusted for anything signed
    /// in that window.
    ClockWentBackwards {
        /// 1-based line number of the later entry.
        line: usize,
        /// The earlier entry's reading.
        previous: u64,
        /// This entry's reading, which is smaller.
        current: u64,
    },
}

impl std::fmt::Display for AnchorFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainBroken { line, names, actual } => write!(
                f,
                "anchor line {line} does not follow the line before it: it names previous digest \
                 {names:?}, and that line hashes to {actual:?}. An entry has been removed, \
                 reordered or edited."
            ),
            Self::Edited { line } => write!(
                f,
                "anchor line {line} has been edited: its contents do not hash to the digest it \
                 carries."
            ),
            Self::ClockWentBackwards {
                line,
                previous,
                current,
            } => write!(
                f,
                "the clock went BACKWARDS at anchor line {line}: the entry before it reads \
                 {previous} and it reads {current}. The chain is intact -- the clock is not. \
                 Anything signed on this machine between those two readings carries a timestamp \
                 that cannot be relied on, and this is the only place that fact is visible, because \
                 a signature over a wrong time is a valid signature."
            ),
        }
    }
}

/// Check a ledger's chain and its monotonicity.
///
/// Every fault is collected rather than returning the first, because the two kinds mean different
/// things and an operator needs both: stopping at the first broken link would hide a clock
/// anomaly further down, and a clock anomaly is the finding that changes what evidence is worth.
#[must_use]
pub fn verify(entries: &[AnchorEntry]) -> Vec<AnchorFault> {
    let mut faults = Vec::new();
    let mut expected_prev = String::new();
    let mut previous_at: Option<u64> = None;
    for (index, entry) in entries.iter().enumerate() {
        let line = index + 1;
        if entry.prev != expected_prev {
            faults.push(AnchorFault::ChainBroken {
                line,
                names: entry.prev.clone(),
                actual: expected_prev.clone(),
            });
        }
        let recomputed = AnchorEntry::compute_digest(
            &entry.warrant_id,
            entry.kind,
            &entry.artifact_digest,
            entry.at,
            &entry.prev,
        );
        if recomputed != entry.digest {
            faults.push(AnchorFault::Edited { line });
        }
        if let Some(previous) = previous_at {
            if entry.at < previous {
                faults.push(AnchorFault::ClockWentBackwards {
                    line,
                    previous,
                    current: entry.at,
                });
            }
        }
        previous_at = Some(entry.at);
        expected_prev = entry.digest.clone();
    }
    faults
}

/// The publishable head: what an operator pastes somewhere with its own clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The head entry's digest, or `None` for an empty ledger.
    pub digest: Option<String>,
    /// How many entries are behind it.
    pub entries: usize,
    /// The clock reading of the newest entry.
    pub newest_at: Option<u64>,
    /// The clock reading of the oldest entry.
    pub oldest_at: Option<u64>,
}

/// Summarise a ledger for `anchor show`.
#[must_use]
pub fn head(entries: &[AnchorEntry]) -> Head {
    Head {
        digest: entries.last().map(|e| e.digest.clone()),
        entries: entries.len(),
        newest_at: entries.last().map(|e| e.at),
        oldest_at: entries.first().map(|e| e.at),
    }
}

/// Where a digest sits in the chain, if it is there at all.
///
/// Answers the question an auditor holding one exported artifact actually has: *was this signed
/// before or after that one?* The position is the answer, and it does not depend on trusting either
/// artifact's own timestamp.
#[must_use]
pub fn position_of(entries: &[AnchorEntry], artifact_digest: &str) -> Option<usize> {
    entries
        .iter()
        .position(|e| e.artifact_digest == artifact_digest)
}

/// The sentence every rendering of this ledger carries.
///
/// Written once, as a constant, for the same reason [`crate::serve::bind_warning`] is a function: a
/// caveat retyped in three places is a caveat that loses a clause in one of them.
pub const ANCHOR_CAVEAT: &str = "\
This ledger establishes ORDER, not TIME. If one artifact precedes another here, it was signed
first -- whatever timestamps the two carry, and without trusting either. A clock that went
backwards is visible, and an edited or removed entry breaks every digest after it.

What it does NOT establish: absolute time, to anyone who does not already hold an earlier copy of
the head. A machine that has always misreported its clock produces a perfectly consistent ledger.
No time-stamping authority is contacted, deliberately: one would make every piece of evidence
depend on somebody else's key and availability, which is a trust root this design does not add.

The bridge is a human step, and it is the head digest below. Paste it into a commit message, a
ticket or a signed email and everything up to this moment is bound to a time somebody else can
attest to -- because that system has its own clock and its own record.";

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "warrantor-anchor-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("tempdir");
        path
    }

    #[test]
    fn an_empty_ledger_has_no_head_and_says_so_rather_than_a_zero_digest() {
        let summary = head(&[]);
        assert_eq!(summary.digest, None);
        assert_eq!(summary.entries, 0);
        assert_eq!(summary.newest_at, None);
    }

    #[test]
    fn entries_chain_and_order_is_established_without_trusting_either_timestamp() {
        // The property the module exists for. Both artifacts below claim implausible times; the
        // ledger still says which was signed first, because position is not a timestamp.
        let dir = tempdir("order");
        append(&dir, "wrt_a", Anchored::Report, b"first artifact", 5_000).expect("a");
        append(&dir, "wrt_b", Anchored::Report, b"second artifact", 6_000).expect("b");

        let entries = read(&dir).expect("read");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prev, "", "the first entry starts the chain");
        assert_eq!(entries[1].prev, entries[0].digest);
        assert!(verify(&entries).is_empty(), "{:?}", verify(&entries));

        let first = sha256_hex(b"first artifact");
        let second = sha256_hex(b"second artifact");
        assert_eq!(position_of(&entries, &first), Some(0));
        assert_eq!(position_of(&entries, &second), Some(1));
    }

    #[test]
    fn a_clock_that_went_backwards_is_a_fault_of_its_own_and_not_a_broken_chain() {
        // The distinction matters because the remedies are unrelated: a broken chain means somebody
        // edited the file, and a backwards clock means everything signed in that window carries a
        // timestamp nothing can vouch for.
        let dir = tempdir("backwards");
        append(&dir, "wrt_a", Anchored::Report, b"a", 9_000).expect("a");
        append(&dir, "wrt_b", Anchored::Report, b"b", 1_000).expect("b");

        let entries = read(&dir).expect("read");
        let faults = verify(&entries);
        assert_eq!(faults.len(), 1, "{faults:?}");
        match &faults[0] {
            AnchorFault::ClockWentBackwards {
                line,
                previous,
                current,
            } => {
                assert_eq!((*line, *previous, *current), (2, 9_000, 1_000));
            }
            other => panic!("wrong fault: {other:?}"),
        }
        let rendered = faults[0].to_string();
        assert!(rendered.contains("chain is intact"), "{rendered}");
        assert!(
            rendered.contains("a signature over a wrong time is a valid signature"),
            "the message has to say why a signature does not help here: {rendered}"
        );
    }

    #[test]
    fn an_edited_entry_is_detected_and_so_is_a_removed_one() {
        let dir = tempdir("tamper");
        for (n, at) in [(b"a".as_slice(), 10u64), (b"b", 20), (b"c", 30)] {
            append(&dir, "wrt_1", Anchored::Report, n, at).expect("append");
        }
        let entries = read(&dir).expect("read");
        assert!(verify(&entries).is_empty());

        // Edit the digest an entry points at.
        let mut edited = entries.clone();
        edited[1].artifact_digest = sha256_hex(b"something else");
        let faults = verify(&edited);
        assert!(
            faults
                .iter()
                .any(|f| matches!(f, AnchorFault::Edited { line: 2 })),
            "{faults:?}"
        );

        // Remove the middle entry.
        let mut removed = entries;
        removed.remove(1);
        let faults = verify(&removed);
        assert!(
            faults
                .iter()
                .any(|f| matches!(f, AnchorFault::ChainBroken { line: 2, .. })),
            "{faults:?}"
        );
    }

    #[test]
    fn every_fault_is_collected_because_a_clock_anomaly_may_sit_below_a_broken_link() {
        // Returning the first fault would hide the finding that changes what evidence is worth.
        let dir = tempdir("both");
        append(&dir, "wrt_1", Anchored::Report, b"a", 10).expect("a");
        append(&dir, "wrt_1", Anchored::Report, b"b", 20).expect("b");
        append(&dir, "wrt_1", Anchored::Report, b"c", 5).expect("c");
        let mut entries = read(&dir).expect("read");
        entries[1].prev = "0".repeat(64);

        let faults = verify(&entries);
        assert!(faults.len() >= 2, "{faults:?}");
        assert!(faults
            .iter()
            .any(|f| matches!(f, AnchorFault::ChainBroken { .. })));
        assert!(faults
            .iter()
            .any(|f| matches!(f, AnchorFault::ClockWentBackwards { .. })));
    }

    #[test]
    fn one_ledger_per_store_so_two_warrants_can_be_ordered_against_each_other() {
        // A per-warrant chain could not answer "was warrant A's report signed before warrant B's",
        // which is the question an incident actually asks.
        let dir = tempdir("cross");
        append(&dir, "wrt_a", Anchored::Report, b"a", 10).expect("a");
        append(&dir, "wrt_b", Anchored::Stop, b"b", 20).expect("b");
        let entries = read(&dir).expect("read");
        assert_eq!(entries[0].warrant_id, "wrt_a");
        assert_eq!(entries[1].warrant_id, "wrt_b");
        assert_eq!(entries[1].prev, entries[0].digest);
    }

    #[test]
    fn the_caveat_refuses_to_claim_absolute_time() {
        assert!(ANCHOR_CAVEAT.contains("ORDER, not TIME"));
        assert!(ANCHOR_CAVEAT.contains("does NOT establish"));
        assert!(
            ANCHOR_CAVEAT.contains("No time-stamping authority is contacted"),
            "the refusal to add a trust root is part of the claim"
        );
    }

    #[test]
    fn a_ledger_line_that_will_not_parse_is_refused_rather_than_truncated() {
        let dir = tempdir("corrupt");
        append(&dir, "wrt_1", Anchored::Report, b"a", 10).expect("a");
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(ledger_path(&dir))
            .expect("open");
        writeln!(file, "{{not json").expect("write");
        let error = read(&dir).expect_err("refuses");
        assert!(
            error.contains("indistinguishable from a chain somebody truncated"),
            "{error}"
        );
    }
}

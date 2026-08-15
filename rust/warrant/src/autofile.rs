//! Filings that happen because a policy said so, and the queue that catches the ones that failed.
//!
//! `--archive` on `report`/`stop`/`spend` is an operator remembering a flag at the moment they
//! export. [`crate::archive_client::AutoFile::Settle`] is the same filing moved to the moment the
//! warrant's story is over — settle — when nobody remembers anything, because from the operator's
//! side they are done.
//!
//! The two hard rules this module exists to keep:
//!
//! * **A failed filing never fails the settle.** The warrant's state is a local fact established
//!   by local keys; an unreachable archive cannot un-settle it. What the failure does instead is
//!   occupy this queue, loudly, and retry at the next settle. The operator is told both facts in
//!   separate sentences — never one sentence that blurs them.
//! * **A queued filing names bytes that exist on disk.** The entry carries the export's path and
//!   its digest. The retry reads those exact bytes and checks them against that digest before
//!   sending: a filing is a promise about specific bytes, and if the file at that path has
//!   changed since queueing, nobody here can say whether the new bytes should be filed — that
//!   becomes an operator decision, and the entry is dropped with a sentence saying so rather
//!   than quietly filing something else.
//!
//! There is deliberately no background daemon retrying this queue. The retry point is the next
//! settle, which is the next moment this machine is already doing archive business. A daemon
//! would be a second place with the device key loaded for no new capability.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::archive_client::{self, ArchiveConfig, ArchiveTransport};

/// The format line of a pending-filing entry.
pub const PENDING_FORMAT: &str = "warrantor.pending-filing/1";

/// One filing that failed and is waiting for the next settle to retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingFiling {
    /// Always [`PENDING_FORMAT`]. A future format is refused, not field-picked.
    pub format: String,
    /// The warrant the evidence is about.
    pub warrant_id: String,
    /// Where the bytes live, absolute, as written by the settle that queued them.
    pub path: String,
    /// The SHA-256 the bytes hashed to when they were queued — checked again before any retry,
    /// because a filing is a promise about specific bytes.
    pub digest: String,
    /// When the filing first failed, epoch seconds.
    pub queued_at: u64,
    /// How many filing attempts have failed, this one included.
    pub attempts: u32,
    /// The most recent failure, in the sentence the caller reported.
    pub last_reason: String,
}

/// Where the pending-filings ledger lives under a store root.
#[must_use]
pub fn pending_path(root: &Path) -> PathBuf {
    root.join("archive").join("pending.jsonl")
}

/// Record a filing that failed, so the next settle retries it.
///
/// Appends one line; never rewrites what is already there, because a queue that rewrites itself
/// on failure is a queue that can lose an entry to the very outage it is recording.
///
/// # Errors
/// When the ledger's directory cannot be made or the line cannot be written. The caller reports
/// this loudly — a filing that failed *and* could not be queued is the worst state here, because
/// nothing will retry it and nothing will say so.
pub fn queue_filing(
    root: &Path,
    warrant_id: &str,
    path: &Path,
    digest: &str,
    reason: &str,
    now: u64,
) -> Result<PendingFiling, String> {
    let entry = PendingFiling {
        format: PENDING_FORMAT.to_string(),
        warrant_id: warrant_id.to_string(),
        path: path.display().to_string(),
        digest: digest.to_string(),
        queued_at: now,
        attempts: 1,
        last_reason: reason.to_string(),
    };
    let ledger = pending_path(root);
    if let Some(parent) = ledger.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut line = serde_json::to_vec(&entry).map_err(|e| format!("encode the entry: {e}"))?;
    line.push(b'\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(&line)
        })
        .map_err(|e| format!("append to {}: {e}", ledger.display()))?;
    Ok(entry)
}

/// Read the pending-filings ledger.
///
/// An absent ledger is an empty queue — that is its normal state, written lazily by the first
/// failure. A ledger that exists and will not parse is an error naming the line, not an empty
/// queue: entries in it are evidence that has not reached the archive, and reading their file as
/// "nothing pending" would silently abandon filings this machine promised to retry.
///
/// # Errors
/// [`String`] naming the unreadable line.
pub fn load_pending(root: &Path) -> Result<Vec<PendingFiling>, String> {
    let ledger = pending_path(root);
    let Ok(bytes) = std::fs::read(&ledger) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (index, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: PendingFiling = serde_json::from_str(line).map_err(|e| {
            format!(
                "{} line {} is not a pending filing this build can read: {e}. The queue is \
                 refused rather than read around — fix or remove the line, because entries in it \
                 are evidence that has not reached the archive.",
                ledger.display(),
                index + 1
            )
        })?;
        if entry.format != PENDING_FORMAT {
            return Err(format!(
                "{} line {} declares format {:?}, and this build reads only {PENDING_FORMAT}. \
                 Nothing is guessed at across formats.",
                ledger.display(),
                index + 1,
                entry.format
            ));
        }
        out.push(entry);
    }
    Ok(out)
}

/// What a drain did, in sentences the operator reads at the settle that triggered it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Filings that reached the archive, in the order they were retried. `already_held` on one of
    /// these is the idempotent case — the archive had these exact bytes — and is reported as such
    /// rather than as a fresh filing.
    pub filed: Vec<archive_client::Filed>,
    /// Filings still queued after this attempt, with one more failure behind them.
    pub still_pending: Vec<String>,
    /// Entries removed without filing, each with the sentence that explains why.
    pub dropped: Vec<String>,
}

/// Retry every pending filing, in the order they failed.
///
/// Three things can happen to an entry, and none of them is a silent skip:
///
/// * it **files** — the bytes are unchanged and the archive took them — and the entry is gone;
/// * it **fails again** — and it stays, with one more attempt and the newest reason, so a queue
///   that never succeeds still tells the truth about how hard it has tried;
/// * it is **dropped** — because the file it names is gone, or no longer hashes to the digest the
///   entry recorded — with a sentence an operator can act on, because filing changed bytes under
///   an old promise is nobody's automatic decision.
///
/// The ledger is rewritten atomically with the survivors, and removed entirely when there are
/// none, so an absent ledger keeps meaning "nothing pending".
///
/// # Errors
/// When the ledger cannot be read (fail-closed — see [`load_pending`]) or the survivors cannot be
/// written back. A caller that then files a *new* export anyway is behaving correctly: a corrupt
/// line left over from an old outage must not stop fresh evidence from reaching the archive, and
/// the drain error is printed at every settle until an operator fixes the line.
pub fn drain_pending<T: ArchiveTransport>(
    transport: &mut T,
    config: &ArchiveConfig,
    key: &SigningKey,
    root: &Path,
    now: u64,
) -> Result<DrainOutcome, String> {
    let entries = load_pending(root)?;
    let mut outcome = DrainOutcome::default();
    let mut survivors: Vec<PendingFiling> = Vec::new();
    for mut entry in entries {
        let path = PathBuf::from(&entry.path);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                outcome.dropped.push(format!(
                    "{}: the export it points at can no longer be read ({e}), so there are no \
                     bytes to file. The bytes may still exist elsewhere; nothing here can name \
                     them. File them manually if they do: warrantor archive push <file>.",
                    entry.warrant_id
                ));
                continue;
            }
        };
        let digest = crate::report::sha256_hex(&bytes);
        if digest != entry.digest {
            outcome.dropped.push(format!(
                "{}: the export at {} changed since the filing was queued (queued {}, hashes {} \
                 now), so the queued promise no longer names those bytes. Whether the new bytes \
                 should be filed is an operator decision, not a retry.",
                entry.warrant_id, entry.path, entry.digest, digest
            ));
            continue;
        }
        match archive_client::push(transport, config, key, &bytes, now) {
            Ok(filed) => {
                outcome.filed.push(filed);
            }
            Err(e) => {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_reason = e.to_string();
                outcome.still_pending.push(format!(
                    "{}: {} (attempt {})",
                    entry.warrant_id, entry.last_reason, entry.attempts
                ));
                survivors.push(entry);
            }
        }
    }
    write_survivors(root, &survivors)?;
    Ok(outcome)
}

/// Rewrite the ledger with the survivors, or remove it when there are none.
fn write_survivors(root: &Path, survivors: &[PendingFiling]) -> Result<(), String> {
    let ledger = pending_path(root);
    if survivors.is_empty() {
        // Absent means "nothing pending" everywhere this ledger is read; an empty file would mean
        // the same thing one tombstone at a time. Remove it.
        return match std::fs::remove_file(&ledger) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {e}", ledger.display())),
        };
    }
    let mut body = String::new();
    for entry in survivors {
        let line = serde_json::to_string(entry).map_err(|e| format!("encode an entry: {e}"))?;
        body.push_str(&line);
        body.push('\n');
    }
    let temporary = ledger.with_extension("jsonl.tmp");
    std::fs::write(&temporary, body.as_bytes())
        .map_err(|e| format!("write {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, &ledger).map_err(|e| format!("write {}: {e}", ledger.display()))
}

/// The result of trying to file one export under the settle policy.
#[derive(Debug, PartialEq, Eq)]
pub enum Filing {
    /// The archive took the bytes. Custody, not a verdict, as ever.
    Filed(archive_client::Filed),
    /// The filing failed and is queued for the next settle. The sentence is the failure, carried
    /// unaltered so the operator reads the archive's own words (or the transport's), not a
    /// paraphrase of them.
    Queued {
        /// The entry as written to the ledger.
        entry: PendingFiling,
        /// Why, in the words of whatever refused.
        reason: String,
    },
}

/// Push the bytes at `path` under the settle policy, queueing them on any failure.
///
/// The digest is computed from the bytes as read back off disk — never handed in from memory —
/// so the entry's promise and the pushed bytes are the same bytes by construction.
///
/// # Errors
/// Never: every failure is a [`Filing::Queued`] carrying the reason. A queue that cannot be
/// written is the one case that returns `Err`, and it is the loudest state this module has, for
/// the same reason as in [`queue_filing`].
pub fn file_or_queue<T: ArchiveTransport>(
    transport: &mut T,
    config: &ArchiveConfig,
    key: &SigningKey,
    root: &Path,
    warrant_id: &str,
    path: &Path,
    now: u64,
) -> Result<Filing, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let reason = format!("read back {}: {e}", path.display());
            let entry = queue_filing(root, warrant_id, path, &reason, &reason, now)?;
            return Ok(Filing::Queued { entry, reason });
        }
    };
    let digest = crate::report::sha256_hex(&bytes);
    match archive_client::push(transport, config, key, &bytes, now) {
        Ok(filed) => Ok(Filing::Filed(filed)),
        Err(e) => {
            let reason = e.to_string();
            let entry = queue_filing(root, warrant_id, path, &digest, &reason, now)?;
            Ok(Filing::Queued { entry, reason })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pending_path_is_under_the_store_root() {
        assert_eq!(
            pending_path(Path::new("/warrantor")),
            PathBuf::from("/warrantor/archive/pending.jsonl")
        );
    }
}

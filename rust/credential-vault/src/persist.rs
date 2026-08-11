//! Durable revocation state for the credential vault (AX-40 / invariant I-05).
//!
//! # Why this module exists
//!
//! Before AX-40 the vault kept its revocation set in a process-global `Mutex<HashSet<String>>`
//! and nothing else. **Restarting the process un-revoked every revoked credential** — the kill
//! switch's "<1s revocation" guarantee (I-05) lasted exactly as long as the process did, and a
//! crash-loop was a credential-reinstatement machine.
//!
//! # Design
//!
//! An **append-only JSONL journal**, `fsync`'d before each mutation is acknowledged, replayed at
//! open. Same rationale as the flight recorder's evidence log: append-then-replay is the entire
//! access pattern, `fsync` on a regular file is the durability primitive, and the file stays
//! auditable with `cat`. Revocation is monotone — a revoked JTI is never un-revoked — so the log
//! never needs compaction for correctness.
//!
//! **Fail-closed ordering.** A revocation is applied to the in-memory set *before* the journal
//! write, and the journal error is still returned. A caller that ignores the error gets a vault
//! that over-revokes (safe); a caller that handles it knows durability was not achieved.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::CredentialError;

/// A mutation recorded in the revocation journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalOp {
    /// A credential was issued and is now tracked for revocation.
    Issued,
    /// A single credential was revoked.
    Revoked,
    /// Every currently-issued credential was revoked (kill-switch fan-out).
    RevokedAll,
}

/// One journal line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    /// What happened.
    pub op: JournalOp,
    /// The affected token id. Empty for [`JournalOp::RevokedAll`].
    #[serde(default)]
    pub jti: String,
    /// Epoch seconds at which the mutation was recorded.
    pub at: u64,
}

impl JournalRecord {
    /// Build a record stamped with the current time.
    #[must_use]
    pub fn now(op: JournalOp, jti: impl Into<String>) -> Self {
        Self {
            op,
            jti: jti.into(),
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

/// An append-only, `fsync`-per-write revocation journal.
#[derive(Debug)]
pub struct RevocationJournal {
    path: PathBuf,
    file: File,
}

impl RevocationJournal {
    /// Open (or create) the journal at `path` and replay it.
    ///
    /// Returns the journal handle plus the records already on disk, in order. A torn trailing
    /// record left by a crash is truncated away (with a warning); a malformed record anywhere
    /// else is a hard [`CredentialError::JournalCorrupt`].
    ///
    /// # Errors
    /// Returns [`CredentialError::Io`] on I/O failure or [`CredentialError::JournalCorrupt`] if
    /// the journal contains an unreadable record that is not a torn tail.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<(Self, Vec<JournalRecord>), CredentialError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|source| CredentialError::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
        }
        let (records, good_bytes, torn) = Self::replay(&path)?;
        if torn {
            eprintln!(
                "warrantor-credential-vault: WARNING torn trailing record in {} — truncating to \
                 {good_bytes} bytes ({} complete records recovered)",
                path.display(),
                records.len()
            );
            let f = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|source| CredentialError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
            f.set_len(good_bytes)
                .map_err(|source| CredentialError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
            f.sync_all().map_err(|source| CredentialError::Io {
                path: path.display().to_string(),
                source,
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| CredentialError::Io {
                path: path.display().to_string(),
                source,
            })?;
        Ok((Self { path, file }, records))
    }

    /// The journal's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a record and `fsync` before returning.
    ///
    /// # Errors
    /// Returns [`CredentialError::Io`] if the write or the `fsync` failed, or
    /// [`CredentialError::Encode`] if the record could not be serialized. Either way the mutation
    /// is **not** durable.
    pub fn append(&mut self, record: &JournalRecord) -> Result<(), CredentialError> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let io_err = |source: std::io::Error| CredentialError::Io {
            path: self.path.display().to_string(),
            source,
        };
        self.file.write_all(&line).map_err(io_err)?;
        self.file.flush().map_err(io_err)?;
        self.file.sync_all().map_err(io_err)?;
        Ok(())
    }

    /// Read every record currently in the journal at `path`.
    ///
    /// # Errors
    /// See [`RevocationJournal::open`].
    pub fn read_all<P: AsRef<Path>>(path: P) -> Result<Vec<JournalRecord>, CredentialError> {
        let (records, _, _) = Self::replay(path.as_ref())?;
        Ok(records)
    }

    fn replay(path: &Path) -> Result<(Vec<JournalRecord>, u64, bool), CredentialError> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Vec::new(), 0, false))
            }
            Err(source) => {
                return Err(CredentialError::Io {
                    path: path.display().to_string(),
                    source,
                })
            }
        };
        let total_len = file
            .metadata()
            .map_err(|source| CredentialError::Io {
                path: path.display().to_string(),
                source,
            })?
            .len();
        let mut raw: Vec<(String, u64)> = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|source| CredentialError::Io {
                path: path.display().to_string(),
                source,
            })?;
            let consumed = line.len() as u64 + 1;
            raw.push((line, consumed));
        }

        let mut records = Vec::new();
        let mut good_bytes: u64 = 0;
        let count = raw.len();
        for (idx, (line, consumed)) in raw.into_iter().enumerate() {
            if line.trim().is_empty() {
                good_bytes += consumed;
                continue;
            }
            match serde_json::from_str::<JournalRecord>(&line) {
                Ok(r) => {
                    good_bytes += consumed;
                    records.push(r);
                }
                Err(e) => {
                    if idx + 1 == count && good_bytes + consumed > total_len {
                        return Ok((records, good_bytes, true));
                    }
                    return Err(CredentialError::JournalCorrupt {
                        line: idx + 1,
                        detail: format!("record is not valid JSON: {e}"),
                    });
                }
            }
        }
        Ok((records, good_bytes, false))
    }
}

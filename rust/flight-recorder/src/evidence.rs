//! Durable, append-only evidence storage for Agent Action Receipts (AX-40 / invariant I-07).
//!
//! # Why this module exists
//!
//! Before AX-40 the flight recorder computed canonical evidence bytes, signed them, and then
//! handed the receipt back to the caller with **no write path to durable storage at all**. The
//! crate's own doc comment disclaimed the invariant it advertises ("the recorder does not enforce
//! persistence (that's the caller's job)"), which made **I-07 — the receipt is signed and durable
//! BEFORE the action commits — unimplementable as specified**.
//!
//! This module supplies the missing half.
//!
//! # Design (dependency-light on purpose)
//!
//! The store is a plain **append-only JSONL file**. One record per line, `fsync`'d with
//! [`std::fs::File::sync_all`] before the append is acknowledged. No embedded database is used:
//!
//! * The access pattern is strictly append-then-replay. There are no queries, no secondary
//!   indexes, no concurrent writers, and no updates or deletes — an evidence log that supports
//!   deletion is not evidence. Every feature `rusqlite`/`sled` would add is a feature this
//!   workload must not have.
//! * `fsync`-per-append on a regular file is exactly the durability primitive I-07 needs, and it
//!   is the same primitive an embedded database would ultimately call.
//! * A JSONL evidence file is externally auditable with `cat`/`jq` by a reviewer who does not
//!   have this crate — which matters for an evidence layer whose whole purpose is third-party
//!   verifiability.
//! * Fewer dependencies is a smaller supply-chain surface for a security-critical crate.
//!
//! Records are **hash-chained**: each record commits to the previous record's digest, mirroring
//! the P4 / `aumos-provena-chain` tamper-evidence design. Truncating or rewriting any record in
//! the middle of the log breaks the chain and is detected on load.
//!
//! # Crash recovery
//!
//! A process that dies mid-`write_all` can leave a torn final line. On load, a malformed
//! **trailing** record on a file that does not end in a newline is treated as a torn tail: the
//! file is truncated back to the last complete record and a warning is emitted. A malformed
//! record anywhere else is a hard [`RecorderError::ChainCorrupt`] — that is tampering, not a
//! crash.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Receipt, RecorderError};

/// The digest that precedes the first record in a chain (32 zero bytes, hex-encoded).
pub const GENESIS_DIGEST_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One durably-persisted evidence record: a receipt plus its position in the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Monotonic sequence number, starting at 0 for the first record in the log.
    pub seq: u64,
    /// The digest of the preceding record (or [`GENESIS_DIGEST_HEX`] for `seq == 0`).
    pub prev_digest_hex: String,
    /// This record's digest: `SHA-256(seq ‖ prev ‖ len‖canonical_bytes ‖ len‖signature_hex)`.
    pub digest_hex: String,
    /// The receipt this record makes durable.
    pub receipt: Receipt,
}

/// Compute a record's chain digest. Length-prefixed so the fields cannot be re-split (the same
/// framing rule [`Receipt::canonical_bytes`] uses).
#[must_use]
pub fn compute_record_digest(seq: u64, prev_digest: &[u8; 32], receipt: &Receipt) -> [u8; 32] {
    let payload = receipt.canonical_bytes();
    let sig = receipt.signature_hex.as_bytes();
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(prev_digest);
    h.update((payload.len() as u64).to_le_bytes());
    h.update(&payload);
    h.update((sig.len() as u64).to_le_bytes());
    h.update(sig);
    h.finalize().into()
}

fn decode_digest(hex_str: &str, seq: u64) -> Result<[u8; 32], RecorderError> {
    let bytes = hex::decode(hex_str).map_err(|e| RecorderError::ChainCorrupt {
        seq,
        detail: format!("digest is not hex: {e}"),
    })?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| RecorderError::ChainCorrupt {
            seq,
            detail: format!("digest must be 32 bytes, got {}", bytes.len()),
        })
}

/// An append-only evidence store.
///
/// **Contract**: [`EvidenceStore::append`] must not return `Ok` until the record is durable on
/// stable storage. An implementation that buffers, or that swallows an I/O error, breaks I-07.
pub trait EvidenceStore {
    /// Append `receipt` to the log and return the durable record.
    ///
    /// # Errors
    /// Returns [`RecorderError::Io`] if the write or the `fsync` failed, or
    /// [`RecorderError::Encode`] if the record could not be serialized. In either case the
    /// caller MUST treat the action as not-recorded and MUST NOT commit it.
    fn append(&mut self, receipt: &Receipt) -> Result<EvidenceRecord, RecorderError>;

    /// The sequence number the next appended record will receive.
    fn next_seq(&self) -> u64;

    /// The digest of the most recent record (or [`GENESIS_DIGEST_HEX`] if the log is empty).
    fn head_digest_hex(&self) -> String;
}

/// A durable, append-only, hash-chained evidence store backed by a JSONL file.
///
/// Every [`FileEvidenceStore::append`] performs `write_all` + `flush` + `sync_all` before
/// returning, so a record that has been acknowledged has reached stable storage.
#[derive(Debug)]
pub struct FileEvidenceStore {
    path: PathBuf,
    file: File,
    next_seq: u64,
    head: [u8; 32],
}

impl FileEvidenceStore {
    /// Open (or create) the evidence log at `path`, replaying and verifying the existing chain.
    ///
    /// A torn final record left by a crash is truncated (with a warning on stderr). Any other
    /// corruption is reported as [`RecorderError::ChainCorrupt`].
    ///
    /// # Errors
    /// Returns [`RecorderError::Io`] on I/O failure or [`RecorderError::ChainCorrupt`] if the
    /// existing log does not form a valid hash chain.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, RecorderError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|source| RecorderError::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
        }
        let (records, good_bytes, torn) = Self::replay(&path)?;
        if torn {
            eprintln!(
                "aumos-flight-recorder: WARNING torn trailing record in {} — truncating to \
                 {good_bytes} bytes (last complete record seq={})",
                path.display(),
                records.last().map_or(-1i64, |r| r.seq as i64)
            );
            let f = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|source| RecorderError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
            f.set_len(good_bytes).map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?;
            f.sync_all().map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?;
        }

        let next_seq = records.last().map_or(0, |r| r.seq + 1);
        let head = match records.last() {
            Some(r) => decode_digest(&r.digest_hex, r.seq)?,
            None => [0u8; 32],
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?;
        file.seek(SeekFrom::End(0))
            .map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?;

        Ok(Self {
            path,
            file,
            next_seq,
            head,
        })
    }

    /// Read and verify every record in the log at `path`.
    ///
    /// # Errors
    /// Returns [`RecorderError::Io`] on I/O failure or [`RecorderError::ChainCorrupt`] if the
    /// chain does not verify.
    pub fn read_all<P: AsRef<Path>>(path: P) -> Result<Vec<EvidenceRecord>, RecorderError> {
        let (records, _, _) = Self::replay(path.as_ref())?;
        Ok(records)
    }

    /// Read and verify every record in this store's log.
    ///
    /// # Errors
    /// See [`FileEvidenceStore::read_all`].
    pub fn records(&self) -> Result<Vec<EvidenceRecord>, RecorderError> {
        Self::read_all(&self.path)
    }

    /// The path this store appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The number of records currently in the log.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.next_seq
    }

    /// True iff the log has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }

    /// Replay the log, returning `(records, byte_offset_after_last_good_record, torn_tail)`.
    fn replay(path: &Path) -> Result<(Vec<EvidenceRecord>, u64, bool), RecorderError> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Vec::new(), 0, false))
            }
            Err(source) => {
                return Err(RecorderError::Io {
                    path: path.display().to_string(),
                    source,
                })
            }
        };
        let total_len = file
            .metadata()
            .map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?
            .len();
        let reader = BufReader::new(file);

        let mut records: Vec<EvidenceRecord> = Vec::new();
        let mut good_bytes: u64 = 0;
        let mut prev = [0u8; 32];
        let mut expected_seq: u64 = 0;
        let mut raw_lines: Vec<(String, u64)> = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?;
            // +1 for the newline the writer always appends.
            let consumed = line.len() as u64 + 1;
            raw_lines.push((line, consumed));
        }

        let line_count = raw_lines.len();
        for (idx, (line, consumed)) in raw_lines.into_iter().enumerate() {
            let is_last = idx + 1 == line_count;
            if line.trim().is_empty() {
                good_bytes += consumed;
                continue;
            }
            let parsed: Result<EvidenceRecord, _> = serde_json::from_str(&line);
            let record = match parsed {
                Ok(r) => r,
                Err(e) => {
                    // A torn tail can only be the last line, and only if the file does not end
                    // with the newline the writer always emits.
                    if is_last && good_bytes + consumed > total_len {
                        return Ok((records, good_bytes, true));
                    }
                    return Err(RecorderError::ChainCorrupt {
                        seq: expected_seq,
                        detail: format!("record is not valid JSON: {e}"),
                    });
                }
            };
            if record.seq != expected_seq {
                return Err(RecorderError::ChainCorrupt {
                    seq: record.seq,
                    detail: format!("out-of-order sequence: expected {expected_seq}"),
                });
            }
            let claimed_prev = decode_digest(&record.prev_digest_hex, record.seq)?;
            if claimed_prev != prev {
                return Err(RecorderError::ChainCorrupt {
                    seq: record.seq,
                    detail: format!(
                        "prev digest mismatch: record claims {}, chain head is {}",
                        record.prev_digest_hex,
                        hex::encode(prev)
                    ),
                });
            }
            let recomputed = compute_record_digest(record.seq, &prev, &record.receipt);
            let claimed = decode_digest(&record.digest_hex, record.seq)?;
            if recomputed != claimed {
                return Err(RecorderError::ChainCorrupt {
                    seq: record.seq,
                    detail: format!(
                        "digest mismatch: record claims {}, recomputed {} (record was altered)",
                        record.digest_hex,
                        hex::encode(recomputed)
                    ),
                });
            }
            prev = claimed;
            expected_seq = record.seq + 1;
            good_bytes += consumed;
            records.push(record);
        }
        Ok((records, good_bytes, false))
    }
}

impl EvidenceStore for FileEvidenceStore {
    fn append(&mut self, receipt: &Receipt) -> Result<EvidenceRecord, RecorderError> {
        let seq = self.next_seq;
        let digest = compute_record_digest(seq, &self.head, receipt);
        let record = EvidenceRecord {
            seq,
            prev_digest_hex: hex::encode(self.head),
            digest_hex: hex::encode(digest),
            receipt: receipt.clone(),
        };
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');

        let io_err = |source: std::io::Error| RecorderError::Io {
            path: self.path.display().to_string(),
            source,
        };
        self.file.write_all(&line).map_err(io_err)?;
        self.file.flush().map_err(io_err)?;
        // I-07: the append is not acknowledged until the bytes are on stable storage.
        self.file.sync_all().map_err(io_err)?;

        self.next_seq = seq + 1;
        self.head = digest;
        Ok(record)
    }

    fn next_seq(&self) -> u64 {
        self.next_seq
    }

    fn head_digest_hex(&self) -> String {
        hex::encode(self.head)
    }
}

/// An in-memory evidence store for tests and for callers that explicitly do not want durability.
///
/// **This store does not satisfy I-07.** It is named to make that obvious and it is never the
/// default anywhere in this crate.
#[derive(Debug, Default)]
pub struct NonDurableMemoryEvidenceStore {
    records: Vec<EvidenceRecord>,
    head: [u8; 32],
}

impl NonDurableMemoryEvidenceStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The records appended so far.
    #[must_use]
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }
}

impl EvidenceStore for NonDurableMemoryEvidenceStore {
    fn append(&mut self, receipt: &Receipt) -> Result<EvidenceRecord, RecorderError> {
        let seq = self.records.len() as u64;
        let digest = compute_record_digest(seq, &self.head, receipt);
        let record = EvidenceRecord {
            seq,
            prev_digest_hex: hex::encode(self.head),
            digest_hex: hex::encode(digest),
            receipt: receipt.clone(),
        };
        self.head = digest;
        self.records.push(record.clone());
        Ok(record)
    }

    fn next_seq(&self) -> u64 {
        self.records.len() as u64
    }

    fn head_digest_hex(&self) -> String {
        hex::encode(self.head)
    }
}

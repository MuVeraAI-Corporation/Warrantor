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
//! the P4 / `warrantor-provena-chain` tamper-evidence design. Truncating or rewriting any record in
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
use std::io::{BufReader, Seek, SeekFrom, Write};
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
    /// Held for the store's lifetime purely for its lock; dropping it releases the lock.
    _lock_file: File,
}

/// Suffix of the sidecar lock file that guards an evidence log.
const LOCK_SUFFIX: &str = ".lock";

impl FileEvidenceStore {
    /// Take the exclusive lock that makes this store the log's only writer.
    ///
    /// Without it, two recorders over one path each cached their own `next_seq` and `head` at
    /// open time, so both assigned the SAME seq to different records and both returned a
    /// durability proof. Each caller then committed its side effect believing the record was
    /// durable, while the log ended up with a duplicated sequence number -- after which every
    /// subsequent read failed with `ChainCorrupt`, including for the record that had been written
    /// correctly. An evidence log that acknowledges a write and then destroys itself is worse
    /// than one that refuses to open.
    ///
    /// The lock lives in a sidecar `<path>.lock` rather than on the log itself, because Windows
    /// file locks are mandatory: locking the log would block this process's own readers
    /// (`records()` opens its own handle) as well as any external auditor running `jq` over the
    /// file. The evidence log must stay readable by anyone at any time -- that is the point of it.
    ///
    /// The OS holds the lock against the open file description, so this also catches two stores
    /// in the same process, not just two processes. Dropping the store closes the handle and
    /// releases the lock.
    fn acquire_lock(path: &Path) -> Result<File, RecorderError> {
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(LOCK_SUFFIX);
        let lock_path = PathBuf::from(lock_path);

        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| RecorderError::Io {
                path: lock_path.display().to_string(),
                source,
            })?;

        // fs4 1.x renamed the advisory-lock methods: `try_lock_exclusive` became `try_lock`,
        // exclusive by default — which is what this always wanted. Same OS-level lock, same
        // open-file-description semantics the doc comment above relies on.
        lock_file.try_lock().map_err(|source| RecorderError::Io {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "evidence log {} is already open by another flight recorder \
                         (lock held on {}); two recorders sharing one log assign the same \
                         sequence number to different records and corrupt the chain: {source}",
                    path.display(),
                    lock_path.display()
                ),
            ),
        })?;

        Ok(lock_file)
    }

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
                "warrantor-flight-recorder: WARNING torn trailing record in {} — truncating to \
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

        let lock_file = Self::acquire_lock(&path)?;

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
            _lock_file: lock_file,
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
        let mut reader = BufReader::new(file);

        let mut records: Vec<EvidenceRecord> = Vec::new();
        let mut good_bytes: u64 = 0;
        let mut prev = [0u8; 32];
        let mut expected_seq: u64 = 0;
        let mut raw_lines: Vec<(String, u64)> = Vec::new();

        // Read as BYTES and decode each line individually.
        //
        // `reader.lines()` fails the whole read with io::ErrorKind::InvalidData the moment any
        // byte sequence is not valid UTF-8, which surfaced as RecorderError::Io -- the variant
        // reserved for device and permission failures. But a flipped byte in an append-only
        // evidence log is not an I/O fault, it is tampering or corruption, and reporting it as
        // Io meant the one signal this component exists to raise was indistinguishable from a
        // failing disk. Decoding per line lets a bad line be reported as ChainCorrupt, with the
        // sequence number of the record it belongs to.
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut raw).map_err(|source| RecorderError::Io {
            path: path.display().to_string(),
            source,
        })?;

        for (index, chunk) in raw.split(|byte| *byte == b'\n').enumerate() {
            // `split` yields a trailing empty chunk when the data ends with a newline; the
            // torn-tail check below is what distinguishes "ended cleanly" from "was truncated".
            if chunk.is_empty() && index == raw.split(|b| *b == b'\n').count() - 1 {
                continue;
            }
            let line = match std::str::from_utf8(chunk) {
                Ok(text) => text.to_string(),
                Err(error) => {
                    return Err(RecorderError::ChainCorrupt {
                        seq: index as u64,
                        detail: format!(
                            "record is not valid UTF-8 at byte {} of the line: {error}",
                            error.valid_up_to()
                        ),
                    });
                }
            };
            // +1 for the newline the writer always appends.
            let consumed = line.len() as u64 + 1;
            raw_lines.push((line, consumed));
        }

        // Does the file end with the newline the writer always emits?
        //
        // This is the only reliable torn-tail signal, and byte arithmetic cannot substitute
        // for it: `consumed` above adds 1 for a newline unconditionally, so a file missing
        // its final newline yields good_bytes == the length it WOULD have had. Comparing
        // good_bytes to total_len therefore either matches (hiding the tear) or overshoots
        // (making the truncation target longer than the file).
        //
        // Previously the torn-tail check lived only inside the JSON-parse-failure arm, so a
        // final record that parsed cleanly but lost its newline was accepted -- and the next
        // append concatenated onto it, producing `}{` on one line. The chain then broke at a
        // record the writer had never touched, blaming the wrong one.
        let ends_with_newline = total_len == 0 || {
            let mut f = File::open(path).map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?;
            f.seek(SeekFrom::End(-1))
                .map_err(|source| RecorderError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
            let mut last = [0u8; 1];
            std::io::Read::read_exact(&mut f, &mut last).map_err(|source| RecorderError::Io {
                path: path.display().to_string(),
                source,
            })?;
            last[0] == b'\n'
        };

        let line_count = raw_lines.len();
        for (idx, (line, consumed)) in raw_lines.into_iter().enumerate() {
            let is_last = idx + 1 == line_count;
            // A final line with no terminating newline is a partial write, whatever it
            // parses as. Stop here: `good_bytes` is the offset of the last COMPLETE record,
            // which is exactly what open() truncates to.
            if is_last && !ends_with_newline {
                return Ok((records, good_bytes, true));
            }
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

#[cfg(test)]
mod torn_tail {
    use super::*;
    use crate::{FlightRecorder, ReceiptInput};

    fn input(n: u8) -> ReceiptInput {
        ReceiptInput {
            actor: format!("spiffe://muveraai.com/agent/{n}"),
            authority_hash_hex: "ab".repeat(32),
            tool_or_api_op: "deploy".into(),
            context_commitment_hex: "cd".repeat(32),
        }
    }

    /// A last record that PARSES but lost its terminating newline is a partial write.
    ///
    /// Accepting it meant the next append concatenated onto it (`}{` on one line), which
    /// corrupted the chain permanently -- and the error surfaced later at a record the
    /// writer had not touched, blaming the wrong one.
    #[test]
    fn a_log_missing_its_final_newline_is_treated_as_torn() {
        let dir = std::env::temp_dir().join(format!("warrantor-torn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("evidence.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut recorder = FlightRecorder::new();
        {
            let mut store = FileEvidenceStore::open(&path).expect("open");
            for n in 0..3u8 {
                let receipt = recorder.emit_pending(input(n)).expect("emit");
                store.append(&receipt).expect("append");
            }
        }

        // Simulate the interrupted write: drop the trailing newline only.
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(
            bytes.last(),
            Some(&b'\n'),
            "writer should terminate records"
        );
        std::fs::write(&path, &bytes[..bytes.len() - 1]).expect("truncate newline");

        // Reopening must NOT silently accept the tail; it is a partial record.
        let store = FileEvidenceStore::open(&path).expect("reopen");
        assert_eq!(
            store.len(),
            2,
            "the unterminated final record must be treated as torn and dropped, \
             leaving 2 whole records -- accepting it corrupts the next append"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The ordinary case must be unaffected: a properly terminated log keeps every record.
    #[test]
    fn a_well_formed_log_keeps_every_record() {
        let dir = std::env::temp_dir().join(format!("warrantor-whole-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("evidence.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut recorder = FlightRecorder::new();
        {
            let mut store = FileEvidenceStore::open(&path).expect("open");
            for n in 0..3u8 {
                let receipt = recorder.emit_pending(input(n)).expect("emit");
                store.append(&receipt).expect("append");
            }
        }
        let store = FileEvidenceStore::open(&path).expect("reopen");
        assert_eq!(store.len(), 3, "a complete log must keep all records");

        let _ = std::fs::remove_file(&path);
    }
}

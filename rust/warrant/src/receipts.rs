//! The per-effect receipt log: a pre-commit receipt before every performed effect, a post-commit
//! after it (I-07), in an append-only, `fsync`'d JSONL file the settle process writes and the
//! report reads.
//!
//! It lives in `receipts/<id>.jsonl`, beside neither `staged/` nor `witness/`, for the same reason
//! `witness/` is not under `staged/`: one `rm` must not take the record of what was performed
//! along with the record of what was queued. This is not an external recorder — L7-02 wants the
//! log outside the agent's write authority, and this file is on the same disk as everything else.
//! What it is: the first consumer of the evidence crate on the settle path, and the bytes the
//! archive push and the export carry. The limitations on every report say the rest.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use warrantor_evidence as evidence;

use crate::settle::ReceiptSink;
use crate::WarrantError;

/// Wire format of one line of the log.
pub const RECEIPT_LOG_FORMAT: &str = "warrantor.effect-receipts/1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LogLine {
    format: String,
    receipt: evidence::WarReceipt,
}

/// The receipts one warrant's settles have issued, in issuance order.
#[derive(Debug)]
pub struct ReceiptLog {
    path: PathBuf,
    receipts: Vec<evidence::WarReceipt>,
}

impl ReceiptLog {
    /// Open (or lazily create) the log at `path`, replaying and signature-checking every line.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] when a line is not this format or its signature does not verify —
    /// an edited receipt is refused at open, not discovered at export.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WarrantError> {
        let path = path.as_ref().to_path_buf();
        let mut receipts = Vec::new();
        if path.exists() {
            let body = std::fs::read_to_string(&path)
                .map_err(|e| WarrantError::Encode(format!("read receipt log: {e}")))?;
            for (number, line) in body.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let parsed: LogLine = serde_json::from_str(line).map_err(|e| {
                    WarrantError::Invalid(format!("receipt log line {}: {e}", number + 1))
                })?;
                if parsed.format != RECEIPT_LOG_FORMAT {
                    return Err(WarrantError::Invalid(format!(
                        "receipt log line {} declares {:?}; this build writes {RECEIPT_LOG_FORMAT}",
                        number + 1,
                        parsed.format
                    )));
                }
                evidence::verify_receipt(&parsed.receipt).map_err(|e| {
                    WarrantError::Invalid(format!(
                        "receipt log line {} does not verify: {e}",
                        number + 1
                    ))
                })?;
                receipts.push(parsed.receipt);
            }
        }
        Ok(Self { path, receipts })
    }

    /// Append one receipt and `fsync` before returning: the caller performs a side effect on the
    /// strength of this returning `Ok`.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] on any I/O failure. The caller must treat that as "do not perform".
    pub fn append(&mut self, receipt: &evidence::WarReceipt) -> Result<(), WarrantError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WarrantError::Encode(format!("create receipts dir: {e}")))?;
        }
        let line = serde_json::to_string(&LogLine {
            format: RECEIPT_LOG_FORMAT.to_string(),
            receipt: receipt.clone(),
        })
        .map_err(|e| WarrantError::Encode(format!("encode receipt: {e}")))?;
        let mut file: File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| WarrantError::Encode(format!("open receipt log: {e}")))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|e| WarrantError::Encode(format!("append receipt log: {e}")))?;
        self.receipts.push(receipt.clone());
        Ok(())
    }

    /// Every receipt, in issuance order.
    #[must_use]
    pub fn receipts(&self) -> &[evidence::WarReceipt] {
        &self.receipts
    }

    /// How many receipts the log holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the log holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}

impl ReceiptSink for ReceiptLog {
    fn record(&mut self, receipt: &evidence::WarReceipt) -> Result<(), String> {
        self.append(receipt).map_err(|e| e.to_string())
    }
}

/// One effect's chain: the pre-commit, and the post-commit if one was issued.
///
/// A pre-commit with no post-commit is a real state — the process died between the receipt and
/// the outcome — and it is reported as such, never dropped and never paired with a stranger.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectChain {
    /// Signed before the effect was attempted.
    pub pre_commit: evidence::WarReceipt,
    /// Signed after, carrying the outcome. `None` if the log ends between the two.
    pub post_commit: Option<evidence::WarReceipt>,
}

/// Pair pre-commits with the post-commits that name them, in pre-commit order.
#[must_use]
pub fn chains(receipts: &[evidence::WarReceipt]) -> Vec<EffectChain> {
    receipts
        .iter()
        .filter(|r| r.predicate.binding.phase == evidence::Phase::PreCommit)
        .map(|pre| {
            let id = &pre.predicate.binding.receipt_id;
            let post = receipts.iter().find(|r| {
                r.predicate.binding.phase == evidence::Phase::PostCommit
                    && r.predicate.binding.parent_receipt.as_deref() == Some(id.as_str())
            });
            EffectChain {
                pre_commit: pre.clone(),
                post_commit: post.cloned(),
            }
        })
        .collect()
}

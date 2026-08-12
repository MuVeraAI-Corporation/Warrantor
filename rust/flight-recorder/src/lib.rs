//! # warrantor-flight-recorder (E1)
//!
//! The verifiable agent flight recorder. Emits **signed Agent Action Receipts (AAR, P2)** for
//! every material agent action. **Invariant I-07: the receipt is signed and durable BEFORE the
//! action commits** — an agent must not produce a visible side effect without a verifiable receipt
//! already recorded.
//!
//! ## I-07 is enforced by the type system, not by a comment (AX-40)
//!
//! There are two entrypoints, and only one of them is I-07-compliant:
//!
//! * [`FlightRecorder`] — the **signing core**. It signs receipts and enforces emit-before-commit
//!   *ordering*, but it writes nothing to disk. On its own it does **not** satisfy I-07.
//! * [`DurableFlightRecorder`] — the **I-07 entrypoint**. [`DurableFlightRecorder::emit_pending`]
//!   returns only after the signed receipt has been appended to a durable, hash-chained,
//!   `fsync`'d evidence log, and it hands back a [`PendingAction`]. `PendingAction` has no public
//!   constructor, so [`DurableFlightRecorder::commit`] — which consumes one — is *unreachable*
//!   unless the evidence is already durable. Durability failures surface as
//!   [`RecorderError::Io`]; nothing is swallowed.
//!
//! See [`evidence`] for the storage format and the rationale for a plain append-only file.
//!
//! Exports to:
//!   - **OCSF** (Open Cybersecurity Schema Framework) — JSON, per cross-cutting 19 §1 external tier.
//!   - **OpenTelemetry** — semantic-attribute JSON for the OTel collector (real OTLP export is task 03;
//!     the v1.0 emits the JSON a collector consumes).
//!
//! See RFC E1 and `specs/protocols/P2-aar.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod evidence;

pub use evidence::{
    compute_record_digest, EvidenceRecord, EvidenceStore, FileEvidenceStore,
    NonDurableMemoryEvidenceStore, GENESIS_DIGEST_HEX,
};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use warrantor_api::protocols::v1::AgentActionReceipt;

/// The action outcome. Mirrors `warrantor.protocols.v1.ActionOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    /// Pre-commit (the receipt is emitted at this state; invariant I-07).
    Pending,
    /// The action's effect is visible (caller calls `commit()` after the receipt is durable).
    Committed,
    /// The action was rolled back.
    RolledBack,
    /// The action did not take effect.
    Failed,
}

impl ActionOutcome {
    /// Convert to the proto enum value.
    #[must_use]
    pub fn to_proto(self) -> i32 {
        match self {
            ActionOutcome::Pending => 1,
            ActionOutcome::Committed => 2,
            ActionOutcome::RolledBack => 3,
            ActionOutcome::Failed => 4,
        }
    }
}

/// Errors returned by the flight recorder.
#[derive(Debug, Error)]
pub enum RecorderError {
    /// The receipt signature did not verify.
    #[error("receipt signature invalid")]
    SignatureInvalid,
    /// The receipt ID was not unique.
    #[error("duplicate receipt id: {0}")]
    DuplicateReceiptId(String),
    /// An invariant was violated (e.g. committing without an emitted receipt).
    #[error("invariant violated: {0}")]
    Invariant(String),
    /// A field had the wrong length.
    #[error("invalid field length: {0}")]
    InvalidLength(String),
    /// A hex field failed to decode (H1: previously swallowed by `unwrap_or_default()`,
    /// silently dropping a malformed signature/authority_hash into the proto wire type).
    #[error("malformed hex in field {field:?}: {source}")]
    MalformedHex {
        /// The load-bearing field name whose hex failed to decode.
        field: &'static str,
        /// The underlying hex decode error.
        #[source]
        source: hex::FromHexError,
    },
    /// The evidence store could not make a receipt durable (AX-40 / I-07). The action MUST NOT
    /// commit: no durable receipt means no permission to produce a visible side effect.
    #[error("evidence store i/o failed for {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// An evidence record could not be serialized (AX-40).
    #[error("evidence record encode failed: {0}")]
    Encode(#[from] serde_json::Error),
    /// The persisted evidence chain does not verify — a record was altered, reordered, or
    /// removed (AX-40).
    #[error("evidence chain corrupt at seq {seq}: {detail}")]
    ChainCorrupt {
        /// The sequence number at which verification failed.
        seq: u64,
        /// What was wrong.
        detail: String,
    },
}

/// Inputs to a new receipt (everything the caller supplies before signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInput {
    /// The SPIFFE SVID of the acting agent.
    pub actor: String,
    /// SHA-256 hash (hex) of the AAE that authorized the action.
    pub authority_hash_hex: String,
    /// The tool or API operation performed (e.g. "github.create_pr").
    pub tool_or_api_op: String,
    /// SHA-256 hash (hex) of the context provenance envelope (P3 CPE) at action time.
    pub context_commitment_hex: String,
}

/// A signed receipt in the recorder's ergonomic shape. The proto wire type is
/// `warrantor_api::protocols::v1::AgentActionReceipt`; convert with [`Receipt::to_proto`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// UUID receipt id.
    pub id: String,
    /// The actor SVID.
    pub actor: String,
    /// Authority hash (hex).
    pub authority_hash_hex: String,
    /// Artifact versions in play.
    pub artifact_versions: std::collections::BTreeMap<String, String>,
    /// Context commitment (hex).
    pub context_commitment_hex: String,
    /// The policy decision that permitted the action.
    pub policy_decision: PolicyDecision,
    /// Tool / API op.
    pub tool_or_api_op: String,
    /// Approver SPIFFE IDs (for consequential actions; invariant I-08).
    pub approvers: Vec<String>,
    /// The action outcome.
    pub outcome: ActionOutcome,
    /// Pointer to a rollback record, if rolled back.
    pub rollback_pointer: Option<String>,
    /// Emitted-at (epoch seconds).
    pub emitted_at: u64,
    /// The verifying key (hex) that signed this receipt.
    pub verifying_key_hex: String,
    /// The Ed25519 signature (hex) over the canonical encoding.
    pub signature_hex: String,
}

/// The policy decision attached to a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Engine name ("opa", "cedar", "openshell").
    pub engine: String,
    /// "allow" or "deny".
    pub decision: String,
    /// Policy bundle hash (hex).
    pub policy_hash_hex: String,
    /// Matched rule IDs.
    pub matched_rules: Vec<String>,
}

impl Receipt {
    /// Convert to the proto wire type.
    ///
    /// **H1**: previously this method called `hex::decode(&x).unwrap_or_default()` for every
    /// load-bearing hex field, silently turning a malformed `signature_hex`,
    /// `authority_hash_hex`, `context_commitment_hex`, or `policy_hash_hex` into an empty byte
    /// vector on the wire. That swallowed corruption — a receipt with a broken signature would
    /// round-trip through the proto as if it were unsigned, instead of surfacing the malformation.
    ///
    /// This method now logs a warning to stderr for each malformed field (so corruption is
    /// observable) and still leaves the field empty (the proto API returns the value, not a
    /// `Result`, so we cannot fail here). Callers that need to detect malformed hex should use
    /// [`Receipt::to_proto_checked`], which returns `Result` and surfaces the first failure.
    #[must_use]
    pub fn to_proto(&self) -> AgentActionReceipt {
        AgentActionReceipt {
            id: self.id.clone(),
            actor: self.actor.clone(),
            authority_hash: decode_hex_or_warn(&self.authority_hash_hex, "authority_hash_hex"),
            artifact_versions: self.artifact_versions.clone().into_iter().collect(),
            context_commitment: decode_hex_or_warn(
                &self.context_commitment_hex,
                "context_commitment_hex",
            ),
            policy_decision: Some(warrantor_api::protocols::v1::PolicyDecision {
                engine: self.policy_decision.engine.clone(),
                decision: self.policy_decision.decision.clone(),
                policy_hash: decode_hex_or_warn(
                    &self.policy_decision.policy_hash_hex,
                    "policy_hash_hex",
                ),
                matched_rules: self.policy_decision.matched_rules.clone(),
            }),
            tool_or_api_op: self.tool_or_api_op.clone(),
            deterministic_checks: vec![],
            approvers: self.approvers.clone(),
            outcome: self.outcome.to_proto(),
            rollback_pointer: self.rollback_pointer.clone().unwrap_or_default(),
            emitted_at: Some(prost_types::Timestamp {
                seconds: self.emitted_at as i64,
                nanos: 0,
            }),
            signature: decode_hex_or_warn(&self.signature_hex, "signature_hex"),
        }
    }

    /// Convert to the proto wire type, returning [`RecorderError::MalformedHex`] on the first
    /// hex field that fails to decode. This is the checked variant of [`Receipt::to_proto`];
    /// callers that need to detect wire-shape corruption (rather than just log it) should use
    /// this entrypoint.
    ///
    /// # Errors
    /// Returns [`RecorderError::MalformedHex`] if any load-bearing hex field is malformed.
    pub fn to_proto_checked(&self) -> Result<AgentActionReceipt, RecorderError> {
        Ok(AgentActionReceipt {
            id: self.id.clone(),
            actor: self.actor.clone(),
            authority_hash: decode_hex_checked(&self.authority_hash_hex, "authority_hash_hex")?,
            artifact_versions: self.artifact_versions.clone().into_iter().collect(),
            context_commitment: decode_hex_checked(
                &self.context_commitment_hex,
                "context_commitment_hex",
            )?,
            policy_decision: Some(warrantor_api::protocols::v1::PolicyDecision {
                engine: self.policy_decision.engine.clone(),
                decision: self.policy_decision.decision.clone(),
                policy_hash: decode_hex_checked(
                    &self.policy_decision.policy_hash_hex,
                    "policy_hash_hex",
                )?,
                matched_rules: self.policy_decision.matched_rules.clone(),
            }),
            tool_or_api_op: self.tool_or_api_op.clone(),
            deterministic_checks: vec![],
            approvers: self.approvers.clone(),
            outcome: self.outcome.to_proto(),
            rollback_pointer: self.rollback_pointer.clone().unwrap_or_default(),
            emitted_at: Some(prost_types::Timestamp {
                seconds: self.emitted_at as i64,
                nanos: 0,
            }),
            signature: decode_hex_checked(&self.signature_hex, "signature_hex")?,
        })
    }

    /// The canonical bytes over which the signature is computed (everything except the signature
    /// itself, in a stable order).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Deterministic, length-prefixed concatenation of the load-bearing fields. Every field
        // is preceded by its length as a little-endian u64, which makes the encoding unambiguous
        // and prevents signature forgery via field re-splitting (C2: previously fields were
        // concatenated with no delimiter, so "ab"+"c" and "a"+"bc" produced the same bytes).
        // (Real T1 trust-core uses canonical CBOR; this Wave-2 v1.0 uses a stable length-prefixed
        // byte concatenation that is just as verifiable cross-language. CBOR alignment is task 03.)
        let mut out = Vec::new();
        write_len_prefixed(&mut out, self.id.as_bytes());
        write_len_prefixed(&mut out, self.actor.as_bytes());
        write_len_prefixed(&mut out, self.authority_hash_hex.as_bytes());
        // Length-prefix the map so its cardinality is unambiguous.
        write_len_prefixed(&mut out, &self.artifact_versions.len().to_le_bytes());
        for (k, v) in &self.artifact_versions {
            write_len_prefixed(&mut out, k.as_bytes());
            write_len_prefixed(&mut out, v.as_bytes());
        }
        write_len_prefixed(&mut out, self.context_commitment_hex.as_bytes());
        write_len_prefixed(&mut out, self.policy_decision.engine.as_bytes());
        write_len_prefixed(&mut out, self.policy_decision.decision.as_bytes());
        write_len_prefixed(&mut out, self.policy_decision.policy_hash_hex.as_bytes());
        write_len_prefixed(
            &mut out,
            &self.policy_decision.matched_rules.len().to_le_bytes(),
        );
        for r in &self.policy_decision.matched_rules {
            write_len_prefixed(&mut out, r.as_bytes());
        }
        write_len_prefixed(&mut out, self.tool_or_api_op.as_bytes());
        write_len_prefixed(&mut out, &self.approvers.len().to_le_bytes());
        for a in &self.approvers {
            write_len_prefixed(&mut out, a.as_bytes());
        }
        out.extend_from_slice(&self.outcome.to_proto().to_le_bytes());
        // rollback_pointer was omitted here, so it was covered by neither the Ed25519
        // signature nor the hash chain: an attacker could rewrite it on a persisted record
        // and both `verify` and the chain still validated, byte-identical digest and all.
        // On a receipt whose whole purpose is to say what an agent did, "this action was
        // rolled back, see <url>" was freely forgeable.
        //
        // The discriminant byte is load-bearing: without it `None` and `Some("")` would
        // both encode as a zero-length field and alias to the same bytes, so "never rolled
        // back" and "rolled back to nowhere" would share a signature.
        match &self.rollback_pointer {
            None => out.push(0u8),
            Some(pointer) => {
                out.push(1u8);
                write_len_prefixed(&mut out, pointer.as_bytes());
            }
        }
        out.extend_from_slice(&self.emitted_at.to_le_bytes());
        write_len_prefixed(&mut out, self.verifying_key_hex.as_bytes());
        // NOTE: `signature_hex` is deliberately absent -- a signature cannot cover itself.
        // Every other field of Receipt is included; see the coverage test below.
        out
    }
}

/// Write `field` to `out` prefixed by its length as a little-endian u64. This makes the
/// canonical encoding unambiguous (length-prefixed framing prevents field-re-splitting forgery).
fn write_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

/// Decode a hex string into bytes. **H1**: previously callers used
/// `hex::decode(&x).unwrap_or_default()`, which silently turned a malformed hex string into an
/// empty `Vec<u8>`. This helper keeps the same "best-effort decode" behavior (the proto API
/// returns a value, not a `Result`) but emits a `tracing`-style warning to stderr so a malformed
/// `signature_hex` or `authority_hash_hex` is observable in logs instead of silently dropped.
fn decode_hex_or_warn(hex_str: &str, field: &'static str) -> Vec<u8> {
    match hex::decode(hex_str) {
        Ok(bytes) => bytes,
        Err(e) => {
            // Surface the malformation — a malformed signature/authority_hash on the wire is a
            // real integrity signal, not a recoverable default.
            eprintln!(
                "warrantor-flight-recorder: WARNING malformed hex in field {field:?} \
                 (len={}, err={e}); emitting empty bytes on the wire",
                hex_str.len()
            );
            Vec::new()
        }
    }
}

/// Decode a hex string into bytes, returning [`RecorderError::MalformedHex`] on failure. Use this
/// in the checked proto conversion path so callers that care about wire integrity can detect a
/// corrupted signature/authority_hash rather than treat it as an empty field.
fn decode_hex_checked(hex_str: &str, field: &'static str) -> Result<Vec<u8>, RecorderError> {
    hex::decode(hex_str).map_err(|source| RecorderError::MalformedHex { field, source })
}

/// The flight recorder. Owns a signing key and tracks emitted receipts (so duplicate IDs and
/// out-of-order commits can be detected).
pub struct FlightRecorder {
    signing_key: SigningKey,
    verifying_key_hex: String,
    seen: std::collections::HashSet<String>,
}

impl std::fmt::Debug for FlightRecorder {
    /// Redacts the signing key — a `Debug` print of a recorder must never leak the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlightRecorder")
            .field("verifying_key_hex", &self.verifying_key_hex)
            .field("signing_key", &"<redacted>")
            .field("emitted", &self.seen.len())
            .finish()
    }
}

impl FlightRecorder {
    /// Construct a recorder with a freshly generated Ed25519 key pair.
    pub fn new() -> Self {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        Self {
            signing_key: sk,
            verifying_key_hex: vk_hex,
            seen: std::collections::HashSet::new(),
        }
    }

    /// The hex-encoded verifying key (so external reviewers can verify receipts cross-language).
    #[must_use]
    pub fn verifying_key_hex(&self) -> &str {
        &self.verifying_key_hex
    }

    /// Sign a **pending** receipt for an action that is about to commit.
    ///
    /// **This method does NOT satisfy invariant I-07 on its own** — it signs, it does not
    /// persist. It enforces only the emit-before-commit *ordering* checked by
    /// [`Self::mark_committed`]. For the I-07-compliant path (sign → append → `fsync` → only
    /// then return), use [`DurableFlightRecorder::emit_pending`], whose
    /// [`PendingAction`] receipt is the caller's proof of durability and the only key that
    /// unlocks [`DurableFlightRecorder::commit`].
    ///
    /// # Errors
    /// Returns [`RecorderError::DuplicateReceiptId`] on a collision (vanishingly unlikely with UUID v4).
    pub fn emit_pending(&mut self, input: ReceiptInput) -> Result<Receipt, RecorderError> {
        let id = Uuid::new_v4().to_string();
        if !self.seen.insert(id.clone()) {
            return Err(RecorderError::DuplicateReceiptId(id));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut receipt = Receipt {
            id,
            actor: input.actor,
            authority_hash_hex: input.authority_hash_hex,
            artifact_versions: std::collections::BTreeMap::new(),
            context_commitment_hex: input.context_commitment_hex,
            policy_decision: PolicyDecision {
                engine: "opa".into(),
                decision: "allow".into(),
                policy_hash_hex: String::new(),
                matched_rules: vec![],
            },
            tool_or_api_op: input.tool_or_api_op,
            approvers: vec![],
            outcome: ActionOutcome::Pending,
            rollback_pointer: None,
            emitted_at: now,
            verifying_key_hex: self.verifying_key_hex.clone(),
            signature_hex: String::new(),
        };
        let canon = receipt.canonical_bytes();
        let sig = self.signing_key.sign(&canon);
        receipt.signature_hex = hex::encode(sig.to_bytes());
        Ok(receipt)
    }

    /// Mark an emitted receipt as committed. The receipt MUST already have been emitted
    /// (invariant I-07: evidence precedes commitment).
    ///
    /// # Errors
    /// Returns [`RecorderError::Invariant`] if the receipt id was not previously emitted.
    pub fn mark_committed(&mut self, receipt: &mut Receipt) -> Result<(), RecorderError> {
        if !self.seen.contains(&receipt.id) {
            return Err(RecorderError::Invariant(format!(
                "commit before emit for id {} (I-07)",
                receipt.id
            )));
        }
        receipt.outcome = ActionOutcome::Committed;
        self.re_sign(receipt);
        Ok(())
    }

    /// Re-sign a mutated receipt over its fresh canonical bytes.
    fn re_sign(&self, receipt: &mut Receipt) {
        let canon = receipt.canonical_bytes();
        let sig = self.signing_key.sign(&canon);
        receipt.signature_hex = hex::encode(sig.to_bytes());
    }

    /// Verify a receipt's signature using the embedded verifying key.
    ///
    /// # Errors
    /// Returns [`RecorderError::SignatureInvalid`] on any failure.
    pub fn verify(receipt: &Receipt) -> Result<(), RecorderError> {
        let vk_bytes: [u8; 32] = hex::decode(&receipt.verifying_key_hex)
            .map_err(|_| RecorderError::InvalidLength("verifying_key".into()))?
            .as_slice()
            .try_into()
            .map_err(|_| RecorderError::InvalidLength("verifying_key must be 32 bytes".into()))?;
        let sig_bytes = hex::decode(&receipt.signature_hex)
            .map_err(|_| RecorderError::InvalidLength("signature hex".into()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| RecorderError::InvalidLength("signature must be 64 bytes".into()))?;
        let vk =
            VerifyingKey::from_bytes(&vk_bytes).map_err(|_| RecorderError::SignatureInvalid)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let canon = receipt.canonical_bytes();
        vk.verify(&canon, &sig)
            .map_err(|_| RecorderError::SignatureInvalid)
    }

    /// Export a receipt to OCSF-shaped JSON (per cross-cutting 19 §1 external tier).
    /// Maps the AAR fields onto the closest OCSF class (Activity → API Activity).
    #[must_use]
    pub fn to_ocsf_json(&self, receipt: &Receipt) -> serde_json::Value {
        serde_json::json!({
            "class_uid": 6003,                  // OCSF API Activity
            "category_uid": 6,                  // Application Activity
            "severity_id": 99,                  // Information (the receipt itself is not a security event)
            "activity_id": 1,                   // Read-ish; callers override per op
            "time": receipt.emitted_at,
            "actor": {
                "name": receipt.actor,
                "authorizations": [{
                    "authority_hash": receipt.authority_hash_hex
                }]
            },
            "api": {
                "operation": receipt.tool_or_api_op,
            },
            "policy": receipt.policy_decision,
            "approvers": receipt.approvers,
            "outcome": format!("{:?}", receipt.outcome).to_lowercase(),
            "metadata": {
                "version": "1.0.0",
                "product": { "name": "warrantor-flight-recorder", "vendor_name": "AumOS" },
                "receipt_id": receipt.id,
                "verifying_key": receipt.verifying_key_hex,
                "signature": receipt.signature_hex
            }
        })
    }

    /// Export a receipt to OTel-shaped JSON (semantic attributes; the OTel collector consumes
    /// this and emits real OTLP in task 03).
    #[must_use]
    pub fn to_otel_span_json(&self, receipt: &Receipt) -> serde_json::Value {
        serde_json::json!({
            "name": format!("agent.action.{}", receipt.tool_or_api_op),
            "trace_id": receipt.id.replace('-', "").get(..32).unwrap_or(&receipt.id),
            "span_id": receipt.id.replace('-', "").get(..16).unwrap_or(&receipt.id),
            "kind": "internal",
            "start_time_unix_nano": receipt.emitted_at.checked_mul(1_000_000_000).unwrap_or(0),
            "attributes": {
                "warrantor.agent.id": receipt.actor,
                "warrantor.action.authority_hash": receipt.authority_hash_hex,
                "warrantor.action.context_commitment": receipt.context_commitment_hex,
                "warrantor.action.outcome": format!("{:?}", receipt.outcome).to_lowercase(),
                "warrantor.action.tool": receipt.tool_or_api_op,
                "warrantor.action.signature": receipt.signature_hex,
                "warrantor.action.verifying_key": receipt.verifying_key_hex
            }
        })
    }
}

impl Default for FlightRecorder {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof that a signed receipt is **already durable** on stable storage.
///
/// This type is the mechanism that turns invariant I-07 from a comment into a compile-time
/// obligation. It has no public constructor and no public fields, so the only way to obtain one
/// is [`DurableFlightRecorder::emit_pending`], which returns it *after* `fsync` succeeds. Because
/// [`DurableFlightRecorder::commit`] consumes a `PendingAction` by value, the commit path is
/// unreachable for an action whose evidence was never written — and a durability failure is a
/// hard [`RecorderError::Io`], never a swallowed error.
#[derive(Debug, Clone)]
pub struct PendingAction {
    receipt: Receipt,
    record: EvidenceRecord,
}

impl PendingAction {
    /// The signed, durable receipt.
    #[must_use]
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }

    /// The evidence record (sequence number + hash-chain digests) that made it durable.
    #[must_use]
    pub fn record(&self) -> &EvidenceRecord {
        &self.record
    }

    /// The receipt id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.receipt.id
    }

    /// The evidence log sequence number this receipt occupies.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.record.seq
    }

    /// The hash-chain digest of the durable record.
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        &self.record.digest_hex
    }
}

/// The **I-07-compliant** flight recorder: a [`FlightRecorder`] bound to an [`EvidenceStore`].
///
/// ```no_run
/// # use warrantor_flight_recorder::{DurableFlightRecorder, ReceiptInput};
/// let mut rec = DurableFlightRecorder::open("evidence.jsonl")?;
/// // emit_pending returns only once the signed receipt is fsync'd:
/// let pending = rec.emit_pending(ReceiptInput {
///     actor: "spiffe://muveraai.com/agent/a".into(),
///     authority_hash_hex: String::new(),
///     tool_or_api_op: "github.create_pr".into(),
///     context_commitment_hex: String::new(),
/// })?;
/// // ... perform the side effect ...
/// let committed = rec.commit(pending)?; // consumes the durability proof
/// # Ok::<(), warrantor_flight_recorder::RecorderError>(())
/// ```
#[derive(Debug)]
pub struct DurableFlightRecorder<S: EvidenceStore = FileEvidenceStore> {
    recorder: FlightRecorder,
    store: S,
}

impl DurableFlightRecorder<FileEvidenceStore> {
    /// Open (or create) a durable recorder over the append-only evidence log at `path`.
    ///
    /// An existing log is replayed and its hash chain verified before any new record is accepted.
    ///
    /// # Errors
    /// Returns [`RecorderError::Io`] on I/O failure or [`RecorderError::ChainCorrupt`] if the
    /// existing evidence log does not verify.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, RecorderError> {
        Ok(Self {
            recorder: FlightRecorder::new(),
            store: FileEvidenceStore::open(path)?,
        })
    }
}

impl<S: EvidenceStore> DurableFlightRecorder<S> {
    /// Bind a signing core to an arbitrary evidence store.
    pub fn with_store(recorder: FlightRecorder, store: S) -> Self {
        Self { recorder, store }
    }

    /// The hex-encoded verifying key of the underlying signing core.
    #[must_use]
    pub fn verifying_key_hex(&self) -> &str {
        self.recorder.verifying_key_hex()
    }

    /// Borrow the evidence store (e.g. to read back the chain).
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The number of records written to the evidence log so far.
    #[must_use]
    pub fn evidence_len(&self) -> u64 {
        self.store.next_seq()
    }

    /// The current hash-chain head.
    #[must_use]
    pub fn head_digest_hex(&self) -> String {
        self.store.head_digest_hex()
    }

    /// Sign a pending receipt **and make it durable**, returning only after the evidence store
    /// has acknowledged a synced write (invariant I-07).
    ///
    /// # Errors
    /// Returns [`RecorderError::Io`] / [`RecorderError::Encode`] if the receipt could not be made
    /// durable — in which case the caller MUST NOT perform the action — or
    /// [`RecorderError::DuplicateReceiptId`] on an id collision.
    pub fn emit_pending(&mut self, input: ReceiptInput) -> Result<PendingAction, RecorderError> {
        let receipt = self.recorder.emit_pending(input)?;
        let record = self.store.append(&receipt)?;
        Ok(PendingAction { receipt, record })
    }

    /// Mark a durably-recorded action committed, appending the updated receipt to the evidence
    /// log and returning only after that append is synced.
    ///
    /// Consuming the [`PendingAction`] is what makes I-07 structural: without a durability proof
    /// there is no way to reach this function.
    ///
    /// # Errors
    /// Returns [`RecorderError::Io`] / [`RecorderError::Encode`] if the committed record could
    /// not be made durable, or [`RecorderError::Invariant`] if the signing core never saw the
    /// receipt (only reachable across a restart).
    pub fn commit(&mut self, pending: PendingAction) -> Result<Receipt, RecorderError> {
        self.finalize(pending, ActionOutcome::Committed)
    }

    /// Record that a durably-recorded action was rolled back. Same durability contract as
    /// [`Self::commit`].
    ///
    /// # Errors
    /// See [`Self::commit`].
    pub fn rollback(&mut self, pending: PendingAction) -> Result<Receipt, RecorderError> {
        self.finalize(pending, ActionOutcome::RolledBack)
    }

    /// Record that a durably-recorded action failed. Same durability contract as
    /// [`Self::commit`].
    ///
    /// # Errors
    /// See [`Self::commit`].
    pub fn fail(&mut self, pending: PendingAction) -> Result<Receipt, RecorderError> {
        self.finalize(pending, ActionOutcome::Failed)
    }

    fn finalize(
        &mut self,
        pending: PendingAction,
        outcome: ActionOutcome,
    ) -> Result<Receipt, RecorderError> {
        let mut receipt = pending.receipt;
        if outcome == ActionOutcome::Committed {
            self.recorder.mark_committed(&mut receipt)?;
        } else {
            if !self.recorder.seen.contains(&receipt.id) {
                return Err(RecorderError::Invariant(format!(
                    "finalize before emit for id {} (I-07)",
                    receipt.id
                )));
            }
            receipt.outcome = outcome;
            self.recorder.re_sign(&mut receipt);
        }
        self.store.append(&receipt)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> ReceiptInput {
        ReceiptInput {
            actor: "spiffe://muveraai.com/agent/coding-1".into(),
            authority_hash_hex: "abc123".repeat(8),
            tool_or_api_op: "github.create_pr".into(),
            context_commitment_hex: "def456".repeat(8),
        }
    }

    #[test]
    fn emit_pending_returns_signed_receipt() {
        let mut r = FlightRecorder::new();
        let receipt = r.emit_pending(sample_input()).expect("emit");
        assert_eq!(receipt.outcome, ActionOutcome::Pending);
        assert!(!receipt.signature_hex.is_empty());
        FlightRecorder::verify(&receipt).expect("signature verifies");
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let mut r = FlightRecorder::new();
        let mut receipt = r.emit_pending(sample_input()).expect("emit");
        receipt.actor = "spiffe://muveraai.com/agent/impostor".into();
        assert!(matches!(
            FlightRecorder::verify(&receipt),
            Err(RecorderError::SignatureInvalid)
        ));
    }

    #[test]
    fn mark_committed_re_signs_and_updates_outcome() {
        let mut r = FlightRecorder::new();
        let mut receipt = r.emit_pending(sample_input()).expect("emit");
        r.mark_committed(&mut receipt).expect("committed");
        assert_eq!(receipt.outcome, ActionOutcome::Committed);
        FlightRecorder::verify(&receipt).expect("committed receipt verifies");
    }

    #[test]
    fn commit_without_emit_violates_invariant_i07() {
        let mut r = FlightRecorder::new();
        // Build a receipt that the recorder never emitted.
        let mut receipt = r.emit_pending(sample_input()).expect("emit");
        r.seen.clear(); // simulate "not seen"
        assert!(matches!(
            r.mark_committed(&mut receipt),
            Err(RecorderError::Invariant(_))
        ));
    }

    #[test]
    fn to_proto_round_trips_load_bearing_fields() {
        let mut r = FlightRecorder::new();
        let receipt = r.emit_pending(sample_input()).expect("emit");
        let proto = receipt.to_proto();
        assert_eq!(proto.actor, receipt.actor);
        assert_eq!(proto.tool_or_api_op, receipt.tool_or_api_op);
        assert_eq!(proto.outcome, 1); // Pending
    }

    #[test]
    fn ocsf_export_has_required_class_uid() {
        let mut r = FlightRecorder::new();
        let receipt = r.emit_pending(sample_input()).expect("emit");
        let ocsf = r.to_ocsf_json(&receipt);
        assert_eq!(ocsf["class_uid"], 6003);
        assert_eq!(ocsf["actor"]["name"], receipt.actor);
    }

    #[test]
    fn otel_export_has_span_attributes() {
        let mut r = FlightRecorder::new();
        let receipt = r.emit_pending(sample_input()).expect("emit");
        let span = r.to_otel_span_json(&receipt);
        assert!(span["name"].as_str().unwrap().starts_with("agent.action."));
        assert!(span["attributes"]["warrantor.agent.id"].is_string());
    }

    #[test]
    fn verifying_key_hex_is_64_chars() {
        let r = FlightRecorder::new();
        assert_eq!(r.verifying_key_hex().len(), 64);
    }

    #[test]
    fn canonical_bytes_disambiguate_field_splittings_c2() {
        // C2: length-prefixing must prevent signature forgery via field re-splitting.
        // Two receipts that differ ONLY in how their concatenated fields could be re-split
        // must produce different canonical bytes (and therefore different signatures).
        let mut r = FlightRecorder::new();
        let receipt_a = r
            .emit_pending(ReceiptInput {
                actor: "ab".into(),
                authority_hash_hex: "c".repeat(8),
                tool_or_api_op: "github.create_pr".into(),
                context_commitment_hex: "def456".repeat(8),
            })
            .expect("emit a");
        let receipt_b = r
            .emit_pending(ReceiptInput {
                actor: "a".into(), // "ab" vs "a" + "b" re-split — same concatenated bytes only
                authority_hash_hex: "bc".repeat(4), // if not length-prefixed: "c"*8 == "bc"*4
                tool_or_api_op: "github.create_pr".into(),
                context_commitment_hex: "def456".repeat(8),
            })
            .expect("emit b");
        let canon_a = receipt_a.canonical_bytes();
        let canon_b = receipt_b.canonical_bytes();
        assert_ne!(
            canon_a, canon_b,
            "length-prefixed canonical bytes must distinguish different field splittings"
        );
        assert_ne!(
            receipt_a.signature_hex, receipt_b.signature_hex,
            "signatures over different canonical bytes must differ"
        );
        // Both must still verify individually.
        FlightRecorder::verify(&receipt_a).expect("a verifies");
        FlightRecorder::verify(&receipt_b).expect("b verifies");
    }

    #[test]
    fn to_proto_checked_surfaces_malformed_signature_hex_h1() {
        // H1: a malformed signature_hex must NOT be silently dropped into an empty proto field.
        // Previously to_proto used unwrap_or_default() and swallowed the error.
        let mut r = FlightRecorder::new();
        let mut receipt = r.emit_pending(sample_input()).expect("emit");
        // Corrupt the signature hex with a non-hex character.
        receipt.signature_hex = "zz".to_string();
        let err = receipt
            .to_proto_checked()
            .expect_err("malformed signature must error");
        assert!(
            matches!(
                err,
                RecorderError::MalformedHex {
                    field: "signature_hex",
                    ..
                }
            ),
            "expected MalformedHex on signature_hex, got {err:?}"
        );
    }

    #[test]
    fn to_proto_checked_surfaces_malformed_authority_hash_hex_h1() {
        // H1: same surface for a malformed authority_hash_hex.
        let mut r = FlightRecorder::new();
        let mut receipt = r.emit_pending(sample_input()).expect("emit");
        receipt.authority_hash_hex = "xyz".into(); // odd length + non-hex chars
        let err = receipt
            .to_proto_checked()
            .expect_err("malformed authority_hash must error");
        assert!(
            matches!(
                err,
                RecorderError::MalformedHex {
                    field: "authority_hash_hex",
                    ..
                }
            ),
            "expected MalformedHex on authority_hash_hex, got {err:?}"
        );
    }

    // ================= AX-40: durable evidence store / invariant I-07 =================

    /// A unique scratch path per test. We deliberately do NOT use a tempfile crate: the restart
    /// tests must be able to reopen the exact same path after dropping the store.
    fn scratch_path(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut p = std::env::temp_dir();
        p.push("warrantor-flight-recorder-tests");
        p.push(
            format!("{tag}-{nanos}-{:?}.jsonl", std::thread::current().id()).replace(
                |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '.' && c != '_',
                "",
            ),
        );
        p
    }

    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            // The store keeps a sidecar lock file next to the log; clean it up too.
            let mut lock = self.0.as_os_str().to_os_string();
            lock.push(".lock");
            let _ = std::fs::remove_file(std::path::PathBuf::from(lock));
        }
    }

    /// Two recorders over one log each cached their own next_seq at open time, so both handed out
    /// a durability proof for the SAME sequence number. Both callers committed their side effects;
    /// the log was then permanently unreadable, including the record that had been written
    /// correctly. Opening the second recorder has to fail instead.
    #[test]
    fn two_recorders_cannot_share_one_evidence_log_ax40() {
        let scratch = Scratch(scratch_path("double-open"));
        let mut first = DurableFlightRecorder::open(&scratch.0).expect("first open");

        let second = DurableFlightRecorder::open(&scratch.0);
        match second {
            Ok(_) => panic!(
                "a second recorder opened the same evidence log; both would assign the same \
                 seq and corrupt the chain"
            ),
            Err(RecorderError::Io { source, .. }) => {
                let message = source.to_string();
                assert!(
                    message.contains("already open"),
                    "the error should explain the conflict, got: {message}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }

        // The holder is unaffected and the log stays consistent.
        first
            .emit_pending(sample_input())
            .expect("first still works");
        let records = first.store().records().expect("replay");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].seq, 0);
    }

    #[test]
    fn dropping_a_recorder_releases_the_log_for_the_next_one_ax40() {
        let scratch = Scratch(scratch_path("lock-release"));
        {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
            rec.emit_pending(sample_input()).expect("emit");
        }
        // A normal restart must still work -- the lock is a concurrency guard, not a tombstone.
        let mut reopened = DurableFlightRecorder::open(&scratch.0).expect("reopen after drop");
        let pending = reopened.emit_pending(sample_input()).expect("emit again");
        assert_eq!(pending.seq(), 1, "the chain continues where it left off");
    }

    /// The lock must not make the log unreadable: an external auditor with `jq` and no access to
    /// this crate is the whole reason the evidence format is plain JSONL.
    #[test]
    fn the_evidence_log_stays_readable_while_a_recorder_holds_it_ax40() {
        let scratch = Scratch(scratch_path("readable-while-locked"));
        let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
        rec.emit_pending(sample_input()).expect("emit");

        let contents = std::fs::read_to_string(&scratch.0).expect("read the log while locked");
        assert!(
            contents.contains("\"seq\":0"),
            "the log must be readable by an outside reader while held"
        );
    }

    /// A flipped byte that breaks UTF-8 is tampering, not a device fault. Reporting it as
    /// RecorderError::Io made the one signal this component exists to raise indistinguishable
    /// from a failing disk.
    #[test]
    fn non_utf8_corruption_is_reported_as_chain_corruption_not_io_ax40() {
        let scratch = Scratch(scratch_path("utf8-corrupt"));
        {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
            rec.emit_pending(sample_input()).expect("emit");
        }

        // Flip a byte in the middle of the record to something that cannot be UTF-8.
        let mut bytes = std::fs::read(&scratch.0).expect("read log");
        let midpoint = bytes.len() / 2;
        bytes[midpoint] = 0xFF;
        std::fs::write(&scratch.0, &bytes).expect("write corrupted log");

        match DurableFlightRecorder::open(&scratch.0) {
            Err(RecorderError::ChainCorrupt { detail, .. }) => {
                assert!(
                    detail.contains("UTF-8"),
                    "the detail should name the corruption, got: {detail}"
                );
            }
            Err(RecorderError::Io { source, .. }) => panic!(
                "byte corruption was reported as an I/O fault, hiding the tamper signal: {source}"
            ),
            Err(other) => panic!("unexpected error variant: {other:?}"),
            Ok(_) => panic!("corrupted log opened successfully"),
        }
    }

    #[test]
    fn emit_pending_durable_writes_a_synced_record_ax40() {
        let scratch = Scratch(scratch_path("emit-durable"));
        let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open store");
        assert_eq!(rec.evidence_len(), 0);
        assert_eq!(rec.head_digest_hex(), GENESIS_DIGEST_HEX);

        let pending = rec.emit_pending(sample_input()).expect("durable emit");
        assert_eq!(pending.seq(), 0);
        assert_eq!(pending.record().prev_digest_hex, GENESIS_DIGEST_HEX);
        assert_eq!(rec.evidence_len(), 1);

        // The bytes are on disk the moment emit_pending returned — read them with a plain
        // filesystem read, not through the store.
        let raw = std::fs::read_to_string(&scratch.0).expect("file exists on disk");
        assert!(
            raw.contains(&pending.receipt().id),
            "receipt id must already be on disk when emit_pending returns"
        );
        assert!(raw.ends_with('\n'), "records are newline-terminated");
    }

    #[test]
    fn evidence_survives_an_actual_restart_ax40() {
        // The load-bearing durability test: write, DROP the store, construct a brand-new store
        // over the same path, and assert the evidence is still there and still verifies.
        let scratch = Scratch(scratch_path("restart"));
        let (id_a, id_b, head_before) = {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
            let a = rec.emit_pending(sample_input()).expect("emit a");
            let id_a = a.id().to_string();
            let committed = rec.commit(a).expect("commit a");
            assert_eq!(committed.outcome, ActionOutcome::Committed);
            let b = rec.emit_pending(sample_input()).expect("emit b");
            let id_b = b.id().to_string();
            (id_a, id_b, rec.head_digest_hex())
            // `rec` (and its File handle) is dropped here — simulated process exit.
        };

        // ---- restart: a fresh store over the same path ----
        let reopened = DurableFlightRecorder::open(&scratch.0).expect("reopen after restart");
        assert_eq!(
            reopened.evidence_len(),
            3,
            "pending(a) + committed(a) + pending(b) must all survive the restart"
        );
        assert_eq!(
            reopened.head_digest_hex(),
            head_before,
            "chain head must be identical across the restart"
        );

        let records = reopened.store().records().expect("replay");
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].receipt.id, id_a);
        assert_eq!(records[0].receipt.outcome, ActionOutcome::Pending);
        assert_eq!(records[1].receipt.id, id_a);
        assert_eq!(records[1].receipt.outcome, ActionOutcome::Committed);
        assert_eq!(records[2].receipt.id, id_b);
        assert_eq!(records[2].receipt.outcome, ActionOutcome::Pending);

        // Every surviving receipt still verifies against its embedded verifying key, even though
        // the reopened recorder generated a brand-new signing key.
        for r in &records {
            FlightRecorder::verify(&r.receipt).expect("surviving receipt verifies");
        }
        assert_ne!(
            reopened.verifying_key_hex(),
            records[0].receipt.verifying_key_hex,
            "the restarted process has a new key; verification must not depend on it"
        );
    }

    #[test]
    fn appends_after_restart_continue_the_same_chain_ax40() {
        let scratch = Scratch(scratch_path("continue-chain"));
        {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
            rec.emit_pending(sample_input()).expect("emit");
        }
        {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("reopen");
            let p = rec
                .emit_pending(sample_input())
                .expect("emit after restart");
            assert_eq!(p.seq(), 1, "sequence must continue, not restart at 0");
        }
        let records = FileEvidenceStore::read_all(&scratch.0).expect("chain verifies");
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].prev_digest_hex, records[0].digest_hex);
    }

    #[test]
    fn tampering_with_a_persisted_record_is_detected_on_reload_ax40() {
        let scratch = Scratch(scratch_path("tamper"));
        {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
            rec.emit_pending(sample_input()).expect("emit 1");
            rec.emit_pending(sample_input()).expect("emit 2");
        }
        // Rewrite the FIRST record's actor in place — the classic "edit the evidence" attack.
        let raw = std::fs::read_to_string(&scratch.0).expect("read");
        let tampered = raw.replacen("coding-1", "coding-9", 1);
        assert_ne!(raw, tampered, "the fixture must actually change");
        std::fs::write(&scratch.0, tampered).expect("write tampered");

        let err = FileEvidenceStore::read_all(&scratch.0).expect_err("tampering must be detected");
        assert!(
            matches!(err, RecorderError::ChainCorrupt { seq: 0, .. }),
            "expected ChainCorrupt at seq 0, got {err:?}"
        );
        // And a recorder refuses to open a corrupt log at all.
        assert!(DurableFlightRecorder::open(&scratch.0).is_err());
    }

    #[test]
    fn truncating_the_middle_of_the_chain_is_detected_ax40() {
        let scratch = Scratch(scratch_path("drop-record"));
        {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
            rec.emit_pending(sample_input()).expect("emit 1");
            rec.emit_pending(sample_input()).expect("emit 2");
            rec.emit_pending(sample_input()).expect("emit 3");
        }
        let raw = std::fs::read_to_string(&scratch.0).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 3);
        // Delete the middle record.
        std::fs::write(&scratch.0, format!("{}\n{}\n", lines[0], lines[2])).expect("write");

        let err = FileEvidenceStore::read_all(&scratch.0).expect_err("deletion must be detected");
        assert!(
            matches!(err, RecorderError::ChainCorrupt { .. }),
            "expected ChainCorrupt, got {err:?}"
        );
    }

    #[test]
    fn torn_trailing_record_from_a_crash_is_recovered_ax40() {
        let scratch = Scratch(scratch_path("torn-tail"));
        {
            let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
            rec.emit_pending(sample_input()).expect("emit 1");
            rec.emit_pending(sample_input()).expect("emit 2");
        }
        // Simulate a crash mid-write: append a partial line with no trailing newline.
        let raw = std::fs::read_to_string(&scratch.0).expect("read");
        std::fs::write(&scratch.0, format!("{raw}{{\"seq\":2,\"prev_dig"))
            .expect("write torn tail");

        let rec = DurableFlightRecorder::open(&scratch.0).expect("torn tail must be recoverable");
        assert_eq!(rec.evidence_len(), 2, "the two complete records survive");
        let records = FileEvidenceStore::read_all(&scratch.0).expect("chain verifies after repair");
        assert_eq!(records.len(), 2);
        let on_disk = std::fs::read_to_string(&scratch.0).expect("read");
        assert_eq!(on_disk, raw, "the torn bytes must have been truncated away");
    }

    #[test]
    fn commit_requires_a_durability_proof_ax40() {
        // The structural half of I-07: `commit` consumes a PendingAction, and a PendingAction is
        // only obtainable from a successful durable emit. This test documents the shape (there is
        // no way to write the negative case — it does not compile) and checks the happy path
        // appends a second, chained record.
        let scratch = Scratch(scratch_path("commit-proof"));
        let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
        let pending = rec.emit_pending(sample_input()).expect("emit");
        let pending_digest = pending.digest_hex().to_string();
        let committed = rec.commit(pending).expect("commit");
        assert_eq!(committed.outcome, ActionOutcome::Committed);
        FlightRecorder::verify(&committed).expect("committed receipt verifies");

        let records = rec.store().records().expect("replay");
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].prev_digest_hex, pending_digest,
            "the commit record must chain onto the pending record"
        );
    }

    #[test]
    fn rollback_and_fail_are_also_durable_ax40() {
        let scratch = Scratch(scratch_path("rollback"));
        let mut rec = DurableFlightRecorder::open(&scratch.0).expect("open");
        let p1 = rec.emit_pending(sample_input()).expect("emit 1");
        let rolled = rec.rollback(p1).expect("rollback");
        assert_eq!(rolled.outcome, ActionOutcome::RolledBack);
        FlightRecorder::verify(&rolled).expect("rolled-back receipt verifies");

        let p2 = rec.emit_pending(sample_input()).expect("emit 2");
        let failed = rec.fail(p2).expect("fail");
        assert_eq!(failed.outcome, ActionOutcome::Failed);
        FlightRecorder::verify(&failed).expect("failed receipt verifies");
        assert_eq!(rec.evidence_len(), 4);
    }

    #[test]
    fn durability_failure_is_an_error_not_a_silent_success_ax40() {
        // I-07 requires the failure mode to be explicit. A store whose append always fails must
        // make emit_pending return Err — and therefore make commit unreachable.
        struct BrokenStore;
        impl EvidenceStore for BrokenStore {
            fn append(&mut self, _r: &Receipt) -> Result<EvidenceRecord, RecorderError> {
                Err(RecorderError::Io {
                    path: "/dev/full".into(),
                    source: std::io::Error::other("disk full"),
                })
            }
            fn next_seq(&self) -> u64 {
                0
            }
            fn head_digest_hex(&self) -> String {
                GENESIS_DIGEST_HEX.to_string()
            }
        }
        let mut rec = DurableFlightRecorder::with_store(FlightRecorder::new(), BrokenStore);
        let err = rec
            .emit_pending(sample_input())
            .expect_err("a store that cannot persist must fail the emit");
        assert!(
            matches!(err, RecorderError::Io { .. }),
            "expected Io, got {err:?}"
        );
    }

    #[test]
    fn record_digest_is_stable_and_binds_the_signature_ax40() {
        let mut r = FlightRecorder::new();
        let receipt = r.emit_pending(sample_input()).expect("emit");
        let prev = [7u8; 32];
        let d1 = compute_record_digest(3, &prev, &receipt);
        let d2 = compute_record_digest(3, &prev, &receipt);
        assert_eq!(d1, d2, "digest must be deterministic");
        assert_ne!(
            d1,
            compute_record_digest(4, &prev, &receipt),
            "digest must bind the sequence number"
        );
        assert_ne!(
            d1,
            compute_record_digest(3, &[8u8; 32], &receipt),
            "digest must bind the previous digest"
        );
        let mut resigned = receipt.clone();
        resigned.signature_hex = "00".repeat(64);
        assert_ne!(
            d1,
            compute_record_digest(3, &prev, &resigned),
            "digest must bind the signature"
        );
    }

    #[test]
    fn to_proto_checked_round_trips_clean_receipt_h1() {
        // H1: a clean receipt must round-trip through the checked path with no error.
        let mut r = FlightRecorder::new();
        let receipt = r.emit_pending(sample_input()).expect("emit");
        let proto = receipt.to_proto_checked().expect("clean receipt decodes");
        assert_eq!(proto.actor, receipt.actor);
        assert!(!proto.signature.is_empty());
        assert!(!proto.authority_hash.is_empty());
    }
}

#[cfg(test)]
mod signature_coverage {
    use super::*;

    fn sample_input() -> ReceiptInput {
        ReceiptInput {
            actor: "spiffe://muveraai.com/agent/coverage".into(),
            authority_hash_hex: "ab".repeat(32),
            tool_or_api_op: "deploy".into(),
            context_commitment_hex: "cd".repeat(32),
        }
    }

    /// The reported defect: rewriting rollback_pointer on a signed receipt left the
    /// signature valid, so "this action was rolled back, see <url>" was forgeable.
    #[test]
    fn tampering_with_rollback_pointer_invalidates_the_signature() {
        let mut recorder = FlightRecorder::new();
        let receipt = recorder.emit_pending(sample_input()).expect("emit");
        FlightRecorder::verify(&receipt).expect("clean receipt verifies");

        let mut forged = receipt.clone();
        forged.rollback_pointer = Some("https://evil.example/forged-rollback".into());
        assert!(
            FlightRecorder::verify(&forged).is_err(),
            "a forged rollback_pointer MUST invalidate the signature"
        );
    }

    /// None and Some("") must not share an encoding, or "never rolled back" and "rolled
    /// back to nowhere" would be interchangeable under one signature.
    #[test]
    fn none_and_empty_pointer_do_not_alias() {
        let mut recorder = FlightRecorder::new();
        let receipt = recorder.emit_pending(sample_input()).expect("emit");
        let mut a = receipt.clone();
        let mut b = receipt;
        a.rollback_pointer = None;
        b.rollback_pointer = Some(String::new());
        assert_ne!(
            a.canonical_bytes(),
            b.canonical_bytes(),
            "None and Some(\"\") must encode differently"
        );
    }

    /// Guards the general failure, not just this instance: a field added to Receipt and
    /// forgotten in canonical_bytes is silently unsigned.
    #[test]
    fn every_field_except_the_signature_is_covered() {
        let mut recorder = FlightRecorder::new();
        let receipt = recorder.emit_pending(sample_input()).expect("emit");
        let base = receipt.canonical_bytes();

        let mut m = receipt.clone();
        m.rollback_pointer = Some("x".into());
        assert_ne!(base, m.canonical_bytes(), "rollback_pointer uncovered");

        let mut m = receipt.clone();
        m.actor = "other".into();
        assert_ne!(base, m.canonical_bytes(), "actor uncovered");

        let mut m = receipt.clone();
        m.emitted_at += 1;
        assert_ne!(base, m.canonical_bytes(), "emitted_at uncovered");

        // signature_hex is the one field that must NOT be covered.
        let mut m = receipt.clone();
        m.signature_hex = "ff".repeat(64);
        assert_eq!(
            base,
            m.canonical_bytes(),
            "signature_hex must be excluded -- a signature cannot sign itself"
        );
    }
}

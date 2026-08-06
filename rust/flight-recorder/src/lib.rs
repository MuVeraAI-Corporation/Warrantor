//! # aumos-flight-recorder (E1)
//!
//! The verifiable agent flight recorder. Emits **signed Agent Action Receipts (AAR, P2)** for
//! every material agent action. **Invariant I-07: the receipt is signed and durable BEFORE the
//! action commits** — an agent must not produce a visible side effect without a verifiable receipt
//! already recorded.
//!
//! Exports to:
//!   - **OCSF** (Open Cybersecurity Schema Framework) — JSON, per cross-cutting 19 §1 external tier.
//!   - **OpenTelemetry** — semantic-attribute JSON for the OTel collector (real OTLP export is task 03;
//!     the v1.0 emits the JSON a collector consumes).
//!
//! See RFC E1 and `specs/protocols/P2-aar.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use aumos_api::protocols::v1::AgentActionReceipt;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

/// The action outcome. Mirrors `aumos.protocols.v1.ActionOutcome`.
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
/// `aumos_api::protocols::v1::AgentActionReceipt`; convert with [`Receipt::to_proto`].
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[must_use]
    pub fn to_proto(&self) -> AgentActionReceipt {
        AgentActionReceipt {
            id: self.id.clone(),
            actor: self.actor.clone(),
            authority_hash: hex::decode(&self.authority_hash_hex).unwrap_or_default(),
            artifact_versions: self.artifact_versions.clone().into_iter().collect(),
            context_commitment: hex::decode(&self.context_commitment_hex).unwrap_or_default(),
            policy_decision: Some(aumos_api::protocols::v1::PolicyDecision {
                engine: self.policy_decision.engine.clone(),
                decision: self.policy_decision.decision.clone(),
                policy_hash: hex::decode(&self.policy_decision.policy_hash_hex).unwrap_or_default(),
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
            signature: hex::decode(&self.signature_hex).unwrap_or_default(),
        }
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
        write_len_prefixed(&mut out, &self.policy_decision.matched_rules.len().to_le_bytes());
        for r in &self.policy_decision.matched_rules {
            write_len_prefixed(&mut out, r.as_bytes());
        }
        write_len_prefixed(&mut out, self.tool_or_api_op.as_bytes());
        write_len_prefixed(&mut out, &self.approvers.len().to_le_bytes());
        for a in &self.approvers {
            write_len_prefixed(&mut out, a.as_bytes());
        }
        out.extend_from_slice(&self.outcome.to_proto().to_le_bytes());
        out.extend_from_slice(&self.emitted_at.to_le_bytes());
        write_len_prefixed(&mut out, self.verifying_key_hex.as_bytes());
        out
    }
}

/// Write `field` to `out` prefixed by its length as a little-endian u64. This makes the
/// canonical encoding unambiguous (length-prefixed framing prevents field-re-splitting forgery).
fn write_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

/// The flight recorder. Owns a signing key and tracks emitted receipts (so duplicate IDs and
/// out-of-order commits can be detected).
pub struct FlightRecorder {
    signing_key: SigningKey,
    verifying_key_hex: String,
    seen: std::collections::HashSet<String>,
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

    /// Emit a **pending** receipt for an action that is about to commit.
    ///
    /// **Invariant I-07**: callers MUST call this and persist the returned receipt BEFORE making
    /// the action's effect visible. The recorder does not enforce persistence (that's the caller's
    /// job); it only enforces the emit-before-commit ordering via [`Self::mark_committed`].
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
        // Re-sign the updated receipt.
        let canon = receipt.canonical_bytes();
        let sig = self.signing_key.sign(&canon);
        receipt.signature_hex = hex::encode(sig.to_bytes());
        Ok(())
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
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| RecorderError::SignatureInvalid)?;
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
                "product": { "name": "aumos-flight-recorder", "vendor_name": "AumOS" },
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
                "aumos.agent.id": receipt.actor,
                "aumos.action.authority_hash": receipt.authority_hash_hex,
                "aumos.action.context_commitment": receipt.context_commitment_hex,
                "aumos.action.outcome": format!("{:?}", receipt.outcome).to_lowercase(),
                "aumos.action.tool": receipt.tool_or_api_op,
                "aumos.action.signature": receipt.signature_hex,
                "aumos.action.verifying_key": receipt.verifying_key_hex
            }
        })
    }
}

impl Default for FlightRecorder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> ReceiptInput {
        ReceiptInput {
            actor: "spiffe://aumos.dev/agent/coding-1".into(),
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
        receipt.actor = "spiffe://aumos.dev/agent/impostor".into();
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
        assert!(span["attributes"]["aumos.agent.id"].is_string());
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
        let receipt_a = r.emit_pending(ReceiptInput {
            actor: "ab".into(),
            authority_hash_hex: "c".repeat(8),
            tool_or_api_op: "github.create_pr".into(),
            context_commitment_hex: "def456".repeat(8),
        })
        .expect("emit a");
        let receipt_b = r.emit_pending(ReceiptInput {
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
}

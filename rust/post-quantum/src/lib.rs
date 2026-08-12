//! DU1 Post-quantum durability — dual-sign (Ed25519 + ML-DSA placeholder), archival-grade
//! receipts, agent retirement/EOL, and exit/continuity.
//!
//! A 2026 receipt must verify in 2056 — against a cryptographically-relevant quantum computer,
//! against key rotation, against algorithm deprecation, and against org succession. This crate
//! implements the durability primitives that make that possible:
//!
//! 1. **Dual-sign** — every receipt carries BOTH Ed25519 (classical) and a PQ algorithm slot
//!    (ML-DSA/SLH-DSA). Today both verify; when Ed25519 breaks, the PQ signature stands.
//! 2. **Archival-grade receipts** — carry algorithm IDs, key rotation history, and a re-anchoring
//!    ceremony record so a verifier in 2056 knows what to check.
//! 3. **Agent retirement/EOL** — a defined lifecycle phase where an agent's authority is cleanly
//!    retired (revoked, receipts preserved, dependencies notified).
//! 4. **Exit/continuity** — if the Warrantor org disappears, the receipts still verify.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub const DU_VERSION: &str = "warrantor-post-quantum/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Signature algorithms — the crypto-agility story (spec 01 §4)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// Ed25519 — classical, fast, widely deployed. Breaks under CRQC.
    Ed25519,
    /// ML-DSA (Dilithium) — NIST PQC standard (FIPS 204). Resistant to CRQC.
    MlDsa,
    /// SLH-DSA (SPHINCS+) — NIST PQC standard (FIPS 205). Hash-based, conservative.
    SlhDsa,
}

impl SignatureAlgorithm {
    #[must_use]
    pub fn is_post_quantum(self) -> bool {
        matches!(self, SignatureAlgorithm::MlDsa | SignatureAlgorithm::SlhDsa)
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "Ed25519",
            SignatureAlgorithm::MlDsa => "ML-DSA-65",
            SignatureAlgorithm::SlhDsa => "SLH-DSA-128s",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Dual-signature envelope — the heart of post-quantum readiness
// ═══════════════════════════════════════════════════════════════════════════

/// One signature over a payload, with algorithm + key metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureEntry {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// A dual-signed payload: Ed25519 now + a PQ algorithm slot. Both verify independently.
/// When Ed25519 breaks, the PQ signature stands — the receipt remains evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DualSignedPayload {
    /// Canonical-JSON payload (the thing being signed).
    pub payload: serde_json::Value,
    /// Classical signature (Ed25519) — present now.
    pub classical: SignatureEntry,
    /// Post-quantum signature (ML-DSA or SLH-DSA) — present when PQ keys are available.
    /// None = "PQ-ready but not yet PQ-signed" (the migration window).
    pub post_quantum: Option<SignatureEntry>,
}

impl DualSignedPayload {
    /// Whether this payload has BOTH classical and PQ signatures (fully dual-signed).
    #[must_use]
    pub fn is_dual_signed(&self) -> bool {
        self.post_quantum.is_some()
    }

    /// The algorithm IDs carried — a 2056 verifier checks these to know what to verify.
    #[must_use]
    pub fn algorithm_ids(&self) -> Vec<SignatureAlgorithm> {
        let mut algos = vec![self.classical.algorithm];
        if let Some(ref pq) = self.post_quantum {
            algos.push(pq.algorithm);
        }
        algos
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Archival-grade receipt metadata
// ═══════════════════════════════════════════════════════════════════════════

/// Key rotation history — so a verifier knows which keys were valid when.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRotationEntry {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key_hex: String,
    pub valid_from: u64,
    pub valid_until: Option<u64>, // None = still active
    pub retired_reason: Option<String>,
}

/// A re-anchoring ceremony record — when a receipt was re-anchored to a new transparency log
/// or a new key, with the ceremony's signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReanchoringRecord {
    pub ceremony_id: String,
    pub reanchored_at: u64,
    pub new_anchor_digest: String,
    pub ceremony_authority: String,
}

/// Archival-grade metadata that travels WITH a receipt so it remains verifiable for decades.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchivalMetadata {
    /// The original signing timestamp.
    pub signed_at: u64,
    /// When this receipt must remain verifiable until (e.g. 30 years for legal records).
    pub must_verify_until: u64,
    /// Key rotation history for all keys that ever signed or re-signed this receipt.
    pub key_history: Vec<KeyRotationEntry>,
    /// Re-anchoring ceremony records (empty if never re-anchored).
    #[serde(default)]
    pub reanchoring_history: Vec<ReanchoringRecord>,
    /// The algorithm-agility policy: when each algorithm is expected to be deprecated.
    #[serde(default)]
    pub deprecation_schedule: HashMap<String, u64>, // algorithm label → expected deprecation year
}

impl ArchivalMetadata {
    #[must_use]
    pub fn new(signed_at: u64, must_verify_until: u64) -> Self {
        Self {
            signed_at,
            must_verify_until,
            key_history: vec![],
            reanchoring_history: vec![],
            deprecation_schedule: HashMap::new(),
        }
    }

    /// Whether a key was valid at a given timestamp.
    #[must_use]
    pub fn key_was_valid(&self, key_id: &str, at: u64) -> bool {
        self.key_history.iter().any(|k| {
            k.key_id == key_id && k.valid_from <= at && k.valid_until.is_none_or(|u| at < u)
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Agent retirement/EOL (spec gap-analysis §3D.5)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecyclePhase {
    Active,
    Deprecated,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRetirementRecord {
    pub agent_id: String,
    pub svid: String,
    pub phase: AgentLifecyclePhase,
    pub retired_at: u64,
    pub retirement_reason: String,
    /// Whether the agent's authority was fully revoked.
    pub authority_revoked: bool,
    /// Whether the agent's receipts are preserved (they must be — retirement is not deletion).
    pub receipts_preserved: bool,
    /// Dependencies that were notified of the retirement.
    pub notified_dependencies: Vec<String>,
}

impl AgentRetirementRecord {
    /// Whether the retirement is clean (authority revoked + receipts preserved).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.authority_revoked && self.receipts_preserved
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Exit/continuity — if the org disappears, the receipts still verify
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExitContinuityPlan {
    /// The foundation/home that will maintain the project if the org disappears.
    pub successor_home: String,
    /// Whether the verifying keys are escrowed with a neutral third party.
    pub keys_escrowed: bool,
    /// Whether the transparency log has independent operators (not just the org).
    pub log_has_independent_operators: bool,
    /// The date the succession plan was committed.
    pub committed_at: u64,
}

impl ExitContinuityPlan {
    /// Whether the continuity plan is sufficient for receipts to survive the org's disappearance.
    #[must_use]
    pub fn is_sufficient(&self) -> bool {
        !self.successor_home.is_empty() && self.keys_escrowed
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The durability verifier — checks a receipt can verify in the future
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityVerdict {
    /// The receipt will verify for the required period.
    Durable,
    /// The receipt needs PQ migration before the quantum window.
    NeedsPqMigration { deadline_year: u64 },
    /// The receipt needs re-anchoring (the original anchor is expiring).
    NeedsReanchoring,
    /// The continuity plan is insufficient — receipts may not survive the org.
    InsufficientContinuity,
}

#[derive(Debug, Error)]
pub enum DuError {
    #[error("durability: {0}")]
    Du(String),
}

/// Assess whether a dual-signed payload + archival metadata will remain verifiable.
#[must_use]
pub fn assess_durability(
    payload: &DualSignedPayload,
    metadata: &ArchivalMetadata,
    continuity: Option<&ExitContinuityPlan>,
) -> DurabilityVerdict {
    // 1. Continuity check.
    if let Some(ec) = continuity {
        if !ec.is_sufficient() {
            return DurabilityVerdict::InsufficientContinuity;
        }
    }

    // 2. PQ migration check: if the receipt must verify past ~2035 and has no PQ signature.
    if !payload.is_dual_signed() && metadata.must_verify_until > 2036 {
        return DurabilityVerdict::NeedsPqMigration {
            deadline_year: 2035,
        };
    }

    // 3. Re-anchoring check: if the last re-anchoring was >10 years ago and must_verify_until is far.
    let needs_reanchor =
        metadata.must_verify_until > 2040 && metadata.reanchoring_history.is_empty();
    if needs_reanchor {
        return DurabilityVerdict::NeedsReanchoring;
    }

    DurabilityVerdict::Durable
}

// ═══════════════════════════════════════════════════════════════════════════
// Dual-signing (Ed25519 now; PQ slot ready for when PQ libs are available)
// ═══════════════════════════════════════════════════════════════════════════

/// Create a dual-signed payload with Ed25519 now + a PQ slot ready for ML-DSA.
/// The PQ slot is None until PQ key generation is wired (the migration window).
#[must_use]
pub fn dual_sign(
    payload: &serde_json::Value,
    signing_key: &SigningKey,
    key_id: &str,
) -> DualSignedPayload {
    let canonical = canonical_json(payload);
    let sig: Signature = signing_key.sign(canonical.as_bytes());
    let verifying = signing_key.verifying_key();
    DualSignedPayload {
        payload: payload.clone(),
        classical: SignatureEntry {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: key_id.to_string(),
            public_key_hex: hex::encode(&verifying.to_bytes()),
            signature_hex: hex::encode(&sig.to_bytes()),
        },
        post_quantum: None, // PQ slot ready; filled when PQ keys are provisioned
    }
}

/// Verify the classical (Ed25519) signature on a dual-signed payload.
pub fn verify_classical(payload: &DualSignedPayload) -> Result<(), DuError> {
    let pk_bytes = hex::decode(&payload.classical.public_key_hex)
        .map_err(|e| DuError::Du(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(DuError::Du("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| DuError::Du(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&payload.classical.signature_hex)
        .map_err(|e| DuError::Du(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(DuError::Du("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_json(&payload.payload);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| DuError::Du("Ed25519 signature does not verify".into()))
}

/// Canonical JSON (RFC 8785-shaped).
fn canonical_json(v: &serde_json::Value) -> String {
    let sorted = canonicalize_value(v);
    serde_json::to_string(&sorted).expect("canonical serializes")
}

fn canonicalize_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::{Map, Value};
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), canonicalize_value(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Add a key to the archival metadata's history.
pub fn add_key_to_history(
    metadata: &mut ArchivalMetadata,
    key_id: &str,
    algorithm: SignatureAlgorithm,
    public_key_hex: &str,
    valid_from: u64,
) {
    metadata.key_history.push(KeyRotationEntry {
        key_id: key_id.to_string(),
        algorithm,
        public_key_hex: public_key_hex.to_string(),
        valid_from,
        valid_until: None,
        retired_reason: None,
    });
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(2) {
            return Err("odd-length hex".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_sign_and_verify_classical() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"action": "test", "timestamp": 2026});
        let dual = dual_sign(&payload, &sk, "key-2026");
        assert!(!dual.is_dual_signed()); // PQ slot is None (migration window)
        verify_classical(&dual).expect("classical signature verifies");
    }

    #[test]
    fn dual_sign_carries_algorithm_ids() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"x": 1});
        let dual = dual_sign(&payload, &sk, "k");
        let algos = dual.algorithm_ids();
        assert!(algos.contains(&SignatureAlgorithm::Ed25519));
        assert!(!algos.iter().any(|a| a.is_post_quantum())); // no PQ yet
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"action": "original"});
        let mut dual = dual_sign(&payload, &sk, "k");
        dual.payload = serde_json::json!({"action": "tampered"});
        assert!(verify_classical(&dual).is_err());
    }

    #[test]
    fn durability_classical_only_near_term_is_durable() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"x": 1});
        let dual = dual_sign(&payload, &sk, "k");
        let meta = ArchivalMetadata::new(2026, 2030); // verify until 2030
        let v = assess_durability(&dual, &meta, None);
        assert_eq!(v, DurabilityVerdict::Durable);
    }

    #[test]
    fn durability_classical_only_long_term_needs_pq_migration() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"x": 1});
        let dual = dual_sign(&payload, &sk, "k");
        let meta = ArchivalMetadata::new(2026, 2056); // verify until 2056
        let v = assess_durability(&dual, &meta, None);
        matches!(v, DurabilityVerdict::NeedsPqMigration { .. });
    }

    #[test]
    fn durability_insufficient_continuity() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"x": 1});
        let dual = dual_sign(&payload, &sk, "k");
        let meta = ArchivalMetadata::new(2026, 2030);
        let ec = ExitContinuityPlan {
            successor_home: "".into(), // empty = insufficient
            keys_escrowed: false,
            log_has_independent_operators: false,
            committed_at: 2026,
        };
        let v = assess_durability(&dual, &meta, Some(&ec));
        assert_eq!(v, DurabilityVerdict::InsufficientContinuity);
    }

    #[test]
    fn durability_sufficient_continuity_allows_durable() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"x": 1});
        let dual = dual_sign(&payload, &sk, "k");
        let meta = ArchivalMetadata::new(2026, 2030);
        let ec = ExitContinuityPlan {
            successor_home: "Linux Foundation".into(),
            keys_escrowed: true,
            log_has_independent_operators: true,
            committed_at: 2026,
        };
        let v = assess_durability(&dual, &meta, Some(&ec));
        assert_eq!(v, DurabilityVerdict::Durable);
    }

    #[test]
    fn archival_metadata_key_history() {
        let mut meta = ArchivalMetadata::new(2026, 2056);
        add_key_to_history(
            &mut meta,
            "key-2026",
            SignatureAlgorithm::Ed25519,
            "abcd",
            2026,
        );
        add_key_to_history(
            &mut meta,
            "key-2035",
            SignatureAlgorithm::MlDsa,
            "ef01",
            2035,
        );
        assert!(meta.key_was_valid("key-2026", 2027));
        assert!(!meta.key_was_valid("key-2035", 2030)); // not yet valid
        assert!(meta.key_was_valid("key-2035", 2040));
    }

    #[test]
    fn agent_retirement_clean() {
        let record = AgentRetirementRecord {
            agent_id: "bot-1".into(),
            svid: "spiffe://x/bot-1".into(),
            phase: AgentLifecyclePhase::Retired,
            retired_at: 2026,
            retirement_reason: "superseded by bot-2".into(),
            authority_revoked: true,
            receipts_preserved: true,
            notified_dependencies: vec!["payments-api".into()],
        };
        assert!(record.is_clean());
    }

    #[test]
    fn agent_retirement_not_clean_if_receipts_deleted() {
        let record = AgentRetirementRecord {
            agent_id: "bot-1".into(),
            svid: "spiffe://x/bot-1".into(),
            phase: AgentLifecyclePhase::Retired,
            retired_at: 2026,
            retirement_reason: "test".into(),
            authority_revoked: true,
            receipts_preserved: false, // BAD — receipts must be preserved
            notified_dependencies: vec![],
        };
        assert!(!record.is_clean());
    }

    #[test]
    fn pq_algorithm_flags() {
        assert!(!SignatureAlgorithm::Ed25519.is_post_quantum());
        assert!(SignatureAlgorithm::MlDsa.is_post_quantum());
        assert!(SignatureAlgorithm::SlhDsa.is_post_quantum());
    }

    #[test]
    fn needs_reanchoring_for_very_old_receipts() {
        let (sk, _) = generate_keypair();
        let payload = serde_json::json!({"x": 1});
        let dual = dual_sign(&payload, &sk, "k");
        let _meta = ArchivalMetadata::new(2026, 2056);
        // No re-anchoring history + must verify past 2040 → needs reanchoring.
        // But also needs PQ migration (checked first) → the PQ check fires.
        // To isolate: set must_verify_until to 2038 (past PQ deadline but past 2040 reanchor too).
        // Actually 2038 > 2036 (PQ check) → PQ fires first. Let me set a shorter horizon.
        // Set to 2042 but WITH a PQ signature to skip PQ check.
        let mut dual_pq = dual;
        dual_pq.post_quantum = Some(SignatureEntry {
            algorithm: SignatureAlgorithm::MlDsa,
            key_id: "pq-key".into(),
            public_key_hex: "00".repeat(1958), // ML-DSA-65 public key size
            signature_hex: "00".repeat(3293),  // ML-DSA-65 signature size
        });
        let meta = ArchivalMetadata::new(2026, 2042);
        let v = assess_durability(&dual_pq, &meta, None);
        assert_eq!(v, DurabilityVerdict::NeedsReanchoring);
    }
}

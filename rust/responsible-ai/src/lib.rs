//! RA1 Responsible-AI receipt fields (gap-analysis §3D.4, §9.9).
//!
//! The receipt becomes a responsible-AI record, not just an authority record. Four mandatory
//! fields added to every receipt:
//!
//! 1. **bias_audit** — was a bias check run? what was the score? which protected classes?
//! 2. **right_to_explanation** — a human-readable explanation of the decision, GDPR Art. 22.
//! 3. **carbon_footprint** — energy/CO2 of this action (green AI accountability).
//! 4. **dynamic_consent** — was the data subject's consent current at action time?
//!
//! The asymmetry: advisory signals may contribute to Deny, never to Allow (spec 01 §3.4).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const RA_VERSION: &str = "warrantor-responsible-ai/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Bias audit (spec gap-analysis §3D.4)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BiasAudit {
    /// Whether a bias check was run for this action.
    pub checked: bool,
    /// The bias score (0.0 = no bias detected, 1.0 = maximum bias). 0.0 if not checked.
    pub score: f64,
    /// Which protected classes were evaluated (e.g. ["gender", "race", "age"]).
    #[serde(default)]
    pub protected_classes: Vec<String>,
    /// The bias checker's model digest (accountability).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checker_model_digest: Option<String>,
}

impl Default for BiasAudit {
    fn default() -> Self {
        Self { checked: false, score: 0.0, protected_classes: vec![], checker_model_digest: None }
    }
}

impl BiasAudit {
    /// Whether the bias score exceeds the deny threshold (advisory → may deny, never allow).
    #[must_use]
    pub fn exceeds_threshold(&self, threshold: f64) -> bool {
        self.checked && self.score > threshold
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Right to explanation (GDPR Art. 22)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RightToExplanation {
    /// Human-readable explanation of the decision (plain language).
    pub explanation: String,
    /// The main factors that influenced the decision.
    #[serde(default)]
    pub key_factors: Vec<String>,
    /// Whether the data subject has a right to human review of this decision.
    pub human_review_available: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Carbon/energy footprint
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CarbonFootprint {
    /// Energy consumed in watt-hours for this action.
    pub energy_wh: f64,
    /// Estimated CO2 in grams (based on the grid's carbon intensity).
    pub co2_grams: f64,
    /// The compute region (affects carbon intensity).
    pub region: String,
    /// The model's reported energy efficiency (wh per 1k tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_efficiency_wh_per_1k: Option<f64>,
}

impl Default for CarbonFootprint {
    fn default() -> Self {
        Self { energy_wh: 0.0, co2_grams: 0.0, region: "unknown".into(), model_efficiency_wh_per_1k: None }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Dynamic consent
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    /// Consent explicitly given at or after the action's timestamp.
    Granted,
    /// Consent explicitly withdrawn.
    Withdrawn,
    /// No consent record found.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DynamicConsent {
    pub state: ConsentState,
    /// When consent was last granted (if ever).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<u64>,
    /// The scope of consent (e.g. "marketing", "healthcare-treatment").
    pub scope: String,
}

impl DynamicConsent {
    #[must_use]
    pub fn is_current(&self, action_timestamp: u64) -> bool {
        match self.state {
            ConsentState::Granted => self.granted_at.map_or(false, |g| g <= action_timestamp),
            _ => false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The RA1 block — attaches to every receipt
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponsibleAiBlock {
    pub bias_audit: BiasAudit,
    pub right_to_explanation: RightToExplanation,
    pub carbon_footprint: CarbonFootprint,
    pub dynamic_consent: DynamicConsent,
}

impl Default for ResponsibleAiBlock {
    fn default() -> Self {
        Self {
            bias_audit: BiasAudit::default(),
            right_to_explanation: RightToExplanation {
                explanation: "No explanation provided".into(),
                key_factors: vec![],
                human_review_available: false,
            },
            carbon_footprint: CarbonFootprint::default(),
            dynamic_consent: DynamicConsent {
                state: ConsentState::Unknown,
                granted_at: None,
                scope: "unspecified".into(),
            },
        }
    }
}

/// Validate the RA1 block. Per spec 01 §3.4 (advisory asymmetry):
/// - A bias score exceeding threshold MAY contribute to a Deny, NEVER to an Allow.
/// - A missing explanation is flagged but does not block.
/// - Consent not current is flagged for review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]  // no Eq: BiasExceedsThreshold carries f64
#[serde(rename_all = "snake_case")]
pub enum RaValidationResult {
    Valid,
    BiasExceedsThreshold { score: f64 },
    ConsentNotCurrent,
    MissingExplanation,
}

#[must_use]
pub fn validate_ra_block(block: &ResponsibleAiBlock, action_timestamp: u64, bias_threshold: f64) -> Vec<RaValidationResult> {
    let mut findings: Vec<RaValidationResult> = vec![RaValidationResult::Valid];

    // Advisory asymmetry: bias exceeding threshold is a finding (may contribute to deny).
    if block.bias_audit.exceeds_threshold(bias_threshold) {
        findings.push(RaValidationResult::BiasExceedsThreshold { score: block.bias_audit.score });
    }

    // Consent not current.
    if !block.dynamic_consent.is_current(action_timestamp) && block.dynamic_consent.state != ConsentState::Unknown {
        findings.push(RaValidationResult::ConsentNotCurrent);
    }

    // Missing explanation.
    if block.right_to_explanation.explanation.is_empty() || block.right_to_explanation.explanation == "No explanation provided" {
        findings.push(RaValidationResult::MissingExplanation);
    }

    findings
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed RA1 receipt attachment
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedRaBlock {
    pub block: ResponsibleAiBlock,
    pub action_id: String,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

#[derive(Debug, Error)]
pub enum RaError {
    #[error("responsible-AI: {0}")]
    RaErr(String),
}

fn canonical_block(block: &ResponsibleAiBlock, action_id: &str) -> String {
    let combined = serde_json::json!({"block": block, "action_id": action_id});
    let v = serde_json::to_value(&combined).expect("serializes");
    let v = canonicalize_value(&v);
    serde_json::to_string(&v).expect("canonical serializes")
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

pub fn sign_ra_block(block: ResponsibleAiBlock, action_id: &str, key: &SigningKey) -> SignedRaBlock {
    let canonical = canonical_block(&block, action_id);
    let sig: Signature = key.sign(canonical.as_bytes());
    let verifying = key.verifying_key();
    SignedRaBlock {
        block,
        action_id: action_id.to_string(),
        signature_algorithm: "Ed25519".into(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_ra_block(signed: &SignedRaBlock) -> Result<(), RaError> {
    let pk_bytes = hex::decode(&signed.signature_public_key)
        .map_err(|e| RaError::RaErr(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(RaError::RaErr("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| RaError::RaErr(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&signed.signature_value)
        .map_err(|e| RaError::RaErr(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(RaError::RaErr("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_block(&signed.block, &signed.action_id);
    vkey
        .verify(canonical.as_bytes(), &sig)
        .map_err(|_| RaError::RaErr("Ed25519 signature does not verify".into()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
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
        if hex.len() % 2 != 0 {
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

    fn clean_block() -> ResponsibleAiBlock {
        ResponsibleAiBlock {
            bias_audit: BiasAudit { checked: true, score: 0.1, protected_classes: vec!["gender".into()], checker_model_digest: Some("sha256:checker".into()) },
            right_to_explanation: RightToExplanation { explanation: "The action was authorized because policy P42 permits it.".into(), key_factors: vec!["policy_p42".into()], human_review_available: true },
            carbon_footprint: CarbonFootprint { energy_wh: 0.5, co2_grams: 0.2, region: "us-west-2".into(), model_efficiency_wh_per_1k: Some(0.01) },
            dynamic_consent: DynamicConsent { state: ConsentState::Granted, granted_at: Some(1000), scope: "data-processing".into() },
        }
    }

    #[test]
    fn clean_block_validates() {
        let findings = validate_ra_block(&clean_block(), 1500, 0.5);
        assert!(findings.iter().all(|f| *f == RaValidationResult::Valid));
    }

    #[test]
    fn bias_exceeding_threshold_flagged() {
        let mut b = clean_block();
        b.bias_audit.score = 0.8;
        let findings = validate_ra_block(&b, 1500, 0.5);
        assert!(findings.iter().any(|f| matches!(f, RaValidationResult::BiasExceedsThreshold { .. })));
    }

    #[test]
    fn bias_below_threshold_not_flagged() {
        let mut b = clean_block();
        b.bias_audit.score = 0.3;
        b.bias_audit.checked = true;
        let findings = validate_ra_block(&b, 1500, 0.5);
        assert!(!findings.iter().any(|f| matches!(f, RaValidationResult::BiasExceedsThreshold { .. })));
    }

    #[test]
    fn consent_not_current_flagged() {
        let mut b = clean_block();
        b.dynamic_consent = DynamicConsent { state: ConsentState::Withdrawn, granted_at: Some(500), scope: "x".into() };
        let findings = validate_ra_block(&b, 1500, 0.5);
        assert!(findings.iter().any(|f| *f == RaValidationResult::ConsentNotCurrent));
    }

    #[test]
    fn missing_explanation_flagged() {
        let mut b = clean_block();
        b.right_to_explanation.explanation = "No explanation provided".into();
        let findings = validate_ra_block(&b, 1500, 0.5);
        assert!(findings.iter().any(|f| *f == RaValidationResult::MissingExplanation));
    }

    #[test]
    fn consent_is_current() {
        let c = DynamicConsent { state: ConsentState::Granted, granted_at: Some(1000), scope: "x".into() };
        assert!(c.is_current(1500));
        assert!(!c.is_current(500)); // action before consent granted
    }

    #[test]
    fn sign_and_verify() {
        let (sk, _) = generate_keypair();
        let signed = sign_ra_block(clean_block(), "action-1", &sk);
        verify_ra_block(&signed).expect("verifies");
    }

    #[test]
    fn tampered_block_fails() {
        let (sk, _) = generate_keypair();
        let mut signed = sign_ra_block(clean_block(), "action-1", &sk);
        signed.block.bias_audit.score = 0.99;
        assert!(verify_ra_block(&signed).is_err());
    }

    #[test]
    fn default_block_has_sensible_defaults() {
        let b = ResponsibleAiBlock::default();
        assert!(!b.bias_audit.checked);
        assert_eq!(b.carbon_footprint.region, "unknown");
        assert_eq!(b.dynamic_consent.state, ConsentState::Unknown);
    }

    #[test]
    fn bias_exceeds_threshold_method() {
        let b = BiasAudit { checked: true, score: 0.7, protected_classes: vec![], checker_model_digest: None };
        assert!(b.exceeds_threshold(0.5));
        assert!(!b.exceeds_threshold(0.8));
    }
}

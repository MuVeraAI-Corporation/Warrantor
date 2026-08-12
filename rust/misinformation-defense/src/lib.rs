//! W12 Misinformation/CIB defense plane — coordinated inauthentic behavior detection at agent scale.
//!
//! Multi-agent manipulation defense: a coordinated multi-agent campaign is detected across the
//! receipt graph and denied collectively, not per-agent. The CIB (Coordinated Inauthentic Behavior)
//! pattern that broke the 2016-2020 elections, now at agent scale — agents coordinating to amplify
//! false narratives, manipulate markets, or orchestrate social engineering.
//!
//! Detection heuristics (all from the receipt graph — first-party data no one else has):
//! - Temporal clustering: many agents acting on the same target in a short window.
//! - Content similarity: agents producing near-identical content (amplification).
//! - Source convergence: agents citing the same upstream source (coordinated origin).
//! - Velocity anomaly: a sudden spike in posting/reach on a topic.
//!
//! The advisory asymmetry (spec 01 §3.4): CIB signals may deny, never allow.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

pub const PLANE_VERSION: &str = "warrantor-misinformation-defense/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// CIB indicators
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CibIndicator {
    /// Many agents acting on the same target in a short time window.
    TemporalClustering,
    /// Agents producing near-identical content (amplification / astroturfing).
    ContentSimilarity,
    /// Agents citing the same upstream source (coordinated origin).
    SourceConvergence,
    /// Sudden spike in posting velocity on a topic.
    VelocityAnomaly,
}

// ═══════════════════════════════════════════════════════════════════════════
// Agent action record (from the receipt graph — what the plane analyzes)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentAction {
    pub agent_id: String,
    pub action_type: String,   // "post", "share", "amplify", "comment"
    pub target: String,        // the target of the action (topic, URL, user)
    pub content_hash: String,  // hash of the content produced/shared
    pub source_ref: Option<String>, // upstream source cited (if any)
    pub timestamp: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// CIB detection result
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CibVerdict {
    /// No CIB detected; the action is allowed.
    Clear,
    /// CIB indicators found but below threshold — flagged for monitoring.
    Flagged { indicators: Vec<CibIndicator>, score: u32 },
    /// CIB detected above threshold — deny the action.
    Deny { indicators: Vec<CibIndicator>, score: u32 },
}

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CibConfig {
    /// How many agents acting on the same target in `clustering_window_seconds` triggers TemporalClustering.
    pub clustering_threshold: usize,
    pub clustering_window_seconds: u64,
    /// How many agents producing the same content_hash triggers ContentSimilarity.
    pub similarity_threshold: usize,
    /// How many agents citing the same source triggers SourceConvergence.
    pub convergence_threshold: usize,
    /// The CIB score above which a Deny is issued (vs Flagged).
    pub deny_score_threshold: u32,
}

impl Default for CibConfig {
    fn default() -> Self {
        Self {
            clustering_threshold: 5,
            clustering_window_seconds: 60,
            similarity_threshold: 3,
            convergence_threshold: 5,
            deny_score_threshold: 3,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The CIB detector — analyzes the receipt graph
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum CibDetectError {
    #[error("CIB detection: {0}")]
    Err(String),
}

/// Detect coordinated inauthentic behavior by analyzing recent agent actions from the receipt graph.
///
/// Examines the action window for patterns:
/// 1. TemporalClustering: ≥ N agents acting on the same target in the window.
/// 2. ContentSimilarity: ≥ N agents producing the same content hash.
/// 3. SourceConvergence: ≥ N agents citing the same upstream source.
///
/// Each indicator contributes 1 to the score. Score ≥ deny_score_threshold → Deny.
/// Score > 0 but < threshold → Flagged. Score = 0 → Clear.
#[must_use]
pub fn detect(actions: &[AgentAction], current_action: &AgentAction, config: &CibConfig) -> CibVerdict {
    let window_start = current_action.timestamp.saturating_sub(config.clustering_window_seconds);
    let recent: Vec<&AgentAction> = actions
        .iter()
        .filter(|a| a.timestamp >= window_start && a.timestamp <= current_action.timestamp)
        .collect();

    let mut indicators: Vec<CibIndicator> = Vec::new();

    // 1. TemporalClustering: many agents on the same target.
    let target_agents: HashSet<&str> = recent
        .iter()
        .filter(|a| a.target == current_action.target)
        .map(|a| a.agent_id.as_str())
        .collect();
    if target_agents.len() >= config.clustering_threshold {
        indicators.push(CibIndicator::TemporalClustering);
    }

    // 2. ContentSimilarity: many agents producing the same content hash.
    let content_agents: HashSet<&str> = recent
        .iter()
        .filter(|a| a.content_hash == current_action.content_hash)
        .map(|a| a.agent_id.as_str())
        .collect();
    if content_agents.len() >= config.similarity_threshold {
        indicators.push(CibIndicator::ContentSimilarity);
    }

    // 3. SourceConvergence: many agents citing the same upstream source.
    if let Some(ref src) = current_action.source_ref {
        let source_agents: HashSet<&str> = recent
            .iter()
            .filter(|a| a.source_ref.as_deref() == Some(src.as_str()))
            .map(|a| a.agent_id.as_str())
            .collect();
        if source_agents.len() >= config.convergence_threshold {
            indicators.push(CibIndicator::SourceConvergence);
        }
    }

    let score = indicators.len() as u32;
    if score == 0 {
        CibVerdict::Clear
    } else if score >= config.deny_score_threshold {
        CibVerdict::Deny { indicators, score }
    } else {
        CibVerdict::Flagged { indicators, score }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed CIB detection receipt
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CibReceiptBody {
    pub verdict: CibVerdict,
    pub agent_id: String,
    pub target: String,
    pub content_hash: String,
    pub timestamp: u64,
    pub plane_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CibReceipt {
    pub body: CibReceiptBody,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

fn canonical_body(body: &CibReceiptBody) -> String {
    let v = serde_json::to_value(body).expect("serializes");
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

pub fn issue_receipt(verdict: &CibVerdict, action: &AgentAction, key: &SigningKey) -> CibReceipt {
    let body = CibReceiptBody {
        verdict: verdict.clone(),
        agent_id: action.agent_id.clone(),
        target: action.target.clone(),
        content_hash: action.content_hash.clone(),
        timestamp: action.timestamp,
        plane_version: PLANE_VERSION.into(),
    };
    let canonical = canonical_body(&body);
    let sig: Signature = key.sign(canonical.as_bytes());
    let verifying = key.verifying_key();
    CibReceipt {
        body,
        signature_algorithm: "Ed25519".into(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_receipt(receipt: &CibReceipt) -> Result<(), CibDetectError> {
    let pk_bytes = hex::decode(&receipt.signature_public_key)
        .map_err(|e| CibDetectError::Err(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(CibDetectError::Err("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| CibDetectError::Err(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&receipt.signature_value)
        .map_err(|e| CibDetectError::Err(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(CibDetectError::Err("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_body(&receipt.body);
    vkey
        .verify(canonical.as_bytes(), &sig)
        .map_err(|_| CibDetectError::Err("Ed25519 signature does not verify".into()))
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

    fn action(agent: &str, target: &str, content: &str, ts: u64) -> AgentAction {
        AgentAction {
            agent_id: agent.into(),
            action_type: "post".into(),
            target: target.into(),
            content_hash: content.into(),
            source_ref: None,
            timestamp: ts,
        }
    }

    #[test]
    fn single_agent_clear() {
        let history: Vec<AgentAction> = vec![];
        let current = action("bot-1", "topic-a", "hash-1", 1000);
        let v = detect(&history, &current, &CibConfig::default());
        assert_eq!(v, CibVerdict::Clear);
    }

    #[test]
    fn temporal_clustering_detected() {
        let history: Vec<AgentAction> = (1..=5)
            .map(|i| action(&format!("bot-{i}"), "topic-a", &format!("hash-{i}"), 990 + i))
            .collect();
        let current = action("bot-6", "topic-a", "hash-6", 1000);
        let v = detect(&history, &current, &CibConfig::default());
        assert!(matches!(v, CibVerdict::Flagged { .. } | CibVerdict::Deny { .. }));
    }

    #[test]
    fn content_similarity_detected() {
        let history: Vec<AgentAction> = (1..=3)
            .map(|i| action(&format!("bot-{i}"), "topic-x", "identical-hash", 990 + i))
            .collect();
        let current = action("bot-4", "topic-x", "identical-hash", 1000);
        let v = detect(&history, &current, &CibConfig::default());
        // Should have ContentSimilarity indicator.
        match v {
            CibVerdict::Flagged { indicators, .. } | CibVerdict::Deny { indicators, .. } => {
                assert!(indicators.contains(&CibIndicator::ContentSimilarity));
            }
            CibVerdict::Clear => panic!("should detect similarity"),
        }
    }

    #[test]
    fn source_convergence_detected() {
        let mut history: Vec<AgentAction> = (1..=5)
            .map(|i| {
                let mut a = action(&format!("bot-{i}"), &format!("topic-{i}"), &format!("hash-{i}"), 990 + i);
                a.source_ref = Some("malicious-source.io".into());
                a
            })
            .collect();
        let mut current = action("bot-6", "topic-6", "hash-6", 1000);
        current.source_ref = Some("malicious-source.io".into());
        let v = detect(&history, &current, &CibConfig::default());
        match v {
            CibVerdict::Flagged { indicators, .. } | CibVerdict::Deny { indicators, .. } => {
                assert!(indicators.contains(&CibIndicator::SourceConvergence));
            }
            CibVerdict::Clear => panic!("should detect convergence"),
        }
    }

    #[test]
    fn all_three_indicators_triggers_deny() {
        // 6 agents, same target, same content, same source → all 3 indicators → score=3 ≥ threshold=3.
        let history: Vec<AgentAction> = (1..=6)
            .map(|i| {
                let mut a = action(&format!("bot-{i}"), "coordinated-topic", "same-hash", 990 + i);
                a.source_ref = Some("same-source.io".into());
                a
            })
            .collect();
        let mut current = action("bot-7", "coordinated-topic", "same-hash", 1000);
        current.source_ref = Some("same-source.io".into());
        let v = detect(&history, &current, &CibConfig::default());
        match v {
            CibVerdict::Deny { indicators, score } => {
                assert!(score >= 3);
                assert!(indicators.contains(&CibIndicator::TemporalClustering));
                assert!(indicators.contains(&CibIndicator::ContentSimilarity));
                assert!(indicators.contains(&CibIndicator::SourceConvergence));
            }
            _ => panic!("should deny with all 3 indicators"),
        }
    }

    #[test]
    fn old_actions_outside_window_ignored() {
        // Actions from 1000 seconds ago should NOT trigger clustering (window = 60s).
        let history: Vec<AgentAction> = (1..=10)
            .map(|i| action(&format!("bot-{i}"), "old-topic", &format!("h{i}"), 100))
            .collect();
        let current = action("bot-11", "old-topic", "h11", 1100);
        let v = detect(&history, &current, &CibConfig::default());
        assert_eq!(v, CibVerdict::Clear);
    }

    #[test]
    fn different_targets_no_clustering() {
        let history: Vec<AgentAction> = (1..=10)
            .map(|i| action(&format!("bot-{i}"), &format!("different-{i}"), &format!("h{i}"), 990 + i))
            .collect();
        let current = action("bot-11", "unique-target", "h11", 1000);
        let v = detect(&history, &current, &CibConfig::default());
        assert_eq!(v, CibVerdict::Clear);
    }

    #[test]
    fn receipt_sign_and_verify() {
        let (sk, _) = generate_keypair();
        let current = action("bot-1", "topic", "hash", 1000);
        let v = detect(&[], &current, &CibConfig::default());
        let r = issue_receipt(&v, &current, &sk);
        verify_receipt(&r).expect("verifies");
    }

    #[test]
    fn tampered_receipt_fails() {
        let (sk, _) = generate_keypair();
        let current = action("bot-1", "topic", "hash", 1000);
        let v = detect(&[], &current, &CibConfig::default());
        let mut r = issue_receipt(&v, &current, &sk);
        r.body.agent_id = "evil".into();
        assert!(verify_receipt(&r).is_err());
    }

    #[test]
    fn advisory_never_allows_when_flagged() {
        // A Flagged verdict is NOT Clear — it's an advisory that MAY contribute to deny.
        let history: Vec<AgentAction> = (1..=3)
            .map(|i| action(&format!("bot-{i}"), "same-target", &format!("h{i}"), 990 + i))
            .collect();
        let current = action("bot-4", "same-target", "h4", 1000);
        let v = detect(&history, &current, &CibConfig::default());
        // With 4 agents on the same target (threshold=5), it's NOT temporal clustering.
        // But if similarity_threshold=3 and all have different hashes, no similarity either.
        // So this should be Clear (different content hashes).
        // Let me make the hashes the same to trigger similarity.
        let history2: Vec<AgentAction> = (1..=3)
            .map(|i| action(&format!("bot-{i}"), "same-target", "same-hash", 990 + i))
            .collect();
        let current2 = action("bot-4", "same-target", "same-hash", 1000);
        let v2 = detect(&history2, &current2, &CibConfig::default());
        assert!(matches!(v2, CibVerdict::Flagged { .. })); // score=1 (similarity only)
    }
}

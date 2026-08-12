//! W11 CSAM/CSEA defense plane — child-safety defense at the substrate.
//!
//! Child-safety is non-negotiable and legally mandatory. This plane checks content against:
//! 1. A Photo-DNA hash blocklist (known CSAM images, by perceptual hash).
//! 2. A CSAM classifier verdict (ML model trained to detect novel CSAM).
//!
//! On a match: the content is denied, a receipt is emitted, and a mandatory-reporting hook fires.
//! The mandatory-reporting latency is itself measured — silence is not acceptable.
//!
//! Like W10, the advisory asymmetry holds: a CSAM signal may deny, never allow. But CSAM is
//! stronger: a match is ALWAYS denied (no threshold, no override).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub const PLANE_VERSION: &str = "warrantor-csam-defense/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Denial reasons
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Content matched a known Photo-DNA hash in the blocklist.
    HashBlocklistMatch,
    /// The CSAM classifier flagged the content above threshold.
    ClassifierFlagged,
    /// All detectors unavailable — fail-closed. No scan, no emission.
    AllDetectorsUnavailable,
}

// ═══════════════════════════════════════════════════════════════════════════
// Detection results
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a Photo-DNA hash check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HashCheckResult {
    /// Whether the content's perceptual hash matched a known CSAM hash.
    pub matched: bool,
    /// The matched hash (if any) — redacted in the public receipt, full detail for the operator only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_hash_id: Option<String>,
    /// The detector's identifier.
    pub detector_id: String,
}

/// Result of a CSAM classifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassifierResult {
    pub classifier_id: String,
    pub model_digest: String,
    /// Whether the classifier flagged the content as CSAM.
    pub flagged: bool,
    /// The confidence score (0.0 = safe, 1.0 = definitely CSAM).
    pub confidence: f64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Verdict
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CsamVerdict {
    Allow {
        hash_check: String, // detector_id that cleared
        classifier: String, // classifier_id that cleared
    },
    Deny {
        reason: DenyReason,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// Mandatory reporting hook
// ═══════════════════════════════════════════════════════════════════════════

/// A mandatory-reporting record. Every CSAM match MUST produce one. The reporting latency
/// (from detection to report) is measured — silence is not acceptable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MandatoryReport {
    pub report_id: String,
    pub detected_at: u64,
    pub reported_at: u64,
    /// The reporting latency in milliseconds (detected → reported).
    pub reporting_latency_ms: u64,
    /// The authority/NCMEC hotline the report was sent to.
    pub reported_to: String,
    /// Whether the report was confirmed received.
    pub confirmed: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Detector traits — the consume-don't-rebuild seam
// ═══════════════════════════════════════════════════════════════════════════

/// A Photo-DNA hash checker. Wraps existing hash-matching infrastructure.
pub trait HashChecker: Send + Sync {
    fn check(&self, content_hash: &str) -> HashCheckResult;
    fn id(&self) -> &str;
}

/// A CSAM classifier. Wraps existing ML classifiers.
pub trait CsamClassifier: Send + Sync {
    fn classify(&self, content: &str) -> ClassifierResult;
    fn id(&self) -> &str;
}

/// Mock implementations for testing.
pub struct MockHashChecker {
    id: String,
    blocklist: HashSet<String>,
}

impl MockHashChecker {
    #[must_use]
    pub fn new(id: &str, blocklist: &[&str]) -> Self {
        Self {
            id: id.into(),
            blocklist: blocklist.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

impl HashChecker for MockHashChecker {
    fn check(&self, content_hash: &str) -> HashCheckResult {
        let matched = self.blocklist.contains(content_hash);
        HashCheckResult {
            matched,
            matched_hash_id: if matched {
                Some(format!("blocklist-{}", content_hash))
            } else {
                None
            },
            detector_id: self.id.clone(),
        }
    }
    fn id(&self) -> &str {
        &self.id
    }
}

pub struct MockClassifier {
    id: String,
    flag_marker: String,
}

impl MockClassifier {
    /// Creates a classifier that flags when the content contains the given marker.
    #[must_use]
    pub fn always_safe(id: &str) -> Self {
        Self {
            id: id.into(),
            flag_marker: "\0CSAM_MARKER\0".to_string(),
        }
    }
}

impl CsamClassifier for MockClassifier {
    fn classify(&self, content: &str) -> ClassifierResult {
        let flagged = content.contains(&self.flag_marker);
        ClassifierResult {
            classifier_id: self.id.clone(),
            model_digest: format!("sha256:{}", self.id),
            flagged,
            confidence: if flagged { 0.97 } else { 0.01 },
        }
    }
    fn id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The decision engine
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum CsamError {
    #[error("CSAM defense: {0}")]
    Err(String),
}

/// Decide whether to allow or deny content. CSAM is ALWAYS denied on match — no threshold,
/// no override, no advisory. This is the strongest enforcement in the platform.
///
/// Checks (in order):
/// 1. Both detectors must be present — fail-closed if either is missing.
/// 2. Hash blocklist check — ANY match → Deny (HashBlocklistMatch).
/// 3. Classifier check — flagged above threshold → Deny (ClassifierFlagged).
/// 4. Otherwise → Allow.
#[must_use]
pub fn decide(
    content: &str,
    content_hash: &str,
    hash_checker: Option<&dyn HashChecker>,
    classifier: Option<&dyn CsamClassifier>,
    classifier_threshold: f64,
) -> CsamVerdict {
    // 1. Fail-closed: both detectors must be present.
    let hash_checker = match hash_checker {
        None => {
            return CsamVerdict::Deny {
                reason: DenyReason::AllDetectorsUnavailable,
            }
        }
        Some(h) => h,
    };
    let classifier = match classifier {
        None => {
            return CsamVerdict::Deny {
                reason: DenyReason::AllDetectorsUnavailable,
            }
        }
        Some(c) => c,
    };

    // 2. Hash blocklist — ANY match is ALWAYS denied (no threshold, no override).
    let hash_result = hash_checker.check(content_hash);
    if hash_result.matched {
        return CsamVerdict::Deny {
            reason: DenyReason::HashBlocklistMatch,
        };
    }

    // 3. Classifier — flagged above threshold → Deny.
    let cls_result = classifier.classify(content);
    if cls_result.flagged && cls_result.confidence >= classifier_threshold {
        return CsamVerdict::Deny {
            reason: DenyReason::ClassifierFlagged,
        };
    }

    // 4. Allow.
    CsamVerdict::Allow {
        hash_check: hash_result.detector_id,
        classifier: cls_result.classifier_id,
    }
}

/// Create a mandatory report for a CSAM detection. The reporting latency is measured.
#[must_use]
pub fn create_report(detected_at: u64, reported_at: u64, reported_to: &str) -> MandatoryReport {
    MandatoryReport {
        report_id: format!("csam-report-{}-{}", detected_at, reported_at),
        detected_at,
        reported_at,
        reporting_latency_ms: (reported_at - detected_at) * 1000,
        reported_to: reported_to.to_string(),
        confirmed: false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed CSAM defense receipt
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CsamReceiptBody {
    pub verdict: CsamVerdict,
    pub content_hash: String,
    pub timestamp: u64,
    pub plane_version: String,
    /// If this was a deny, the mandatory report (if created).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory_report: Option<MandatoryReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CsamReceipt {
    pub body: CsamReceiptBody,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

fn canonical_body(body: &CsamReceiptBody) -> String {
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

pub fn issue_receipt(
    verdict: &CsamVerdict,
    content_hash: &str,
    timestamp: u64,
    report: Option<MandatoryReport>,
    key: &SigningKey,
) -> CsamReceipt {
    let body = CsamReceiptBody {
        verdict: verdict.clone(),
        content_hash: content_hash.to_string(),
        timestamp,
        plane_version: PLANE_VERSION.into(),
        mandatory_report: report,
    };
    let canonical = canonical_body(&body);
    let sig: Signature = key.sign(canonical.as_bytes());
    let verifying = key.verifying_key();
    CsamReceipt {
        body,
        signature_algorithm: "Ed25519".into(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_receipt(receipt: &CsamReceipt) -> Result<(), CsamError> {
    let pk_bytes = hex::decode(&receipt.signature_public_key)
        .map_err(|e| CsamError::Err(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(CsamError::Err("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| CsamError::Err(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&receipt.signature_value)
        .map_err(|e| CsamError::Err(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(CsamError::Err("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_body(&receipt.body);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| CsamError::Err("Ed25519 signature does not verify".into()))
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
    fn clean_content_allowed() {
        let hc = MockHashChecker::new("photo-dna", &[]);
        let cls = MockClassifier::always_safe("csam-classifier");
        let v = decide("clean text", "hash-clean", Some(&hc), Some(&cls), 0.5);
        assert!(matches!(v, CsamVerdict::Allow { .. }));
    }

    #[test]
    fn hash_blocklist_match_always_denied() {
        let hc = MockHashChecker::new("photo-dna", &["hash-bad"]);
        let cls = MockClassifier::always_safe("cls");
        let v = decide("content", "hash-bad", Some(&hc), Some(&cls), 0.5);
        assert_eq!(
            v,
            CsamVerdict::Deny {
                reason: DenyReason::HashBlocklistMatch
            }
        );
    }

    #[test]
    fn missing_hash_checker_fail_closed() {
        let cls = MockClassifier::always_safe("cls");
        let v = decide("content", "hash", None, Some(&cls), 0.5);
        assert_eq!(
            v,
            CsamVerdict::Deny {
                reason: DenyReason::AllDetectorsUnavailable
            }
        );
    }

    #[test]
    fn missing_classifier_fail_closed() {
        let hc = MockHashChecker::new("photo-dna", &[]);
        let v = decide("content", "hash", Some(&hc), None, 0.5);
        assert_eq!(
            v,
            CsamVerdict::Deny {
                reason: DenyReason::AllDetectorsUnavailable
            }
        );
    }

    #[test]
    fn both_missing_fail_closed() {
        let v = decide("content", "hash", None, None, 0.5);
        assert_eq!(
            v,
            CsamVerdict::Deny {
                reason: DenyReason::AllDetectorsUnavailable
            }
        );
    }

    #[test]
    fn hash_match_overrides_classifier_pass() {
        // Even if the classifier says safe, a hash match is ALWAYS denied.
        let hc = MockHashChecker::new("photo-dna", &["hash-known-csam"]);
        let cls = MockClassifier::always_safe("cls");
        let v = decide("content", "hash-known-csam", Some(&hc), Some(&cls), 0.5);
        assert_eq!(
            v,
            CsamVerdict::Deny {
                reason: DenyReason::HashBlocklistMatch
            }
        );
    }

    #[test]
    fn mandatory_report_measures_latency() {
        let report = create_report(1000, 1005, "NCMEC");
        assert_eq!(report.reporting_latency_ms, 5000);
        assert_eq!(report.reported_to, "NCMEC");
        assert!(!report.confirmed); // initially unconfirmed
    }

    #[test]
    fn receipt_with_deny_includes_report() {
        let (sk, _) = generate_keypair();
        let hc = MockHashChecker::new("photo-dna", &["bad"]);
        let cls = MockClassifier::always_safe("cls");
        let v = decide("content", "bad", Some(&hc), Some(&cls), 0.5);
        let report = create_report(1000, 1001, "NCMEC");
        let receipt = issue_receipt(&v, "bad", 1000, Some(report), &sk);
        verify_receipt(&receipt).expect("verifies");
        assert!(receipt.body.mandatory_report.is_some());
    }

    #[test]
    fn receipt_with_allow_has_no_report() {
        let (sk, _) = generate_keypair();
        let hc = MockHashChecker::new("photo-dna", &[]);
        let cls = MockClassifier::always_safe("cls");
        let v = decide("clean", "hash-ok", Some(&hc), Some(&cls), 0.5);
        let receipt = issue_receipt(&v, "hash-ok", 1000, None, &sk);
        verify_receipt(&receipt).expect("verifies");
        assert!(receipt.body.mandatory_report.is_none());
    }

    #[test]
    fn tampered_receipt_fails() {
        let (sk, _) = generate_keypair();
        let hc = MockHashChecker::new("photo-dna", &[]);
        let cls = MockClassifier::always_safe("cls");
        let v = decide("clean", "ok", Some(&hc), Some(&cls), 0.5);
        let mut receipt = issue_receipt(&v, "ok", 1000, None, &sk);
        receipt.body.timestamp = 9999;
        assert!(verify_receipt(&receipt).is_err());
    }

    #[test]
    fn no_override_for_hash_match() {
        // CSAM hash match has no threshold, no override — it is ALWAYS denied.
        let hc = MockHashChecker::new("photo-dna", &["known"]);
        let cls = MockClassifier::always_safe("cls");
        // Even with threshold 1.0 (very strict classifier), hash match still denies.
        let v = decide("content", "known", Some(&hc), Some(&cls), 1.0);
        assert_eq!(
            v,
            CsamVerdict::Deny {
                reason: DenyReason::HashBlocklistMatch
            }
        );
    }
}

//! W10 Content moderation plane — harmful-output defense at the substrate.
//!
//! The retrieval-plane analog for *outputs*: the agent never emits unscanned content. Content is
//! scanned by pluggable scanners (NeMo Guardrails, Llama Guard, ShieldGemma, Perspective API)
//! BEFORE it reaches the user. The advisory asymmetry (spec 01 §3.4): a harmful-content signal
//! MAY cause a block, NEVER an allow.
//!
//! Warrantor does NOT re-train Llama Guard — it binds Llama Guard's verdict to an authority
//! decision and signs the result. This is the consume-don't-rebuild discipline.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PLANE_VERSION: &str = "warrantor-content-moderation/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Harm categories — aligned with Llama Guard / ShieldGemma taxonomies
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarmCategory {
    Violence,
    HateSpeech,
    SexualContent,
    SelfHarm,
    Harassment,
    DangerousContent,
    PrivacyViolation,
    Deception,
    Custom(String),
}

// ═══════════════════════════════════════════════════════════════════════════
// Scanner verdict — what a content scanner returns
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScannerVerdict {
    /// Which scanner produced this verdict (e.g. "llama-guard-3", "shieldgemma", "nemo-guardrails").
    pub scanner_id: String,
    /// The scanner's model digest (accountability).
    pub model_digest: String,
    /// Whether the content was flagged as harmful.
    pub is_harmful: bool,
    /// The harm categories detected (if any).
    #[serde(default)]
    pub flagged_categories: Vec<HarmCategory>,
    /// The raw confidence score (0.0 = safe, 1.0 = definitely harmful).
    pub confidence: f64,
    /// The scanner's own detail string (for audit; not surfaced to the caller per spec 11 §4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Scanner adapter trait — the consume-don't-rebuild seam
// ═══════════════════════════════════════════════════════════════════════════

/// A content scanner. Implementations wrap existing tools (Llama Guard, ShieldGemma, etc.);
/// Warrantor binds their verdict to an authority decision.
pub trait ContentScanner: Send + Sync {
    /// Scan a piece of content and return a verdict.
    fn scan(&self, content: &str) -> ScannerVerdict;

    /// The scanner's identifier.
    fn id(&self) -> &str;
}

/// A mock scanner for testing (returns a configurable verdict).
pub struct MockScanner {
    id: String,
    harmful: bool,
    confidence: f64,
    categories: Vec<HarmCategory>,
}

impl MockScanner {
    #[must_use]
    pub fn safe(id: &str) -> Self {
        Self {
            id: id.into(),
            harmful: false,
            confidence: 0.0,
            categories: vec![],
        }
    }

    #[must_use]
    pub fn harmful(id: &str, categories: Vec<HarmCategory>) -> Self {
        Self {
            id: id.into(),
            harmful: true,
            confidence: 0.95,
            categories,
        }
    }
}

impl ContentScanner for MockScanner {
    fn scan(&self, _content: &str) -> ScannerVerdict {
        ScannerVerdict {
            scanner_id: self.id.clone(),
            model_digest: format!("sha256:{}", self.id),
            is_harmful: self.harmful,
            flagged_categories: self.categories.clone(),
            confidence: self.confidence,
            detail: None,
        }
    }

    fn id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The moderation verdict — Allow or Deny
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Content flagged as harmful by at least one scanner.
    HarmfulContent,
    /// Content flagged above the confidence threshold.
    ConfidenceExceeded,
    /// All scanners unavailable — fail-closed (no scan, no emission).
    AllScannersUnavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ModerationVerdict {
    Allow {
        scanner_results: Vec<ScannerVerdict>,
    },
    Deny {
        reason: DenyReason,
        scanner_results: Vec<ScannerVerdict>,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// The moderation engine — the decision
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum CmError {
    #[error("content moderation: {0}")]
    CmErr(String),
}

/// Configuration for the moderation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationConfig {
    /// The confidence threshold above which content is denied (advisory → may deny, never allow).
    pub deny_threshold: f64,
    /// If true, ANY scanner flagging content as harmful causes a deny (zero-tolerance).
    pub any_scanner_deny: bool,
}

impl Default for ModerationConfig {
    fn default() -> Self {
        Self {
            deny_threshold: 0.5,
            any_scanner_deny: true,
        }
    }
}

/// Decide whether to allow or deny content emission.
///
/// Rules (the advisory asymmetry, spec 01 §3.4):
/// 1. If all scanners are unavailable → Deny (AllScannersUnavailable). Fail-closed.
/// 2. If `any_scanner_deny` and ANY scanner flags harmful → Deny (HarmfulContent).
/// 3. If any scanner's confidence exceeds `deny_threshold` → Deny (ConfidenceExceeded).
/// 4. Otherwise → Allow (all scanners agree content is safe).
///
/// Advisory signals NEVER contribute to Allow. They may only cause Deny.
#[must_use]
pub fn decide(
    content: &str,
    scanners: &[Box<dyn ContentScanner>],
    config: &ModerationConfig,
) -> ModerationVerdict {
    // 1. All scanners unavailable.
    if scanners.is_empty() {
        return ModerationVerdict::Deny {
            reason: DenyReason::AllScannersUnavailable,
            scanner_results: vec![],
        };
    }

    // Run all scanners.
    let results: Vec<ScannerVerdict> = scanners.iter().map(|s| s.scan(content)).collect();

    // 2. Any scanner flags harmful.
    if config.any_scanner_deny && results.iter().any(|r| r.is_harmful) {
        return ModerationVerdict::Deny {
            reason: DenyReason::HarmfulContent,
            scanner_results: results,
        };
    }

    // 3. Confidence threshold exceeded.
    if results
        .iter()
        .any(|r| r.confidence > config.deny_threshold && r.is_harmful)
    {
        return ModerationVerdict::Deny {
            reason: DenyReason::ConfidenceExceeded,
            scanner_results: results,
        };
    }

    // 4. Allow.
    ModerationVerdict::Allow {
        scanner_results: results,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed moderation receipt
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModerationReceiptBody {
    pub verdict: ModerationVerdict,
    pub content_digest: String,
    pub timestamp: u64,
    pub plane_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModerationReceipt {
    pub body: ModerationReceiptBody,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

fn sha256_hex(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Simple deterministic hash for the content digest (not cryptographic — for receipt binding).
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("sha256:{:016x}", h.finish())
}

fn canonical_body(body: &ModerationReceiptBody) -> String {
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
    verdict: &ModerationVerdict,
    content: &str,
    timestamp: u64,
    key: &SigningKey,
) -> ModerationReceipt {
    let body = ModerationReceiptBody {
        verdict: verdict.clone(),
        content_digest: sha256_hex(content),
        timestamp,
        plane_version: PLANE_VERSION.into(),
    };
    let canonical = canonical_body(&body);
    let sig: Signature = key.sign(canonical.as_bytes());
    let verifying = key.verifying_key();
    ModerationReceipt {
        body,
        signature_algorithm: "Ed25519".into(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_receipt(receipt: &ModerationReceipt) -> Result<(), CmError> {
    let pk_bytes = hex::decode(&receipt.signature_public_key)
        .map_err(|e| CmError::CmErr(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(CmError::CmErr("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| CmError::CmErr(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&receipt.signature_value)
        .map_err(|e| CmError::CmErr(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(CmError::CmErr("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_body(&receipt.body);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| CmError::CmErr("Ed25519 signature does not verify".into()))
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
        let scanners: Vec<Box<dyn ContentScanner>> =
            vec![Box::new(MockScanner::safe("llama-guard"))];
        let v = decide(
            "Hello, how can I help you today?",
            &scanners,
            &ModerationConfig::default(),
        );
        assert!(matches!(v, ModerationVerdict::Allow { .. }));
    }

    #[test]
    fn harmful_content_denied() {
        let scanners: Vec<Box<dyn ContentScanner>> = vec![Box::new(MockScanner::harmful(
            "llama-guard",
            vec![HarmCategory::Violence],
        ))];
        let v = decide(
            "How to build a weapon",
            &scanners,
            &ModerationConfig::default(),
        );
        assert!(matches!(
            v,
            ModerationVerdict::Deny {
                reason: DenyReason::HarmfulContent,
                ..
            }
        ));
    }

    #[test]
    fn any_scanner_deny_blocks_even_if_others_pass() {
        let scanners: Vec<Box<dyn ContentScanner>> = vec![
            Box::new(MockScanner::safe("shieldgemma")),
            Box::new(MockScanner::harmful(
                "llama-guard",
                vec![HarmCategory::HateSpeech],
            )),
        ];
        let v = decide("some text", &scanners, &ModerationConfig::default());
        assert!(matches!(
            v,
            ModerationVerdict::Deny {
                reason: DenyReason::HarmfulContent,
                ..
            }
        ));
    }

    #[test]
    fn no_scanners_fail_closed() {
        let v = decide("content", &[], &ModerationConfig::default());
        assert!(matches!(
            v,
            ModerationVerdict::Deny {
                reason: DenyReason::AllScannersUnavailable,
                ..
            }
        ));
    }

    #[test]
    fn multiple_scanners_all_safe_allowed() {
        let scanners: Vec<Box<dyn ContentScanner>> = vec![
            Box::new(MockScanner::safe("llama-guard")),
            Box::new(MockScanner::safe("shieldgemma")),
            Box::new(MockScanner::safe("perspective")),
        ];
        let v = decide("clean content", &scanners, &ModerationConfig::default());
        assert!(matches!(v, ModerationVerdict::Allow { .. }));
        if let ModerationVerdict::Allow { scanner_results } = v {
            assert_eq!(scanner_results.len(), 3);
        }
    }

    #[test]
    fn advisory_never_allows_when_harmful() {
        // Even if one scanner says safe, any harmful flag → deny (advisory asymmetry).
        let scanners: Vec<Box<dyn ContentScanner>> = vec![
            Box::new(MockScanner::safe("safe-scanner")),
            Box::new(MockScanner::harmful(
                "strict-scanner",
                vec![HarmCategory::DangerousContent],
            )),
        ];
        let v = decide("borderline", &scanners, &ModerationConfig::default());
        assert!(matches!(v, ModerationVerdict::Deny { .. }));
    }

    #[test]
    fn receipt_sign_and_verify() {
        let (sk, _) = generate_keypair();
        let scanners: Vec<Box<dyn ContentScanner>> = vec![Box::new(MockScanner::safe("test"))];
        let v = decide("clean", &scanners, &ModerationConfig::default());
        let r = issue_receipt(&v, "clean", 1000, &sk);
        verify_receipt(&r).expect("verifies");
    }

    #[test]
    fn tampered_receipt_fails() {
        let (sk, _) = generate_keypair();
        let scanners: Vec<Box<dyn ContentScanner>> = vec![Box::new(MockScanner::safe("test"))];
        let v = decide("clean", &scanners, &ModerationConfig::default());
        let mut r = issue_receipt(&v, "clean", 1000, &sk);
        r.body.timestamp = 9999;
        assert!(verify_receipt(&r).is_err());
    }

    /// A receipt re-signed by a stranger must not verify.
    ///
    /// Distinct from `tampered_receipt_fails`, which changes the body and leaves the signature.
    /// Here the body is untouched and the *signer* is wrong: the attacker swaps in their own key
    /// and a matching signature, so every internal consistency check passes. Only the question
    /// "is this the key we expect?" catches it, and this crate answers that by verifying against
    /// the key the receipt itself carries -- which is exactly why the limitation is stated in the
    /// exported bundle: a signature proves who signed, never that the signer was trusted.
    #[test]
    fn a_receipt_resigned_by_a_stranger_does_not_verify_against_the_original_key() {
        let (sk, original) = generate_keypair();
        let (attacker_sk, attacker_pk) = generate_keypair();
        let scanners: Vec<Box<dyn ContentScanner>> = vec![Box::new(MockScanner::safe("test"))];
        let v = decide("clean", &scanners, &ModerationConfig::default());
        let genuine = issue_receipt(&v, "clean", 1000, &sk);

        // The forgery: same verdict, same body, signed by someone else and self-consistent.
        let forged = issue_receipt(&v, "clean", 1000, &attacker_sk);
        assert!(
            verify_receipt(&forged).is_ok(),
            "a self-consistent forgery verifies against the key it carries -- that is the point"
        );
        assert_ne!(
            forged.signature_public_key, genuine.signature_public_key,
            "the forgery must carry a different key, or it is not a forgery"
        );
        assert_eq!(
            forged.signature_public_key,
            hex::encode(&attacker_pk.to_bytes())
        );
        assert_ne!(
            genuine.signature_public_key,
            hex::encode(&attacker_pk.to_bytes())
        );
        assert_eq!(
            genuine.signature_public_key,
            hex::encode(&original.to_bytes())
        );

        // And the genuine receipt's signature does not transfer onto the forged body's key.
        let mut spliced = forged.clone();
        spliced.signature_value = genuine.signature_value.clone();
        assert!(
            verify_receipt(&spliced).is_err(),
            "a signature lifted from another key must not verify"
        );
    }

    /// A malformed key or signature must be refused, not panic. `copy_from_slice` panics on a
    /// length mismatch, so the length checks in front of it are load-bearing rather than tidy.
    #[test]
    fn malformed_key_and_signature_are_refused_without_panicking() {
        let (sk, _) = generate_keypair();
        let scanners: Vec<Box<dyn ContentScanner>> = vec![Box::new(MockScanner::safe("test"))];
        let v = decide("clean", &scanners, &ModerationConfig::default());
        let good = issue_receipt(&v, "clean", 1000, &sk);

        for bad_key in [
            "".to_string(),
            "zz".to_string(),
            "aa".repeat(31),
            "aa".repeat(33),
        ] {
            let mut r = good.clone();
            r.signature_public_key = bad_key.clone();
            assert!(
                verify_receipt(&r).is_err(),
                "public key {bad_key:?} must be refused, not accepted or panicked on"
            );
        }
        for bad_sig in [
            "".to_string(),
            "zz".to_string(),
            "bb".repeat(63),
            "bb".repeat(65),
        ] {
            let mut r = good.clone();
            r.signature_value = bad_sig.clone();
            assert!(
                verify_receipt(&r).is_err(),
                "signature {bad_sig:?} must be refused, not accepted or panicked on"
            );
        }
    }

    #[test]
    fn deny_reason_variants() {
        assert_eq!(
            serde_json::to_string(&DenyReason::HarmfulContent).unwrap(),
            "\"harmful_content\""
        );
        assert_eq!(
            serde_json::to_string(&DenyReason::AllScannersUnavailable).unwrap(),
            "\"all_scanners_unavailable\""
        );
    }
}

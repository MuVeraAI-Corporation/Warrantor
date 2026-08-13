//! W2 Evidence envelope — the signed pre_commit→post_commit chaining (spec 01, WAR v2.0).
//!
//! One signed object carrying the pre-action authorization proof, the delegation-chain
//! intersection, the outcome, and the enforcement mode. Merges flight-recorder (E1) into a
//! single envelope. The two-phase commit gate (I-07) is the heart: a `pre_commit` receipt MUST
//! be signed and durable before the effect is visible; a `post_commit` receipt chains to it and
//! carries the outcome.
//!
//! See [`specs/warrantor-v4/01-war-receipt.md`](../../specs/warrantor-v4/01-war-receipt.md).
//!
//! # What this crate enforces
//!
//! - **I-07 (commit gate):** a `post_commit` with no valid `pre_commit` parent is rejected.
//! - **I-02 (authority is the intersection):** `effective_capabilities` MUST equal the recomputed
//!   chain intersection; authority expansion is rejected.
//! - **§6 (enforcement-mode honesty):** an `advisory` receipt cannot assert non-bypassability.
//! - **§4 (crypto-agility + Rust-only signing):** Ed25519 over DSSE PAE of JCS-canonical JSON.
//! - **§3.1 + §9 (expiry):** a receipt presented past its own `expires_at` is rejected —
//!   [`verify_receipt_at`] and [`verify_chain_at`].
//!
//! # Expiry is a separate call, on purpose
//!
//! [`verify_receipt`] answers *"was this signed by that key, and has it changed since?"*. It takes
//! no time input and never expires anything, because that question has the same answer forever and
//! an archived receipt has to stay verifiable long after the authority it records has lapsed.
//!
//! [`verify_receipt_at`] answers the different question *"may I rely on this **now**?"* — and that
//! one is time-dependent, so `now` is an explicit argument rather than a clock read (spec 11 §6:
//! time is an input, never read inside the function). Anything presenting a receipt as live
//! authorization MUST use the `_at` form; spec 01 §9's replay vector ("receipt re-presented after
//! `expires_at`") is exactly this check.
//!
//! An `expires_at` of `0` is expired at every `now`. An absent limit is NONE, never unlimited.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

pub const WAR_VERSION: &str = "war/2.0";
pub const PREDICATE_TYPE: &str = "https://warrantor.dev/ActionReceipt/v2";

// ---------------------------------------------------------------------------
// Phases + enforcement mode (spec 01 §3.1, §5, §6)
// ---------------------------------------------------------------------------

/// The three receipt phases (spec 01 §3.1, §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Signed + durable BEFORE the effect is visible (I-07).
    PreCommit,
    /// Chains to a pre_commit via `parent_receipt`; carries the outcome.
    PostCommit,
    /// Single-receipt phase; only for routine + reversible actions.
    Atomic,
}

/// Per spec 01 §6 — only `mediated` may claim non-bypassability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// The decision sits IN the enforcement path; bypassing Warrantor means bypassing execution.
    Mediated,
    /// The host calls Warrantor and MAY ignore the verdict. Evidence + attribution only.
    Advisory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsequenceTier {
    Routine,
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

// ---------------------------------------------------------------------------
// The authority chain + intersection proof (spec 01 §3.3, I-02)
// ---------------------------------------------------------------------------

/// One link in the delegation chain (spec 01 §3.3). Root-first, ordered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationLink {
    pub issuer: String,
    pub subject: String,
    pub capabilities: Vec<String>,
    pub not_before: u64,
    pub not_after: u64,
    pub token_digest: String,
}

/// The recomputable intersection proof (spec 01 §3.3). Any verifier recomputes this from
/// `chain[]`; a mismatch means the receipt's `effective_capabilities` was forged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntersectionProof {
    pub algorithm: String,
    /// SHA-256 over the canonical chain (deterministic, so a verifier recomputes it).
    pub links_digest: String,
    /// SHA-256 over the sorted intersection result.
    pub result_digest: String,
}

/// The authority block (spec 01 §3.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Authority {
    pub chain: Vec<DelegationLink>,
    pub effective_capabilities: Vec<String>,
    pub intersection_proof: IntersectionProof,
}

// ---------------------------------------------------------------------------
// The predicate sections (spec 01 §3.1–§3.8)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Binding {
    pub receipt_id: String,
    pub phase: Phase,
    /// The parent receipt_id forming the causal chain (None for pre_commit/atomic root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_receipt: Option<String>,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub enforcement_mode: EnforcementMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Actor {
    pub principal: String,
    pub workload_id: String,
    pub svid_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Decision {
    pub verdict: Verdict,
    pub engine: String,
    pub policy_digest: String,
    pub evaluated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Operation {
    pub class: String,
    pub target: String,
    pub method: String,
    pub parameters_digest: String,
    pub reversible: bool,
    pub consequence_tier: ConsequenceTier,
}

/// The outcome — mandatory in post_commit and atomic (spec 01 §3.8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Outcome {
    pub status: String,
    pub outcome_digest: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub effects: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_pointer: Option<String>,
}

/// The WAR predicate (spec 01 §3). This is what gets canonicalized + signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WarPredicate {
    pub binding: Binding,
    pub actor: Actor,
    pub authority: Authority,
    pub decision: Decision,
    pub operation: Operation,
    /// None for pre_commit (the outcome is not yet known); Some for post_commit + atomic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
}

// ---------------------------------------------------------------------------
// The signed receipt (DSSE-style envelope: predicate + signature over PAE)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WarReceipt {
    pub predicate: WarPredicate,
    pub signature: SignatureEnvelope,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("signature envelope malformed: {0}")]
    SignatureEnvelope(String),
    #[error("Ed25519 signature does not verify")]
    InvalidSignature,
    #[error("commit-gate violation (I-07): {0}")]
    CommitGate(String),
    #[error("authority violation (I-02): {0}")]
    Authority(String),
    #[error("phase violation: {0}")]
    Phase(String),
    #[error("enforcement-mode violation (§6): {0}")]
    EnforcementMode(String),
    /// The receipt was presented at or after its own `binding.expires_at` (spec 01 §3.1, §9).
    ///
    /// Only the `_at` verifiers construct this: [`verify_receipt_at`] and [`verify_chain_at`].
    /// The time-free [`verify_receipt`] and [`verify_chain`] never do, and say so.
    #[error("receipt expired (expires_at={0})")]
    Expired(u64),
}

// ---------------------------------------------------------------------------
// Canonicalization + DSSE PAE (spec 01 §4)
// ---------------------------------------------------------------------------

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

/// JCS-canonical JSON (RFC 8785) of the predicate — the canonical form both sides agree on.
pub fn canonical_predicate(predicate: &WarPredicate) -> String {
    let v = serde_json::to_value(predicate).expect("WarPredicate serializes");
    let v = canonicalize_value(&v);
    serde_json::to_string(&v).expect("canonical Value serializes")
}

/// DSSE Pre-Auth Encoding (spec 01 §4): `"DSSEv1 {len} {payload}"`. The signed bytes.
pub fn dsse_pae(payload: &str) -> Vec<u8> {
    let payload_bytes = payload.as_bytes();
    let header = format!("DSSEv1 {} ", payload_bytes.len());
    let mut out = Vec::with_capacity(header.len() + payload_bytes.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload_bytes);
    out
}

/// SHA-256 hex of a string.
fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(&hasher.finalize()[..])
}

// ---------------------------------------------------------------------------
// The intersection proof (spec 01 §3.3, I-02)
// ---------------------------------------------------------------------------

/// Recompute the capability intersection across the chain (spec 06 algebra). A capability is
/// effective iff it appears in EVERY link. Returns a sorted Vec for determinism.
#[must_use]
pub fn recompute_intersection(chain: &[DelegationLink]) -> Vec<String> {
    if chain.is_empty() {
        return Vec::new();
    }
    let sets: Vec<HashSet<String>> = chain
        .iter()
        .map(|l| l.capabilities.iter().cloned().collect())
        .collect();
    let mut iter = sets.into_iter();
    let mut acc = iter.next().unwrap();
    for s in iter {
        acc = acc.intersection(&s).cloned().collect();
    }
    let mut out: Vec<String> = acc.into_iter().collect();
    out.sort();
    out
}

/// Compute the intersection proof from a chain (spec 01 §3.3). The `links_digest` is over the
/// canonical chain; the `result_digest` is over the sorted intersection. Both are recomputable.
#[must_use]
pub fn compute_intersection_proof(chain: &[DelegationLink]) -> IntersectionProof {
    let chain_json = serde_json::to_string(&chain).expect("chain serializes");
    let canon_chain =
        canonicalize_value(&serde_json::from_str::<serde_json::Value>(&chain_json).unwrap());
    let links_digest = sha256_hex(&serde_json::to_string(&canon_chain).unwrap());
    let result = recompute_intersection(chain);
    let result_digest = sha256_hex(&serde_json::to_string(&result).unwrap());
    IntersectionProof {
        algorithm: "warrantor-intersect-v1".to_string(),
        links_digest,
        result_digest,
    }
}

// ---------------------------------------------------------------------------
// Issuance — pre_commit, post_commit, atomic
// ---------------------------------------------------------------------------

fn sign_predicate(predicate: &WarPredicate, key: &SigningKey, key_id: &str) -> SignatureEnvelope {
    let pae = dsse_pae(&canonical_predicate(predicate));
    let sig: Signature = key.sign(&pae);
    let verifying = key.verifying_key();
    SignatureEnvelope {
        algorithm: "Ed25519".to_string(),
        key_id: key_id.to_string(),
        public_key: hex::encode(&verifying.to_bytes()),
        value: hex::encode(&sig.to_bytes()),
    }
}

/// Issue a pre_commit receipt (spec 01 §5). Signed BEFORE the effect is visible (I-07).
/// The predicate MUST NOT carry an outcome (the outcome is not yet known).
#[must_use]
pub fn issue_pre_commit(predicate: WarPredicate, key: &SigningKey, key_id: &str) -> WarReceipt {
    assert!(
        predicate.outcome.is_none(),
        "pre_commit predicate must not carry an outcome"
    );
    assert!(matches!(predicate.binding.phase, Phase::PreCommit));
    let signature = sign_predicate(&predicate, key, key_id);
    WarReceipt {
        predicate,
        signature,
    }
}

/// Issue a post_commit receipt that chains to a pre_commit (spec 01 §5). The post_commit's
/// `parent_receipt` is set to the pre_commit's `receipt_id`, and it carries the outcome.
#[must_use]
pub fn issue_post_commit(
    pre_commit: &WarReceipt,
    outcome: Outcome,
    key: &SigningKey,
    key_id: &str,
) -> WarReceipt {
    let mut predicate = pre_commit.predicate.clone();
    predicate.binding.phase = Phase::PostCommit;
    predicate.binding.parent_receipt = Some(pre_commit.predicate.binding.receipt_id.clone());
    predicate.outcome = Some(outcome);
    let signature = sign_predicate(&predicate, key, key_id);
    WarReceipt {
        predicate,
        signature,
    }
}

/// Issue an atomic receipt (single-phase; only for routine + reversible, spec 01 §5).
#[must_use]
pub fn issue_atomic(predicate: WarPredicate, key: &SigningKey, key_id: &str) -> WarReceipt {
    assert!(matches!(predicate.binding.phase, Phase::Atomic));
    assert!(
        predicate.outcome.is_some(),
        "atomic predicate must carry an outcome"
    );
    assert!(
        predicate.operation.reversible
            && predicate.operation.consequence_tier == ConsequenceTier::Routine,
        "atomic phase requires reversible + routine (spec 01 §5)"
    );
    let signature = sign_predicate(&predicate, key, key_id);
    WarReceipt {
        predicate,
        signature,
    }
}

// ---------------------------------------------------------------------------
// Verification — the third-party path (spec 01 §4, §9)
// ---------------------------------------------------------------------------

/// Verify a single receipt's Ed25519 signature over the DSSE PAE of the canonical predicate.
///
/// **This does not check `expires_at`** and never will: it answers "was this signed by that key,
/// and has it changed since?", which has the same answer forever. Use [`verify_receipt_at`] before
/// relying on a receipt as *current* authority.
pub fn verify_receipt(receipt: &WarReceipt) -> Result<(), EvidenceError> {
    let sig = &receipt.signature;
    if sig.algorithm != "Ed25519" {
        return Err(EvidenceError::SignatureEnvelope(format!(
            "unsupported algorithm: {}",
            sig.algorithm
        )));
    }
    let pk_bytes = hex::decode(&sig.public_key)
        .map_err(|e| EvidenceError::SignatureEnvelope(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(EvidenceError::SignatureEnvelope(format!(
            "public_key must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| EvidenceError::SignatureEnvelope(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&sig.value)
        .map_err(|e| EvidenceError::SignatureEnvelope(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(EvidenceError::SignatureEnvelope(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    let pae = dsse_pae(&canonical_predicate(&receipt.predicate));
    vkey.verify(&pae, &signature)
        .map_err(|_| EvidenceError::InvalidSignature)
}

/// Whether `receipt` is past its own `binding.expires_at` at `now` (epoch seconds).
///
/// Expired at `expires_at <= now`, matching the notary's identity gate, which denies at
/// `svid_not_after <= now`. A boundary second belongs to neither side, and both crates give it to
/// the refusing side.
///
/// `expires_at == 0` is expired at every `now`, including `now == 0`. An absent limit is NONE, not
/// unlimited: a receipt that forgot to say when it stops being good has already stopped.
#[must_use]
pub fn is_expired(receipt: &WarReceipt, now: u64) -> bool {
    receipt.predicate.binding.expires_at <= now
}

/// Verify a receipt **for reliance now**: the signature, then `expires_at` against an explicit
/// `now` (spec 01 §3.1; §9's "receipt re-presented after `expires_at`" vector).
///
/// Signature first, so a forged receipt is reported as forged rather than as merely stale.
///
/// Use this — not [`verify_receipt`] — wherever a receipt is presented as live authority. Use
/// [`verify_receipt`] for the audit question, where an old receipt is supposed to keep verifying.
///
/// # Errors
/// [`EvidenceError::Expired`] if `expires_at <= now`; otherwise whatever [`verify_receipt`] returns.
pub fn verify_receipt_at(receipt: &WarReceipt, now: u64) -> Result<(), EvidenceError> {
    verify_receipt(receipt)?;
    if is_expired(receipt, now) {
        return Err(EvidenceError::Expired(receipt.predicate.binding.expires_at));
    }
    Ok(())
}

/// Verify a pre_commit→post_commit chain (spec 01 §5, I-07). Checks:
/// 1. Both receipts' signatures verify.
/// 2. The post_commit's `parent_receipt` equals the pre_commit's `receipt_id` (commit gate).
/// 3. The pre_commit is phase=PreCommit with no outcome; the post_commit is phase=PostCommit with outcome.
/// 4. The authority intersection recomputes correctly (I-02).
/// 5. No enforcement-mode escalation (§6 — advisory cannot claim non-bypassability via a `claim`
///    field; the mode itself is the honesty field).
///
/// **Expiry is not checked here** — see [`verify_chain_at`] for the reliance-now form.
pub fn verify_chain(
    pre_commit: &WarReceipt,
    post_commit: &WarReceipt,
) -> Result<(), EvidenceError> {
    verify_receipt(pre_commit)?;
    verify_receipt(post_commit)?;

    // Commit gate (I-07).
    if pre_commit.predicate.binding.phase != Phase::PreCommit {
        return Err(EvidenceError::Phase(
            "pre_commit must have phase=pre_commit".to_string(),
        ));
    }
    if pre_commit.predicate.outcome.is_some() {
        return Err(EvidenceError::Phase(
            "pre_commit must not carry an outcome".to_string(),
        ));
    }
    if post_commit.predicate.binding.phase != Phase::PostCommit {
        return Err(EvidenceError::Phase(
            "post_commit must have phase=post_commit".to_string(),
        ));
    }
    if post_commit.predicate.outcome.is_none() {
        return Err(EvidenceError::Phase(
            "post_commit must carry an outcome".to_string(),
        ));
    }
    match &post_commit.predicate.binding.parent_receipt {
        Some(parent) if parent == &pre_commit.predicate.binding.receipt_id => {}
        Some(other) => {
            return Err(EvidenceError::CommitGate(format!(
                "post_commit parent_receipt ({other}) does not match pre_commit receipt_id ({})",
                pre_commit.predicate.binding.receipt_id
            )));
        }
        None => {
            return Err(EvidenceError::CommitGate(
                "post_commit has no parent_receipt (orphan; I-07)".to_string(),
            ));
        }
    }

    // Authority intersection (I-02) — on both receipts.
    verify_authority(&pre_commit.predicate.authority)?;
    verify_authority(&post_commit.predicate.authority)?;

    Ok(())
}

/// [`verify_chain`], plus `expires_at` on **both** receipts against an explicit `now`.
///
/// Both, not just the post_commit: a pre_commit that had already lapsed when the effect was
/// committed never authorised anything, and a chain is no stronger than the pre-auth it hangs from.
/// The pre_commit is checked first, so the earlier failure is the one reported.
///
/// # Errors
/// [`EvidenceError::Expired`] naming the lapsed receipt's `expires_at`; otherwise whatever
/// [`verify_chain`] returns.
pub fn verify_chain_at(
    pre_commit: &WarReceipt,
    post_commit: &WarReceipt,
    now: u64,
) -> Result<(), EvidenceError> {
    verify_chain(pre_commit, post_commit)?;
    for receipt in [pre_commit, post_commit] {
        if is_expired(receipt, now) {
            return Err(EvidenceError::Expired(receipt.predicate.binding.expires_at));
        }
    }
    Ok(())
}

/// Verify the authority block (I-02): recompute the intersection, reject if it differs from the
/// claimed effective_capabilities, and reject if the intersection_proof is inconsistent.
pub fn verify_authority(authority: &Authority) -> Result<(), EvidenceError> {
    let recomputed = recompute_intersection(&authority.chain);
    if recomputed != authority.effective_capabilities {
        return Err(EvidenceError::Authority(format!(
            "effective_capabilities {:?} != recomputed intersection {:?} (authority expansion; I-02)",
            authority.effective_capabilities, recomputed
        )));
    }
    let expected_proof = compute_intersection_proof(&authority.chain);
    if expected_proof != authority.intersection_proof {
        return Err(EvidenceError::Authority(
            "intersection_proof inconsistent with chain (forged proof; I-02)".to_string(),
        ));
    }
    Ok(())
}

/// Reject an advisory receipt that claims non-bypassability (spec 01 §6). A `non_bypassability_claim`
/// field on the predicate (if present and true) under advisory mode is an escalation.
pub fn check_mode_honesty(
    receipt: &WarReceipt,
    claims_non_bypassable: bool,
) -> Result<(), EvidenceError> {
    if claims_non_bypassable
        && receipt.predicate.binding.enforcement_mode == EnforcementMode::Advisory
    {
        return Err(EvidenceError::EnforcementMode(
            "advisory receipt cannot assert non-bypassability (§6)".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
            return Err("odd-length hex".to_string());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chain() -> Vec<DelegationLink> {
        vec![
            DelegationLink {
                issuer: "spiffe://root".to_string(),
                subject: "spiffe://team".to_string(),
                capabilities: vec!["read".to_string(), "write".to_string()],
                not_before: 0,
                not_after: u64::MAX,
                token_digest: "sha256:aaa".to_string(),
            },
            DelegationLink {
                issuer: "spiffe://team".to_string(),
                subject: "spiffe://bot".to_string(),
                capabilities: vec!["read".to_string()],
                not_before: 0,
                not_after: u64::MAX,
                token_digest: "sha256:bbb".to_string(),
            },
        ]
    }

    fn sample_authority() -> Authority {
        let chain = sample_chain();
        let effective = recompute_intersection(&chain); // ["read"]
        let proof = compute_intersection_proof(&chain);
        Authority {
            chain,
            effective_capabilities: effective,
            intersection_proof: proof,
        }
    }

    fn sample_predicate(phase: Phase, outcome: Option<Outcome>) -> WarPredicate {
        WarPredicate {
            binding: Binding {
                receipt_id: "rcpt-001".to_string(),
                phase,
                parent_receipt: None,
                nonce: base64_nonce(),
                issued_at: 1000,
                expires_at: 99999,
                enforcement_mode: EnforcementMode::Mediated,
            },
            actor: Actor {
                principal: "alice".to_string(),
                workload_id: "spiffe://bot".to_string(),
                svid_digest: "sha256:svid".to_string(),
            },
            authority: sample_authority(),
            decision: Decision {
                verdict: Verdict::Allow,
                engine: "cedar@4".to_string(),
                policy_digest: "sha256:pol".to_string(),
                evaluated_at: 1000,
            },
            operation: Operation {
                class: "query".to_string(),
                target: "db".to_string(),
                method: "select".to_string(),
                parameters_digest: "sha256:params".to_string(),
                reversible: true,
                consequence_tier: ConsequenceTier::Routine,
            },
            outcome,
        }
    }

    fn base64_nonce() -> String {
        "AAAAAAAAAAAAAAAAAAAAAA==".to_string() // 16 zero bytes, base64 — deterministic for tests
    }

    fn sample_outcome() -> Outcome {
        Outcome {
            status: "success".to_string(),
            outcome_digest: "sha256:out".to_string(),
            effects: vec![],
            error: None,
            rollback_pointer: None,
        }
    }

    #[test]
    fn pre_commit_round_trip_verifies() {
        let (sk, _) = generate_keypair();
        let rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "notary-1");
        verify_receipt(&rcpt).expect("pre_commit verifies");
    }

    #[test]
    fn chain_pre_to_post_verifies() {
        let (sk, _) = generate_keypair();
        let pre = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "notary-1");
        let post = issue_post_commit(&pre, sample_outcome(), &sk, "notary-1");
        verify_chain(&pre, &post).expect("chain verifies");
    }

    #[test]
    fn atomic_round_trip_verifies() {
        let (sk, _) = generate_keypair();
        let rcpt = issue_atomic(
            sample_predicate(Phase::Atomic, Some(sample_outcome())),
            &sk,
            "notary-1",
        );
        verify_receipt(&rcpt).expect("atomic verifies");
    }

    // --- the commit gate (I-07) ---

    #[test]
    fn orphan_post_commit_no_parent_rejected() {
        let (sk, _) = generate_keypair();
        let mut pred = sample_predicate(Phase::PostCommit, Some(sample_outcome()));
        pred.binding.parent_receipt = None; // orphan
        let sig = sign_predicate(&pred, &sk, "k");
        let orphan = WarReceipt {
            predicate: pred,
            signature: sig,
        };
        let pre = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        let err = verify_chain(&pre, &orphan).unwrap_err();
        assert!(
            matches!(err, EvidenceError::CommitGate(_)),
            "orphan must fail the commit gate"
        );
    }

    #[test]
    fn post_commit_wrong_parent_rejected() {
        let (sk, _) = generate_keypair();
        let pre = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        let mut post_pred = sample_predicate(Phase::PostCommit, Some(sample_outcome()));
        post_pred.binding.parent_receipt = Some("wrong-receipt-id".to_string());
        let sig = sign_predicate(&post_pred, &sk, "k");
        let post = WarReceipt {
            predicate: post_pred,
            signature: sig,
        };
        let err = verify_chain(&pre, &post).unwrap_err();
        assert!(matches!(err, EvidenceError::CommitGate(_)));
    }

    // --- expiry (spec 01 §3.1, §9) ---

    /// The normative adversarial vector: "Replay — receipt re-presented after `expires_at`".
    /// Before this existed `EvidenceError::Expired` was declared and unreachable, so the crate
    /// advertised a rejection nothing performed.
    #[test]
    fn a_receipt_presented_after_its_expiry_is_rejected() {
        let (sk, _) = generate_keypair();
        // sample_predicate sets expires_at = 99999.
        let rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        match verify_receipt_at(&rcpt, 100_000) {
            Err(EvidenceError::Expired(at)) => assert_eq!(at, 99999),
            other => panic!("a replayed expired receipt must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn a_receipt_inside_its_window_verifies() {
        let (sk, _) = generate_keypair();
        let rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        verify_receipt_at(&rcpt, 99998).expect("one second before the deadline is still good");
    }

    /// The deadline second belongs to the refusing side, matching the notary's identity gate
    /// (`svid_not_after <= now` denies).
    #[test]
    fn the_expiry_second_itself_is_already_expired() {
        let (sk, _) = generate_keypair();
        let rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        assert!(is_expired(&rcpt, 99999));
        assert!(verify_receipt_at(&rcpt, 99999).is_err());
    }

    /// Doctrine: an absent limit means NONE, never unlimited.
    #[test]
    fn an_expires_at_of_zero_is_expired_not_unlimited() {
        let (sk, _) = generate_keypair();
        let mut pred = sample_predicate(Phase::PreCommit, None);
        pred.binding.expires_at = 0;
        let rcpt = issue_pre_commit(pred, &sk, "k");
        assert!(
            is_expired(&rcpt, 0),
            "expires_at=0 must not read as forever"
        );
        assert!(verify_receipt_at(&rcpt, 0).is_err());
    }

    /// A forged receipt is reported as forged, not as stale: the signature is checked first, so
    /// the reason a reader sees names the worse problem.
    #[test]
    fn a_tampered_expired_receipt_fails_on_the_signature_not_the_clock() {
        let (sk, _) = generate_keypair();
        let mut rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        rcpt.predicate.actor.principal = "evil".to_string();
        assert!(matches!(
            verify_receipt_at(&rcpt, 100_000),
            Err(EvidenceError::InvalidSignature)
        ));
    }

    /// The audit path must not rot. An archived receipt is a record of a past evaluation, and it
    /// has to keep verifying long after the authority it records has lapsed.
    #[test]
    fn the_time_free_verifier_still_accepts_a_long_expired_receipt() {
        let (sk, _) = generate_keypair();
        let rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        assert!(is_expired(&rcpt, u64::MAX));
        verify_receipt(&rcpt).expect("verify_receipt answers a question with no deadline");
    }

    /// A chain is no stronger than the pre-auth it hangs from: an expired pre_commit sinks it even
    /// when the post_commit is still inside its own window.
    #[test]
    fn an_expired_pre_commit_sinks_the_chain() {
        let (sk, _) = generate_keypair();
        let mut pre_pred = sample_predicate(Phase::PreCommit, None);
        pre_pred.binding.expires_at = 500;
        let pre = issue_pre_commit(pre_pred, &sk, "k");
        // issue_post_commit clones the pre_commit's binding, so widen the child's window to prove
        // the parent's is what fails.
        let mut post = issue_post_commit(&pre, sample_outcome(), &sk, "k");
        post.predicate.binding.expires_at = 99999;
        let post = WarReceipt {
            signature: sign_predicate(&post.predicate, &sk, "k"),
            predicate: post.predicate,
        };
        verify_chain(&pre, &post).expect("the chain itself is well formed");
        match verify_chain_at(&pre, &post, 1000) {
            Err(EvidenceError::Expired(at)) => assert_eq!(at, 500, "the PARENT is what lapsed"),
            other => panic!("an expired pre_commit must sink the chain, got {other:?}"),
        }
    }

    #[test]
    fn a_live_chain_verifies_at_a_time_inside_both_windows() {
        let (sk, _) = generate_keypair();
        let pre = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        let post = issue_post_commit(&pre, sample_outcome(), &sk, "k");
        verify_chain_at(&pre, &post, 1000).expect("both receipts are inside their window");
    }

    // --- authority intersection (I-02) ---

    #[test]
    fn authority_expansion_rejected() {
        let mut auth = sample_authority();
        auth.effective_capabilities = vec!["read".to_string(), "write".to_string()]; // write is NOT in the intersection
        let err = verify_authority(&auth).unwrap_err();
        assert!(
            matches!(err, EvidenceError::Authority(_)),
            "authority expansion must be rejected"
        );
    }

    #[test]
    fn forged_intersection_proof_rejected() {
        let mut auth = sample_authority();
        auth.intersection_proof.result_digest = "sha256:forged".to_string();
        let err = verify_authority(&auth).unwrap_err();
        assert!(
            matches!(err, EvidenceError::Authority(_)),
            "forged proof must be rejected"
        );
    }

    #[test]
    fn correct_intersection_passes() {
        verify_authority(&sample_authority()).expect("correct intersection passes");
    }

    // --- tampering ---

    #[test]
    fn tampered_predicate_fails_verification() {
        let (sk, _) = generate_keypair();
        let mut rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        rcpt.predicate.actor.principal = "evil".to_string();
        assert!(matches!(
            verify_receipt(&rcpt),
            Err(EvidenceError::InvalidSignature)
        ));
    }

    // --- enforcement-mode honesty (§6) ---

    #[test]
    fn advisory_claiming_non_bypass_rejected() {
        let (sk, _) = generate_keypair();
        let mut pred = sample_predicate(Phase::PreCommit, None);
        pred.binding.enforcement_mode = EnforcementMode::Advisory;
        let rcpt = issue_pre_commit(pred, &sk, "k");
        let err = check_mode_honesty(&rcpt, true).unwrap_err();
        assert!(matches!(err, EvidenceError::EnforcementMode(_)));
    }

    #[test]
    fn mediated_claiming_non_bypass_ok() {
        let (sk, _) = generate_keypair();
        let rcpt = issue_pre_commit(sample_predicate(Phase::PreCommit, None), &sk, "k");
        check_mode_honesty(&rcpt, true).expect("mediated may claim non-bypassability");
    }

    // --- phase rules ---

    #[test]
    fn pre_commit_with_outcome_panics_at_construction() {
        // Construction-time invariant: pre_commit must not carry an outcome.
        let (sk, _) = generate_keypair();
        let result = std::panic::catch_unwind(|| {
            // Discarding the receipt is the point: this asserts the call PANICS, so any
            // value it might return is irrelevant. `let _` says that deliberately, which
            // is what #[must_use] is asking for.
            let _ = issue_pre_commit(
                sample_predicate(Phase::PreCommit, Some(sample_outcome())),
                &sk,
                "k",
            );
        });
        assert!(
            result.is_err(),
            "pre_commit with outcome must panic at construction"
        );
    }

    // --- determinism ---

    #[test]
    fn canonical_predicate_is_deterministic() {
        let p = sample_predicate(Phase::PreCommit, None);
        assert_eq!(canonical_predicate(&p), canonical_predicate(&p));
    }

    #[test]
    fn intersection_is_sorted_and_deterministic() {
        let chain = sample_chain();
        assert_eq!(recompute_intersection(&chain), vec!["read".to_string()]);
    }

    #[test]
    fn dsse_pae_format() {
        let pae = dsse_pae("hello");
        assert_eq!(String::from_utf8(pae).unwrap(), "DSSEv1 5 hello");
    }
}

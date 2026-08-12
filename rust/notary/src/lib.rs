//! W1 Notary core — the narrowed trust-core decision+proof hot path.
//!
//! The one place in Warrantor where `allow` is decided. The 9-gate composite verdict function
//! (spec 11) + WAR receipt emission (spec 01/02). Implemented **once**, in Rust; Python,
//! TypeScript, and Go call it through bindings and MUST NOT re-implement any part of it
//! (spec 11 §1: *no security invariant may have two authoritative implementations*).
//!
//! # Properties (spec 11)
//!
//! - **Total, deterministic, side-effect-free** except for emitting the receipt (§1).
//! - **Nine gates, evaluated in order**, short-circuiting on the first denial (§2).
//! - **Indeterminate is denial** — no input yields `Allow` under error/timeout/unknown (§3).
//! - **Denial reasons are coarse** — they identify the gate, not the internal condition (§4).
//! - **Time is an explicit input**, never read from the clock inside the function (§6).
//!
//! See [`specs/warrantor-v4/11-verdict-function.md`](../../specs/warrantor-v4/11-verdict-function.md)
//! and [`specs/warrantor-v4/02-notary-api.md`](../../specs/warrantor-v4/02-notary-api.md).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

pub const NOTARY_VERSION: &str = "warrantor-notary/1.0";

// ---------------------------------------------------------------------------
// The 9 gates, in normative order (spec 11 §2). Order is part of the contract.
// ---------------------------------------------------------------------------

/// The nine verdict gates, in the order they MUST be evaluated. Cheap, unambiguous checks
/// precede expensive, interpretive ones (spec 11 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    /// I-12: a kill-switch is active for this scope.
    Containment = 1,
    /// I-01: SVID absent, expired, revoked, or unverifiable.
    Identity = 2,
    /// I-10: nonce reused, timestamp outside window, clock skew.
    Freshness = 3,
    /// I-02: a delegation link fails signature or validity-window checks.
    Chain = 4,
    /// I-02: requested operation not in the recomputed intersection.
    Authority = 5,
    /// I-06: a digest unverified, unsigned, or mismatched.
    Artifacts = 6,
    /// Autonomy budget exhausted or blast-radius cap exceeded.
    Budget = 7,
    /// I-04: policy engine returns deny, evaluated now.
    Policy = 8,
    /// I-08: critical action without valid, non-delegable human approval.
    Approval = 9,
}

impl Gate {
    /// All nine gates in normative order. Conformance checks the order is exactly this.
    #[must_use]
    pub fn in_order() -> [Gate; 9] {
        [
            Gate::Containment,
            Gate::Identity,
            Gate::Freshness,
            Gate::Chain,
            Gate::Authority,
            Gate::Artifacts,
            Gate::Budget,
            Gate::Policy,
            Gate::Approval,
        ]
    }
}

// ---------------------------------------------------------------------------
// The verdict — Allow or Deny. Coarse by design (spec 11 §4).
// ---------------------------------------------------------------------------

/// The decision. `Deny` carries only the failing gate — never the specific missing capability,
/// matching policy rule, or mismatched digest (spec 11 §4: an agent that learns *why* it was
/// denied learns the shape of the boundary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Verdict {
    Allow { effective_capabilities: Vec<String> },
    Deny { gate: Gate },
}

impl Verdict {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }
}

// ---------------------------------------------------------------------------
// Request + context — the inputs to the verdict function.
// ---------------------------------------------------------------------------

/// A delegated capability link in the authority chain (I-02).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationLink {
    pub delegatee_svid: String,
    pub capabilities: Vec<String>,
    pub not_before: u64,
    pub not_after: u64,
    /// Whether the link's own signature verifies. The verdict function does NOT re-verify
    /// signatures (gate 4 checks this flag); signature verification is the caller's job, once,
    /// before constructing the request. This keeps the verdict function pure + cheap (spec 11 §6).
    pub signature_verified: bool,
}

/// The actor requesting authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Actor {
    pub svid: String,
    pub svid_not_after: u64,
    pub own_capabilities: Vec<String>,
    pub delegation_chain: Vec<DelegationLink>,
}

/// How consequential the action is — gates the human-approval requirement (I-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsequenceTier {
    Routine,
    Elevated,
    Critical,
}

/// The operation being authorized.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Operation {
    pub class: String,
    pub capabilities_requested: Vec<String>,
    pub consequence_tier: ConsequenceTier,
    /// The containment scope this action belongs to (matched against active kill-switches, gate 1).
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactDigest {
    pub digest: String,
    /// Whether the artifact's digest has been independently verified. Like delegation signatures,
    /// the verification is the caller's job; the verdict function consumes the flag (gate 6).
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Approval {
    pub valid: bool,
    pub non_delegable: bool,
}

/// The action being authorized. All fields are explicit inputs (spec 11 §6: no clock reads).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerdictRequest {
    pub actor: Actor,
    pub operation: Operation,
    pub artifacts: Vec<ArtifactDigest>,
    pub nonce: String,
    /// When the request was made. Explicit, not `SystemTime::now()` (determinism).
    pub timestamp: u64,
    pub approval: Option<Approval>,
}

/// The state the verdict is evaluated against. Also fully explicit (determinism).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerdictContext {
    /// The notary's notion of now. Explicit input.
    pub now: u64,
    /// Active containment scopes (gate 1).
    pub contained_scopes: Vec<String>,
    /// Revoked SVIDs (gate 2).
    pub revoked_svids: Vec<String>,
    /// Nonces already seen (gate 3 — replay protection).
    pub seen_nonces: Vec<String>,
    /// How many seconds of clock skew / staleness is tolerated (gate 3).
    pub freshness_window_seconds: u64,
    /// Artifacts whose digests the notary has verified (gate 6).
    pub verified_artifacts: Vec<String>,
    /// Remaining autonomy budget (gate 7).
    pub budget_remaining: u64,
    /// The policy engine's decision, evaluated now against a digest-identified policy (gate 8).
    /// The verdict function consumes this; it does NOT call the engine (keeping the function pure).
    pub policy_decision: bool,
}

// ---------------------------------------------------------------------------
// The composite verdict function — spec 11 §2–§3.
// ---------------------------------------------------------------------------

/// Decide `Allow` or `Deny(gate)` for a request against a context.
///
/// Nine gates, evaluated **in order**, short-circuiting on the first denial. Indeterminate is
/// denial. Advisory signals never contribute to `Allow`. Deterministic given identical inputs.
///
/// This is the single authoritative implementation (spec 11 §1).
#[must_use]
pub fn verdict(req: &VerdictRequest, ctx: &VerdictContext) -> Verdict {
    // Gate 1 — Containment (I-12). A contained system must not spend effort adjudicating.
    if ctx.contained_scopes.contains(&req.operation.scope) {
        return Verdict::Deny {
            gate: Gate::Containment,
        };
    }

    // Gate 2 — Identity (I-01). No active identity, no action.
    if req.actor.svid.is_empty()
        || ctx.revoked_svids.contains(&req.actor.svid)
        || req.actor.svid_not_after <= ctx.now
    {
        return Verdict::Deny {
            gate: Gate::Identity,
        };
    }

    // Gate 3 — Freshness (I-10). Replay + staleness protection.
    if ctx.seen_nonces.contains(&req.nonce) {
        return Verdict::Deny {
            gate: Gate::Freshness,
        };
    }
    let skew = req
        .timestamp
        .saturating_sub(ctx.now)
        .max(ctx.now.saturating_sub(req.timestamp));
    if skew > ctx.freshness_window_seconds {
        return Verdict::Deny {
            gate: Gate::Freshness,
        };
    }

    // Gate 4 — Chain (I-02). Every delegation link's signature + validity window.
    for link in &req.actor.delegation_chain {
        if !link.signature_verified || link.not_before > ctx.now || link.not_after <= ctx.now {
            return Verdict::Deny { gate: Gate::Chain };
        }
    }

    // Gate 5 — Authority (I-02). Requested capabilities must be within the recomputed intersection.
    let effective = effective_capabilities(&req.actor);
    for cap in &req.operation.capabilities_requested {
        if !effective.contains(cap) {
            return Verdict::Deny {
                gate: Gate::Authority,
            };
        }
    }

    // Gate 6 — Artifacts (I-06). Every digest verified + provider-resolved.
    for artifact in &req.artifacts {
        if !artifact.verified || !ctx.verified_artifacts.contains(&artifact.digest) {
            return Verdict::Deny {
                gate: Gate::Artifacts,
            };
        }
    }

    // Gate 7 — Budget.
    if ctx.budget_remaining == 0 {
        return Verdict::Deny { gate: Gate::Budget };
    }

    // Gate 8 — Policy (I-04). Evaluated now; never cached across actions.
    if !ctx.policy_decision {
        return Verdict::Deny { gate: Gate::Policy };
    }

    // Gate 9 — Approval (I-08). Critical actions require valid, non-delegable human approval.
    if req.operation.consequence_tier == ConsequenceTier::Critical {
        match &req.approval {
            Some(a) if a.valid && a.non_delegable => {}
            _ => {
                return Verdict::Deny {
                    gate: Gate::Approval,
                }
            }
        }
    }

    Verdict::Allow {
        effective_capabilities: effective,
    }
}

/// The capability intersection across the actor's own capabilities and the full delegation chain
/// (spec 06 capability algebra). A capability is effective iff it appears in the actor's own set
/// AND in every link of the chain — the union trap (spec 12) is that a single link dropping a
/// capability removes it from the intersection.
#[must_use]
pub fn effective_capabilities(actor: &Actor) -> Vec<String> {
    // Start with the actor's own capabilities.
    let mut sets: Vec<HashSet<String>> = vec![actor.own_capabilities.iter().cloned().collect()];
    for link in &actor.delegation_chain {
        sets.push(link.capabilities.iter().cloned().collect());
    }
    if sets.is_empty() {
        return Vec::new();
    }
    let mut iter = sets.into_iter();
    let mut acc = iter.next().unwrap();
    for s in iter {
        acc = acc.intersection(&s).cloned().collect();
    }
    // Deterministic order (sorted) so the receipt is reproducible (spec 11 §6).
    let mut out: Vec<String> = acc.into_iter().collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// WAR receipt — the signed proof. Universally verifiable (canonical JSON + Ed25519).
// ---------------------------------------------------------------------------

/// Per spec 03 — only `mediated` may substantiate a containment claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Observed,
    Mediated,
}

/// The Ed25519 signature envelope over the receipt body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String, // hex, 32-byte Ed25519 verifying key
    pub value: String,      // hex, 64-byte signature
}

/// The body of a WAR receipt — what is canonically serialized and signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptBody {
    pub verdict: Verdict,
    pub actor_svid: String,
    pub operation_class: String,
    pub timestamp: u64,
    pub enforcement_mode: EnforcementMode,
    pub notary_version: String,
}

/// A signed WAR receipt — the proof that a verdict was reached. A third party verifies this
/// with no privileged access and no shared secret (spec 02 §2.5, spec 11 §6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WarReceipt {
    pub body: ReceiptBody,
    pub signature: SignatureEnvelope,
}

#[derive(Debug, Error)]
pub enum NotaryError {
    #[error("signature envelope malformed: {0}")]
    SignatureEnvelope(String),
    #[error("Ed25519 signature does not verify")]
    InvalidSignature,
}

/// Issue (sign) a WAR receipt for a verdict + request. The receipt is the proof; the verdict
/// function is the decision. Separating them keeps the decision pure (spec 11 §1).
pub fn issue_receipt(
    verdict_result: &Verdict,
    req: &VerdictRequest,
    enforcement_mode: EnforcementMode,
    signing_key: &SigningKey,
    key_id: &str,
) -> WarReceipt {
    let body = ReceiptBody {
        verdict: verdict_result.clone(),
        actor_svid: req.actor.svid.clone(),
        operation_class: req.operation.class.clone(),
        timestamp: req.timestamp,
        enforcement_mode,
        notary_version: NOTARY_VERSION.to_string(),
    };
    let canonical = canonical_receipt_body(&body);
    let sig: Signature = signing_key.sign(canonical.as_bytes());
    let verifying = signing_key.verifying_key();
    WarReceipt {
        body,
        signature: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            key_id: key_id.to_string(),
            public_key: hex::encode(&verifying.to_bytes()),
            value: hex::encode(&sig.to_bytes()),
        },
    }
}

/// Verify a WAR receipt: recompute canonical bytes, verify the Ed25519 signature. Any third
/// party can run this with no privileged access (spec 02 §2.5).
pub fn verify_receipt(receipt: &WarReceipt) -> Result<(), NotaryError> {
    if receipt.signature.algorithm != "Ed25519" {
        return Err(NotaryError::SignatureEnvelope(format!(
            "unsupported algorithm: {}",
            receipt.signature.algorithm
        )));
    }
    let pk_bytes = hex::decode(&receipt.signature.public_key)
        .map_err(|e| NotaryError::SignatureEnvelope(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(NotaryError::SignatureEnvelope(format!(
            "public_key must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| NotaryError::SignatureEnvelope(format!("public_key: {e}")))?;

    let sig_bytes = hex::decode(&receipt.signature.value)
        .map_err(|e| NotaryError::SignatureEnvelope(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(NotaryError::SignatureEnvelope(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let canonical = canonical_receipt_body(&receipt.body);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| NotaryError::InvalidSignature)
}

/// The receipt body's canonical SHA-256 digest — what other receipts reference when they chain
/// to this one (e.g. a post_commit receipt chains to its pre_commit).
#[must_use]
pub fn receipt_digest(body: &ReceiptBody) -> [u8; 32] {
    let canonical = canonical_receipt_body(body);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

#[must_use]
pub fn receipt_digest_hex(body: &ReceiptBody) -> String {
    hex::encode(&receipt_digest(body)[..])
}

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785-shaped) — so a third party recomputes identical bytes (spec 11 §6).
// ---------------------------------------------------------------------------

fn canonical_receipt_body(body: &ReceiptBody) -> String {
    let v = serde_json::to_value(body).expect("ReceiptBody serializes to Value");
    let v = canonicalize_value(&v);
    serde_json::to_string(&v).expect("canonical Value serializes")
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate an Ed25519 keypair using the OS RNG. For tests + notary bootstrap; production keys
/// come from KMS/HSM.
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
            return Err("odd-length hex".to_string());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests — each gate fires correctly, all-pass allows, determinism, coarse denial, receipts.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn base_actor() -> Actor {
        Actor {
            svid: "spiffe://yourcorp/agents/bot-1".to_string(),
            svid_not_after: u64::MAX,
            own_capabilities: vec!["read".to_string(), "write".to_string()],
            delegation_chain: vec![],
        }
    }

    fn base_request() -> VerdictRequest {
        VerdictRequest {
            actor: base_actor(),
            operation: Operation {
                class: "query".to_string(),
                capabilities_requested: vec!["read".to_string()],
                consequence_tier: ConsequenceTier::Routine,
                scope: "prod".to_string(),
            },
            artifacts: vec![],
            nonce: "nonce-1".to_string(),
            timestamp: 1000,
            approval: None,
        }
    }

    fn base_context() -> VerdictContext {
        VerdictContext {
            now: 1000,
            contained_scopes: vec![],
            revoked_svids: vec![],
            seen_nonces: vec![],
            freshness_window_seconds: 60,
            verified_artifacts: vec![],
            budget_remaining: 100,
            policy_decision: true,
        }
    }

    #[test]
    fn all_pass_yields_allow() {
        let v = verdict(&base_request(), &base_context());
        assert_eq!(
            v,
            Verdict::Allow {
                effective_capabilities: vec!["read".to_string(), "write".to_string()]
            }
        );
    }

    // --- each gate fires correctly (in order) ---

    #[test]
    fn gate1_containment_denies_first() {
        let mut ctx = base_context();
        ctx.contained_scopes = vec!["prod".to_string()];
        let v = verdict(&base_request(), &ctx);
        assert_eq!(
            v,
            Verdict::Deny {
                gate: Gate::Containment
            }
        );
    }

    #[test]
    fn gate2_identity_revoked_svid_denies() {
        let mut ctx = base_context();
        ctx.revoked_svids = vec!["spiffe://yourcorp/agents/bot-1".to_string()];
        assert_eq!(
            verdict(&base_request(), &ctx),
            Verdict::Deny {
                gate: Gate::Identity
            }
        );
    }

    #[test]
    fn gate2_identity_expired_svid_denies() {
        let mut req = base_request();
        req.actor.svid_not_after = 500; // expired before ctx.now=1000
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny {
                gate: Gate::Identity
            }
        );
    }

    #[test]
    fn gate3_freshness_replayed_nonce_denies() {
        let mut ctx = base_context();
        ctx.seen_nonces = vec!["nonce-1".to_string()];
        assert_eq!(
            verdict(&base_request(), &ctx),
            Verdict::Deny {
                gate: Gate::Freshness
            }
        );
    }

    #[test]
    fn gate3_freshness_stale_timestamp_denies() {
        let mut req = base_request();
        req.timestamp = 1000 + 120; // outside the 60s window
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny {
                gate: Gate::Freshness
            }
        );
    }

    #[test]
    fn gate4_chain_broken_signature_denies() {
        let mut req = base_request();
        req.actor.delegation_chain.push(DelegationLink {
            delegatee_svid: "spiffe://yourcorp/agents/bot-1".to_string(),
            capabilities: vec!["read".to_string(), "write".to_string()],
            not_before: 0,
            not_after: u64::MAX,
            signature_verified: false, // broken
        });
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny { gate: Gate::Chain }
        );
    }

    #[test]
    fn gate5_authority_outside_intersection_denies() {
        let mut req = base_request();
        req.operation.capabilities_requested = vec!["financial".to_string()]; // not in actor's set
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny {
                gate: Gate::Authority
            }
        );
    }

    #[test]
    fn gate5_authority_intersection_drops_capability_when_a_link_lacks_it() {
        // The union trap (spec 12): a chain link that lacks "write" removes it from the intersection.
        let mut req = base_request();
        req.actor.own_capabilities = vec!["read".to_string(), "write".to_string()];
        req.actor.delegation_chain.push(DelegationLink {
            delegatee_svid: "spiffe://yourcorp/agents/bot-1".to_string(),
            capabilities: vec!["read".to_string()], // drops "write"
            not_before: 0,
            not_after: u64::MAX,
            signature_verified: true,
        });
        req.operation.capabilities_requested = vec!["write".to_string()];
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny {
                gate: Gate::Authority
            },
            "write was dropped by the chain intersection"
        );
        // And read still passes the authority gate (proves it's the intersection, not a blanket deny).
        req.operation.capabilities_requested = vec!["read".to_string()];
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Allow {
                effective_capabilities: vec!["read".to_string()]
            }
        );
    }

    #[test]
    fn gate6_artifacts_unverified_digest_denies() {
        let mut req = base_request();
        req.artifacts = vec![ArtifactDigest {
            digest: "sha256:abc".to_string(),
            verified: false,
        }];
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny {
                gate: Gate::Artifacts
            }
        );
    }

    #[test]
    fn gate7_budget_exhausted_denies() {
        let mut ctx = base_context();
        ctx.budget_remaining = 0;
        assert_eq!(
            verdict(&base_request(), &ctx),
            Verdict::Deny { gate: Gate::Budget }
        );
    }

    #[test]
    fn gate8_policy_denied_denies() {
        let mut ctx = base_context();
        ctx.policy_decision = false;
        assert_eq!(
            verdict(&base_request(), &ctx),
            Verdict::Deny { gate: Gate::Policy }
        );
    }

    #[test]
    fn gate9_approval_critical_without_human_approval_denies() {
        let mut req = base_request();
        req.operation.consequence_tier = ConsequenceTier::Critical;
        req.approval = None;
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny {
                gate: Gate::Approval
            }
        );
    }

    #[test]
    fn gate9_approval_critical_with_delegable_approval_still_denies() {
        let mut req = base_request();
        req.operation.consequence_tier = ConsequenceTier::Critical;
        req.approval = Some(Approval {
            valid: true,
            non_delegable: false,
        }); // delegable → invalid for critical
        assert_eq!(
            verdict(&req, &base_context()),
            Verdict::Deny {
                gate: Gate::Approval
            }
        );
    }

    #[test]
    fn gate9_approval_critical_with_valid_non_delegable_approval_allows() {
        let mut req = base_request();
        req.operation.consequence_tier = ConsequenceTier::Critical;
        req.approval = Some(Approval {
            valid: true,
            non_delegable: true,
        });
        assert!(verdict(&req, &base_context()).is_allow());
    }

    // --- ordering: gate 1 precedes gate 2 precedes ... ---

    #[test]
    fn gates_fire_in_normative_order_short_circuit() {
        // Fail ALL gates at once; the first one (Containment) must win.
        let mut req = base_request();
        req.actor.svid = String::new(); // gate 2 would fail
        req.nonce = ctx_seen_nonce(); // gate 3 would fail
        req.operation.capabilities_requested = vec!["impossible".to_string()]; // gate 5
        req.operation.consequence_tier = ConsequenceTier::Critical; // gate 9
        let mut ctx = base_context();
        ctx.contained_scopes = vec!["prod".to_string()]; // gate 1
        ctx.revoked_svids = vec!["spiffe://x".to_string()];
        ctx.seen_nonces = vec!["seen".to_string()];
        ctx.policy_decision = false;
        ctx.budget_remaining = 0;
        assert_eq!(
            verdict(&req, &ctx),
            Verdict::Deny {
                gate: Gate::Containment
            },
            "gate 1 (Containment) must short-circuit before all others"
        );
    }

    fn ctx_seen_nonce() -> String {
        "seen".to_string()
    }

    // --- determinism ---

    #[test]
    fn verdict_is_deterministic() {
        let req = base_request();
        let ctx = base_context();
        assert_eq!(verdict(&req, &ctx), verdict(&req, &ctx));
    }

    // --- denial-reason coarseness (spec 11 §4) ---

    #[test]
    fn denial_does_not_disclose_the_missing_capability() {
        let mut req = base_request();
        req.operation.capabilities_requested = vec!["financial".to_string()];
        let v = verdict(&req, &base_context());
        match v {
            Verdict::Deny { gate } => {
                let serialized = serde_json::to_string(&gate).unwrap();
                assert!(
                    !serialized.contains("financial"),
                    "denial must not disclose the missing capability; got {serialized}"
                );
            }
            Verdict::Allow { .. } => panic!("should deny"),
        }
    }

    // --- receipts ---

    #[test]
    fn receipt_round_trip_verifies() {
        let (sk, _) = generate_keypair();
        let v = verdict(&base_request(), &base_context());
        let receipt = issue_receipt(
            &v,
            &base_request(),
            EnforcementMode::Mediated,
            &sk,
            "notary-1",
        );
        verify_receipt(&receipt).expect("freshly issued receipt verifies");
    }

    #[test]
    fn tampered_receipt_body_fails_verification() {
        let (sk, _) = generate_keypair();
        let v = verdict(&base_request(), &base_context());
        let mut receipt = issue_receipt(
            &v,
            &base_request(),
            EnforcementMode::Mediated,
            &sk,
            "notary-1",
        );
        receipt.body.actor_svid = "spiffe://evil".to_string(); // tamper AFTER signing
        assert!(matches!(
            verify_receipt(&receipt),
            Err(NotaryError::InvalidSignature)
        ));
    }

    #[test]
    fn receipt_carries_the_verdict_and_enforcement_mode() {
        let (sk, _) = generate_keypair();
        let v = verdict(&base_request(), &base_context());
        let receipt = issue_receipt(
            &v,
            &base_request(),
            EnforcementMode::Observed,
            &sk,
            "notary-1",
        );
        assert_eq!(receipt.body.verdict, v);
        assert_eq!(receipt.body.enforcement_mode, EnforcementMode::Observed);
        assert_eq!(receipt.body.notary_version, NOTARY_VERSION);
    }

    #[test]
    fn effective_capabilities_intersection_is_sorted_for_determinism() {
        let actor = Actor {
            svid: "spiffe://x".to_string(),
            svid_not_after: u64::MAX,
            own_capabilities: vec!["write".to_string(), "read".to_string(), "audit".to_string()],
            delegation_chain: vec![],
        };
        let caps = effective_capabilities(&actor);
        assert_eq!(
            caps,
            vec!["audit".to_string(), "read".to_string(), "write".to_string()]
        );
    }

    #[test]
    fn gate_order_constant_matches_spec() {
        assert_eq!(
            Gate::in_order(),
            [
                Gate::Containment,
                Gate::Identity,
                Gate::Freshness,
                Gate::Chain,
                Gate::Authority,
                Gate::Artifacts,
                Gate::Budget,
                Gate::Policy,
                Gate::Approval,
            ]
        );
    }
}

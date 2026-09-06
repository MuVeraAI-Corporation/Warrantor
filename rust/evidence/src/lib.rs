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
use thiserror::Error;
use warrantor_delegation_chain::{intersect_chain, WarrantScope, WarrantStore};

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

// ---------------------------------------------------------------------------
// The causal section (L7-01) — the route, inside the signed bytes
// ---------------------------------------------------------------------------

/// One hop of the recorded route: which effect, performed by which tool, depending on which
/// earlier hops.
///
/// # There is deliberately no `authorized` flag here
///
/// A field saying whether the hop was permitted would be a field an attacker who can sign sets to
/// `true`. [`causal_verdict`] therefore recomputes authorization from
/// `authority.effective_capabilities`, which is itself recomputed from the delegation chain by
/// [`verify_authority`] (I-02). The record carries the facts; the verdict carries the judgment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CausalStep {
    /// Position in the release order, from 1. Gated against its own position by
    /// [`causal_verdict`], because every refusal in this module names a hop by this number.
    pub index: u64,
    /// The typed handle this hop mints, e.g. `pr://staged/wrt_7f3a/1`.
    pub handle: String,
    /// The tool that performs it. Compared against the recomputed capability intersection.
    pub tool: String,
    /// Handles this hop depends on. A `Vec` rather than a set because the signed bytes are an
    /// array whose order is part of the signature; it is populated from a `BTreeSet`, so it is
    /// sorted and a verifier recomputes it byte-for-byte.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

/// The recorded route: the staged-effect DAG in release order, pinned to the log it came from.
///
/// `queue_head` is the staged log's hash-chain head, not a re-listing of the log. That is what
/// makes the section checkable against the file rather than merely internally consistent: a log
/// rewritten after this receipt was signed no longer hashes to the head inside the signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Causality {
    /// Head of the staged-effect log's hash chain at the moment the route was read.
    pub queue_head: String,
    /// How many hops the route holds. Gated against `steps.len()` by [`causal_verdict`]: a count
    /// beside a list it disagrees with is the defect this repository keeps catching in prose.
    pub step_count: u64,
    /// The hops, in release order — dependencies before dependents.
    pub steps: Vec<CausalStep>,
}

/// Why a causal verdict refused. Every variant names an index or a version, because "the chain is
/// bad" is not an auditable refusal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CausalRefusal {
    /// A hop used a tool the recomputed capability intersection does not contain. This is the
    /// "right result, wrong route" case: the outcome may be permitted and this hop is not.
    #[error(
        "hop {index} ({handle}) used tool {tool:?}, which the recomputed capability intersection \
         does not contain. The outcome may be permitted; this route is not."
    )]
    UnauthorizedHop {
        /// The hop's own recorded index.
        index: u64,
        /// The handle it minted.
        handle: String,
        /// The tool it used.
        tool: String,
    },
    /// A hop depends on a handle that no earlier hop in the recorded order minted, so the route
    /// is not a coherent order: the dependent runs before the thing it depends on exists.
    #[error(
        "hop {index} depends on {missing}, which no earlier hop in this order minted. Dependencies \
         must precede dependents, so this is not a coherent release order."
    )]
    OrderBroken {
        /// The dependent hop's own recorded index.
        index: u64,
        /// The handle it depends on and nothing earlier produced.
        missing: String,
    },
    /// A hop's recorded index is not its position in the order. Refused because every other
    /// refusal here names a hop by that number.
    #[error(
        "the hop at position {position} records index {declared}. The index is what every causal \
         refusal names, so a label that is not its position makes those refusals unreadable."
    )]
    IndexBroken {
        /// Position in `steps`, from 1.
        position: u64,
        /// The index the step recorded for itself.
        declared: u64,
    },
    /// `step_count` disagrees with the list it counts.
    #[error("the causality section declares {declared} hop(s) and carries {actual}")]
    CountMismatch {
        /// What the section says.
        declared: u64,
        /// What it holds.
        actual: u64,
    },
    /// The recorded staged-log head is not the head the reader observed, so this section describes
    /// a different state of that log than the one in front of the reader.
    #[error(
        "the causality section records staged-log head {recorded} and the log observed now is at \
         {observed}. This route describes a different state of that log."
    )]
    QueueHeadMismatch {
        /// The head inside the signature.
        recorded: String,
        /// The head the caller observed.
        observed: String,
    },
    /// There is no route in this receipt to compute a verdict over. **Not a pass.** A v1 receipt
    /// carries no causality section at all, and a verdict over it can only say so.
    #[error(
        "this receipt (predicate_version {predicate_version}) carries no causality section, so \
         there is no recorded route to compute a verdict over. Nothing about the pathway was \
         checked."
    )]
    Unrepresentable {
        /// The version the predicate declared, or `absent` when it declared none.
        predicate_version: String,
    },
    /// There **is** a route in this receipt and this build has no rule for reading it. Kept
    /// separate from [`CausalRefusal::Unrepresentable`] so neither message is ever said about the
    /// wrong record: "carries no causality section" must not be rendered for a predicate that
    /// carries one.
    #[error(
        "this receipt carries a causality section under predicate_version {predicate_version}, \
         which this build has no rule for reading. The route was not checked."
    )]
    Uninterpretable {
        /// The version the predicate declared, or `absent` when it declared none.
        predicate_version: String,
    },
}

/// The WAR predicate (spec 01 §3). This is what gets canonicalized + signed.
///
/// # Two fields, two canonical rules, one verifier
///
/// `predicate_version` and `causality` were added by Task 10.1 (L7-01). Both are `Option` with
/// `skip_serializing_if`, which is not a style choice: [`canonical_predicate`] is what every
/// archived signature was taken over, so a field that serialized as `null` or as an empty string
/// when unset would change those bytes and turn every receipt ever signed into an apparent
/// forgery. An absent field means v1, and an absent field must stay absent —
/// `rust/evidence/tests/v1_predicates_still_verify.rs` is what holds that line.
///
/// `deny_unknown_fields` closes the other half. Serde's default is to drop a key it does not know,
/// so a newer predicate handed to an older verifier would deserialize, lose the field,
/// re-canonicalize without it, and fail as [`EvidenceError::InvalidSignature`] — a version mismatch
/// reported to a third-party auditor as a forgery.
///
/// Note that the *struct* field order below is not the canonical key order: `canonicalize_value`
/// sorts keys, so `predicate_version` lands between `operation` and `outcome` in the signed bytes
/// no matter where it is declared here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WarPredicate {
    /// Which rule reads this predicate. Absent means v1 (no causal section). [`PREDICATE_TYPE`]
    /// means v2, and then `causality` is the section this build knows how to read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_version: Option<String>,
    pub binding: Binding,
    pub actor: Actor,
    pub authority: Authority,
    pub decision: Decision,
    pub operation: Operation,
    /// None for pre_commit (the outcome is not yet known); Some for post_commit + atomic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// The recorded route. `Option` rather than a defaulted empty struct because "no queue was
    /// read" and "a queue was read and it was empty" are different claims, and only the first is
    /// [`CausalRefusal::Unrepresentable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causality: Option<Causality>,
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
    /// The warrant, or an ancestor in its lineage, was revoked; nothing below it binds
    /// (L6-01: any link's revocation voids everything below it). Named by the warrant asked to
    /// bind, never by the revoked ancestor: the refusal carries only what the caller presented.
    #[error("delegation lineage revoked at or above {0}; refused at bind")]
    Revoked(String),
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
    /// The predicate declares a `predicate_version` this build has no rule for.
    ///
    /// Constructed **before** the signature is checked, on purpose. Without it a v3 predicate
    /// handed to this build would be reported as [`EvidenceError::InvalidSignature`] — telling a
    /// third-party auditor that a genuine newer receipt is a forgery.
    #[error(
        "unrecognized predicate_version {0:?}; this build reads an absent field as v1 and \
         \"https://warrantor.dev/ActionReceipt/v2\" as v2, and refuses anything else here rather \
         than reporting it as a bad signature"
    )]
    UnknownVersion(String),
    /// The predicate carries a `causality` section but declares no version, so nothing says which
    /// rule reads that section. Refused rather than read under the v1 rule, which has no rule for
    /// it at all.
    #[error(
        "the predicate carries a causality section and declares no predicate_version; nothing says \
         how to read that section, so it is refused rather than interpreted"
    )]
    UnversionedCausality,
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

/// A receipt link as the delegation algebra sees it. The link carries capabilities and a validity
/// window; it carries no resource classes and no budget, so those arrive empty and zero and can
/// never widen. `not_after` goes in as `expires_at_ms` unconverted: the algebra compares two
/// numbers and never interprets units, and both sides of every comparison come from this function.
fn scope_of(link: &DelegationLink) -> WarrantScope {
    WarrantScope {
        capabilities: link.capabilities.clone(),
        resource_classes: Vec::new(),
        expires_at_ms: link.not_after,
        budget_micros: 0,
    }
}

/// Narrow a root-first chain with the one delegation algebra
/// ([`warrantor_delegation_chain::intersect_chain`], spec 06; I-02).
///
/// Every link must be an intersection with the link before it. The first link that widens —
/// a capability its parent never held, or a later `not_after` — is refused by index, and the
/// refusal cites the invariant. The result is sorted and deduplicated so a verifier recomputes it
/// byte-for-byte.
///
/// # Errors
/// [`EvidenceError::Authority`] naming the widening link.
pub fn narrow_chain(chain: &[DelegationLink]) -> Result<Vec<String>, EvidenceError> {
    let scopes: Vec<WarrantScope> = chain.iter().map(scope_of).collect();
    let effective = intersect_chain(&scopes).map_err(|widened| {
        EvidenceError::Authority(format!(
            "link {} widens beyond its parent: {:?} (authority expansion; I-02)",
            widened.link, widened.escalation
        ))
    })?;
    let mut out = effective.capabilities;
    out.sort();
    out.dedup();
    Ok(out)
}

/// Recompute the capability intersection across the chain (spec 06 algebra). A capability is
/// effective iff every link on the way down held it. Returns a sorted Vec for determinism.
///
/// Total on purpose: `compute_intersection_proof` must be computable over *any* chain, forged or
/// not, so a verifier can compare digests. A chain with a widening link confers nothing and
/// recomputes as empty; [`verify_authority`] reports *why* through [`narrow_chain`].
#[must_use]
pub fn recompute_intersection(chain: &[DelegationLink]) -> Vec<String> {
    narrow_chain(chain).unwrap_or_default()
}

/// A stored lineage, root first, as receipt links. The root has no issuer of its own and is
/// recorded as self-issued; every later link is issued by the warrant above it. `not_before` is
/// `0` because the stored scope has no floor; `token_digest` is the warrant's content digest.
#[must_use]
pub fn chain_from_lineage(lineage: &[warrantor_delegation_chain::Warrant]) -> Vec<DelegationLink> {
    lineage
        .iter()
        .map(|warrant| DelegationLink {
            issuer: warrant.parent.clone().unwrap_or_else(|| warrant.id.clone()),
            subject: warrant.id.clone(),
            capabilities: warrant.scope.capabilities.clone(),
            not_before: 0,
            not_after: warrant.scope.expires_at_ms,
            token_digest: warrant.digest.clone(),
        })
        .collect()
}

/// Bind an authority block from a warrant's stored lineage — the moment a staged action asks
/// what it may do. Refuses if the warrant is unknown, or if it or any ancestor is revoked; the
/// chain it returns recomputes under [`verify_authority`].
///
/// # Errors
/// [`EvidenceError::Authority`] for an id the store never issued; [`EvidenceError::Revoked`] if
/// the lineage no longer stands; whatever [`narrow_chain`] returns otherwise.
pub fn bind_authority(store: &WarrantStore, warrant_id: &str) -> Result<Authority, EvidenceError> {
    let lineage = store.chain_of(warrant_id);
    if lineage.is_empty() {
        return Err(EvidenceError::Authority(format!(
            "unknown warrant {warrant_id}; nothing to bind"
        )));
    }
    if !store.is_valid(warrant_id) {
        return Err(EvidenceError::Revoked(warrant_id.to_string()));
    }
    let chain = chain_from_lineage(&lineage);
    let effective_capabilities = narrow_chain(&chain)?;
    let intersection_proof = compute_intersection_proof(&chain);
    Ok(Authority {
        chain,
        effective_capabilities,
        intersection_proof,
    })
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

/// Which canonical rule reads this predicate — checked **before** any signature, so a version this
/// build does not know is reported as a version and never as a forgery.
///
/// Two rules, one verifier, selected by a field the reader can see: an absent `predicate_version`
/// is v1 (no causal section), and [`PREDICATE_TYPE`] is v2.
///
/// # Errors
/// [`EvidenceError::UnknownVersion`] naming a version this build has no rule for;
/// [`EvidenceError::UnversionedCausality`] for a causal section with no version to read it under.
pub fn check_predicate_version(predicate: &WarPredicate) -> Result<(), EvidenceError> {
    match predicate.predicate_version.as_deref() {
        None if predicate.causality.is_some() => Err(EvidenceError::UnversionedCausality),
        None => Ok(()),
        Some(version) if version == PREDICATE_TYPE => Ok(()),
        Some(other) => Err(EvidenceError::UnknownVersion(other.to_string())),
    }
}

/// Verify a single receipt's Ed25519 signature over the DSSE PAE of the canonical predicate.
///
/// The version is read first ([`check_predicate_version`]), then the signature. Ordering matters:
/// a receipt from a newer format must be refused as "I do not know this version", never as "this
/// is forged".
///
/// **This does not check `expires_at`** and never will: it answers "was this signed by that key,
/// and has it changed since?", which has the same answer forever. Use [`verify_receipt_at`] before
/// relying on a receipt as *current* authority.
pub fn verify_receipt(receipt: &WarReceipt) -> Result<(), EvidenceError> {
    check_predicate_version(&receipt.predicate)?;
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

/// Verify the authority block (I-02): narrow the chain with the one delegation algebra (refusing
/// any link that widens), reject if the result differs from the claimed effective_capabilities,
/// and reject if the intersection_proof is inconsistent.
///
/// # Errors
/// [`EvidenceError::Authority`] for a widening link, a claimed capability set the chain does not
/// produce, or an intersection proof inconsistent with the chain.
pub fn verify_authority(authority: &Authority) -> Result<(), EvidenceError> {
    let recomputed = narrow_chain(&authority.chain)?;
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

// ---------------------------------------------------------------------------
// The causal verdict (L7-01, proof gate F-02)
// ---------------------------------------------------------------------------

/// The causal verdict: was the recorded route the authorized one?
///
/// A receipt records that an outcome was allowed. This asks the different question — whether the
/// **pathway** to it was one the warrant permitted, in an order that could actually have run. "Right
/// result, wrong route" is a violation: a three-hop chain whose middle hop uses a tool the warrant
/// never granted refuses here even when the final outcome is permitted, which the notary's single
/// question over a *set union* of staged tools cannot see.
///
/// # This is a separate verdict, never folded into `decision.verdict`
///
/// `decision.verdict` stays exactly what the notary decided. A single field could not carry both
/// without losing **which one refused**, and which one refused is the whole value here: a denial by
/// policy and a violation of the route call for opposite responses. So a `Deny` outcome over a clean
/// route returns `Ok` from this function, and an `Allow` outcome over a broken route returns `Err`.
///
/// # What it is computed from
///
/// Only the signed predicate: `authority.effective_capabilities` (itself recomputable from the
/// chain by [`verify_authority`]) and the ordering relation among `causality.steps`. Nothing is
/// taken on the record's word — there is no `authorized` flag for a re-signer to flip.
///
/// # What it does not establish
///
/// That the recorded route is the route the agent took. Effects reach this section by being
/// *staged*; a route that never passed through the staging queue is invisible here. See the
/// `limitations()` sentence in `rust/warrant/src/report.rs` and Tier C in
/// `docs/task-evidence/task-10.1.md`.
///
/// # Errors
/// The [`CausalRefusal`] naming the first violation found: an unreadable or absent section as
/// [`CausalRefusal::Unrepresentable`], then the count, then per hop in order the dependency
/// relation and the tool, then the index labels.
pub fn causal_verdict(predicate: &WarPredicate) -> Result<(), CausalRefusal> {
    let causality = readable_causality(predicate)?;

    let actual = causality.steps.len() as u64;
    if causality.step_count != actual {
        return Err(CausalRefusal::CountMismatch {
            declared: causality.step_count,
            actual,
        });
    }

    // The dependency relation is over handles, so it is decidable whatever the index labels say.
    // It is therefore checked before the labels: a reordered chain is refused for being
    // incoherent, which is the substantive finding, rather than for being mislabeled.
    let granted: std::collections::BTreeSet<&str> = predicate
        .authority
        .effective_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    let mut minted: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for step in &causality.steps {
        for dependency in &step.depends_on {
            if !minted.contains(dependency.as_str()) {
                return Err(CausalRefusal::OrderBroken {
                    index: step.index,
                    missing: dependency.clone(),
                });
            }
        }
        if !granted.contains(step.tool.as_str()) {
            return Err(CausalRefusal::UnauthorizedHop {
                index: step.index,
                handle: step.handle.clone(),
                tool: step.tool.clone(),
            });
        }
        minted.insert(step.handle.as_str());
    }

    for (position, step) in causality.steps.iter().enumerate() {
        let position = position as u64 + 1;
        if step.index != position {
            return Err(CausalRefusal::IndexBroken {
                position,
                declared: step.index,
            });
        }
    }

    Ok(())
}

/// [`causal_verdict`], plus the check that the section describes the staged log the caller is
/// actually holding.
///
/// The head is passed in rather than read, for the same reason `now` is passed to
/// [`verify_receipt_at`]: this crate reads no files and holds no clock. The caller that owns the
/// staged log (`warrantor_warrant::staging::StagingQueue::head_digest`) supplies it.
///
/// The head is compared **first**, because a mismatched head means the route describes a different
/// state of that log — and judging a route against the wrong log would produce a confident verdict
/// about the wrong thing.
///
/// # Errors
/// [`CausalRefusal::QueueHeadMismatch`], or whatever [`causal_verdict`] returns.
pub fn causal_verdict_pinned(
    predicate: &WarPredicate,
    observed_queue_head: &str,
) -> Result<(), CausalRefusal> {
    let causality = readable_causality(predicate)?;
    if causality.queue_head != observed_queue_head {
        return Err(CausalRefusal::QueueHeadMismatch {
            recorded: causality.queue_head.clone(),
            observed: observed_queue_head.to_string(),
        });
    }
    causal_verdict(predicate)
}

/// The causal section, or the named refusal that says why there is none to read.
///
/// A version this build has no rule for is [`CausalRefusal::Unrepresentable`] rather than a pass:
/// the section might be there, and this build still cannot say what it means.
fn readable_causality(predicate: &WarPredicate) -> Result<&Causality, CausalRefusal> {
    let declared = predicate.predicate_version.as_deref().unwrap_or("absent");
    // Absence of the section is checked FIRST so the rendered sentence is true of the record it
    // describes: "carries no causality section" must not be said about a predicate that carries
    // one, whatever its version says. The two refusals are separate for exactly that reason.
    let Some(causality) = predicate.causality.as_ref() else {
        return Err(CausalRefusal::Unrepresentable {
            predicate_version: declared.to_string(),
        });
    };
    if declared != PREDICATE_TYPE {
        return Err(CausalRefusal::Uninterpretable {
            predicate_version: declared.to_string(),
        });
    }
    Ok(causality)
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
            predicate_version: None,
            causality: None,
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

    // --- one delegation algebra (L6-01) ---

    fn widening_chain() -> Vec<DelegationLink> {
        let mut chain = sample_chain();
        // The child claims a capability the parent never held.
        chain[1].capabilities.push("admin".to_string());
        chain
    }

    #[test]
    fn a_widening_link_is_named_and_refused() {
        match narrow_chain(&widening_chain()) {
            Err(EvidenceError::Authority(message)) => {
                assert!(message.contains("link 1 "), "names the link: {message}");
                assert!(
                    message.contains(r#"Capability("admin")"#),
                    "names what widened: {message}"
                );
                assert!(message.contains("I-02"), "cites the invariant: {message}");
            }
            other => panic!("a widening link must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_widening_chain_confers_nothing() {
        assert!(recompute_intersection(&widening_chain()).is_empty());
    }

    #[test]
    fn verify_authority_refuses_a_widening_chain_even_when_the_claim_is_empty() {
        let chain = widening_chain();
        let auth = Authority {
            effective_capabilities: Vec::new(),
            intersection_proof: compute_intersection_proof(&chain),
            chain,
        };
        assert!(matches!(
            verify_authority(&auth),
            Err(EvidenceError::Authority(_))
        ));
    }

    #[test]
    fn a_child_that_outlives_its_parent_is_refused() {
        let mut chain = sample_chain();
        chain[0].not_after = 1_000;
        chain[1].not_after = 1_001;
        assert!(matches!(
            narrow_chain(&chain),
            Err(EvidenceError::Authority(message)) if message.contains("Time")
        ));
    }

    #[test]
    fn dsse_pae_format() {
        let pae = dsse_pae("hello");
        assert_eq!(String::from_utf8(pae).unwrap(), "DSSEv1 5 hello");
    }

    // --- drift guard: the proof format did not move ---

    /// The algorithm this crate shipped as `warrantor-intersect-v1`, verbatim, kept only here.
    /// If the delegated fold ever disagrees with it on a chain that narrows, the proof format has
    /// changed and needs a new name.
    fn retired_set_intersection(chain: &[DelegationLink]) -> Vec<String> {
        use std::collections::HashSet;
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

    #[test]
    fn the_delegated_fold_matches_the_retired_algorithm_on_every_narrowing_chain() {
        let mut four_deep = sample_chain();
        four_deep.push(DelegationLink {
            issuer: "spiffe://bot".to_string(),
            subject: "spiffe://worker".to_string(),
            capabilities: vec!["read".to_string(), "read".to_string()],
            not_before: 0,
            not_after: 5_000,
            token_digest: "sha256:ccc".to_string(),
        });
        four_deep.push(DelegationLink {
            issuer: "spiffe://worker".to_string(),
            subject: "spiffe://leaf".to_string(),
            capabilities: vec![],
            not_before: 0,
            not_after: 5_000,
            token_digest: "sha256:ddd".to_string(),
        });
        for chain in [Vec::new(), sample_chain(), four_deep] {
            assert_eq!(
                recompute_intersection(&chain),
                retired_set_intersection(&chain)
            );
            let proof = compute_intersection_proof(&chain);
            assert_eq!(proof.algorithm, "warrantor-intersect-v1");
            assert_eq!(
                proof.result_digest,
                sha256_hex(&serde_json::to_string(&retired_set_intersection(&chain)).unwrap()),
                "result_digest must be byte-identical to what v1 verifiers compute"
            );
        }
    }
}

//! # warrantor-authority-spec (T2)
//!
//! The normative reference for the **Agent Authority Envelope (AAE, P1)** — the signed
//! task-specific delegation that authorizes an agent to act. AumOS components consume this
//! crate to validate an AAE's signature, expiry, and delegation constraints.
//!
//! Schema lives in `specs/protocols/P1-aae.{cddl,schema.json}`. Wire type in
//! `warrantor_api::identity::v1::AgentAuthorityEnvelope`. See RFC T2 and `specs/protocols/P1-aae.md`.
//!
//! ## What the reference validator checks
//!
//! 1. **Signature** — the Ed25519 signature over the canonical-CBOR encoding of the envelope
//!    (without the `signature` field) verifies against an expected issuer verifying key.
//! 2. **Expiry** — `expiry` is in the future at the supplied "now" timestamp.
//! 3. **Side-effect class** — the AAE's `side_effect_class` is within an allowed set for the
//!    caller (e.g. a coding agent may not present a `financial` AAE).
//! 4. **Consequential-action approval** — if `side_effect_class` is `financial`, `destructive`,
//!    or `physical` (invariant I-08), the AAE must carry at least one approval.
//! 5. **Delegation depth** — for delegated AAEs, the chain's depth does not exceed the limit.
//!
//! ## What it does NOT check
//!
//! - Policy (that's R5/R6); this crate only validates the AAE's structural + cryptographic
//!   integrity. Policy decisions consume a validated AAE.
//! - Revocation freshness (that's I1's job — the revocation handle must be checked against the
//!   live revocation stream, not just the envelope).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// The side-effect classes an AAE may authorize. Mirrors the JSON-Schema enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SideEffectClass {
    /// Read-only access.
    Read,
    /// Mutating but non-financial.
    Write,
    /// Spends or moves money.
    Financial,
    /// Destroys data or resources.
    Destructive,
    /// Actuates physical systems.
    Physical,
}

impl SideEffectClass {
    /// True if this class is "consequential" — requires a human approval (invariant I-08).
    #[must_use]
    pub const fn is_consequential(self) -> bool {
        matches!(
            self,
            SideEffectClass::Financial | SideEffectClass::Destructive | SideEffectClass::Physical
        )
    }

    /// Parse from the wire string.
    ///
    /// # Errors
    /// Returns [`AaeError::InvalidSideEffectClass`] on an unknown class.
    pub fn parse(s: &str) -> Result<Self, AaeError> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "financial" => Ok(Self::Financial),
            "destructive" => Ok(Self::Destructive),
            "physical" => Ok(Self::Physical),
            other => Err(AaeError::InvalidSideEffectClass(other.to_string())),
        }
    }

    /// Render to the wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Financial => "financial",
            Self::Destructive => "destructive",
            Self::Physical => "physical",
        }
    }
}

/// Validation options supplied by the caller.
#[derive(Debug, Clone)]
pub struct ValidateOptions<'a> {
    /// The verifying key of the issuer the caller expects (confused-deputy defense: the AAE
    /// must be signed by the issuer the caller trusts, not just any issuer).
    pub issuer_verifying_key: &'a VerifyingKey,
    /// The "now" timestamp (epoch seconds). If `None`, uses `SystemTime::now()`.
    pub now: Option<u64>,
    /// The set of side-effect classes this caller is willing to honor. The AAE's class must be
    /// in this set.
    pub allowed_side_effect_classes: &'a [SideEffectClass],
    /// The maximum delegation depth the caller accepts. AAEs with `delegation_depth` greater
    /// than this are rejected.
    pub max_delegation_depth: u32,
}

// Suppress the unused import warning for `Serialize`/`Deserialize` derive paths in test only.
#[allow(dead_code)]
fn _phantom_serialize_import_marker() {
    let _ = std::any::TypeId::of::<SideEffectClass>();
}

impl<'a> ValidateOptions<'a> {
    /// Default options for a coding-agent caller: honors read+write, rejects consequential
    /// classes, accepts delegation depth up to 2.
    pub fn coding_agent(issuer_verifying_key: &'a VerifyingKey) -> Self {
        static ALLOWED: &[SideEffectClass] = &[SideEffectClass::Read, SideEffectClass::Write];
        Self {
            issuer_verifying_key,
            now: None,
            allowed_side_effect_classes: ALLOWED,
            max_delegation_depth: 2,
        }
    }
}

/// Errors returned by the AAE validator.
#[derive(Debug, Error)]
pub enum AaeError {
    /// The signature did not verify against the expected issuer key.
    #[error("AAE signature invalid")]
    SignatureInvalid,
    /// The AAE has expired.
    #[error("AAE expired at {expired_at} (now is {now})")]
    Expired {
        /// The expiry timestamp recorded in the AAE (epoch seconds).
        expired_at: u64,
        /// The current timestamp used for the comparison (epoch seconds).
        now: u64,
    },
    /// The side-effect class is not in the allowed set.
    #[error("AAE side-effect class '{0}' not allowed by this caller")]
    SideEffectClassNotAllowed(String),
    /// A consequential side-effect class is used without an approval (invariant I-08).
    #[error("consequential side-effect class '{0}' requires at least one approval")]
    MissingApproval(String),
    /// The delegation depth exceeds the caller's maximum.
    #[error("AAE delegation_depth {depth} exceeds caller max {max}")]
    DelegationDepthExceeded {
        /// The delegation depth declared by the AAE.
        depth: u32,
        /// The caller's configured maximum.
        max: u32,
    },
    /// The side-effect class string was not recognized.
    #[error("invalid side-effect class: {0}")]
    InvalidSideEffectClass(String),
    /// A field had the wrong length (signature, key).
    #[error("invalid field length: {0}")]
    InvalidLength(String),
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reconstruct the canonical-CBOR bytes of the envelope's **unsigned** fields (everything except
/// `signature`), in a deterministic order. This is what the issuer's signature is computed over
/// and what the validator verifies against.
///
/// C6: the validator MUST reconstruct these bytes itself from the envelope rather than trusting
/// bytes supplied by the caller. Previously the caller handed in `unsigned_canonical_cbor`
/// directly, which made the signature meaningless — a caller could present any bytes they liked
/// and a signature over a different (attacker-chosen) message, and the validator would happily
/// verify it. Now the validator derives the to-be-signed bytes from the envelope's own fields,
/// so the signature cryptographically binds the envelope's contents.
fn canonical_unsigned_bytes(
    envelope: &warrantor_api::identity::v1::AgentAuthorityEnvelope,
) -> Result<Vec<u8>, AaeError> {
    // Deterministic, sorted-key map serialized as canonical CBOR. We include every field the
    // issuer could have intended to sign (the unsigned envelope fields), omitting only
    // `signature`. Expiry is included as its seconds value so the encoding is stable across
    // protobuf Timestamp wire encodings.
    let expiry_seconds = envelope.expiry.as_ref().map(|t| t.seconds).unwrap_or(0);
    let unsigned = serde_json::json!({
        "issuer": envelope.issuer,
        "subject": envelope.subject,
        "purpose": envelope.purpose,
        "resources": envelope.resources,
        "tools": envelope.tools,
        "data_classes": envelope.data_classes,
        "side_effect_class": envelope.side_effect_class,
        "spend_budget": envelope.spend_budget,
        "time_budget_seconds": envelope.time_budget_seconds,
        "token_budget": envelope.token_budget,
        "geography": envelope.geography,
        "delegation_depth": envelope.delegation_depth,
        "approvals": envelope.approvals,
        "expiry_seconds": expiry_seconds,
        "revocation_handle": envelope.revocation_handle,
    });
    serde_cbor::to_vec(&unsigned).map_err(|_| {
        // Serialization of a serde_json::Value to CBOR cannot fail for finite inputs; this is
        // purely defensive.
        AaeError::InvalidLength("envelope failed canonical serialization".into())
    })
}

/// Validate an AAE wire message against the supplied options.
///
/// `envelope` is the proto wire type. The canonical-CBOR bytes the signature covers are
/// **reconstructed from the envelope's unsigned fields by this function** (C6: the validator no
/// longer trusts caller-supplied bytes). The signature hex-decodes from `envelope.signature`
/// and verifies against `options.issuer_verifying_key` over those reconstructed bytes.
///
/// # Errors
/// Returns [`AaeError`] on any validation failure. Fail-closed (no partial validation).
pub fn validate(
    envelope: &warrantor_api::identity::v1::AgentAuthorityEnvelope,
    options: &ValidateOptions<'_>,
) -> Result<(), AaeError> {
    // 1. Signature. C6: reconstruct the to-be-signed bytes from the envelope's own fields rather
    //    than trusting caller-supplied bytes, so the signature actually binds the envelope.
    let unsigned_canonical_cbor = canonical_unsigned_bytes(envelope)?;
    let sig_bytes = &envelope.signature;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AaeError::InvalidLength("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    if options
        .issuer_verifying_key
        .verify(&unsigned_canonical_cbor, &sig)
        .is_err()
    {
        return Err(AaeError::SignatureInvalid);
    }

    // 2. Expiry
    let now = options.now.unwrap_or_else(now_epoch);
    let expiry = envelope
        .expiry
        .as_ref()
        .map(|t| t.seconds.max(0) as u64)
        .unwrap_or(0);
    if expiry <= now {
        return Err(AaeError::Expired {
            expired_at: expiry,
            now,
        });
    }

    // 3. Side-effect class
    let class = SideEffectClass::parse(&envelope.side_effect_class)?;
    if !options.allowed_side_effect_classes.contains(&class) {
        return Err(AaeError::SideEffectClassNotAllowed(class.as_str().into()));
    }

    // 4. Consequential-action approval (invariant I-08)
    if class.is_consequential() && envelope.approvals.is_empty() {
        return Err(AaeError::MissingApproval(class.as_str().into()));
    }

    // 5. Delegation depth
    if envelope.delegation_depth > options.max_delegation_depth {
        return Err(AaeError::DelegationDepthExceeded {
            depth: envelope.delegation_depth,
            max: options.max_delegation_depth,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use warrantor_api::identity::v1::AgentAuthorityEnvelope;

    /// Build an unsigned envelope body (the JSON map the signature covers) for the given fields.
    /// Must stay in sync with [`canonical_unsigned_bytes`].
    fn unsigned_body(
        issuer: &str,
        subject: &str,
        class: &str,
        approvals: &[&str],
        delegation_depth: u32,
        expiry_seconds: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "issuer": issuer,
            "subject": subject,
            "purpose": "open a pull request",
            "resources": Vec::<String>::new(),
            "tools": Vec::<String>::new(),
            "data_classes": Vec::<String>::new(),
            "side_effect_class": class,
            "spend_budget": 0i64,
            "time_budget_seconds": 0i64,
            "token_budget": 0i64,
            "geography": "",
            "delegation_depth": delegation_depth,
            "approvals": approvals.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "expiry_seconds": expiry_seconds,
            "revocation_handle": "",
        })
    }

    fn make_signed_envelope(
        class: &str,
        approvals: Vec<&str>,
        delegation_depth: u32,
    ) -> (AgentAuthorityEnvelope, SigningKey) {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let issuer = "spiffe://muveraai.com/agent-identity";
        let subject = "spiffe://muveraai.com/agent/coding-1";
        let expiry_seconds = (now_epoch() + 3600) as i64;
        // C6: sign over the SAME canonical-CBOR bytes the validator will reconstruct from the
        // envelope's unsigned fields. We build the body, serialize it to canonical CBOR, and
        // sign that. The envelope is then assembled from the same fields.
        let body = unsigned_body(
            issuer,
            subject,
            class,
            &approvals,
            delegation_depth,
            expiry_seconds,
        );
        let canon = serde_cbor::to_vec(&body).expect("canonical");
        let sig = sk.sign(&canon);
        let envelope = AgentAuthorityEnvelope {
            issuer: issuer.into(),
            subject: subject.into(),
            purpose: "open a pull request".into(),
            side_effect_class: class.into(),
            approvals: approvals.into_iter().map(String::from).collect(),
            delegation_depth,
            signature: sig.to_bytes().to_vec(),
            expiry: Some(prost_types::Timestamp {
                seconds: expiry_seconds,
                nanos: 0,
            }),
            ..Default::default()
        };
        (envelope, sk)
    }

    #[test]
    fn valid_read_envelope_validates() {
        let (envelope, sk) = make_signed_envelope("read", vec![], 0);
        let vk = sk.verifying_key();
        let opts = ValidateOptions::coding_agent(&vk);
        validate(&envelope, &opts).expect("valid read envelope");
    }

    #[test]
    fn tampered_signature_fails() {
        let (mut envelope, sk) = make_signed_envelope("read", vec![], 0);
        let vk = sk.verifying_key();
        // Flip a bit in the signature.
        envelope.signature[0] ^= 0xff;
        let opts = ValidateOptions::coding_agent(&vk);
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_envelope_field_fails_c6() {
        // C6: the validator reconstructs the to-be-signed bytes from the envelope's own fields,
        // so mutating ANY signed field must invalidate the signature (previously the caller could
        // supply arbitrary bytes and a matching signature over those bytes, so a field mutation
        // would NOT be detected unless the caller also updated the supplied bytes).
        let (mut envelope, sk) = make_signed_envelope("read", vec![], 0);
        let vk = sk.verifying_key();
        envelope.subject = "spiffe://muveraai.com/agent/impostor".into();
        let opts = ValidateOptions::coding_agent(&vk);
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::SignatureInvalid)
        ));
    }

    #[test]
    fn caller_supplied_bytes_are_ignored_c6() {
        // C6: even if a malicious caller mutates the envelope's fields AND supplies the original
        // canonical bytes, the validator must reject it (it no longer accepts caller-supplied
        // bytes at all — the signature has no `unsigned_canonical_cbor` parameter to abuse).
        let (mut envelope, sk) = make_signed_envelope("read", vec![], 0);
        let vk = sk.verifying_key();
        // The signature still verifies over the ORIGINAL fields; mutate a field.
        envelope.purpose = "exfiltrate secrets".into();
        let opts = ValidateOptions::coding_agent(&vk);
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::SignatureInvalid)
        ));
    }

    #[test]
    fn expired_envelope_fails() {
        let (mut envelope, sk) = make_signed_envelope("read", vec![], 0);
        let vk = sk.verifying_key();
        // Re-sign with an expiry in the past so the signature is still valid over the mutated
        // expiry field (otherwise this would trip SignatureInvalid, not Expired).
        let issuer = "spiffe://muveraai.com/agent-identity";
        let subject = "spiffe://muveraai.com/agent/coding-1";
        let past_seconds: i64 = 1;
        let body = unsigned_body(issuer, subject, "read", &[], 0, past_seconds);
        let canon = serde_cbor::to_vec(&body).expect("canonical");
        let sig = sk.sign(&canon);
        envelope.expiry = Some(prost_types::Timestamp {
            seconds: past_seconds,
            nanos: 0,
        });
        envelope.signature = sig.to_bytes().to_vec();
        let opts = ValidateOptions {
            issuer_verifying_key: &vk,
            now: Some(now_epoch()),
            allowed_side_effect_classes: &[SideEffectClass::Read],
            max_delegation_depth: 2,
        };
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::Expired { .. })
        ));
    }

    #[test]
    fn financial_class_rejected_by_coding_agent() {
        let (envelope, sk) = make_signed_envelope("financial", vec![], 0);
        let vk = sk.verifying_key();
        let opts = ValidateOptions::coding_agent(&vk); // allows read+write only
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::SideEffectClassNotAllowed(_))
        ));
    }

    #[test]
    fn financial_class_with_approval_validates_when_allowed() {
        let (envelope, sk) =
            make_signed_envelope("financial", vec!["spiffe://muveraai.com/human/alice"], 0);
        let vk = sk.verifying_key();
        let opts = ValidateOptions {
            issuer_verifying_key: &vk,
            now: None,
            allowed_side_effect_classes: &[SideEffectClass::Financial],
            max_delegation_depth: 0,
        };
        validate(&envelope, &opts).expect("financial with approval validates");
    }

    #[test]
    fn financial_class_without_approval_fails_invariant_i08() {
        let (envelope, sk) = make_signed_envelope("financial", vec![], 0);
        let vk = sk.verifying_key();
        let opts = ValidateOptions {
            issuer_verifying_key: &vk,
            now: None,
            allowed_side_effect_classes: &[SideEffectClass::Financial],
            max_delegation_depth: 0,
        };
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::MissingApproval(_))
        ));
    }

    #[test]
    fn delegation_depth_exceeded_fails() {
        let (envelope, sk) = make_signed_envelope("read", vec![], 5);
        let vk = sk.verifying_key();
        let opts = ValidateOptions {
            issuer_verifying_key: &vk,
            now: None,
            allowed_side_effect_classes: &[SideEffectClass::Read],
            max_delegation_depth: 2,
        };
        assert!(matches!(
            validate(&envelope, &opts),
            Err(AaeError::DelegationDepthExceeded { depth: 5, max: 2 })
        ));
    }

    #[test]
    fn side_effect_class_is_consequential() {
        assert!(!SideEffectClass::Read.is_consequential());
        assert!(!SideEffectClass::Write.is_consequential());
        assert!(SideEffectClass::Financial.is_consequential());
        assert!(SideEffectClass::Destructive.is_consequential());
        assert!(SideEffectClass::Physical.is_consequential());
    }

    #[test]
    fn parse_rejects_unknown_class() {
        assert!(matches!(
            SideEffectClass::parse("nuke"),
            Err(AaeError::InvalidSideEffectClass(_))
        ));
    }
}

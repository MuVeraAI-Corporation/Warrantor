//! Signed tool and skill admission manifests (L4-09).
//!
//! A manifest is signed by the party that vouches for a tool server and is verified against a
//! key this machine pinned out of band under a NAME (`crate::trust`). No key travels inside the
//! file: a file that carries its own verifying key verifies nothing but its own consistency.
//! Everything decided here is decided at the MCP proxy and is `BoundStrength::Mediated`; the
//! skill half (`AdmissionKind::Skill`) has no chokepoint at all and is `Observed`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::effects::{Decomposition, DecompositionRegistry, Syscall};
use crate::mcp::ToolSpec;
use crate::report::sha256_hex;
use crate::trust::Directory;

/// The manifest wire format. A new shape gets a new name, never a silent change.
pub const MANIFEST_FORMAT: &str = "warrantor.tool-manifest/1";
/// The admission receipt wire format.
pub const RECEIPT_FORMAT: &str = "warrantor.admission-receipt/1";
/// The export `warrantor verify` dispatches on.
pub const EXPORT_FORMAT: &str = "warrantor.admission-export/1";

const MANIFEST_DOMAIN: &[u8] = b"warrantor-tool-manifest-v1";
const RECEIPT_DOMAIN: &[u8] = b"warrantor-admission-receipt-v1";

/// Length-prefixed, domain-separated signing input: the same shape `lib.rs` uses for warrants,
/// so a signature over one kind of object can never be replayed as another.
fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len() + 16);
    out.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// What the manifest admits: an MCP tool server, or a skill file identified by content digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionKind {
    /// An MCP server; `tools` names every tool it may publish.
    Tool,
    /// A skill file; `subject_digest` is its SHA-256 and `tools` names the tools it may call.
    Skill,
}

/// One tool's declared decomposition and data classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEntry {
    /// The syscalls this tool performs. Never empty: a tool with no effect still attests.
    pub effects: BTreeSet<Syscall>,
    /// Data classes the tool may receive or return, as the issuer names them. Recorded in the
    /// receipt; checked against a warrant bound only once Task 2.5 gives payloads a class.
    pub data_classes: BTreeSet<String>,
    /// SHA-256 hex of the tool's `inputSchema`, when pinned. A published schema that differs is
    /// the server's behavior disagreeing with its manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_digest: Option<String>,
}

/// The signed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestClaims {
    /// Always [`MANIFEST_FORMAT`].
    pub format: String,
    /// The upstream name the tools are published under: the `UpstreamSpec::name` rule applies.
    pub server: String,
    /// Tool server or skill.
    pub kind: AdmissionKind,
    /// The issuer's version string. Recorded, not interpreted.
    pub version: String,
    /// The PINNED NAME of the signer in `trusted/issuers.json`. Never a key.
    pub issuer: String,
    /// Epoch seconds.
    pub issued_at: u64,
    /// Epoch seconds. A manifest without an end never ends, so zero is refused.
    pub expires_at: u64,
    /// For `Skill`: SHA-256 hex of the skill file. Refused when absent on a skill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_digest: Option<String>,
    /// Bare tool name (no `<server>.` prefix) -> entry. A `BTreeMap`, so the bytes are stable.
    pub tools: BTreeMap<String, ToolEntry>,
}

/// A manifest and its Ed25519 signature over `signing_input(MANIFEST_DOMAIN, canonical claims)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The claims.
    pub claims: ManifestClaims,
    /// Hex signature. Empty is "unsigned", and unsigned is refused by name.
    pub signature: String,
}

/// What refused, in one sentence the operator can act on.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    /// The file's shape is wrong.
    #[error("manifest refused: {0}")]
    Format(String),
    /// The signature does not verify against the resolved issuer key.
    #[error("manifest refused: the signature does not verify against the pinned issuer key")]
    Signature,
    /// The manifest is past its end.
    #[error("manifest refused: it expired at {expires_at}; now is {now}")]
    Expired {
        /// Epoch seconds.
        expires_at: u64,
        /// Epoch seconds.
        now: u64,
    },
    /// The issuer name is not pinned on this machine.
    #[error("manifest refused: issuer {0:?} is not pinned on this machine. Check the issuer's key out of band and pin it: warrantor issuer add {0} <hex>")]
    UnpinnedIssuer(String),
    /// The file carries no signature at all.
    #[error("manifest refused: it is unsigned. A tool server that cannot present a signed manifest is refused, not guessed at")]
    Unsigned,
    /// The server publishes something its manifest does not name.
    #[error("server {server:?} revoked: {detail}")]
    Publication {
        /// The upstream name.
        server: String,
        /// What disagreed.
        detail: String,
    },
    /// The server's manifest was revoked earlier.
    #[error("server {server:?} was revoked at {at}: {reason}")]
    Revoked {
        /// The upstream name.
        server: String,
        /// Epoch seconds.
        at: u64,
        /// Why.
        reason: String,
    },
    /// The store could not be read or written.
    #[error("admission store: {0}")]
    Io(String),
}

fn canonical(claims: &ManifestClaims) -> Result<Vec<u8>, AdmissionError> {
    serde_json::to_vec(claims).map_err(|e| AdmissionError::Format(e.to_string()))
}

/// Sign claims with the issuer's key. The signature covers the canonical JSON of `claims`, which
/// is byte-stable because every map is a `BTreeMap` and the struct's field order is fixed.
#[must_use]
pub fn sign_manifest(claims: ManifestClaims, key: &SigningKey) -> SignedManifest {
    let body = canonical(&claims).expect("claims are always serializable");
    let signature = key.sign(&signing_input(MANIFEST_DOMAIN, &body));
    SignedManifest {
        claims,
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Verify format, shape, signature and expiry against an issuer key the CALLER resolved.
///
/// # Errors
/// [`AdmissionError`] naming the first thing wrong. Shape is checked before the signature so a
/// file from a future build is refused for what it is rather than for a signature this build
/// cannot compute.
pub fn verify_manifest(
    manifest: &SignedManifest,
    issuer: &VerifyingKey,
    now: u64,
) -> Result<(), AdmissionError> {
    let claims = &manifest.claims;
    if claims.format != MANIFEST_FORMAT {
        return Err(AdmissionError::Format(format!(
            "it declares format {:?}, and this build reads only {MANIFEST_FORMAT}",
            claims.format
        )));
    }
    if claims.server.is_empty()
        || !claims
            .server
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AdmissionError::Format(format!(
            "server {:?} must be letters, digits, '-' or '_', the same rule as --upstream",
            claims.server
        )));
    }
    crate::trust::check_name(&claims.issuer).map_err(AdmissionError::Format)?;
    if claims.expires_at == 0 {
        return Err(AdmissionError::Format(
            "expires_at is required: a manifest without an end never ends".to_string(),
        ));
    }
    if claims.kind == AdmissionKind::Skill && claims.subject_digest.is_none() {
        return Err(AdmissionError::Format(
            "a skill manifest must carry subject_digest, the SHA-256 of the skill file".to_string(),
        ));
    }
    if claims.tools.is_empty() {
        return Err(AdmissionError::Format(
            "a manifest naming no tools admits nothing; state the tools explicitly".to_string(),
        ));
    }
    for (tool, entry) in &claims.tools {
        if entry.effects.is_empty() {
            return Err(AdmissionError::Format(format!(
                "{tool} declares no effect syscall. A tool that only answers is `attest`; a \
                 tool with an effect must say which"
            )));
        }
    }
    if manifest.signature.is_empty() {
        return Err(AdmissionError::Unsigned);
    }
    let body = canonical(claims)?;
    let raw = hex::decode(&manifest.signature).map_err(|_| AdmissionError::Signature)?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AdmissionError::Signature)?;
    issuer
        .verify(
            &signing_input(MANIFEST_DOMAIN, &body),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| AdmissionError::Signature)?;
    if now >= claims.expires_at {
        return Err(AdmissionError::Expired {
            expires_at: claims.expires_at,
            now,
        });
    }
    Ok(())
}

/// SHA-256 hex over the serialized manifest, claims and signature: the identity every receipt
/// names, so a re-signed manifest is a different manifest.
#[must_use]
pub fn manifest_digest(manifest: &SignedManifest) -> String {
    let body = serde_json::to_vec(manifest).expect("a manifest is always serializable");
    sha256_hex(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn entry(effects: &[Syscall]) -> ToolEntry {
        ToolEntry {
            effects: effects.iter().copied().collect(),
            data_classes: ["public".to_string()].into_iter().collect(),
            schema_digest: None,
        }
    }

    fn claims() -> ManifestClaims {
        let mut tools = BTreeMap::new();
        tools.insert("echo".to_string(), entry(&[Syscall::Attest]));
        tools.insert("fetch".to_string(), entry(&[Syscall::Net]));
        ManifestClaims {
            format: MANIFEST_FORMAT.to_string(),
            server: "selftest".to_string(),
            kind: AdmissionKind::Tool,
            version: "1.0.0".to_string(),
            issuer: "vendor".to_string(),
            issued_at: 1_786_000_000,
            expires_at: 1_786_000_000 + 86_400,
            subject_digest: None,
            tools,
        }
    }

    #[test]
    fn a_signed_manifest_verifies_and_a_tampered_one_does_not() {
        let signer = key(7);
        let signed = sign_manifest(claims(), &signer);
        verify_manifest(&signed, &signer.verifying_key(), 1_786_000_100).expect("verifies");

        let mut tampered = signed.clone();
        tampered.claims.tools.get_mut("echo").expect("echo").effects.insert(Syscall::Net);
        assert_eq!(
            verify_manifest(&tampered, &signer.verifying_key(), 1_786_000_100),
            Err(AdmissionError::Signature)
        );
        assert_eq!(
            verify_manifest(&signed, &key(8).verifying_key(), 1_786_000_100),
            Err(AdmissionError::Signature),
            "a different key is not the issuer"
        );
        assert!(matches!(
            verify_manifest(&signed, &signer.verifying_key(), 1_786_000_000 + 86_401),
            Err(AdmissionError::Expired { .. })
        ));
        let unsigned = SignedManifest { claims: claims(), signature: String::new() };
        assert_eq!(
            verify_manifest(&unsigned, &signer.verifying_key(), 1_786_000_100),
            Err(AdmissionError::Unsigned)
        );
    }

    #[test]
    fn a_foreign_format_an_empty_effect_set_and_a_digestless_skill_are_refused_before_the_signature() {
        let mut other = claims();
        other.format = "warrantor.tool-manifest/2".to_string();
        let signed = sign_manifest(other, &key(7));
        let err = verify_manifest(&signed, &key(7).verifying_key(), 1_786_000_100).expect_err("foreign");
        assert!(matches!(&err, AdmissionError::Format(m) if m.contains("warrantor.tool-manifest/2")), "{err}");

        let mut empty = claims();
        empty.tools.insert("noop".to_string(), entry(&[]));
        let err = verify_manifest(&sign_manifest(empty, &key(7)), &key(7).verifying_key(), 1_786_000_100)
            .expect_err("empty effects");
        assert!(matches!(&err, AdmissionError::Format(m) if m.contains("noop")), "{err}");

        let mut skill = claims();
        skill.kind = AdmissionKind::Skill;
        let err = verify_manifest(&sign_manifest(skill, &key(7)), &key(7).verifying_key(), 1_786_000_100)
            .expect_err("skill without digest");
        assert!(matches!(&err, AdmissionError::Format(m) if m.contains("subject_digest")), "{err}");
    }
}

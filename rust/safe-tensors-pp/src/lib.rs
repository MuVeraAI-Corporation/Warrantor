//! # warrantor-safe-tensors-pp (S1)
//!
//! Drop-in extension of HuggingFace Safetensors that adds a `__provenance__` block to the JSON
//! header. The provenance block carries the signer, signature (Ed25519), signing timestamp,
//! evaluations, and lineage — signed by T1 trust-core. **Backward-compatible**: a Safetensors
//! file without `__provenance__` parses fine; it is just treated as "unverified".
//!
//! ## Safetensors on-disk format (recap)
//!
//! ```text
//! [u64 LE: header_length][header JSON bytes][tensor data...]
//! ```
//! The header is a JSON object mapping tensor name → {dtype, shape, data_offsets}. Safetensors++
//! adds one reserved key `__provenance__` to the header (alongside the existing `__metadata__`
//! that vanilla Safetensors defines).
//!
//! See RFC S1 and `specs/protocols/P1-aae.md` (the provenance block reuses AAE-style signing).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

/// The reserved header key for the provenance block.
pub const PROVENANCE_KEY: &str = "__provenance__";

/// The provenance block embedded in a Safetensors++ header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    /// The signer identity (e.g. "did:web:muveraai.com" or a SPIFFE ID).
    pub signer: String,
    /// Hex-encoded Ed25519 verifying key (32 bytes).
    pub verifying_key: String,
    /// Hex-encoded Ed25519 signature (64 bytes) over the canonical bytes.
    pub signature: String,
    /// Signing timestamp (epoch seconds).
    pub signed_at: u64,
    /// SHA-256 of the tensor data region (hex), so the signature binds to the weights.
    pub data_digest: String,
    /// Optional evaluation references (URIs or AAR ids).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluations: Vec<String>,
    /// Optional lineage (parent model URIs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage: Vec<String>,
}

/// Build the exact bytes a Safetensors++ signature covers.
///
/// Shared by [`sign`] and [`verify`] so the two cannot drift -- when they were written out
/// separately, the metadata was omitted from both and neither side noticed.
///
/// # What is covered, and why
///
/// The header (minus `__provenance__`), the data digest, and the provenance METADATA:
/// `signer`, `signed_at`, `evaluations`, `lineage`, `verifying_key`.
///
/// Previously only `header || digest` was signed, so the entire provenance block was
/// unauthenticated -- yet `verify()` returned it to the caller as though it had been
/// attested. Rewriting `signer` from `did:web:honest-lab.example` to any other identity
/// left the signature valid and `verify()` returned `Ok` with the forged attribution. For a
/// component whose purpose is answering "who signed these weights", the answer was
/// editable by anyone holding the file.
///
/// `signature` is excluded because a signature cannot cover itself. `data_digest` is
/// excluded from the metadata section because the digest is already committed above it;
/// including it twice would only add a place for the two copies to disagree.
///
/// Every field is length-prefixed so it cannot be re-split -- without that,
/// `signer="ab"` + `evaluations=["c"]` and `signer="a"` + `evaluations=["bc"]` would
/// produce identical bytes.
fn canonical_signing_bytes(
    header_without_provenance: &serde_json::Value,
    data_digest_hex: &str,
    signer: &str,
    verifying_key_hex: &str,
    signed_at: u64,
    evaluations: &[String],
    lineage: &[String],
) -> Result<Vec<u8>, StppError> {
    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    let header_canon = serde_json::to_vec(header_without_provenance)?;
    let mut canon = Vec::with_capacity(header_canon.len() + 256);
    // Preserved from the original format so the header/digest framing is unchanged.
    canon.extend_from_slice(&header_canon);
    canon.push(b'|');
    canon.extend_from_slice(data_digest_hex.as_bytes());
    // Metadata section.
    canon.push(b'|');
    put(&mut canon, signer.as_bytes());
    put(&mut canon, verifying_key_hex.as_bytes());
    canon.extend_from_slice(&signed_at.to_le_bytes());
    put(&mut canon, &(evaluations.len() as u64).to_le_bytes());
    for e in evaluations {
        put(&mut canon, e.as_bytes());
    }
    put(&mut canon, &(lineage.len() as u64).to_le_bytes());
    for l in lineage {
        put(&mut canon, l.as_bytes());
    }
    Ok(canon)
}

/// Errors returned by Safetensors++.
#[derive(Debug, Error)]
pub enum StppError {
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The header length prefix was invalid.
    #[error("invalid header length prefix")]
    InvalidHeaderLength,
    /// The header was missing `__metadata__` (vanilla Safetensors requires it).
    #[error("header missing __metadata__ (not a safetensors file)")]
    NotSafetensors,
    /// A signature was invalid.
    #[error("provenance signature invalid")]
    SignatureInvalid,
    /// The header had no `__provenance__` block.
    #[error("no __provenance__ block (unverified file)")]
    NoProvenance,
    /// Hex decode failed.
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    /// A field had the wrong length.
    #[error("invalid length: {0}")]
    InvalidLength(String),
}

/// Read a Safetensors file from `reader` and return (header_json, data_bytes).
///
/// # Errors
/// Returns [`StppError`] on any I/O, length, or JSON failure.
pub fn read_safetensors<R: Read>(
    reader: &mut R,
) -> Result<(serde_json::Value, Vec<u8>), StppError> {
    let mut len_bytes = [0u8; 8];
    reader.read_exact(&mut len_bytes)?;
    let header_len = u64::from_le_bytes(len_bytes);
    if header_len > 100 * 1024 * 1024 {
        // Hard cap at 100 MB headers (real safetensors files are typically < 1 MB).
        return Err(StppError::InvalidHeaderLength);
    }
    let mut header_buf = vec![0u8; header_len as usize];
    reader.read_exact(&mut header_buf)?;
    let header: serde_json::Value = serde_json::from_slice(&header_buf)?;
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    Ok((header, data))
}

/// Write a Safetensors file to `writer` given its header JSON and data bytes.
///
/// # Errors
/// Returns [`StppError`] on any I/O failure.
pub fn write_safetensors<W: Write>(
    writer: &mut W,
    header: &serde_json::Value,
    data: &[u8],
) -> Result<(), StppError> {
    let header_bytes = serde_json::to_vec(header)?;
    let len = header_bytes.len() as u64;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&header_bytes)?;
    writer.write_all(data)?;
    Ok(())
}

/// Extract the `__provenance__` block from a header, if present.
///
/// # Errors
/// Returns [`StppError::NoProvenance`] if absent.
pub fn provenance_from_header(header: &serde_json::Value) -> Result<Provenance, StppError> {
    let p = header.get(PROVENANCE_KEY).ok_or(StppError::NoProvenance)?;
    Ok(serde_json::from_value(p.clone())?)
}

/// Compute the SHA-256 of the data region (hex).
#[must_use]
pub fn data_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    hex::encode(out)
}

/// Sign a Safetensors header+data in place: insert a `__provenance__` block signed by
/// `signing_key`.
///
/// The signature covers: header (without `__provenance__`) || data_digest. This binds the
/// signature to the weights, not just the metadata.
///
/// # Errors
/// Returns [`StppError`] if the header isn't a JSON object.
pub fn sign(
    header: &mut serde_json::Value,
    data: &[u8],
    signer: &str,
    signing_key: &SigningKey,
) -> Result<(), StppError> {
    // Remove any existing provenance before computing the canonical signing bytes.
    if let Some(obj) = header.as_object_mut() {
        let _ = obj.remove(PROVENANCE_KEY);
    }
    let digest = data_digest(data);
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let evaluations: Vec<String> = vec![];
    let lineage: Vec<String> = vec![];

    // The metadata is signed, not merely attached. See canonical_signing_bytes.
    let canon = canonical_signing_bytes(
        header,
        &digest,
        signer,
        &verifying_key_hex,
        signed_at,
        &evaluations,
        &lineage,
    )?;
    let sig = signing_key.sign(&canon);
    let provenance = Provenance {
        signer: signer.to_string(),
        verifying_key: verifying_key_hex,
        signature: hex::encode(sig.to_bytes()),
        signed_at,
        data_digest: digest,
        evaluations,
        lineage,
    };
    // Now re-borrow mutably to insert the provenance block.
    let obj = header
        .as_object_mut()
        .ok_or_else(|| StppError::InvalidLength("header must be a JSON object".into()))?;
    obj.insert(
        PROVENANCE_KEY.to_string(),
        serde_json::to_value(&provenance)?,
    );
    Ok(())
}

/// Verify the `__provenance__` block of a header against the data region.
///
/// # Errors
/// Returns [`StppError::NoProvenance`] if absent, [`StppError::SignatureInvalid`] on any
/// verification failure.
pub fn verify(header: &serde_json::Value, data: &[u8]) -> Result<Provenance, StppError> {
    let p = provenance_from_header(header)?;
    // Recompute the data digest and check it matches what was signed.
    let digest = data_digest(data);
    if digest != p.data_digest {
        return Err(StppError::SignatureInvalid);
    }
    // Reconstruct the canonical bytes from the SAME function sign() used, including the
    // provenance metadata. Reconstructing them inline here is what let the two drift.
    let mut header_copy = header.clone();
    if let Some(obj) = header_copy.as_object_mut() {
        obj.remove(PROVENANCE_KEY);
    }
    let canon = canonical_signing_bytes(
        &header_copy,
        &digest,
        &p.signer,
        &p.verifying_key,
        p.signed_at,
        &p.evaluations,
        &p.lineage,
    )?;

    let vk_bytes: [u8; 32] = hex::decode(&p.verifying_key)?
        .as_slice()
        .try_into()
        .map_err(|_| StppError::InvalidLength("verifying_key".into()))?;
    let sig_bytes = hex::decode(&p.signature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| StppError::InvalidLength("signature".into()))?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| StppError::SignatureInvalid)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify(&canon, &sig)
        .map_err(|_| StppError::SignatureInvalid)?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn test_header() -> serde_json::Value {
        serde_json::json!({
            "__metadata__": { "format": "pt" },
            "weight_0": {
                "dtype": "F32",
                "shape": [2, 2],
                "data_offsets": [0, 16]
            }
        })
    }

    fn test_data() -> Vec<u8> {
        vec![0u8; 16]
    }

    fn test_key() -> SigningKey {
        let mut rng = OsRng;
        SigningKey::generate(&mut rng)
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let mut header = test_header();
        let data = test_data();
        let key = test_key();
        sign(&mut header, &data, "did:web:muveraai.com", &key).expect("sign");
        let p = verify(&header, &data).expect("verify");
        assert_eq!(p.signer, "did:web:muveraai.com");
    }

    #[test]
    fn tampered_data_fails_verification() {
        let mut header = test_header();
        let data = test_data();
        let key = test_key();
        sign(&mut header, &data, "did:web:muveraai.com", &key).expect("sign");
        let mut tampered = data.clone();
        tampered[0] ^= 0xff;
        assert!(matches!(
            verify(&header, &tampered),
            Err(StppError::SignatureInvalid)
        ));
    }

    #[test]
    fn header_without_provenance_returns_no_provenance_error() {
        let header = test_header();
        let data = test_data();
        assert!(matches!(
            verify(&header, &data),
            Err(StppError::NoProvenance)
        ));
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut header = test_header();
        let data = test_data();
        let key = test_key();
        sign(&mut header, &data, "did:web:muveraai.com", &key).expect("sign");
        let mut buf = Vec::new();
        write_safetensors(&mut buf, &header, &data).expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        let (h2, d2) = read_safetensors(&mut cursor).expect("read");
        assert_eq!(d2, data);
        verify(&h2, &d2).expect("verified after round trip");
    }

    #[test]
    fn data_digest_is_stable() {
        let d = test_data();
        assert_eq!(data_digest(&d), data_digest(&d));
        assert_ne!(data_digest(&d), data_digest(&[1u8; 16]));
    }

    #[test]
    fn provenance_round_trips_through_json() {
        let p = Provenance {
            signer: "did:web:muveraai.com".into(),
            verifying_key: "ab".repeat(16),
            signature: "cd".repeat(32),
            signed_at: 1000,
            data_digest: "ef".repeat(16),
            evaluations: vec!["aar://123".into()],
            lineage: vec!["model://parent".into()],
        };
        let json = serde_json::to_value(&p).unwrap();
        let back: Provenance = serde_json::from_value(json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn read_rejects_oversized_header_length() {
        // 1 TB header length prefix → must reject without allocating.
        let huge = u64::MAX;
        // Use a stream that yields the huge length then nothing.
        let mut reader = std::io::Cursor::new(huge.to_le_bytes().to_vec());
        let res = read_safetensors(&mut reader);
        assert!(res.is_err(), "oversized header must be rejected");
    }
}

#[cfg(test)]
mod provenance_is_signed {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signed_header() -> (serde_json::Value, Vec<u8>) {
        let data = b"weights-go-here".to_vec();
        let mut header = serde_json::json!({
            "t": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 15]}
        });
        let key = SigningKey::from_bytes(&[7u8; 32]);
        sign(&mut header, &data, "did:web:honest-lab.example", &key).expect("sign");
        (header, data)
    }

    fn provenance_field_mut<'a>(
        header: &'a mut serde_json::Value,
        field: &str,
    ) -> &'a mut serde_json::Value {
        header
            .get_mut(PROVENANCE_KEY)
            .and_then(|p| p.get_mut(field))
            .expect("provenance field")
    }

    /// The reported forgery: rewrite `signer` and the signature still verified, so
    /// `verify()` returned Ok while reporting an attacker-chosen identity.
    #[test]
    fn rewriting_the_signer_invalidates_the_signature() {
        let (header, data) = signed_header();
        let honest = verify(&header, &data).expect("clean file verifies");
        assert_eq!(honest.signer, "did:web:honest-lab.example");

        let mut forged = header.clone();
        *provenance_field_mut(&mut forged, "signer") =
            serde_json::Value::String("did:web:anthropic.com".into());
        assert!(
            verify(&forged, &data).is_err(),
            "a rewritten signer MUST invalidate the signature -- attribution is the point"
        );
    }

    #[test]
    fn rewriting_signed_at_invalidates_the_signature() {
        let (header, data) = signed_header();
        let mut forged = header;
        *provenance_field_mut(&mut forged, "signed_at") = serde_json::json!(1u64);
        assert!(verify(&forged, &data).is_err(), "signed_at must be covered");
    }

    /// Evaluations and lineage are provenance claims a downstream consumer acts on, so
    /// injecting them must break the signature rather than silently enrich the record.
    #[test]
    fn injecting_evaluations_or_lineage_invalidates_the_signature() {
        let (header, data) = signed_header();

        let mut forged = header.clone();
        forged[PROVENANCE_KEY]["evaluations"] =
            serde_json::json!(["https://evil.example/passed-every-eval"]);
        assert!(
            verify(&forged, &data).is_err(),
            "evaluations must be covered"
        );

        let mut forged = header;
        forged[PROVENANCE_KEY]["lineage"] = serde_json::json!(["did:web:reputable-lab.example"]);
        assert!(verify(&forged, &data).is_err(), "lineage must be covered");
    }

    /// The existing guarantees must survive: tampered weights and a tampered header still
    /// fail, and an untouched file still verifies.
    #[test]
    fn existing_protections_are_unchanged() {
        let (header, data) = signed_header();
        assert!(verify(&header, &data).is_ok(), "clean file must verify");

        let mut tampered_data = data.clone();
        tampered_data[0] ^= 0xff;
        assert!(verify(&header, &tampered_data).is_err(), "weights covered");

        let mut tampered_header = header;
        tampered_header["t"]["shape"] = serde_json::json!([4, 4]);
        assert!(verify(&tampered_header, &data).is_err(), "header covered");
    }
}

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

/// The reserved header key vanilla Safetensors defines for file-level metadata.
pub const METADATA_KEY: &str = "__metadata__";

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
    /// The header was not a JSON object, so the file is not Safetensors at all.
    #[error("header is not a JSON object (not a safetensors file)")]
    NotSafetensors,
    /// The header is structurally invalid: a tensor entry is malformed, or its `data_offsets`
    /// do not describe a real region of the data block.
    #[error("invalid safetensors header: {0}")]
    InvalidHeader(String),
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

/// Byte width of each Safetensors dtype. A dtype outside this set is not a Safetensors dtype.
fn dtype_size(dtype: &str) -> Option<u64> {
    Some(match dtype {
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" => 1,
        "I16" | "U16" | "F16" | "BF16" => 2,
        "I32" | "U32" | "F32" => 4,
        "I64" | "U64" | "F64" => 8,
        _ => return None,
    })
}

/// Structurally validate a Safetensors header against the data block it describes.
///
/// Neither `sign()` nor `verify()` used to look at the header's contents at all: `sign` signed
/// whatever JSON it was handed and `verify` checked only the digest and the Ed25519 signature. So
/// a header claiming a tensor spanning `0..1<<40` over a 16-byte data block was signed and then
/// verified `Ok` -- as were overlapping tensors, reversed offsets (`end < start`), negative
/// offsets, and shapes whose element count did not match the byte span. A signature over a header
/// that cannot be true is a signature attesting to nonsense: the downstream loader is the one that
/// hits the out-of-bounds read, and it does so holding a valid provenance attestation.
///
/// This is the check that makes the signature mean something.
///
/// # Errors
/// Returns [`StppError::NotSafetensors`] if the header is not a JSON object, or
/// [`StppError::InvalidHeader`] describing the first structural problem found.
pub fn validate_header(header: &serde_json::Value, data_len: u64) -> Result<(), StppError> {
    // A header that is not a JSON object is not a Safetensors header at all.
    //
    // `__metadata__` is deliberately NOT required here. It is a reserved key for free-form
    // file-level metadata and is optional in the Safetensors format; requiring it would reject
    // spec-valid files produced by other tools, which is a worse failure than the checks below
    // are worth. What must hold is that every tensor entry describes a real region of the data.
    let object = header.as_object().ok_or(StppError::NotSafetensors)?;

    for (name, entry) in object {
        // Reserved keys carry metadata, not tensors.
        if name == METADATA_KEY || name == PROVENANCE_KEY {
            continue;
        }
        let entry = entry.as_object().ok_or_else(|| {
            StppError::InvalidHeader(format!("tensor {name:?}: entry is not an object"))
        })?;

        let dtype = entry
            .get("dtype")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                StppError::InvalidHeader(format!("tensor {name:?}: missing string `dtype`"))
            })?;
        let element_size = dtype_size(dtype).ok_or_else(|| {
            StppError::InvalidHeader(format!("tensor {name:?}: unknown dtype {dtype:?}"))
        })?;

        let shape = entry
            .get("shape")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                StppError::InvalidHeader(format!("tensor {name:?}: missing array `shape`"))
            })?;
        // A zero-length shape is a scalar: one element, not zero.
        let mut elements: u64 = 1;
        for dimension in shape {
            let dimension = dimension.as_u64().ok_or_else(|| {
                StppError::InvalidHeader(format!(
                    "tensor {name:?}: shape dimension {dimension} is not a non-negative integer"
                ))
            })?;
            elements = elements.checked_mul(dimension).ok_or_else(|| {
                StppError::InvalidHeader(format!("tensor {name:?}: shape overflows u64"))
            })?;
        }

        let offsets = entry
            .get("data_offsets")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                StppError::InvalidHeader(format!("tensor {name:?}: missing array `data_offsets`"))
            })?;
        if offsets.len() != 2 {
            return Err(StppError::InvalidHeader(format!(
                "tensor {name:?}: data_offsets must have exactly 2 entries, got {}",
                offsets.len()
            )));
        }
        // as_u64 rejects negatives and non-integers in one step.
        let start = offsets[0].as_u64().ok_or_else(|| {
            StppError::InvalidHeader(format!(
                "tensor {name:?}: data_offsets[0] is not a non-negative integer"
            ))
        })?;
        let end = offsets[1].as_u64().ok_or_else(|| {
            StppError::InvalidHeader(format!(
                "tensor {name:?}: data_offsets[1] is not a non-negative integer"
            ))
        })?;

        if end < start {
            return Err(StppError::InvalidHeader(format!(
                "tensor {name:?}: data_offsets end {end} precedes start {start}"
            )));
        }
        if end > data_len {
            return Err(StppError::InvalidHeader(format!(
                "tensor {name:?}: data_offsets end {end} is past the end of the {data_len}-byte \
                 data block"
            )));
        }

        let declared = end - start;
        let expected = elements.checked_mul(element_size).ok_or_else(|| {
            StppError::InvalidHeader(format!("tensor {name:?}: byte length overflows u64"))
        })?;
        if declared != expected {
            return Err(StppError::InvalidHeader(format!(
                "tensor {name:?}: shape {shape:?} of {dtype} needs {expected} bytes but \
                 data_offsets span {declared}"
            )));
        }
    }

    check_no_overlaps(object)
}

/// Reject tensors whose byte ranges overlap.
///
/// Overlapping tensors are not merely odd: two names aliasing the same bytes means the file does
/// not have one unambiguous interpretation, and a signature over it attests to whichever reading
/// the loader happens to pick.
fn check_no_overlaps(object: &serde_json::Map<String, serde_json::Value>) -> Result<(), StppError> {
    let mut spans: Vec<(u64, u64, &str)> = Vec::new();
    for (name, entry) in object {
        if name == METADATA_KEY || name == PROVENANCE_KEY {
            continue;
        }
        // validate_header has already established these shapes.
        let Some(offsets) = entry
            .get("data_offsets")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        let (Some(start), Some(end)) = (offsets[0].as_u64(), offsets[1].as_u64()) else {
            continue;
        };
        // Zero-length tensors occupy no bytes and cannot overlap anything.
        if end > start {
            spans.push((start, end, name));
        }
    }
    spans.sort_unstable();
    for pair in spans.windows(2) {
        let (_, previous_end, previous_name) = pair[0];
        let (start, _, name) = pair[1];
        if start < previous_end {
            return Err(StppError::InvalidHeader(format!(
                "tensors {previous_name:?} and {name:?} overlap: {previous_name:?} ends at \
                 {previous_end} but {name:?} starts at {start}"
            )));
        }
    }
    Ok(())
}

/// Read a Safetensors file from `reader` and return (header_json, data_bytes).
///
/// The header is structurally validated against the data block before it is returned, so a
/// caller cannot receive a header describing tensors that do not fit the file.
///
/// # Errors
/// Returns [`StppError`] on any I/O, length, or JSON failure, or
/// [`StppError::InvalidHeader`] if the header does not describe the data.
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
    validate_header(&header, data.len() as u64)?;
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
    // Validate BEFORE signing. Signing a header that cannot be true produces a valid
    // attestation over nonsense, which is worse than no attestation at all.
    validate_header(header, data.len() as u64)?;
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
    // A structurally impossible header must not verify, even when the signature over it is
    // cryptographically sound -- the file may have been signed by an older or malicious tool.
    validate_header(header, data.len() as u64)?;
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
        // 16 bytes: shape [2,2] of F32 is 4 elements x 4 bytes. The previous fixture used 15
        // bytes with the same shape -- a header that could not be true, which the validator now
        // rejects and which nothing checked before.
        let data = b"weights-go-here!".to_vec();
        let mut header = serde_json::json!({
            "t": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}
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

#[cfg(test)]
mod header_validation {
    use super::*;
    use ed25519_dalek::SigningKey;

    const DATA: &[u8] = b"0123456789abcdef"; // 16 bytes

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn valid_header() -> serde_json::Value {
        serde_json::json!({
            "__metadata__": {"format": "pt"},
            "t": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}
        })
    }

    /// Each of these was signed AND verified `Ok` -- with an attacker-chosen signer -- before the
    /// header was validated at all.
    fn malformed_headers() -> Vec<(&'static str, serde_json::Value)> {
        vec![
            (
                "offsets past EOF",
                serde_json::json!({"__metadata__": {},
                    "t": {"dtype": "U8", "shape": [1099511627776u64], "data_offsets": [0, 1099511627776u64]}}),
            ),
            (
                "overlapping tensors",
                serde_json::json!({"__metadata__": {},
                    "a": {"dtype": "U8", "shape": [16], "data_offsets": [0, 16]},
                    "b": {"dtype": "U8", "shape": [8],  "data_offsets": [8, 16]}}),
            ),
            (
                "reversed offsets",
                serde_json::json!({"__metadata__": {},
                    "t": {"dtype": "U8", "shape": [16], "data_offsets": [16, 0]}}),
            ),
            (
                "negative offsets",
                serde_json::json!({"__metadata__": {},
                    "t": {"dtype": "U8", "shape": [16], "data_offsets": [-1, -100]}}),
            ),
            (
                "shape does not match the byte span",
                serde_json::json!({"__metadata__": {},
                    "t": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 4]}}),
            ),
            (
                "unknown dtype",
                serde_json::json!({"__metadata__": {},
                    "t": {"dtype": "COMPLEX256", "shape": [1], "data_offsets": [0, 16]}}),
            ),
            (
                "negative shape dimension",
                serde_json::json!({"__metadata__": {},
                    "t": {"dtype": "U8", "shape": [-4], "data_offsets": [0, 16]}}),
            ),
            (
                "data_offsets with three entries",
                serde_json::json!({"__metadata__": {},
                    "t": {"dtype": "U8", "shape": [16], "data_offsets": [0, 8, 16]}}),
            ),
            (
                "tensor entry is not an object",
                serde_json::json!({"__metadata__": {}, "t": "not an object"}),
            ),
        ]
    }

    #[test]
    fn sign_refuses_every_malformed_header() {
        for (label, mut header) in malformed_headers() {
            let result = sign(&mut header, DATA, "did:web:evil", &key());
            assert!(
                result.is_err(),
                "sign() blessed a malformed header [{label}] -- the signature would attest to \
                 a file that cannot be loaded"
            );
        }
    }

    /// Defence in depth: a file signed by an older or malicious tool must not verify either.
    #[test]
    fn verify_refuses_every_malformed_header() {
        for (label, header) in malformed_headers() {
            let result = verify(&header, DATA);
            assert!(
                result.is_err(),
                "verify() accepted a malformed header [{label}]"
            );
        }
    }

    #[test]
    fn read_safetensors_refuses_a_malformed_header() {
        for (label, header) in malformed_headers() {
            let mut buffer = Vec::new();
            write_safetensors(&mut buffer, &header, DATA).expect("write");
            let mut cursor = std::io::Cursor::new(buffer);
            assert!(
                read_safetensors(&mut cursor).is_err(),
                "read_safetensors returned a malformed header to its caller [{label}]"
            );
        }
    }

    #[test]
    fn a_well_formed_file_still_signs_and_verifies() {
        let mut header = valid_header();
        sign(&mut header, DATA, "did:web:honest-lab.example", &key()).expect("sign");
        let provenance = verify(&header, DATA).expect("verify");
        assert_eq!(provenance.signer, "did:web:honest-lab.example");
    }

    /// `__metadata__` is optional in the Safetensors format. Requiring it would reject spec-valid
    /// files written by other tools.
    #[test]
    fn a_header_without_metadata_is_accepted() {
        let mut header = serde_json::json!({
            "t": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}
        });
        sign(&mut header, DATA, "did:web:honest-lab.example", &key()).expect("sign");
        verify(&header, DATA).expect("verify");
    }

    #[test]
    fn adjacent_tensors_do_not_count_as_overlapping() {
        let mut header = serde_json::json!({
            "__metadata__": {},
            "a": {"dtype": "U8", "shape": [8], "data_offsets": [0, 8]},
            "b": {"dtype": "U8", "shape": [8], "data_offsets": [8, 16]}
        });
        sign(&mut header, DATA, "did:web:honest-lab.example", &key()).expect("sign");
        verify(&header, DATA).expect("verify");
    }

    #[test]
    fn a_scalar_tensor_is_one_element_not_zero() {
        // An empty shape denotes a scalar: 1 element, so an F32 scalar spans 4 bytes.
        let mut header = serde_json::json!({
            "__metadata__": {},
            "s": {"dtype": "F32", "shape": [], "data_offsets": [0, 4]}
        });
        sign(
            &mut header,
            &DATA[..4],
            "did:web:honest-lab.example",
            &key(),
        )
        .expect("sign");
        verify(&header, &DATA[..4]).expect("verify");
    }
}

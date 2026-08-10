use crate::format::{
    inspect_reader, payload_digest_reader, rewrite_metadata, GgufError, GgufLimits, GgufValue,
    MetadataEntry, SAFETY_PREFIX,
};
use warrantor_trust_core::signing::SigningKeyWrapper;
use warrantor_trust_core::verification;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Exact stable safety profile identifier.
pub const SAFETY_PROFILE: &str = "osaf.gguf.safety/1";
const SIGNATURE_DOMAIN: &[u8] = b"AUMOS-GGUF-SAFETY-SIGNATURE-V1\0";
const SIGNATURE_ALGORITHM: &str = "ed25519";

const PROFILE_KEY: &str = "osaf.safety.profile";
const MANIFEST_KEY: &str = "osaf.safety.manifest";
const MANIFEST_DIGEST_KEY: &str = "osaf.safety.manifest_sha256";
const PAYLOAD_DIGEST_KEY: &str = "osaf.safety.payload_sha256";
const ALGORITHM_KEY: &str = "osaf.safety.signature_algorithm";
const VERIFYING_KEY: &str = "osaf.safety.verifying_key";
const SIGNATURE_KEY: &str = "osaf.safety.signature";
const ISSUED_AT_KEY: &str = "osaf.safety.issued_at";
const EXPIRES_AT_KEY: &str = "osaf.safety.expires_at";

fn known_safety_keys() -> BTreeSet<&'static str> {
    [
        PROFILE_KEY,
        MANIFEST_KEY,
        MANIFEST_DIGEST_KEY,
        PAYLOAD_DIGEST_KEY,
        ALGORITHM_KEY,
        VERIFYING_KEY,
        SIGNATURE_KEY,
        ISSUED_AT_KEY,
        EXPIRES_AT_KEY,
    ]
    .into_iter()
    .collect()
}

/// Validated RFC 8785 canonical P6 manifest bytes and time claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyManifest {
    canonical_json: String,
    issued_at: u64,
    expires_at: Option<u64>,
}

impl SafetyManifest {
    /// Parse an already-canonical JSON object and validate the P6/S3 required fields.
    ///
    /// # Errors
    /// Rejects invalid JSON, non-canonical bytes, non-object manifests, missing AATM bindings,
    /// invalid timestamps, and expiry before issuance.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, SafetyManifestError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| SafetyManifestError::InvalidJson(error.to_string()))?;
        let object = value
            .as_object()
            .ok_or(SafetyManifestError::ObjectRequired)?;
        let canonical = serde_jcs::to_vec(&value)
            .map_err(|error| SafetyManifestError::Canonicalization(error.to_string()))?;
        if canonical != bytes {
            return Err(SafetyManifestError::NonCanonical);
        }
        for field in [
            "model",
            "dataset",
            "tokenizer",
            "prompt",
            "adapter",
            "container",
            "policy",
            "skill",
            "eval",
            "deployment_attestations",
        ] {
            if !object.contains_key(field) {
                return Err(SafetyManifestError::MissingAatmField(field.into()));
            }
        }
        let issued_at = object
            .get("issued_at")
            .and_then(serde_json::Value::as_u64)
            .ok_or(SafetyManifestError::InvalidIssuedAt)?;
        let expires_at = object
            .get("expires_at")
            .map(|value| value.as_u64().ok_or(SafetyManifestError::InvalidExpiresAt))
            .transpose()?;
        if expires_at.is_some_and(|expiry| expiry < issued_at) {
            return Err(SafetyManifestError::ExpiryBeforeIssue);
        }
        let canonical_json = String::from_utf8(canonical)
            .map_err(|error| SafetyManifestError::Canonicalization(error.to_string()))?;
        Ok(Self {
            canonical_json,
            issued_at,
            expires_at,
        })
    }

    /// Canonical JSON string.
    #[must_use]
    pub fn canonical_json(&self) -> &str {
        &self.canonical_json
    }

    /// Manifest issue time.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Optional manifest expiry.
    #[must_use]
    pub const fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_json.as_bytes()).into()
    }
}

/// Manifest validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SafetyManifestError {
    /// JSON syntax or data model is invalid.
    #[error("invalid safety manifest JSON: {0}")]
    InvalidJson(String),
    /// Manifest must be a JSON object.
    #[error("safety manifest must be a JSON object")]
    ObjectRequired,
    /// RFC 8785 encoding failed.
    #[error("safety manifest canonicalization failed: {0}")]
    Canonicalization(String),
    /// Input bytes differ from RFC 8785 canonical bytes.
    #[error("safety manifest is not RFC 8785 canonical JSON")]
    NonCanonical,
    /// Mandatory P6 artifact binding is absent.
    #[error("safety manifest is missing AATM field {0}")]
    MissingAatmField(String),
    /// `issued_at` is absent or not an unsigned integer.
    #[error("safety manifest issued_at must be uint64")]
    InvalidIssuedAt,
    /// `expires_at` is not an unsigned integer.
    #[error("safety manifest expires_at must be uint64")]
    InvalidExpiresAt,
    /// Expiry precedes issue time.
    #[error("safety manifest expiry precedes issue time")]
    ExpiryBeforeIssue,
}

/// Injected signing boundary; KMS/HSM implementations can satisfy this trait.
pub trait ManifestSigner {
    /// Raw Ed25519 verifying key.
    fn verifying_key(&self) -> [u8; 32];
    /// Sign an already-domain-separated message.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

/// T1 trust-core software-key adapter.
pub struct TrustCoreManifestSigner {
    signing_key: SigningKeyWrapper,
}

impl TrustCoreManifestSigner {
    /// Wrap a zeroizing T1 signing key.
    #[must_use]
    pub const fn new(signing_key: SigningKeyWrapper) -> Self {
        Self { signing_key }
    }
}

impl ManifestSigner for TrustCoreManifestSigner {
    fn verifying_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.signing_key.sign_bytes(message).to_bytes())
    }
}

/// Rewrite a validated GGUF stream with one atomic safety-profile metadata set.
///
/// The output must be a new or logically empty stream. Tensor bytes are copied in bounded chunks.
///
/// # Errors
/// Returns parser, manifest, signer, or output errors. Existing safety keys are removed together
/// before the new complete set is appended.
pub fn rewrite_with_profile<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    manifest: &SafetyManifest,
    signer: &dyn ManifestSigner,
    limits: &GgufLimits,
) -> Result<(), ProfileError> {
    let payload_digest = payload_digest_reader(input, limits)?;
    let info = inspect_reader(input, limits)?;
    let manifest_digest = manifest.digest();
    let signature_message =
        signature_message(&payload_digest, &manifest_digest, manifest.issued_at());
    let signature = signer
        .sign(&signature_message)
        .map_err(ProfileError::Signer)?;
    let verifying_key = signer.verifying_key();
    VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| ProfileError::Signer("signer returned an invalid Ed25519 key".into()))?;
    verification::verify_bytes(
        &signature_message,
        &Signature::from_bytes(&signature),
        &VerifyingKey::from_bytes(&verifying_key)
            .map_err(|_| ProfileError::Signer("signer returned an invalid Ed25519 key".into()))?,
    )
    .map_err(|_| ProfileError::Signer("signer returned a signature that does not verify".into()))?;

    let mut metadata = info
        .metadata
        .into_iter()
        .filter(|entry| !entry.key.starts_with(SAFETY_PREFIX))
        .collect::<Vec<_>>();
    metadata.extend(profile_entries(
        manifest,
        payload_digest,
        manifest_digest,
        verifying_key,
        signature,
    ));
    rewrite_metadata(input, output, &metadata, limits)?;
    Ok(())
}

/// Remove the entire safety namespace while preserving ordinary metadata and tensor bytes.
///
/// # Errors
/// Returns any parse or rewrite failure.
pub fn strip_safety<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    limits: &GgufLimits,
) -> Result<(), ProfileError> {
    let info = inspect_reader(input, limits)?;
    let metadata = info
        .metadata
        .into_iter()
        .filter(|entry| !entry.key.starts_with(SAFETY_PREFIX))
        .collect::<Vec<_>>();
    rewrite_metadata(input, output, &metadata, limits)?;
    Ok(())
}

/// Atomically strip the safety namespace through a same-directory temporary file.
///
/// # Errors
/// Existing destinations and aliases require `replace`; the original remains intact on failure.
pub fn strip_safety_path(
    input_path: &Path,
    output_path: &Path,
    limits: &GgufLimits,
    replace: bool,
) -> Result<(), ProfileError> {
    validate_path_replacement(input_path, output_path, replace)?;
    let parent = output_parent(output_path);
    let mut temporary = NamedTempFile::new_in(parent)?;
    {
        let mut input = File::open(input_path)?;
        strip_safety(&mut input, temporary.as_file_mut(), limits)?;
        temporary.as_file_mut().sync_all()?;
    }
    temporary
        .persist(output_path)
        .map_err(|error| ProfileError::Io(error.error))?;
    sync_parent(parent)?;
    Ok(())
}

/// Atomically rewrite a path through a same-directory temporary file.
///
/// If `replace` is false, an existing destination or input/output alias is rejected. If true,
/// replacement is requested through the platform-aware `tempfile` persistence operation.
///
/// # Errors
/// The original input remains intact on every pre-persist failure.
pub fn rewrite_path_with_profile(
    input_path: &Path,
    output_path: &Path,
    manifest: &SafetyManifest,
    signer: &dyn ManifestSigner,
    limits: &GgufLimits,
    replace: bool,
) -> Result<(), ProfileError> {
    validate_path_replacement(input_path, output_path, replace)?;
    let parent = output_parent(output_path);
    let mut temporary = NamedTempFile::new_in(parent)?;
    {
        let mut input = File::open(input_path)?;
        rewrite_with_profile(
            &mut input,
            temporary.as_file_mut(),
            manifest,
            signer,
            limits,
        )?;
        temporary.as_file_mut().sync_all()?;
    }
    temporary
        .persist(output_path)
        .map_err(|error| ProfileError::Io(error.error))?;
    sync_parent(parent)?;
    Ok(())
}

fn validate_path_replacement(
    input_path: &Path,
    output_path: &Path,
    replace: bool,
) -> Result<(), ProfileError> {
    let input_identity = std::fs::canonicalize(input_path)?;
    let output_identity = std::fs::canonicalize(output_path).ok();
    if output_identity.as_ref() == Some(&input_identity) && !replace {
        return Err(ProfileError::AliasedPaths);
    }
    if output_path.exists() && !replace {
        return Err(ProfileError::DestinationExists(output_path.to_path_buf()));
    }
    Ok(())
}

fn output_parent(output_path: &Path) -> &Path {
    output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent(parent: &Path) -> Result<(), ProfileError> {
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

fn profile_entries(
    manifest: &SafetyManifest,
    payload_digest: [u8; 32],
    manifest_digest: [u8; 32],
    verifying_key: [u8; 32],
    signature: [u8; 64],
) -> Vec<MetadataEntry> {
    let mut entries = vec![
        string_entry(PROFILE_KEY, SAFETY_PROFILE),
        string_entry(MANIFEST_KEY, manifest.canonical_json()),
        string_entry(MANIFEST_DIGEST_KEY, &digest_string(&manifest_digest)),
        string_entry(PAYLOAD_DIGEST_KEY, &digest_string(&payload_digest)),
        string_entry(ALGORITHM_KEY, SIGNATURE_ALGORITHM),
        string_entry(VERIFYING_KEY, &hex::encode(verifying_key)),
        string_entry(SIGNATURE_KEY, &hex::encode(signature)),
        MetadataEntry {
            key: ISSUED_AT_KEY.into(),
            value: GgufValue::Uint64(manifest.issued_at()),
        },
    ];
    if let Some(expires_at) = manifest.expires_at() {
        entries.push(MetadataEntry {
            key: EXPIRES_AT_KEY.into(),
            value: GgufValue::Uint64(expires_at),
        });
    }
    entries
}

fn string_entry(key: &str, value: &str) -> MetadataEntry {
    MetadataEntry {
        key: key.into(),
        value: GgufValue::String(value.into()),
    }
}

fn digest_string(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

fn signature_message(
    payload_digest: &[u8; 32],
    manifest_digest: &[u8; 32],
    issued_at: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 72);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(payload_digest);
    message.extend_from_slice(manifest_digest);
    message.extend_from_slice(&issued_at.to_le_bytes());
    message
}

/// Trusted verification-time and parser policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyPolicy {
    /// Parser/resource limits.
    pub limits: GgufLimits,
    /// Trusted current time snapshot in epoch seconds.
    pub now: u64,
    /// Allowed clock skew in seconds.
    pub clock_skew_seconds: u64,
    /// Maximum age since issuance. `None` disables this bound.
    pub maximum_age_seconds: Option<u64>,
    /// Whether `expires_at` is mandatory.
    pub require_expiry: bool,
}

impl VerifyPolicy {
    /// Construct a strict policy requiring explicit expiry and limiting age to 30 days.
    #[must_use]
    pub fn strict(now: u64) -> Self {
        Self {
            limits: GgufLimits::default(),
            now,
            clock_skew_seconds: 300,
            maximum_age_seconds: Some(30 * 24 * 60 * 60),
            require_expiry: true,
        }
    }
}

/// Successfully verified safety profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedSafetyProfile {
    /// Normalized payload digest.
    pub payload_sha256: String,
    /// Canonical manifest digest.
    pub manifest_sha256: String,
    /// Signer Ed25519 verifying key.
    pub verifying_key: String,
    /// Issue time.
    pub issued_at: u64,
    /// Optional expiry.
    pub expires_at: Option<u64>,
    /// Canonical manifest JSON.
    pub manifest: String,
}

/// Parse, bind, and cryptographically verify one S3 safety profile.
///
/// # Errors
/// Rejects missing/unknown/wrongly typed profile keys, non-canonical manifest JSON, digest
/// mismatch, invalid Ed25519 material/signature, future issuance, expiry, and excess age.
pub fn verify<R: Read + Seek>(
    reader: &mut R,
    policy: &VerifyPolicy,
) -> Result<VerifiedSafetyProfile, VerifyError> {
    let info = inspect_reader(reader, &policy.limits)?;
    let mut safety = BTreeMap::new();
    let known = known_safety_keys();
    for entry in info
        .metadata
        .iter()
        .filter(|entry| entry.key.starts_with(SAFETY_PREFIX))
    {
        if !known.contains(entry.key.as_str()) {
            return Err(VerifyError::UnknownSafetyKey(entry.key.clone()));
        }
        safety.insert(entry.key.as_str(), &entry.value);
    }
    for required in [
        PROFILE_KEY,
        MANIFEST_KEY,
        MANIFEST_DIGEST_KEY,
        PAYLOAD_DIGEST_KEY,
        ALGORITHM_KEY,
        VERIFYING_KEY,
        SIGNATURE_KEY,
        ISSUED_AT_KEY,
    ] {
        if !safety.contains_key(required) {
            return Err(VerifyError::MissingSafetyKey(required.into()));
        }
    }
    let profile = required_string(&safety, PROFILE_KEY)?;
    if profile != SAFETY_PROFILE {
        return Err(VerifyError::UnsupportedProfile(profile.into()));
    }
    let algorithm = required_string(&safety, ALGORITHM_KEY)?;
    if algorithm != SIGNATURE_ALGORITHM {
        return Err(VerifyError::UnsupportedAlgorithm(algorithm.into()));
    }
    let manifest_text = required_string(&safety, MANIFEST_KEY)?;
    let manifest = SafetyManifest::from_canonical_json(manifest_text.as_bytes())?;
    let issued_at = required_u64(&safety, ISSUED_AT_KEY)?;
    if issued_at != manifest.issued_at() {
        return Err(VerifyError::ManifestTimeMismatch(ISSUED_AT_KEY.into()));
    }
    let expires_at = safety
        .get(EXPIRES_AT_KEY)
        .map(|value| exact_u64(value, EXPIRES_AT_KEY))
        .transpose()?;
    if expires_at != manifest.expires_at() {
        return Err(VerifyError::ManifestTimeMismatch(EXPIRES_AT_KEY.into()));
    }
    if policy.require_expiry && expires_at.is_none() {
        return Err(VerifyError::ExpiryRequired);
    }
    validate_time(policy, issued_at, expires_at)?;

    let manifest_digest = manifest.digest();
    let encoded_manifest_digest = required_string(&safety, MANIFEST_DIGEST_KEY)?;
    if encoded_manifest_digest != digest_string(&manifest_digest) {
        return Err(VerifyError::ManifestDigestMismatch);
    }
    let payload_digest = payload_digest_reader(reader, &policy.limits)?;
    let encoded_payload_digest = required_string(&safety, PAYLOAD_DIGEST_KEY)?;
    if encoded_payload_digest != digest_string(&payload_digest) {
        return Err(VerifyError::PayloadDigestMismatch);
    }
    let verifying_key_hex = required_string(&safety, VERIFYING_KEY)?;
    let verifying_key_bytes = decode_lower_hex::<32>(verifying_key_hex, VERIFYING_KEY)?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| VerifyError::InvalidVerifyingKey)?;
    let signature_hex = required_string(&safety, SIGNATURE_KEY)?;
    let signature_bytes = decode_lower_hex::<64>(signature_hex, SIGNATURE_KEY)?;
    let message = signature_message(&payload_digest, &manifest_digest, issued_at);
    verification::verify_bytes(
        &message,
        &Signature::from_bytes(&signature_bytes),
        &verifying_key,
    )
    .map_err(|_| VerifyError::InvalidSignature)?;
    Ok(VerifiedSafetyProfile {
        payload_sha256: digest_string(&payload_digest),
        manifest_sha256: digest_string(&manifest_digest),
        verifying_key: verifying_key_hex.into(),
        issued_at,
        expires_at,
        manifest: manifest.canonical_json().into(),
    })
}

fn required_string<'a>(
    safety: &'a BTreeMap<&str, &GgufValue>,
    key: &str,
) -> Result<&'a str, VerifyError> {
    safety
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| VerifyError::WrongSafetyType {
            key: key.into(),
            expected: "string",
        })
}

fn required_u64(safety: &BTreeMap<&str, &GgufValue>, key: &str) -> Result<u64, VerifyError> {
    safety
        .get(key)
        .map(|value| exact_u64(value, key))
        .transpose()?
        .ok_or_else(|| VerifyError::MissingSafetyKey(key.into()))
}

fn exact_u64(value: &GgufValue, key: &str) -> Result<u64, VerifyError> {
    match value {
        GgufValue::Uint64(value) => Ok(*value),
        _ => Err(VerifyError::WrongSafetyType {
            key: key.into(),
            expected: "uint64",
        }),
    }
}

fn decode_lower_hex<const N: usize>(value: &str, key: &str) -> Result<[u8; N], VerifyError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerifyError::InvalidLowerHex(key.into()));
    }
    let decoded = hex::decode(value).map_err(|_| VerifyError::InvalidLowerHex(key.into()))?;
    decoded
        .try_into()
        .map_err(|_| VerifyError::InvalidLowerHex(key.into()))
}

fn validate_time(
    policy: &VerifyPolicy,
    issued_at: u64,
    expires_at: Option<u64>,
) -> Result<(), VerifyError> {
    let latest_now = policy.now.saturating_add(policy.clock_skew_seconds);
    if issued_at > latest_now {
        return Err(VerifyError::IssuedInFuture {
            issued_at,
            now: policy.now,
        });
    }
    let earliest_now = policy.now.saturating_sub(policy.clock_skew_seconds);
    if expires_at.is_some_and(|expiry| earliest_now > expiry) {
        return Err(VerifyError::Expired {
            expires_at: expires_at.unwrap_or_default(),
            now: policy.now,
        });
    }
    if let Some(maximum_age) = policy.maximum_age_seconds {
        let oldest_allowed = issued_at
            .checked_add(maximum_age)
            .and_then(|value| value.checked_add(policy.clock_skew_seconds))
            .unwrap_or(u64::MAX);
        if policy.now > oldest_allowed {
            return Err(VerifyError::TooOld {
                issued_at,
                maximum_age,
                now: policy.now,
            });
        }
    }
    Ok(())
}

/// Profile rewrite failures.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// GGUF parse or write failed.
    #[error(transparent)]
    Gguf(#[from] GgufError),
    /// Filesystem operation failed.
    #[error("GGUF profile filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// Injected signer failed or returned inconsistent output.
    #[error("GGUF profile signer failed: {0}")]
    Signer(String),
    /// Input and output identify the same file without explicit replacement.
    #[error("input and output paths alias; explicit replacement is required")]
    AliasedPaths,
    /// Destination exists and replacement was not authorized.
    #[error("destination already exists: {0}")]
    DestinationExists(PathBuf),
}

/// Safety profile verification failures.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// GGUF parsing/digest failed.
    #[error(transparent)]
    Gguf(#[from] GgufError),
    /// Canonical manifest validation failed.
    #[error(transparent)]
    Manifest(#[from] SafetyManifestError),
    /// Required stable safety key is absent.
    #[error("missing safety metadata key {0}")]
    MissingSafetyKey(String),
    /// Profile v1 does not permit unknown safety keys.
    #[error("unknown safety metadata key {0}")]
    UnknownSafetyKey(String),
    /// Safety metadata value has the wrong exact GGUF type.
    #[error("safety metadata {key} must have GGUF type {expected}")]
    WrongSafetyType {
        /// Key.
        key: String,
        /// Required type.
        expected: &'static str,
    },
    /// Profile identifier is unsupported.
    #[error("unsupported GGUF safety profile {0}")]
    UnsupportedProfile(String),
    /// Signature algorithm is unsupported.
    #[error("unsupported GGUF safety signature algorithm {0}")]
    UnsupportedAlgorithm(String),
    /// Metadata timestamp differs from canonical manifest.
    #[error("safety metadata timestamp does not match manifest: {0}")]
    ManifestTimeMismatch(String),
    /// Verification policy requires expiry.
    #[error("safety profile expiry is required")]
    ExpiryRequired,
    /// Manifest digest is incorrect.
    #[error("safety manifest digest mismatch")]
    ManifestDigestMismatch,
    /// Normalized payload digest is incorrect.
    #[error("GGUF payload digest mismatch")]
    PayloadDigestMismatch,
    /// Key or signature is not exact lowercase fixed-length hex.
    #[error("safety metadata must be exact lowercase hex: {0}")]
    InvalidLowerHex(String),
    /// Ed25519 verifying key encoding is invalid.
    #[error("invalid Ed25519 verifying key")]
    InvalidVerifyingKey,
    /// Ed25519 signature verification failed.
    #[error("GGUF safety signature verification failed")]
    InvalidSignature,
    /// Issue time is beyond allowed clock skew.
    #[error("safety profile issued in future: issued_at={issued_at}, now={now}")]
    IssuedInFuture {
        /// Issue time.
        issued_at: u64,
        /// Trusted time.
        now: u64,
    },
    /// Profile expired.
    #[error("safety profile expired: expires_at={expires_at}, now={now}")]
    Expired {
        /// Expiry.
        expires_at: u64,
        /// Trusted time.
        now: u64,
    },
    /// Profile exceeds maximum age.
    #[error("safety profile too old: issued_at={issued_at}, maximum_age={maximum_age}, now={now}")]
    TooOld {
        /// Issue time.
        issued_at: u64,
        /// Maximum age.
        maximum_age: u64,
        /// Trusted time.
        now: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{inspect, test_fixture, TensorInfo};
    use std::io::Cursor;

    fn entry(key: &str, value: GgufValue) -> MetadataEntry {
        MetadataEntry {
            key: key.into(),
            value,
        }
    }

    fn tensor() -> TensorInfo {
        TensorInfo {
            name: "weight".into(),
            dimensions: vec![2],
            tensor_type: 0,
            offset: 0,
            byte_length: 8,
        }
    }

    fn unsigned_fixture() -> Vec<u8> {
        test_fixture(
            &[entry(
                "general.architecture",
                GgufValue::String("test".into()),
            )],
            &[tensor()],
            &[1, 2, 3, 4, 5, 6, 7, 8],
        )
    }

    fn manifest(issued_at: u64, expires_at: Option<u64>) -> SafetyManifest {
        let mut value = serde_json::json!({
            "adapter": [],
            "container": {"digest": "sha256:container"},
            "dataset": [],
            "deployment_attestations": [],
            "eval": {"digest": "sha256:eval"},
            "issued_at": issued_at,
            "model": {"digest": "sha256:model"},
            "policy": {"digest": "sha256:policy"},
            "prompt": [],
            "skill": [],
            "tokenizer": {"digest": "sha256:tokenizer"}
        });
        if let Some(expires_at) = expires_at {
            value
                .as_object_mut()
                .expect("manifest object")
                .insert("expires_at".into(), expires_at.into());
        }
        let canonical = serde_jcs::to_vec(&value).expect("canonical JSON");
        SafetyManifest::from_canonical_json(&canonical).expect("valid manifest")
    }

    fn signer() -> TrustCoreManifestSigner {
        TrustCoreManifestSigner::new(SigningKeyWrapper::from_bytes(&[9; 32]))
    }

    fn signed_fixture() -> Vec<u8> {
        let mut input = Cursor::new(unsigned_fixture());
        let mut output = Cursor::new(Vec::new());
        rewrite_with_profile(
            &mut input,
            &mut output,
            &manifest(1_000, Some(2_000)),
            &signer(),
            &GgufLimits::default(),
        )
        .expect("sign fixture");
        output.into_inner()
    }

    fn verify_policy(now: u64) -> VerifyPolicy {
        VerifyPolicy {
            limits: GgufLimits::default(),
            now,
            clock_skew_seconds: 0,
            maximum_age_seconds: Some(10_000),
            require_expiry: true,
        }
    }

    #[test]
    fn canonical_manifest_requires_all_aatm_fields_and_matching_time_order() {
        assert_eq!(
            SafetyManifest::from_canonical_json(b"{\"issued_at\":1}"),
            Err(SafetyManifestError::MissingAatmField("model".into()))
        );
        assert_eq!(
            SafetyManifest::from_canonical_json(b"{ \"issued_at\": 1 }"),
            Err(SafetyManifestError::NonCanonical)
        );
        let invalid = serde_jcs::to_vec(&serde_json::json!({
            "adapter": [], "container": {}, "dataset": [], "deployment_attestations": [],
            "eval": {}, "expires_at": 9, "issued_at": 10, "model": {}, "policy": {},
            "prompt": [], "skill": [], "tokenizer": {}
        }))
        .expect("canonical invalid manifest");
        assert_eq!(
            SafetyManifest::from_canonical_json(&invalid),
            Err(SafetyManifestError::ExpiryBeforeIssue)
        );
    }

    #[test]
    fn profile_rewrite_roundtrip_verifies_and_preserves_payload_identity() {
        let unsigned = unsigned_fixture();
        let unsigned_digest =
            payload_digest_reader(&mut Cursor::new(&unsigned), &GgufLimits::default())
                .expect("unsigned digest");
        let signed = signed_fixture();
        let signed_digest =
            payload_digest_reader(&mut Cursor::new(&signed), &GgufLimits::default())
                .expect("signed digest");
        assert_eq!(unsigned_digest, signed_digest);
        let verified = verify(&mut Cursor::new(&signed), &verify_policy(1_500))
            .expect("verified safety profile");
        assert_eq!(verified.payload_sha256, digest_string(&signed_digest));
        assert_eq!(verified.issued_at, 1_000);
        assert_eq!(verified.expires_at, Some(2_000));
        assert_eq!(verified.verifying_key.len(), 64);
    }

    #[test]
    fn tensor_metadata_manifest_and_signature_tampering_fail_distinct_checks() {
        let signed = signed_fixture();
        let mut tensor_tampered = signed.clone();
        *tensor_tampered.last_mut().expect("tensor byte") ^= 1;
        assert!(matches!(
            verify(&mut Cursor::new(tensor_tampered), &verify_policy(1_500)),
            Err(VerifyError::PayloadDigestMismatch)
        ));

        let info = inspect(Cursor::new(&signed), &GgufLimits::default()).expect("inspect signed");
        let signature = info
            .metadata(SIGNATURE_KEY)
            .and_then(GgufValue::as_str)
            .expect("signature")
            .as_bytes()
            .to_vec();
        let mut signature_tampered = signed.clone();
        let signature_position = signature_tampered
            .windows(signature.len())
            .position(|window| window == signature)
            .expect("signature position");
        signature_tampered[signature_position] = if signature[0] == b'a' { b'b' } else { b'a' };
        assert!(matches!(
            verify(&mut Cursor::new(signature_tampered), &verify_policy(1_500)),
            Err(VerifyError::InvalidSignature)
        ));

        let manifest_text = info
            .metadata(MANIFEST_KEY)
            .and_then(GgufValue::as_str)
            .expect("manifest");
        let marker = b"sha256:model";
        let marker_offset = manifest_text
            .as_bytes()
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("manifest marker");
        let manifest_position = signed
            .windows(manifest_text.len())
            .position(|window| window == manifest_text.as_bytes())
            .expect("manifest position");
        let mut manifest_tampered = signed;
        manifest_tampered[manifest_position + marker_offset] = b't';
        assert!(matches!(
            verify(&mut Cursor::new(manifest_tampered), &verify_policy(1_500)),
            Err(VerifyError::ManifestDigestMismatch)
        ));
    }

    #[test]
    fn unknown_safety_key_wrong_type_and_missing_expiry_fail_closed() {
        let signed = signed_fixture();
        let info = inspect(Cursor::new(&signed), &GgufLimits::default()).expect("inspect signed");
        let data = signed[info.tensor_data_offset as usize..].to_vec();
        let mut unknown_metadata = info.metadata.clone();
        unknown_metadata.push(entry(
            "osaf.safety.future_extension",
            GgufValue::String("ignored?".into()),
        ));
        let unknown = test_fixture(&unknown_metadata, &info.tensors, &data);
        assert!(matches!(
            verify(&mut Cursor::new(unknown), &verify_policy(1_500)),
            Err(VerifyError::UnknownSafetyKey(_))
        ));

        let mut wrong_metadata = info.metadata.clone();
        wrong_metadata
            .iter_mut()
            .find(|entry| entry.key == ISSUED_AT_KEY)
            .expect("issued_at")
            .value = GgufValue::Uint32(1_000);
        let wrong = test_fixture(&wrong_metadata, &info.tensors, &data);
        assert!(matches!(
            verify(&mut Cursor::new(wrong), &verify_policy(1_500)),
            Err(VerifyError::WrongSafetyType { .. })
        ));

        let mut no_expiry_policy = verify_policy(1_500);
        let unsigned_expiry = {
            let mut input = Cursor::new(unsigned_fixture());
            let mut output = Cursor::new(Vec::new());
            rewrite_with_profile(
                &mut input,
                &mut output,
                &manifest(1_000, None),
                &signer(),
                &GgufLimits::default(),
            )
            .expect("profile without expiry");
            output.into_inner()
        };
        assert!(matches!(
            verify(&mut Cursor::new(&unsigned_expiry), &no_expiry_policy),
            Err(VerifyError::ExpiryRequired)
        ));
        no_expiry_policy.require_expiry = false;
        verify(&mut Cursor::new(unsigned_expiry), &no_expiry_policy)
            .expect("policy explicitly permits absent expiry");
    }

    #[test]
    fn trusted_clock_enforces_future_expiry_and_maximum_age() {
        let signed = signed_fixture();
        assert!(matches!(
            verify(&mut Cursor::new(&signed), &verify_policy(999)),
            Err(VerifyError::IssuedInFuture { .. })
        ));
        assert!(matches!(
            verify(&mut Cursor::new(&signed), &verify_policy(2_001)),
            Err(VerifyError::Expired { .. })
        ));
        let mut age_policy = verify_policy(1_101);
        age_policy.maximum_age_seconds = Some(100);
        assert!(matches!(
            verify(&mut Cursor::new(signed), &age_policy),
            Err(VerifyError::TooOld { .. })
        ));
    }

    #[test]
    fn strip_removes_only_safety_namespace_and_preserves_tensor_bytes() {
        let signed = signed_fixture();
        let signed_info =
            inspect(Cursor::new(&signed), &GgufLimits::default()).expect("signed info");
        let mut output = Cursor::new(Vec::new());
        strip_safety(
            &mut Cursor::new(&signed),
            &mut output,
            &GgufLimits::default(),
        )
        .expect("strip");
        let stripped = output.into_inner();
        let stripped_info =
            inspect(Cursor::new(&stripped), &GgufLimits::default()).expect("stripped info");
        assert!(stripped_info
            .metadata
            .iter()
            .all(|entry| !entry.key.starts_with(SAFETY_PREFIX)));
        assert_eq!(
            &signed[signed_info.tensor_data_offset as usize..],
            &stripped[stripped_info.tensor_data_offset as usize..]
        );
    }

    struct FailingSigner;

    impl ManifestSigner for FailingSigner {
        fn verifying_key(&self) -> [u8; 32] {
            [0; 32]
        }

        fn sign(&self, _message: &[u8]) -> Result<[u8; 64], String> {
            Err("HSM unavailable".into())
        }
    }

    #[test]
    fn signer_outage_cannot_produce_partial_success() {
        let result = rewrite_with_profile(
            &mut Cursor::new(unsigned_fixture()),
            &mut Cursor::new(Vec::new()),
            &manifest(1_000, Some(2_000)),
            &FailingSigner,
            &GgufLimits::default(),
        );
        assert!(matches!(result, Err(ProfileError::Signer(_))));
    }

    #[test]
    fn path_rewrite_is_atomic_and_requires_explicit_replacement() {
        let directory = tempfile::tempdir().expect("temp directory");
        let input = directory.path().join("input.gguf");
        let output = directory.path().join("output.gguf");
        std::fs::write(&input, unsigned_fixture()).expect("write input");
        rewrite_path_with_profile(
            &input,
            &output,
            &manifest(1_000, Some(2_000)),
            &signer(),
            &GgufLimits::default(),
            false,
        )
        .expect("atomic output");
        assert!(matches!(
            rewrite_path_with_profile(
                &input,
                &output,
                &manifest(1_000, Some(2_000)),
                &signer(),
                &GgufLimits::default(),
                false,
            ),
            Err(ProfileError::DestinationExists(_))
        ));
        rewrite_path_with_profile(
            &input,
            &input,
            &manifest(1_000, Some(2_000)),
            &signer(),
            &GgufLimits::default(),
            true,
        )
        .expect("explicit in-place atomic replacement");
        verify(
            &mut File::open(input).expect("replaced input"),
            &verify_policy(1_500),
        )
        .expect("replacement verifies");
    }
}

//! Agent Manifest (`agent.yaml`) — the OpenAPI for agents.
//!
//! A declarative, signed, receipted description of what an agent *is*: identity, the side-effect
//! classes it may use, the policies that bind it, the model/tools/data it depends on, the runtime
//! attestation it requires, and its enforcement mode. An agent without a valid signed manifest
//! cannot obtain authority.
//!
//! See [`specs/warrantor-v4/16-agent-manifest.md`](../../specs/warrantor-v4/16-agent-manifest.md).
//!
//! This crate is deliberately tokio-free and async-runtime-free: it is part of the trusted-core
//! dependency surface, so its transitive tree is part of its threat model. Ed25519 is provided by
//! `ed25519-dalek` (pure Rust, no system crypto).

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants — the schema in code form (mirrors 16-agent-manifest.schema.json)
// ---------------------------------------------------------------------------

pub const API_VERSION: &str = "agent.warrantor.io/v1";
pub const KIND: &str = "AgentManifest";

/// The invariant I-08 side-effect-class ladder, ordered by escalating consequence.
pub const CAPABILITY_LADDER: &[&str] = &["read", "write", "financial", "destructive", "physical"];

pub const ENFORCEMENT_MODES: &[&str] = &["observed", "mediated"];

// ---------------------------------------------------------------------------
// Error model — codes match testvectors/agent-manifest/vectors.json
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("malformed JSON: {0}")]
    MalformedJson(String),
    #[error("manifest must be a JSON object at the top level")]
    NotAnObject,
    #[error("missing required field: {field}")]
    MissingRequiredField { field: String },
    #[error("unexpected field: {field}")]
    UnexpectedField { field: String },
    #[error("invalid apiVersion: expected '{API_VERSION}'")]
    InvalidApiVersion,
    #[error("invalid kind: expected '{KIND}'")]
    InvalidKind,
    #[error("invalid identity ({field}): must be a spiffe:// URI")]
    InvalidIdentity { field: String },
    #[error("empty capabilities: at least one side-effect class is required")]
    EmptyCapabilities { field: String },
    #[error("invalid capability '{bad}' in {field}: must be one of {allowed:?}")]
    InvalidCapability {
        field: String,
        bad: String,
        allowed: &'static [&'static str],
    },
    #[error("empty policy_refs: at least one policy binding is required")]
    EmptyPolicyRefs { field: String },
    #[error("invalid enforcement_mode '{bad}' in {field}: must be one of {allowed:?}")]
    InvalidEnforcementMode {
        field: String,
        bad: String,
        allowed: &'static [&'static str],
    },
    #[error("invalid version '{bad}' in {field}: must be semver (X.Y.Z)")]
    InvalidVersion { field: String, bad: String },
    #[error("invalid model digest '{bad}' in {field}: must match ^[a-z0-9]+:[a-f0-9]+$")]
    InvalidModelDigest { field: String, bad: String },
    #[error("signature: {0}")]
    Signature(String),
    #[error("signature envelope malformed: {0}")]
    SignatureEnvelope(String),
    #[error("manifest has expired (expires_at={0})")]
    Expired(String),
    #[error("manifest not yet valid (issued_at={0})")]
    NotYetValid(String),
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dependencies {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentManifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub identity: String,
    pub capabilities: Vec<String>,
    pub policy_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dependencies: Option<Dependencies>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attestation: Option<Vec<String>>,
    pub enforcement_mode: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureEnvelope {
    pub algorithm: String, // "Ed25519"
    pub key_id: String,
    pub public_key: String, // hex, 32-byte Ed25519 verifying key
    pub value: String,      // hex, 64-byte Ed25519 signature
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedManifest {
    pub manifest: AgentManifest,
    pub signature: SignatureEnvelope,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub issued_at: Option<String>,  // RFC 3339
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub issuer: Option<String>,     // SPIFFE ID of the issuer
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<String>, // RFC 3339
}

// ---------------------------------------------------------------------------
// Parse + validate — produces the precise error codes the vectors require
// ---------------------------------------------------------------------------

/// Parse a JSON string into a validated [`AgentManifest`], producing the exact error code for any
/// rule violation. This is the entry point a gateway / SDK calls.
pub fn parse_and_validate(json: &str) -> Result<AgentManifest, ManifestError> {
    let value: Value = serde_json::from_str(json).map_err(|e| ManifestError::MalformedJson(e.to_string()))?;
    let obj = value.as_object().ok_or(ManifestError::NotAnObject)?;
    validate_object(obj)
}

/// Validate an already-parsed JSON object. Separated so a caller that has a `Value` need not
/// re-serialize.
pub fn validate_object(obj: &Map<String, Value>) -> Result<AgentManifest, ManifestError> {
    // 1. Reject unexpected fields (additionalProperties: false).
    let allowed: HashSet<&str> = [
        "apiVersion", "kind", "name", "identity", "capabilities", "policy_refs",
        "dependencies", "attestation", "enforcement_mode", "description", "version",
    ].into_iter().collect();
    for key in obj.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(ManifestError::UnexpectedField { field: key.clone() });
        }
    }

    // 2. Required fields.
    let require_str = |field: &str| -> Result<String, ManifestError> {
        match obj.get(field) {
            None => Err(ManifestError::MissingRequiredField { field: field.to_string() }),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(ManifestError::MissingRequiredField { field: field.to_string() }),
        }
    };
    let api_version = require_str("apiVersion")?;
    let kind = require_str("kind")?;
    let name = require_str("name")?;
    let identity = require_str("identity")?;
    let enforcement_mode = require_str("enforcement_mode")?;

    if api_version != API_VERSION {
        return Err(ManifestError::InvalidApiVersion);
    }
    if kind != KIND {
        return Err(ManifestError::InvalidKind);
    }
    if name.is_empty() {
        return Err(ManifestError::MissingRequiredField { field: "name".to_string() });
    }
    if !identity.starts_with("spiffe://") {
        return Err(ManifestError::InvalidIdentity { field: "identity".to_string() });
    }

    // capabilities — non-empty, all on the ladder.
    let capabilities: Vec<String> = match obj.get("capabilities") {
        None => return Err(ManifestError::MissingRequiredField { field: "capabilities".to_string() }),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(String::from))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ManifestError::EmptyCapabilities { field: "capabilities".to_string() })?,
        Some(_) => return Err(ManifestError::EmptyCapabilities { field: "capabilities".to_string() }),
    };
    if capabilities.is_empty() {
        return Err(ManifestError::EmptyCapabilities { field: "capabilities".to_string() });
    }
    for c in &capabilities {
        if !CAPABILITY_LADDER.contains(&c.as_str()) {
            return Err(ManifestError::InvalidCapability {
                field: "capabilities".to_string(),
                bad: c.clone(),
                allowed: CAPABILITY_LADDER,
            });
        }
    }

    // policy_refs — non-empty.
    let policy_refs: Vec<String> = match obj.get("policy_refs") {
        None => return Err(ManifestError::MissingRequiredField { field: "policy_refs".to_string() }),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(String::from))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ManifestError::EmptyPolicyRefs { field: "policy_refs".to_string() })?,
        Some(_) => return Err(ManifestError::EmptyPolicyRefs { field: "policy_refs".to_string() }),
    };
    if policy_refs.is_empty() {
        return Err(ManifestError::EmptyPolicyRefs { field: "policy_refs".to_string() });
    }

    // enforcement_mode enum.
    if !ENFORCEMENT_MODES.contains(&enforcement_mode.as_str()) {
        return Err(ManifestError::InvalidEnforcementMode {
            field: "enforcement_mode".to_string(),
            bad: enforcement_mode.clone(),
            allowed: ENFORCEMENT_MODES,
        });
    }

    // optional version — semver check.
    let version = match obj.get("version") {
        None => None,
        Some(Value::String(s)) => {
            if !is_semver(s) {
                return Err(ManifestError::InvalidVersion {
                    field: "version".to_string(),
                    bad: s.clone(),
                });
            }
            Some(s.clone())
        }
        Some(_) => return Err(ManifestError::InvalidVersion {
            field: "version".to_string(),
            bad: "<non-string>".to_string(),
        }),
    };

    // optional dependencies.
    let dependencies = match obj.get("dependencies") {
        None => None,
        Some(Value::Object(d)) => {
            let dep = parse_dependencies(d)?;
            Some(dep)
        }
        Some(_) => return Err(ManifestError::InvalidModelDigest {
            field: "dependencies".to_string(),
            bad: "<non-object>".to_string(),
        }),
    };
    // dependencies.model digest pattern, if present.
    if let Some(Dependencies { model: Some(m), .. }) = &dependencies {
        if !is_digest(m) {
            return Err(ManifestError::InvalidModelDigest {
                field: "dependencies.model".to_string(),
                bad: m.clone(),
            });
        }
    }

    let attestation = match obj.get("attestation") {
        None => None,
        Some(Value::Array(a)) => Some(
            a.iter()
                .map(|v| v.as_str().map(String::from))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| ManifestError::UnexpectedField { field: "attestation".to_string() })?,
        ),
        Some(_) => return Err(ManifestError::UnexpectedField { field: "attestation".to_string() }),
    };

    let description = match obj.get("description") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(ManifestError::UnexpectedField { field: "description".to_string() }),
    };

    Ok(AgentManifest {
        api_version,
        kind,
        name,
        identity,
        capabilities,
        policy_refs,
        dependencies,
        attestation,
        enforcement_mode,
        description,
        version,
    })
}

fn parse_dependencies(d: &Map<String, Value>) -> Result<Dependencies, ManifestError> {
    let allowed: HashSet<&str> = ["model", "tools", "data"].into_iter().collect();
    for k in d.keys() {
        if !allowed.contains(k.as_str()) {
            return Err(ManifestError::UnexpectedField { field: format!("dependencies.{}", k) });
        }
    }
    let model = match d.get("model") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(ManifestError::InvalidModelDigest {
            field: "dependencies.model".to_string(),
            bad: "<non-string>".to_string(),
        }),
    };
    let tools = match d.get("tools") {
        None => None,
        Some(Value::Array(a)) => Some(
            a.iter()
                .map(|v| v.as_str().map(String::from))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| ManifestError::UnexpectedField { field: "dependencies.tools".to_string() })?,
        ),
        Some(_) => return Err(ManifestError::UnexpectedField { field: "dependencies.tools".to_string() }),
    };
    let data = match d.get("data") {
        None => None,
        Some(Value::Array(a)) => Some(
            a.iter()
                .map(|v| v.as_str().map(String::from))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| ManifestError::UnexpectedField { field: "dependencies.data".to_string() })?,
        ),
        Some(_) => return Err(ManifestError::UnexpectedField { field: "dependencies.data".to_string() }),
    };
    Ok(Dependencies { model, tools, data })
}

fn is_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn is_digest(s: &str) -> bool {
    // ^[a-z0-9]+:[a-f0-9]+$
    let mut colon_seen = false;
    let mut algo_len = 0usize;
    let mut hex_len = 0usize;
    for c in s.chars() {
        if !colon_seen {
            if c == ':' {
                if algo_len == 0 {
                    return false;
                }
                colon_seen = true;
            } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
                algo_len += 1;
            } else {
                return false;
            }
        } else if c.is_ascii_hexdigit() && !c.is_ascii_uppercase() {
            hex_len += 1;
        } else {
            return false;
        }
    }
    colon_seen && hex_len > 0
}

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785-shaped: sorted keys, compact, UTF-8) + digest
// ---------------------------------------------------------------------------

/// Recursively sort object keys so two implementations compute byte-identical canonical bytes.
fn canonicalize_value(v: &Value) -> Value {
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

/// Deterministic serialization of the manifest. A third party recomputing this from the same
/// manifest fields gets byte-identical output — which is what makes the signature verifiable.
pub fn canonical_json(m: &AgentManifest) -> String {
    let v = serde_json::to_value(m).expect("AgentManifest serializes to Value");
    let v = canonicalize_value(&v);
    serde_json::to_string(&v).expect("canonical Value serializes")
}

/// SHA-256 of the canonical-JSON bytes — the manifest digest that goes into every receipt.
pub fn digest(m: &AgentManifest) -> [u8; 32] {
    let canonical = canonical_json(m);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Hex-encoded digest, for embedding in receipts/manifest refs.
pub fn digest_hex(m: &AgentManifest) -> String {
    hex::encode(&digest(m)[..])
}

// ---------------------------------------------------------------------------
// Ed25519 signature envelope
// ---------------------------------------------------------------------------

/// Sign a manifest with an Ed25519 key. The signed object's `signature.value` is over
/// `canonical_json(manifest)`.
pub fn sign(m: &AgentManifest, key: &SigningKey, key_id: &str) -> SignedManifest {
    let canonical = canonical_json(m);
    let sig: Signature = key.sign(canonical.as_bytes());
    let verifying = key.verifying_key();
    SignedManifest {
        manifest: m.clone(),
        signature: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            key_id: key_id.to_string(),
            public_key: hex::encode(&verifying.to_bytes()),
            value: hex::encode(&sig.to_bytes()),
        },
        issued_at: None,
        issuer: None,
        expires_at: None,
    }
}

/// Verify a signed manifest: recompute canonical JSON, verify the Ed25519 signature against the
/// embedded public key.
pub fn verify(sm: &SignedManifest) -> Result<(), ManifestError> {
    if sm.signature.algorithm != "Ed25519" {
        return Err(ManifestError::SignatureEnvelope(format!(
            "unsupported algorithm: {}",
            sm.signature.algorithm
        )));
    }
    let pk_bytes = hex::decode(&sm.signature.public_key)
        .map_err(|e| ManifestError::SignatureEnvelope(format!("public_key hex: {}", e)))?;
    if pk_bytes.len() != 32 {
        return Err(ManifestError::SignatureEnvelope(format!(
            "public_key must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| ManifestError::SignatureEnvelope(format!("public_key: {}", e)))?;

    let sig_bytes = hex::decode(&sm.signature.value)
        .map_err(|e| ManifestError::SignatureEnvelope(format!("signature hex: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(ManifestError::SignatureEnvelope(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let canonical = canonical_json(&sm.manifest);
    vkey
        .verify(canonical.as_bytes(), &sig)
        .map_err(|_| ManifestError::Signature("Ed25519 signature does not verify".to_string()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convenience: generate a keypair using the OS RNG. Intended for tests and the manifest-issuer
/// bootstrap; production keys come from KMS/HSM.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

// hex — minimal inline implementation to avoid pulling a crate just for two functions.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
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
// Unit tests — schema + signature round-trip + tamper
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> &'static str {
        r#"{
            "apiVersion": "agent.warrantor.io/v1",
            "kind": "AgentManifest",
            "name": "research-bot-1",
            "identity": "spiffe://yourcorp/agents/research-bot-1",
            "capabilities": ["read"],
            "policy_refs": ["pol_default"],
            "enforcement_mode": "observed"
        }"#
    }

    #[test]
    fn minimal_valid_parses() {
        let m = parse_and_validate(minimal()).expect("minimal manifest is valid");
        assert_eq!(m.identity, "spiffe://yourcorp/agents/research-bot-1");
        assert_eq!(m.capabilities, vec!["read".to_string()]);
    }

    #[test]
    fn canonical_json_is_stable_and_sorted() {
        let m = parse_and_validate(minimal()).unwrap();
        let a = canonical_json(&m);
        let b = canonical_json(&m);
        assert_eq!(a, b, "canonical must be deterministic");
        // keys appear in sorted order: apiVersion, capabilities, enforcement_mode, identity, kind, name, policy_refs
        let api = a.find("\"apiVersion\"").unwrap();
        let caps = a.find("\"capabilities\"").unwrap();
        let enf = a.find("\"enforcement_mode\"").unwrap();
        let id = a.find("\"identity\"").unwrap();
        let kind = a.find("\"kind\"").unwrap();
        assert!(api < caps && caps < enf && enf < id && id < kind, "keys must be sorted: {}", a);
    }

    #[test]
    fn digest_is_32_bytes_and_deterministic() {
        let m = parse_and_validate(minimal()).unwrap();
        let d1 = digest(&m);
        let d2 = digest(&m);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn signature_round_trip_verifies() {
        let m = parse_and_validate(minimal()).unwrap();
        let (sk, _) = generate_keypair();
        let signed = sign(&m, &sk, "test-key-1");
        verify(&signed).expect("freshly signed manifest verifies");
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let m = parse_and_validate(minimal()).unwrap();
        let (sk, _) = generate_keypair();
        let mut signed = sign(&m, &sk, "test-key-1");
        // tamper: change the name AFTER signing
        signed.manifest.name = "evil-twin".to_string();
        let err = verify(&signed).unwrap_err();
        assert!(matches!(err, ManifestError::Signature(_)), "tamper must be detected");
    }

    #[test]
    fn bad_public_key_length_rejected() {
        let m = parse_and_validate(minimal()).unwrap();
        let (sk, _) = generate_keypair();
        let mut signed = sign(&m, &sk, "test-key-1");
        signed.signature.public_key = "00".to_string(); // wrong length
        let err = verify(&signed).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureEnvelope(_)));
    }

    #[test]
    fn missing_required_field_identity() {
        let bad = r#"{
            "apiVersion": "agent.warrantor.io/v1",
            "kind": "AgentManifest",
            "name": "x",
            "capabilities": ["read"],
            "policy_refs": ["pol"],
            "enforcement_mode": "observed"
        }"#;
        let err = parse_and_validate(bad).unwrap_err();
        match err {
            ManifestError::MissingRequiredField { field } => assert_eq!(field, "identity"),
            other => panic!("expected MissingRequiredField(identity), got {:?}", other),
        }
    }

    #[test]
    fn invalid_capability_rejected() {
        let bad = r#"{
            "apiVersion": "agent.warrantor.io/v1", "kind": "AgentManifest", "name": "x",
            "identity": "spiffe://y/z", "capabilities": ["read", "deploy"],
            "policy_refs": ["pol"], "enforcement_mode": "observed"
        }"#;
        let err = parse_and_validate(bad).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidCapability { .. }));
    }

    #[test]
    fn unexpected_field_rejected() {
        let bad = r#"{
            "apiVersion": "agent.warrantor.io/v1", "kind": "AgentManifest", "name": "x",
            "identity": "spiffe://y/z", "capabilities": ["read"], "policy_refs": ["pol"],
            "enforcement_mode": "observed", "rogue": true
        }"#;
        let err = parse_and_validate(bad).unwrap_err();
        match err {
            ManifestError::UnexpectedField { field } => assert_eq!(field, "rogue"),
            other => panic!("expected UnexpectedField(rogue), got {:?}", other),
        }
    }

    #[test]
    fn is_digest_works() {
        assert!(is_digest("sha256:1a2b3c"));
        assert!(is_digest("sha512:deadbeef"));
        assert!(!is_digest("not-a-digest"));
        assert!(!is_digest("sha256:ABCDEF")); // uppercase hex rejected
        assert!(!is_digest(":1a2b")); // empty algo
        assert!(!is_digest("sha256:")); // empty hex
    }

    #[test]
    fn is_semver_works() {
        assert!(is_semver("1.2.0"));
        assert!(!is_semver("1.2"));
        assert!(!is_semver("1.2.3.4"));
        assert!(!is_semver("v1.2.0"));
    }
}

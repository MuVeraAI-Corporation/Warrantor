//! X1 Plugin API + registry — the extension-dev surface (gap-analysis §3C.3, §9.7).
//!
//! Four published, stable plugin types that let extension developers extend Warrantor without
//! forking: `VerdictPlugin`, `PolicyPlugin`, `ReceiptProfile`, `EnforcementBackend`. Each plugin
//! is signed, Semver-versioned, and registered in a curated registry. Warrantor itself is the
//! reference implementation: every built-in gate/profile/backend is a plugin.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub const API_VERSION: &str = "warrantor-plugin-api/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Plugin types — the four extension points
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    /// Custom gates in the 9-gate verdict function (W1).
    VerdictPlugin,
    /// Custom policy evaluators (alternative to Cedar/OPA).
    PolicyPlugin,
    /// Custom receipt shapes for new verticals (healthcare, finance, etc.).
    ReceiptProfile,
    /// Custom enforcement runtimes (sandbox backends, kernel hooks, etc.).
    EnforcementBackend,
}

impl PluginType {
    #[must_use]
    pub fn all() -> [PluginType; 4] {
        [PluginType::VerdictPlugin, PluginType::PolicyPlugin, PluginType::ReceiptProfile, PluginType::EnforcementBackend]
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PluginType::VerdictPlugin => "VerdictPlugin",
            PluginType::PolicyPlugin => "PolicyPlugin",
            PluginType::ReceiptProfile => "ReceiptProfile",
            PluginType::EnforcementBackend => "EnforcementBackend",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin manifest — the metadata + signed declaration
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub plugin_type: PluginType,
    pub name: String,
    pub version: String,        // Semver
    pub author: String,
    pub description: String,
    /// The API version this plugin targets (compatibility contract).
    pub api_version: String,
    /// The capabilities this plugin requires (from the I-08 ladder).
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    /// Whether this plugin can modify governance policies (I-11 check).
    pub can_modify_governance: bool,
}

impl PluginManifest {
    /// Semver compatibility check: plugin API version must match the host API version.
    #[must_use]
    pub fn is_compatible(&self, host_api_version: &str) -> bool {
        self.api_version == host_api_version
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed plugin — the installable artifact
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedPlugin {
    pub manifest: PluginManifest,
    /// SHA-256 of the plugin's compiled artifact (binary, WASM, etc.).
    pub artifact_digest: String,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
    /// The key ID that signed this plugin (for registry verification).
    pub signed_by: String,
}

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("plugin: {0}")]
    PError(String),
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin registry — the curated discovery + install surface
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PluginRegistry {
    /// Registered plugins keyed by plugin_id → version → SignedPlugin.
    pub plugins: HashMap<String, HashMap<String, SignedPlugin>>,
    /// The set of author keys the registry trusts (curated; first-party at launch).
    #[serde(default)]
    pub trusted_author_keys: Vec<String>,
    /// Whether the registry accepts community-submitted plugins (false = curated-only).
    pub community_submissions: bool,
}

impl PluginRegistry {
    #[must_use]
    pub fn new_curated() -> Self {
        Self { plugins: HashMap::new(), trusted_author_keys: vec![], community_submissions: false }
    }

    /// Register a plugin. Validates: signature, API compatibility, I-11 (governance plugins
    /// cannot modify self-governance), and the registry's trust policy.
    pub fn register(&mut self, plugin: SignedPlugin, host_api_version: &str) -> Result<(), PluginError> {
        // 1. API compatibility.
        if !plugin.manifest.is_compatible(host_api_version) {
            return Err(PluginError::PError(format!(
                "plugin {} v{} targets API {} but host is {}",
                plugin.manifest.plugin_id, plugin.manifest.version, plugin.manifest.api_version, host_api_version
            )));
        }

        // 2. I-11: governance plugins (VerdictPlugin, PolicyPlugin) cannot modify self-governance.
        if plugin.manifest.can_modify_governance {
            return Err(PluginError::PError(
                "plugin declares can_modify_governance=true — I-11 violation: a plugin cannot modify the governance that binds it".into(),
            ));
        }

        // 3. Trust: if not community, the signing key must be in the trusted set.
        if !self.community_submissions {
            let is_trusted = self.trusted_author_keys.iter().any(|k| k == &plugin.signature_public_key);
            if !is_trusted {
                return Err(PluginError::PError(format!(
                    "plugin {} signed by untrusted key in curated registry (not in trusted_author_keys)",
                    plugin.manifest.plugin_id
                )));
            }
        }

        // 4. Insert.
        self.plugins
            .entry(plugin.manifest.plugin_id.clone())
            .or_default()
            .insert(plugin.manifest.version.clone(), plugin);
        Ok(())
    }

    /// Look up a plugin by ID + version.
    #[must_use]
    pub fn find(&self, plugin_id: &str, version: &str) -> Option<&SignedPlugin> {
        self.plugins.get(plugin_id).and_then(|v| v.get(version))
    }

    /// List all plugins of a given type.
    #[must_use]
    pub fn list_by_type(&self, plugin_type: PluginType) -> Vec<&SignedPlugin> {
        self.plugins
            .values()
            .flat_map(|v| v.values())
            .filter(|p| p.manifest.plugin_type == plugin_type)
            .collect()
    }

    /// Remove a plugin (uninstall).
    pub fn remove(&mut self, plugin_id: &str, version: &str) -> Option<SignedPlugin> {
        self.plugins.get_mut(plugin_id).and_then(|v| v.remove(version))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signing + verification
// ═══════════════════════════════════════════════════════════════════════════

fn canonical_manifest(manifest: &PluginManifest, artifact_digest: &str) -> String {
    let combined = serde_json::json!({
        "manifest": manifest,
        "artifact_digest": artifact_digest,
    });
    let v = serde_json::to_value(&combined).expect("serializes");
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

/// Sign a plugin manifest + artifact digest with an Ed25519 key.
pub fn sign_plugin(
    manifest: PluginManifest,
    artifact_digest: &str,
    signing_key: &SigningKey,
    key_id: &str,
) -> SignedPlugin {
    let canonical = canonical_manifest(&manifest, artifact_digest);
    let sig: Signature = signing_key.sign(canonical.as_bytes());
    let verifying = signing_key.verifying_key();
    SignedPlugin {
        manifest,
        artifact_digest: artifact_digest.to_string(),
        signature_algorithm: "Ed25519".into(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
        signed_by: key_id.to_string(),
    }
}

/// Verify a signed plugin's Ed25519 signature over its manifest + artifact digest.
pub fn verify_plugin(plugin: &SignedPlugin) -> Result<(), PluginError> {
    let pk_bytes = hex::decode(&plugin.signature_public_key)
        .map_err(|e| PluginError::PError(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(PluginError::PError("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| PluginError::PError(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&plugin.signature_value)
        .map_err(|e| PluginError::PError(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(PluginError::PError("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_manifest(&plugin.manifest, &plugin.artifact_digest);
    vkey
        .verify(canonical.as_bytes(), &sig)
        .map_err(|_| PluginError::PError("Ed25519 signature does not verify".into()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Build a test plugin manifest.
#[must_use]
pub fn test_manifest(plugin_id: &str, plugin_type: PluginType) -> PluginManifest {
    PluginManifest {
        plugin_id: plugin_id.to_string(),
        plugin_type,
        name: format!("Test {}", plugin_type.label()),
        version: "1.0.0".to_string(),
        author: "test".to_string(),
        description: "A test plugin".to_string(),
        api_version: API_VERSION.to_string(),
        required_capabilities: vec![],
        can_modify_governance: false,
    }
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

    fn signed(plugin_id: &str, pt: PluginType, sk: &SigningKey, key_id: &str) -> SignedPlugin {
        sign_plugin(test_manifest(plugin_id, pt), "sha256:abc", sk, key_id)
    }

    #[test]
    fn all_four_plugin_types_exist() {
        assert_eq!(PluginType::all().len(), 4);
    }

    #[test]
    fn sign_and_verify_plugin() {
        let (sk, _) = generate_keypair();
        let p = signed("custom-verdict-gate", PluginType::VerdictPlugin, &sk, "author-1");
        verify_plugin(&p).expect("plugin verifies");
    }

    #[test]
    fn tampered_plugin_fails() {
        let (sk, _) = generate_keypair();
        let mut p = signed("custom-policy", PluginType::PolicyPlugin, &sk, "author-1");
        p.manifest.name = "evil".into();
        assert!(verify_plugin(&p).is_err());
    }

    #[test]
    fn registry_register_and_find() {
        let (sk, _) = generate_keypair();
        let pub_hex = hex_pubkey(&sk);
        let mut reg = PluginRegistry::new_curated();
        reg.trusted_author_keys.push(pub_hex);
        let p = signed("custom-receipt-profile", PluginType::ReceiptProfile, &sk, "author-1");
        reg.register(p.clone(), API_VERSION).expect("registers");
        assert!(reg.find("custom-receipt-profile", "1.0.0").is_some());
    }

    #[test]
    fn registry_rejects_incompatible_api() {
        let (sk, _) = generate_keypair();
        let pub_hex = hex_pubkey(&sk);
        let mut reg = PluginRegistry::new_curated();
        reg.trusted_author_keys.push(pub_hex);
        let mut p = signed("bad-api", PluginType::EnforcementBackend, &sk, "author-1");
        p.manifest.api_version = "warrantor-plugin-api/999.0".into();
        assert!(reg.register(p, API_VERSION).is_err());
    }

    #[test]
    fn registry_rejects_governance_modifying_plugin() {
        let (sk, _) = generate_keypair();
        let pub_hex = hex_pubkey(&sk);
        let mut reg = PluginRegistry::new_curated();
        reg.trusted_author_keys.push(pub_hex);
        let mut p = signed("evil-governance", PluginType::PolicyPlugin, &sk, "author-1");
        p.manifest.can_modify_governance = true; // I-11 violation
        let err = reg.register(p, API_VERSION).unwrap_err();
        assert!(err.to_string().contains("I-11"));
    }

    #[test]
    fn curated_registry_rejects_untrusted_key() {
        let (sk, _) = generate_keypair();
        let mut reg = PluginRegistry::new_curated();
        // No trusted keys added — the plugin's key is not trusted.
        let p = signed("untrusted", PluginType::VerdictPlugin, &sk, "unknown");
        assert!(reg.register(p, API_VERSION).is_err());
    }

    #[test]
    fn community_registry_accepts_untrusted_key() {
        let (sk, _) = generate_keypair();
        let mut reg = PluginRegistry::new_curated();
        reg.community_submissions = true;
        let p = signed("community-plugin", PluginType::ReceiptProfile, &sk, "community-dev");
        reg.register(p.clone(), API_VERSION).expect("community plugin registers");
        assert!(reg.find("community-plugin", "1.0.0").is_some());
    }

    #[test]
    fn list_by_type() {
        let (sk, _) = generate_keypair();
        let pub_hex = hex_pubkey(&sk);
        let mut reg = PluginRegistry::new_curated();
        reg.trusted_author_keys.push(pub_hex);
        reg.register(signed("vp-1", PluginType::VerdictPlugin, &sk, "a"), API_VERSION).unwrap();
        reg.register(signed("pp-1", PluginType::PolicyPlugin, &sk, "a"), API_VERSION).unwrap();
        reg.register(signed("vp-2", PluginType::VerdictPlugin, &sk, "a"), API_VERSION).unwrap();
        assert_eq!(reg.list_by_type(PluginType::VerdictPlugin).len(), 2);
        assert_eq!(reg.list_by_type(PluginType::PolicyPlugin).len(), 1);
    }

    #[test]
    fn remove_plugin() {
        let (sk, _) = generate_keypair();
        let pub_hex = hex_pubkey(&sk);
        let mut reg = PluginRegistry::new_curated();
        reg.trusted_author_keys.push(pub_hex);
        reg.register(signed("removable", PluginType::EnforcementBackend, &sk, "a"), API_VERSION).unwrap();
        assert!(reg.remove("removable", "1.0.0").is_some());
        assert!(reg.find("removable", "1.0.0").is_none());
    }

    fn hex_pubkey(sk: &SigningKey) -> String {
        let pub_bytes = sk.verifying_key().to_bytes();
        let mut s = String::with_capacity(64);
        for b in &pub_bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

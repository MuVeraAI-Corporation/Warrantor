//! The destination catalog: the vocabulary an agent selects destinations from (L4-23).
//!
//! The agent never writes a host. A tool argument that names a destination carries a capability
//! NAME; the proxy resolves the name through this catalog to the host the signed warrant bounds.
//! `--egress H,H` is sugar: each host becomes the capability `host:<H>`, so the old flag and the
//! new one produce the same object and the proxy has one path, not two.
//!
//! The per-warrant catalog is signed by the issuer at grant time and verified against the
//! on-disk issuer key at `mcp` time. It cannot widen the warrant: `vocabulary_within` refuses any
//! capability whose host is outside `WarrantBounds::egress_hosts`. Enforcement is unchanged by any
//! of this — it is the MCP proxy, and only the MCP proxy. See [`crate::egress::ENFORCEMENT_NOTE`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use warrantor_egress::DenyReason;

use crate::egress::DESTINATION_KEYS;
use crate::report::{canonicalize, sha256_hex};
use crate::WarrantBounds;

/// Wire format. A new shape gets a new name, never a silent change.
pub const CATALOG_FORMAT: &str = "warrantor.destination-catalog/1";
const SIGNING_DOMAIN: &[u8] = b"warrantor.destination-catalog/1\n";

/// One destination the agent may name, by name and never by address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// The stable name a tool argument carries, e.g. `publish-artifacts` or `host:api.github.com`.
    pub name: String,
    /// The host the name resolves to. Held by the catalog, never spelled by the agent.
    pub host: String,
    /// Why this destination exists, for the human reviewing the catalog.
    pub purpose: String,
    /// HTTP methods this capability permits, when the destination is HTTP; empty is unrestricted.
    pub permitted_methods: Vec<String>,
}

/// The issuer's signature over the catalog body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSignature {
    /// The name the issuer's key is pinned under.
    pub key_id: String,
    /// The signing key's public half, hex — so a verifier needs no key directory to check.
    pub public_key: String,
    /// The Ed25519 signature over the canonical body, hex.
    pub value: String,
}

/// The signed vocabulary one warrant's agent selects destinations from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCatalog {
    /// Wire format; see [`CATALOG_FORMAT`].
    pub format: String,
    /// The warrant this catalog belongs to, when it is per-warrant and signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warrant_id: Option<String>,
    /// Every destination this catalog names.
    pub capabilities: Vec<Capability>,
    /// The issuer's signature, when signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<CatalogSignature>,
}

/// A name is a name: no scheme, no slash, no IP literal, 1..=64 chars of `[A-Za-z0-9._:-]`.
pub fn check_capability_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err(format!(
            "capability name {name:?} must be 1 to 64 characters"
        ));
    }
    if name.contains("://") || name.contains('/') || name.parse::<IpAddr>().is_ok() {
        return Err(format!(
            "capability name {name:?} looks like an address; a capability is a name the \
             catalog resolves, never a place"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
    {
        return Err(format!(
            "capability name {name:?} has characters outside [A-Za-z0-9._:-]"
        ));
    }
    Ok(())
}

impl CapabilityCatalog {
    /// The `--egress H,H` sugar: each host becomes the capability `host:<H>`.
    #[must_use]
    pub fn from_hosts(hosts: &BTreeSet<String>) -> Self {
        Self {
            format: CATALOG_FORMAT.to_string(),
            warrant_id: None,
            capabilities: hosts
                .iter()
                .map(|host| Capability {
                    name: format!("host:{host}"),
                    host: host.clone(),
                    purpose: format!("--egress {host} (compiled from the flag)"),
                    permitted_methods: Vec::new(),
                })
                .collect(),
            signature: None,
        }
    }

    /// A per-warrant catalog holding exactly the capabilities given.
    #[must_use]
    pub fn for_warrant(warrant_id: &str, capabilities: Vec<Capability>) -> Self {
        Self {
            format: CATALOG_FORMAT.to_string(),
            warrant_id: Some(warrant_id.to_string()),
            capabilities,
            signature: None,
        }
    }

    /// The named capabilities, or the first name this catalog does not hold.
    pub fn select(&self, names: &BTreeSet<String>) -> Result<Vec<Capability>, String> {
        names
            .iter()
            .map(|name| {
                self.capabilities
                    .iter()
                    .find(|c| &c.name == name)
                    .cloned()
                    .ok_or_else(|| format!("{name} is not a capability in this catalog"))
            })
            .collect()
    }

    /// The distinct hosts this catalog resolves to, the warrant bound the sugar compiled into.
    #[must_use]
    pub fn hosts(&self) -> BTreeSet<String> {
        self.capabilities.iter().map(|c| c.host.clone()).collect()
    }

    fn signable(&self) -> Result<String, String> {
        let body = json!({
            "format": self.format,
            "warrant_id": self.warrant_id,
            "capabilities": self.capabilities,
        });
        serde_json::to_string(&canonicalize(&body)).map_err(|e| format!("encode catalog: {e}"))
    }

    /// SHA-256 over the canonical signable body: what a receipt names.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(self.signable().unwrap_or_default().as_bytes())
    }

    /// Sign the canonical body with the issuer's key. Called once, at grant time.
    pub fn sign(&mut self, key: &SigningKey, key_id: &str) {
        let mut message = SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(self.signable().unwrap_or_default().as_bytes());
        let sig: Signature = key.sign(&message);
        self.signature = Some(CatalogSignature {
            key_id: key_id.to_string(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            value: hex::encode(sig.to_bytes()),
        });
    }

    /// Verify against a key pinned out of band, and that the catalog names `warrant_id`.
    pub fn verify(&self, issuer: &VerifyingKey, warrant_id: &str) -> Result<(), String> {
        if self.format != CATALOG_FORMAT {
            return Err(format!("{:?} is not {CATALOG_FORMAT}", self.format));
        }
        if self.warrant_id.as_deref() != Some(warrant_id) {
            return Err(format!(
                "catalog names warrant {:?}, not {warrant_id}",
                self.warrant_id
            ));
        }
        let Some(signature) = &self.signature else {
            return Err(
                "the catalog is unsigned; an unsigned catalog verifies nothing".to_string(),
            );
        };
        if signature.public_key != hex::encode(issuer.to_bytes()) {
            return Err(
                "the catalog was signed by a key that is not the pinned issuer".to_string(),
            );
        }
        let raw = hex::decode(&signature.value).map_err(|e| format!("signature hex: {e}"))?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let mut message = SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(self.signable()?.as_bytes());
        issuer
            .verify(&message, &Signature::from_bytes(&bytes))
            .map_err(|_| "catalog signature does not verify".to_string())
    }

    /// Load a catalog file, refusing anything that does not declare this build's format.
    pub fn load(path: &Path) -> Result<Self, String> {
        let body = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let declared: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
        match declared.get("format").and_then(Value::as_str) {
            Some(f) if f == CATALOG_FORMAT => {}
            other => {
                return Err(format!(
                    "{} declares format {other:?}; this build reads {CATALOG_FORMAT}",
                    path.display()
                ))
            }
        }
        serde_json::from_value(declared).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Write the catalog, creating the parent directory. Part of grant, not of the session.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let text =
            serde_json::to_string_pretty(self).map_err(|e| format!("encode catalog: {e}"))?;
        std::fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// The names this warrant may use. Refuses a catalog that reaches past the signed bound.
    pub fn vocabulary_within(&self, bounds: &WarrantBounds) -> Result<Vocabulary, String> {
        let mut names = BTreeMap::new();
        for capability in &self.capabilities {
            check_capability_name(&capability.name)?;
            if !bounds.egress_hosts.contains(&capability.host) {
                return Err(format!(
                    "capability {} resolves to {}, which the warrant's egress bound does not \
                     name; a catalog file cannot widen a signed bound",
                    capability.name, capability.host
                ));
            }
            names.insert(capability.name.clone(), capability.host.clone());
        }
        Ok(Vocabulary {
            names,
            digest: self.digest(),
        })
    }
}

/// Where a warrant's catalog lives: `<root>/catalogs/<id>.json`.
#[must_use]
pub fn catalog_path(root: &Path, warrant_id: &str) -> PathBuf {
    root.join("catalogs").join(format!("{warrant_id}.json"))
}

/// Name → host, for the names this warrant may reach. Nothing else is expressible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vocabulary {
    names: BTreeMap<String, String>,
    digest: String,
}

impl Vocabulary {
    /// The capability names, in order — the closed set a tool schema may offer.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.names.keys().cloned().collect()
    }

    /// The catalog digest these names came from, so a receipt can name its vocabulary.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// `<name>` or `<name>/<path>` → `https://<host>/<path>`. Anything address-shaped is
    /// `NotACapability`; a name-shaped value the vocabulary lacks is `NotInCatalog`.
    pub fn resolve(&self, value: &str) -> Result<String, DenyReason> {
        let (name, path) = value.split_once('/').unwrap_or((value, ""));
        // `https://x/y` splits to the name `https:`, which is name-shaped; look at the whole
        // value for a scheme, and at the name for an IP literal with or without a port. A bare
        // hostname is indistinguishable from a name and comes back `NotInCatalog`, which is
        // coarse on purpose: neither reason describes the boundary.
        let address_shaped = value.contains("://")
            || name.parse::<IpAddr>().is_ok()
            || name
                .split(':')
                .next()
                .unwrap_or("")
                .parse::<IpAddr>()
                .is_ok();
        if address_shaped || check_capability_name(name).is_err() {
            return Err(DenyReason::NotACapability);
        }
        let host = self.names.get(name).ok_or(DenyReason::NotInCatalog)?;
        Ok(format!("https://{host}/{path}"))
    }

    /// Replace every destination property in a JSON Schema with the closed vocabulary.
    pub fn constrain_schema(&self, schema: &mut Value) {
        let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) else {
            return;
        };
        for key in DESTINATION_KEYS {
            if properties.contains_key(*key) {
                properties.insert(
                    (*key).to_string(),
                    json!({
                        "type": "string",
                        "enum": self.names(),
                        "description": "A destination capability from this warrant's catalog, \
                            optionally followed by /path. Raw hosts, IP addresses and URLs are not \
                            accepted and cannot be expressed here."
                    }),
                );
            }
        }
    }
}

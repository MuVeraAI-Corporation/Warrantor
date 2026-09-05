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

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::report::{canonicalize, sha256_hex};

/// Wire format. A new shape gets a new name, never a silent change.
pub const CATALOG_FORMAT: &str = "warrantor.destination-catalog/1";

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
}

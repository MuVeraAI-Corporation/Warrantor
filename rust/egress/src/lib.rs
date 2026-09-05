//! W5 Egress broker — model-belief-independent, default-deny network enforcement (spec 08).
//!
//! The core rule: **the agent never supplies a destination.** It names a capability; the broker
//! resolves that capability to a destination set using a signed catalog the agent cannot influence.
//! A destination the agent cannot express is a destination it cannot reach, regardless of what any
//! injected instruction tells it to do.
//!
//! See [`specs/warrantor-v4/08-egress-broker.md`](../../specs/warrantor-v4/08-egress-broker.md).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

// ---------------------------------------------------------------------------
// The denial reasons (spec 08 §9) — coarse, identify the gate not the detail
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The agent supplied a raw hostname/IP/URL instead of a capability (spec §1).
    NotACapability,
    /// The logical endpoint is not in the catalog.
    NotInCatalog,
    /// The endpoint is in the catalog but the delegation chain doesn't grant reachability.
    NotInChainIntersection,
    /// The resolved address is in a metadata range (169.254.0.0/16 etc.) — never catalog-addable.
    MetadataRange,
    /// The resolved address is in a private range (10.x, 172.16-31.x, 192.168.x) without explicit catalog.
    PrivateRange,
    /// The catalog is unavailable — deny (spec §7).
    CatalogUnavailable,
    /// The catalog signature is invalid — deny + alarm (spec §7).
    CatalogInvalidSignature,
    /// A discovery request (new destination) requires elevated/critical authorization with approval.
    DiscoveryRequiresApproval,
    /// An agent attempted to amend the catalog (I-11 — self-change protection).
    AgentCannotAmendCatalog,
    /// A redirect targets a destination outside the resolved set.
    RedirectOutOfSet,
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// The egress decision. Default-deny: if no rule allows, the answer is Deny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EgressVerdict {
    Allow {
        logical_endpoint: String,
        pinned_addresses: Vec<String>,
        tls_identity: Option<String>,
        catalog_digest: String,
    },
    Deny {
        reason: DenyReason,
    },
}

// ---------------------------------------------------------------------------
// The destination catalog (spec §2) — signed, versioned, agent-immutable
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CatalogEntry {
    pub logical_endpoint: String,
    pub addresses: Vec<String>, // pre-resolved IPs or explicit hostnames
    pub tls_identity: Option<String>,
    pub permitted_methods: Vec<String>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DestinationCatalog {
    pub version: String,
    pub entries: Vec<CatalogEntry>,
    pub digest: String,
    pub signature: Option<String>, // hex Ed25519; None = unsigned (rejected in production)
}

impl DestinationCatalog {
    /// Compute the content digest (SHA-256 of canonical JSON).
    pub fn compute_digest(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(&hasher.finalize()[..])
    }

    /// Find an entry by logical endpoint.
    pub fn find(&self, logical_endpoint: &str) -> Option<&CatalogEntry> {
        self.entries
            .iter()
            .find(|e| e.logical_endpoint == logical_endpoint)
    }
}

// ---------------------------------------------------------------------------
// The request — what the agent provides. NOTE: no hostname field (spec §1).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EgressRequest {
    /// The capability the agent is exercising — e.g. "net.egress:db:prod.customers".
    /// This is the ONLY way the agent names a destination.
    pub capability: String,
    /// The logical endpoint resolved from the capability (matched against the catalog).
    pub logical_endpoint: String,
    /// The delegation chain's net.egress capabilities (for the intersection check).
    pub chain_capabilities: Vec<String>,
    /// The enforcement mode the broker operates under.
    pub enforcement_mode: String, // "mediated" | "advisory"
    /// Whether this is a discovery request (new destination, spec §5).
    pub is_discovery: bool,
    /// For discovery: whether human approval was obtained.
    pub has_approval: bool,
}

// ---------------------------------------------------------------------------
// The broker — the decision engine
// ---------------------------------------------------------------------------

/// Cloud metadata hosts named by DNS rather than by address.
///
/// `addresses` is documented at the `CatalogEntry` field as "pre-resolved IPs or explicit
/// hostnames", and `rust/warrant/src/egress.rs` puts a hostname there, so a name that resolves to a
/// metadata service has to be refused by name as well as by address.
const METADATA_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata.goog", "metadata"];

/// Metadata addresses outside the link-local range, which range checks alone would miss.
/// Alibaba Cloud's metadata service lives in 100.64.0.0/10 (carrier NAT), not in 169.254.0.0/16.
const METADATA_ADDRESSES: &[Ipv4Addr] = &[Ipv4Addr::new(100, 100, 100, 200)];

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("egress broker: {0}")]
    Broker(String),
}

/// Decide whether to allow or deny an egress request.
///
/// The decision is model-belief-independent: the agent's beliefs about connectivity are irrelevant.
/// The broker checks the catalog, the chain intersection, and the address ranges — nothing the
/// agent says can influence the outcome.
#[must_use]
pub fn decide(request: &EgressRequest, catalog: Option<&DestinationCatalog>) -> EgressVerdict {
    // 0. Discovery requests require approval (spec §5).
    if request.is_discovery && !request.has_approval {
        return EgressVerdict::Deny {
            reason: DenyReason::DiscoveryRequiresApproval,
        };
    }

    // 1. The request must be a capability, not a hostname/IP.
    //    Heuristic: if the capability looks like a raw IP or URL, reject it.
    if looks_like_address(&request.capability) {
        return EgressVerdict::Deny {
            reason: DenyReason::NotACapability,
        };
    }

    // 2. Catalog must be available (spec §7).
    let catalog = match catalog {
        None => {
            return EgressVerdict::Deny {
                reason: DenyReason::CatalogUnavailable,
            }
        }
        Some(c) => c,
    };

    // 3. The logical endpoint must be in the catalog.
    let entry = match catalog.find(&request.logical_endpoint) {
        None => {
            return EgressVerdict::Deny {
                reason: DenyReason::NotInCatalog,
            }
        }
        Some(e) => e,
    };

    // 4. Capability meet: the endpoint must be reachable under the chain's capabilities.
    //    The chain can only narrow reachability (spec §2).
    let chain_set: HashSet<&str> = request
        .chain_capabilities
        .iter()
        .map(|s| s.as_str())
        .collect();
    if !chain_set.contains(request.capability.as_str()) && !chain_set.contains("net.egress") {
        return EgressVerdict::Deny {
            reason: DenyReason::NotInChainIntersection,
        };
    }

    // 5. Address checks: metadata ranges ALWAYS denied; private ranges denied unless catalogued.
    for addr in &entry.addresses {
        if is_metadata_range(addr) {
            return EgressVerdict::Deny {
                reason: DenyReason::MetadataRange,
            };
        }
        if is_private_range(addr) {
            // Private ranges are allowed ONLY if explicitly in the catalog — which it is, since we
            // got here from the catalog. But spec §3 says "Denied unless explicitly catalogued."
            // Since the address IS in a catalog entry, it's explicitly catalogued → allow.
            // However, metadata ranges are NEVER catalog-addable (checked above).
        }
    }

    // 6. Allow — with pinned addresses (DNS resolved by the broker, not the agent).
    EgressVerdict::Allow {
        logical_endpoint: entry.logical_endpoint.clone(),
        pinned_addresses: entry.addresses.clone(),
        tls_identity: entry.tls_identity.clone(),
        catalog_digest: catalog.digest.clone(),
    }
}

/// Reduce a catalog address to the host it actually names, then to an `IpAddr` if it is one.
///
/// This exists because the checks below used to be `str::starts_with` over dotted-quad prefixes,
/// which held for `169.254.169.254` and for nothing else that resolves to the same host. Eight
/// other spellings of the metadata service reached Allow: the decimal, hexadecimal and octal
/// integer forms, the IPv4-mapped IPv6 form, an uppercase scheme, an uppercase IPv6 literal, a
/// leading space, and Alibaba Cloud's address, which was simply absent. Every one of them is
/// accepted by ordinary HTTP clients and by the OS resolver. `rust/egress/tests/metadata_floor.rs`
/// asserts each spelling by name.
///
/// Returns `None` when the host is not an address at all -- a DNS name, which the field explicitly
/// permits. A name is matched against `METADATA_HOSTNAMES` instead. Anything else unparseable is
/// still allowed through, because failing closed here would refuse the hostnames
/// `rust/warrant/src/egress.rs:204` already puts in this field; making the floor fail closed is
/// Task 7.1's decision (L4-25), not a bug fix's.
fn host_only(addr: &str) -> String {
    let mut host = addr.trim();
    // Schemes, matched without regard to case: `trim_start_matches` is case-sensitive, so
    // `HTTP://169.254.169.254` used to survive with its scheme attached and match no prefix.
    for scheme in ["https://", "http://", "ftp://"] {
        if host.len() >= scheme.len() && host[..scheme.len()].eq_ignore_ascii_case(scheme) {
            host = &host[scheme.len()..];
            break;
        }
    }
    host = host.split('/').next().unwrap_or(host).trim();
    // A bracketed IPv6 literal, with or without a port.
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(inner) = rest.split(']').next() {
            return inner.trim().to_ascii_lowercase();
        }
    }
    // A trailing `:port` on an IPv4 address or a name. Bare IPv6 literals contain colons of their
    // own, so only strip when exactly one colon is present.
    if host.matches(':').count() == 1 {
        if let Some((before, _port)) = host.split_once(':') {
            host = before;
        }
    }
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse the numeric forms an HTTP client and the OS resolver both accept for an IPv4 address:
/// dotted quad, a bare 32-bit integer in decimal or hex, and dotted octal.
fn parse_ipv4_any_radix(host: &str) -> Option<Ipv4Addr> {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(v4);
    }
    if let Some(hex) = host.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok().map(Ipv4Addr::from);
    }
    // A bare decimal integer, e.g. 2852039166 == 169.254.169.254.
    if host.chars().all(|c| c.is_ascii_digit()) && !host.starts_with('0') {
        if let Ok(raw) = host.parse::<u32>() {
            return Some(Ipv4Addr::from(raw));
        }
    }
    // Dotted octal, e.g. 0251.0376.0251.0376.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 && parts.iter().any(|p| p.starts_with('0') && p.len() > 1) {
        let mut octets = [0u8; 4];
        for (slot, part) in octets.iter_mut().zip(&parts) {
            let value = if let Some(rest) = part.strip_prefix('0') {
                if rest.is_empty() {
                    Ok(0)
                } else {
                    u32::from_str_radix(rest, 8)
                }
            } else {
                part.parse::<u32>()
            };
            *slot = u8::try_from(value.ok()?).ok()?;
        }
        return Some(Ipv4Addr::from(octets));
    }
    None
}

/// The address a catalog entry names, in canonical form, or `None` if it names a DNS host.
fn canonical_ip(addr: &str) -> Option<IpAddr> {
    let host = host_only(addr);
    if let Some(v4) = parse_ipv4_any_radix(&host) {
        return Some(IpAddr::V4(v4));
    }
    match host.parse::<Ipv6Addr>() {
        // An IPv4-mapped or IPv4-compatible address is the IPv4 address it wraps. Classifying the
        // wrapper as "some IPv6 address" is how ::ffff:169.254.169.254 reached Allow.
        Ok(v6) => Some(match v6.to_ipv4() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }),
        Err(_) => None,
    }
}

/// Check whether a catalog address is a metadata service or a link-local address.
fn is_metadata_range(addr: &str) -> bool {
    match canonical_ip(addr) {
        Some(IpAddr::V4(v4)) => v4.is_link_local() || METADATA_ADDRESSES.contains(&v4),
        Some(IpAddr::V6(v6)) => {
            let head = v6.segments()[0];
            // fe80::/10 unicast link-local, and fc00::/7 unique-local, which the previous prefix
            // list covered only for the fd00: half.
            (head & 0xffc0) == 0xfe80 || (head & 0xfe00) == 0xfc00
        }
        None => METADATA_HOSTNAMES.contains(&host_only(addr).as_str()),
    }
}

/// Check whether a catalog address is in a private range.
fn is_private_range(addr: &str) -> bool {
    match canonical_ip(addr) {
        Some(IpAddr::V4(v4)) => v4.is_private() || v4.is_loopback() || v4.is_unspecified(),
        Some(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        // Names are not addresses, and the prefix list this replaced never matched a name either.
        None => false,
    }
}

/// Heuristic: does the capability string look like a raw address the agent should not be supplying?
fn looks_like_address(s: &str) -> bool {
    // IP literal
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    // URL scheme
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
        return true;
    }
    // Port suffix on a digit (e.g. "203.0.113.9:443")
    if s.contains(':') && s.split(':').next().unwrap_or("").parse::<IpAddr>().is_ok() {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Signed egress receipt — the proof of the decision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EgressReceiptBody {
    pub verdict: EgressVerdict,
    pub capability: String,
    pub timestamp: u64,
    pub broker_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EgressReceipt {
    pub body: EgressReceiptBody,
    pub signature_algorithm: String,
    pub signature_key_id: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

pub const BROKER_VERSION: &str = "warrantor-egress/1.0";

fn canonical_body(body: &EgressReceiptBody) -> String {
    let v = serde_json::to_value(body).expect("serializes");
    canonicalize_value(&v)
}

fn canonicalize_value(v: &serde_json::Value) -> String {
    use serde_json::{Map, Value};
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), Value::String(canonicalize_value(val)));
            }
            serde_json::to_string(&Value::Object(out)).unwrap_or_default()
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonicalize_value).collect();
            format!("[{}]", parts.join(","))
        }
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        other => other.to_string(),
    }
}

/// Issue a signed egress receipt for a decision.
pub fn issue_receipt(
    verdict: &EgressVerdict,
    request: &EgressRequest,
    timestamp: u64,
    signing_key: &SigningKey,
    key_id: &str,
) -> EgressReceipt {
    let body = EgressReceiptBody {
        verdict: verdict.clone(),
        capability: request.capability.clone(),
        timestamp,
        broker_version: BROKER_VERSION.to_string(),
    };
    let canonical = canonical_body(&body);
    let sig: Signature = signing_key.sign(canonical.as_bytes());
    let verifying = signing_key.verifying_key();
    EgressReceipt {
        body,
        signature_algorithm: "Ed25519".to_string(),
        signature_key_id: key_id.to_string(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

/// Verify an egress receipt's Ed25519 signature.
pub fn verify_receipt(receipt: &EgressReceipt) -> Result<(), EgressError> {
    let pk_bytes = hex::decode(&receipt.signature_public_key)
        .map_err(|e| EgressError::Broker(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(EgressError::Broker("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| EgressError::Broker(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&receipt.signature_value)
        .map_err(|e| EgressError::Broker(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(EgressError::Broker("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_body(&receipt.body);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| EgressError::Broker("Ed25519 signature does not verify".into()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
            return Err("odd-length hex".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

/// Build a minimal valid catalog for testing.
#[must_use]
pub fn test_catalog() -> DestinationCatalog {
    let entries = vec![CatalogEntry {
        logical_endpoint: "db:prod.customers".to_string(),
        addresses: vec!["10.0.1.5".to_string()],
        tls_identity: Some("db.prod.internal".to_string()),
        permitted_methods: vec!["GET".to_string(), "POST".to_string()],
        expires_at: u64::MAX,
    }];
    let mut cat = DestinationCatalog {
        version: "v1".to_string(),
        entries,
        digest: String::new(),
        signature: None,
    };
    cat.digest = cat.compute_digest();
    cat
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn req(capability: &str, endpoint: &str, chain: &[&str]) -> EgressRequest {
        EgressRequest {
            capability: capability.to_string(),
            logical_endpoint: endpoint.to_string(),
            chain_capabilities: chain.iter().map(|s| s.to_string()).collect(),
            enforcement_mode: "mediated".to_string(),
            is_discovery: false,
            has_approval: false,
        }
    }

    #[test]
    fn valid_capability_resolves_to_allow() {
        let cat = test_catalog();
        let r = req(
            "net.egress:db:prod.customers",
            "db:prod.customers",
            &["net.egress:db:prod.customers"],
        );
        let v = decide(&r, Some(&cat));
        assert!(matches!(v, EgressVerdict::Allow { .. }));
    }

    #[test]
    fn agent_supplies_hostname_rejected() {
        let cat = test_catalog();
        let r = req("203.0.113.9", "203.0.113.9", &["net.egress"]);
        let v = decide(&r, Some(&cat));
        assert_eq!(
            v,
            EgressVerdict::Deny {
                reason: DenyReason::NotACapability
            }
        );
    }

    #[test]
    fn agent_supplies_url_rejected() {
        let cat = test_catalog();
        let r = req(
            "https://evil.example.com",
            "evil.example.com",
            &["net.egress"],
        );
        let v = decide(&r, Some(&cat));
        assert_eq!(
            v,
            EgressVerdict::Deny {
                reason: DenyReason::NotACapability
            }
        );
    }

    #[test]
    fn not_in_catalog_rejected() {
        let cat = test_catalog();
        let r = req("net.egress:unknown", "unknown", &["net.egress"]);
        let v = decide(&r, Some(&cat));
        assert_eq!(
            v,
            EgressVerdict::Deny {
                reason: DenyReason::NotInCatalog
            }
        );
    }

    #[test]
    fn not_in_chain_intersection_rejected() {
        let cat = test_catalog();
        // The chain doesn't include the capability or net.egress.
        let r = req(
            "net.egress:db:prod.customers",
            "db:prod.customers",
            &["read"],
        );
        let v = decide(&r, Some(&cat));
        assert_eq!(
            v,
            EgressVerdict::Deny {
                reason: DenyReason::NotInChainIntersection
            }
        );
    }

    #[test]
    fn metadata_range_always_denied() {
        let mut cat = test_catalog();
        cat.entries.push(CatalogEntry {
            logical_endpoint: "metadata".to_string(),
            addresses: vec!["169.254.169.254".to_string()],
            tls_identity: None,
            permitted_methods: vec!["GET".to_string()],
            expires_at: u64::MAX,
        });
        cat.digest = cat.compute_digest();
        let r = req("net.egress:metadata", "metadata", &["net.egress"]);
        let v = decide(&r, Some(&cat));
        assert_eq!(
            v,
            EgressVerdict::Deny {
                reason: DenyReason::MetadataRange
            }
        );
    }

    #[test]
    fn catalog_unavailable_denies() {
        let r = req(
            "net.egress:db:prod.customers",
            "db:prod.customers",
            &["net.egress"],
        );
        let v = decide(&r, None);
        assert_eq!(
            v,
            EgressVerdict::Deny {
                reason: DenyReason::CatalogUnavailable
            }
        );
    }

    #[test]
    fn discovery_without_approval_denied() {
        let cat = test_catalog();
        let mut r = req("net.egress:new-endpoint", "new-endpoint", &["net.egress"]);
        r.is_discovery = true;
        r.has_approval = false;
        let v = decide(&r, Some(&cat));
        assert_eq!(
            v,
            EgressVerdict::Deny {
                reason: DenyReason::DiscoveryRequiresApproval
            }
        );
    }

    #[test]
    fn discovery_with_approval_allowed_if_catalogued() {
        let mut cat = test_catalog();
        cat.entries.push(CatalogEntry {
            logical_endpoint: "new-api".to_string(),
            addresses: vec!["52.84.1.1".to_string()],
            tls_identity: Some("api.example.com".to_string()),
            permitted_methods: vec!["GET".to_string()],
            expires_at: u64::MAX,
        });
        cat.digest = cat.compute_digest();
        let mut r = req("net.egress:new-api", "new-api", &["net.egress"]);
        r.is_discovery = true;
        r.has_approval = true;
        let v = decide(&r, Some(&cat));
        assert!(matches!(v, EgressVerdict::Allow { .. }));
    }

    #[test]
    fn receipt_round_trip_verifies() {
        let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
        let sk = SigningKey::generate(&mut csprng);
        let cat = test_catalog();
        let r = req(
            "net.egress:db:prod.customers",
            "db:prod.customers",
            &["net.egress"],
        );
        let v = decide(&r, Some(&cat));
        let receipt = issue_receipt(&v, &r, 1000, &sk, "egress-1");
        verify_receipt(&receipt).expect("receipt verifies");
    }

    #[test]
    fn tampered_receipt_fails() {
        let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
        let sk = SigningKey::generate(&mut csprng);
        let cat = test_catalog();
        let r = req(
            "net.egress:db:prod.customers",
            "db:prod.customers",
            &["net.egress"],
        );
        let v = decide(&r, Some(&cat));
        let mut receipt = issue_receipt(&v, &r, 1000, &sk, "egress-1");
        receipt.body.capability = "evil".to_string();
        assert!(verify_receipt(&receipt).is_err());
    }

    #[test]
    fn net_egress_wildcard_allows() {
        let cat = test_catalog();
        // "net.egress" as a chain capability should allow any catalogued endpoint.
        let r = req(
            "net.egress:db:prod.customers",
            "db:prod.customers",
            &["net.egress"],
        );
        let v = decide(&r, Some(&cat));
        assert!(matches!(v, EgressVerdict::Allow { .. }));
    }

    #[test]
    fn looks_like_address_works() {
        assert!(looks_like_address("203.0.113.9"));
        assert!(looks_like_address("https://evil.com"));
        assert!(looks_like_address("10.0.0.1:443"));
        assert!(!looks_like_address("net.egress:db:prod"));
        assert!(!looks_like_address("db:prod.customers"));
    }
}

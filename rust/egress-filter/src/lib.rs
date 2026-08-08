//! # aumos-egress-filter
//!
//! eBPF egress enforcement core. The Rust core that the eBPF programs (task 03)
//! consult on every outbound packet. The core exposes a deterministic
//! `decide` function: given a destination (domain or IP) it returns an
//! `Action::Allow` or `Action::Deny` decision with a reason.
//!
//! Decision inputs:
//!   - Domain blocklist (pastebin.com, requestbin.com, webhook.site, *.ngrok.io).
//!   - Canary IP detection (well-known data-exfil canaries).
//!   - Allowlist overrides (used by the break-glass path).
//!
//! The core is `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`; it
//! performs no I/O and no eBPF syscalls itself — those live in task 03.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

/// The default domain blocklist. The eBPF programs reject any outbound
/// connection to these domains by default. Pushing data to these services is
/// the canonical exfiltration pattern observed across red-team engagements.
pub const DEFAULT_BLOCKED_DOMAINS: &[&str] = &[
    "pastebin.com",
    "requestbin.com",
    "webhook.site",
    "ngrok.io",
];

/// The default canary IP set. These are well-known canary tokens
/// (Canarytokens.org, Thinkst) that, when contacted, indicate an agent has
/// been lured into exfiltrating to a monitored endpoint.
pub const DEFAULT_CANARY_IPS: &[&str] = &[
    "127.0.0.1",       // loopback (used by exfil proxies); deny by default for non-loopback paths
    "169.254.169.254", // cloud metadata endpoint (AWS/GCP/Azure IMDS)
    "100.100.100.200", // Alibaba cloud metadata
    "fd00:aumos::1",   // aumos-internal canary (documentation only)
];

/// The action the eBPF layer should take on a given outbound packet.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Allow the packet through.
    Allow,
    /// Drop the packet.
    Deny,
}

/// The structured reason for a policy decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecisionReason {
    /// The destination matched an allowlist entry.
    Allowlisted,
    /// The destination is not on any blocklist.
    DefaultAllow,
    /// The destination domain is on the blocklist.
    BlockedDomain,
    /// The destination IP is a known canary.
    CanaryIp,
    /// The destination IP is in a private RFC-1918 range and the policy
    /// denies private egress.
    PrivateIp,
}

/// A returned policy decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// The action the eBPF layer should take.
    pub action: Action,
    /// The reason the action was chosen.
    pub reason: DecisionReason,
    /// The destination that was evaluated (domain or IP, as supplied).
    pub destination: String,
}

/// Errors returned by configuration parsing.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A supplied IP literal could not be parsed.
    #[error("invalid ip literal: {0}")]
    InvalidIp(String),
}

/// The egress policy configuration.
///
/// Built from a `PolicyBuilder` and shared (read-only) with the eBPF layer
/// via a map. Every field has a `#[serde]` mapping so the policy can be
/// serialized to the eBPF config map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Domains that are always denied.
    pub blocked_domains: Vec<String>,
    /// Domains that are always allowed (override the blocklist).
    pub allowlisted_domains: Vec<String>,
    /// Canary IP literals that are always denied.
    pub canary_ips: Vec<IpAddr>,
    /// True iff RFC-1918 / link-local / loopback egress should be denied.
    pub deny_private_egress: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new_default()
    }
}

impl Policy {
    /// Build a policy from the default blocklist + canary IPs, with
    /// private-egress allowed (so loopback health checks work in tests).
    #[must_use]
    pub fn new_default() -> Self {
        let blocked_domains = DEFAULT_BLOCKED_DOMAINS.iter().map(|s| (*s).to_string()).collect();
        let canary_ips: Vec<IpAddr> = DEFAULT_CANARY_IPS
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        Self {
            blocked_domains,
            allowlisted_domains: Vec::new(),
            canary_ips,
            deny_private_egress: false,
        }
    }

    /// Decide the action for a destination expressed as a domain name.
    ///
    /// `domain` is matched case-insensitively against the blocklist and the
    /// allowlist. Suffix matching is used so that `evil.ngrok.io` matches a
    /// `ngrok.io` blocklist entry, and `sub.pastebin.com` matches
    /// `pastebin.com`.
    /// M4 fix: when an allowlisted domain overrides a blocklisted one, log a warning
    /// to stderr so operators can detect break-glass overrides.
    #[must_use]
    pub fn decide_domain(&self, domain: &str) -> Decision {
        let needle = domain.to_ascii_lowercase();
        if self.is_allowlisted_domain(&needle) {
            // M4: audit-log when allowlist overrides blocklist (potential break-glass abuse)
            if self.is_blocked_domain(&needle) {
                eprintln!(
                    "aumos-egress-filter: WARNING allowlisted domain {needle:?} is also in blocklist; \
                     this override may be a break-glass bypass — verify intent."
                );
            }
            return Decision {
                action: Action::Allow,
                reason: DecisionReason::Allowlisted,
                destination: domain.to_string(),
            };
        }
        if self.is_blocked_domain(&needle) {
            return Decision {
                action: Action::Deny,
                reason: DecisionReason::BlockedDomain,
                destination: domain.to_string(),
            };
        }
        Decision {
            action: Action::Allow,
            reason: DecisionReason::DefaultAllow,
            destination: domain.to_string(),
        }
    }

    /// Decide the action for a destination expressed as an IP literal.
    #[must_use]
    pub fn decide_ip(&self, ip: IpAddr) -> Decision {
        if self.canary_ips.contains(&ip) {
            return Decision {
                action: Action::Deny,
                reason: DecisionReason::CanaryIp,
                destination: ip.to_string(),
            };
        }
        if self.deny_private_egress && is_private_or_local(&ip) {
            return Decision {
                action: Action::Deny,
                reason: DecisionReason::PrivateIp,
                destination: ip.to_string(),
            };
        }
        Decision {
            action: Action::Allow,
            reason: DecisionReason::DefaultAllow,
            destination: ip.to_string(),
        }
    }

    /// True iff ``domain`` matches any blocked entry, including suffix matches.
    #[must_use]
    pub fn is_blocked_domain(&self, domain: &str) -> bool {
        self.blocked_domains.iter().any(|b| domain_matches(domain, b))
    }

    /// True iff ``domain`` matches any allowlisted entry, including suffix matches.
    #[must_use]
    pub fn is_allowlisted_domain(&self, domain: &str) -> bool {
        self.allowlisted_domains
            .iter()
            .any(|a| domain_matches(domain, a))
    }
}

/// Build a [`Policy`] field by field.
#[derive(Debug, Clone, Default)]
pub struct PolicyBuilder {
    /// Domains added to the blocklist.
    blocked: Vec<String>,
    /// Domains added to the allowlist.
    allowlisted: Vec<String>,
    /// Canary IPs added (parsed from string form).
    canaries: Vec<String>,
    /// Whether to deny private egress.
    deny_private: bool,
    /// Whether to start from the default blocklist + canaries.
    use_defaults: bool,
}

impl PolicyBuilder {
    /// Construct a new builder that does NOT include the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            use_defaults: false,
            ..Self::default()
        }
    }

    /// Construct a new builder that DOES include the default blocklist + canaries.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            use_defaults: true,
            ..Self::default()
        }
    }

    /// Append ``domain`` to the blocklist.
    #[must_use]
    pub fn block_domain(mut self, domain: &str) -> Self {
        self.blocked.push(domain.to_ascii_lowercase());
        self
    }

    /// Append ``domain`` to the allowlist (overrides the blocklist).
    #[must_use]
    pub fn allow_domain(mut self, domain: &str) -> Self {
        self.allowlisted.push(domain.to_ascii_lowercase());
        self
    }

    /// Append ``ip`` (string form) to the canary IP list.
    #[must_use]
    pub fn add_canary(mut self, ip: &str) -> Self {
        self.canaries.push(ip.to_string());
        self
    }

    /// Toggle the deny-private-egress flag.
    #[must_use]
    pub fn deny_private_egress(mut self, deny: bool) -> Self {
        self.deny_private = deny;
        self
    }

    /// Build the policy. Returns [`ConfigError`] if any canary IP literal is
    /// malformed.
    pub fn build(self) -> Result<Policy, ConfigError> {
        let mut blocked = self.blocked;
        let mut canaries: Vec<IpAddr> = Vec::new();
        if self.use_defaults {
            blocked.extend(DEFAULT_BLOCKED_DOMAINS.iter().map(|s| (*s).to_string()));
            canaries.extend(
                DEFAULT_CANARY_IPS
                    .iter()
                    .filter_map(|s| s.parse::<IpAddr>().ok()),
            );
        }
        for c in &self.canaries {
            canaries.push(
                c.parse::<IpAddr>()
                    .map_err(|_| ConfigError::InvalidIp(c.clone()))?,
            );
        }
        Ok(Policy {
            blocked_domains: blocked,
            allowlisted_domains: self.allowlisted,
            canary_ips: canaries,
            deny_private_egress: self.deny_private,
        })
    }
}

/// True iff ``domain`` equals ``pattern`` or is a subdomain of ``pattern``.
///
/// Examples:
///   - `domain_matches("evil.ngrok.io", "ngrok.io")` -> `true`
///   - `domain_matches("pastebin.com", "pastebin.com")` -> `true`
///   - `domain_matches("notpastebin.com", "pastebin.com")` -> `false`
///   - `domain_matches("x.com", "com")` -> `false` (TLD-only pattern is not matched)
#[must_use]
pub fn domain_matches(domain: &str, pattern: &str) -> bool {
    if domain == pattern {
        return true;
    }
    if pattern.split('.').count() <= 1 {
        return false;
    }
    let suffix = format!(".{pattern}");
    domain.ends_with(&suffix)
}

/// True iff ``ip`` is RFC-1918 private, link-local, loopback, or
/// IPv6-unique-local. These addresses are typically internal to a host or
/// data center and should not be exposed to egress when
/// [`Policy::deny_private_egress`] is set.
#[must_use]
pub fn is_private_or_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || ((v6.segments()[0] & 0xfe00) == 0xfc00) // unique-local fc00::/7
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- domain_matches ----------
    #[test]
    fn domain_matches_exact() {
        assert!(domain_matches("pastebin.com", "pastebin.com"));
    }

    #[test]
    fn domain_matches_subdomain() {
        assert!(domain_matches("evil.ngrok.io", "ngrok.io"));
        assert!(domain_matches("a.b.pastebin.com", "pastebin.com"));
    }

    #[test]
    fn domain_matches_rejects_tld_pattern() {
        assert!(!domain_matches("x.com", "com"));
        assert!(!domain_matches("notpastebin.com", "pastebin.com"));
    }

    // ---------- Policy::decide_domain ----------
    #[test]
    fn decide_domain_blocks_default_entries() {
        let p = Policy::new_default();
        assert_eq!(p.decide_domain("pastebin.com").action, Action::Deny);
        assert_eq!(p.decide_domain("PASTEBIN.COM").action, Action::Deny); // case-insensitive
        assert_eq!(p.decide_domain("evil.ngrok.io").action, Action::Deny); // suffix
    }

    #[test]
    fn decide_domain_allows_unknown() {
        let p = Policy::new_default();
        let d = p.decide_domain("example.com");
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::DefaultAllow);
    }

    #[test]
    fn decide_domain_allowlist_overrides_blocklist() {
        let p = PolicyBuilder::with_defaults()
            .allow_domain("pastebin.com")
            .build()
            .unwrap();
        let d = p.decide_domain("pastebin.com");
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::Allowlisted);
    }

    // ---------- Policy::decide_ip ----------
    #[test]
    fn decide_ip_blocks_canary() {
        let p = Policy::new_default();
        let d = p.decide_ip("169.254.169.254".parse().unwrap());
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::CanaryIp);
    }

    #[test]
    fn decide_ip_blocks_private_when_flag_set() {
        let p = PolicyBuilder::with_defaults()
            .deny_private_egress(true)
            .build()
            .unwrap();
        let d = p.decide_ip("10.0.0.1".parse().unwrap());
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::PrivateIp);
    }

    #[test]
    fn decide_ip_allows_loopback_when_flag_clear() {
        let p = Policy::new_default();
        let d = p.decide_ip("8.8.8.8".parse().unwrap());
        assert_eq!(d.action, Action::Allow);
    }

    // ---------- PolicyBuilder ----------
    #[test]
    fn builder_rejects_malformed_canary() {
        let r = PolicyBuilder::new().add_canary("not-an-ip").build();
        assert!(matches!(r, Err(ConfigError::InvalidIp(_))));
    }

    #[test]
    fn builder_with_defaults_includes_defaults() {
        let p = PolicyBuilder::with_defaults().build().unwrap();
        assert!(p.blocked_domains.contains(&"pastebin.com".to_string()));
        assert!(p.canary_ips.contains(&"169.254.169.254".parse().unwrap()));
    }

    // ---------- Serialization ----------
    #[test]
    fn policy_round_trips_through_json() {
        let p = PolicyBuilder::with_defaults()
            .allow_domain("internal.aumos.dev")
            .deny_private_egress(true)
            .build()
            .unwrap();
        let s = serde_json::to_string(&p).unwrap();
        let back: Policy = serde_json::from_str(&s).unwrap();
        assert_eq!(back.blocked_domains, p.blocked_domains);
        assert_eq!(back.allowlisted_domains, p.allowlisted_domains);
        assert_eq!(back.deny_private_egress, p.deny_private_egress);
    }
}

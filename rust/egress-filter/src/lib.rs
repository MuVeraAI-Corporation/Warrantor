//! # warrantor-egress-filter
//!
//! eBPF egress enforcement core. The Rust core that the eBPF programs (task 03)
//! consult on every outbound packet. The core exposes a deterministic
//! `decide` function: given a destination (domain or IP) it returns an
//! `Action::Allow` or `Action::Deny` decision with a reason.
//!
//! ## Polarity: **default deny** (AX-05)
//!
//! This core used to end every decision path with `Action::Allow` /
//! `DecisionReason::DefaultAllow` — the opposite polarity to `warrantor-policy-bridge` in the same
//! workspace, which correctly refuses to load a policy whose default effect is not `Deny`. A
//! security control whose failure mode is "let it through" is not a control. The terminal branch
//! is now [`DecisionReason::DefaultDeny`]: a destination reaches the network only if it is
//! explicitly allowlisted.
//!
//! Everything else AX-05 fixed here was a *bypass* of the blocklist:
//!
//! | bypass | fix |
//! |---|---|
//! | `"pastebin.com."` (trailing root dot) missed the blocklist | [`normalize_hostname`] strips trailing dots, lowercases, and rejects non-ASCII (supply punycode) |
//! | `::ffff:10.0.0.1` (IPv4-mapped IPv6) missed `deny_private_egress` | [`normalize_ip`] unwraps mapped/compatible forms before every check |
//! | `deny_private_egress` defaulted to **false** | it now defaults to **true**, including when a serialized policy omits the field |
//! | `fd00:aumos::1` is not valid IPv6 (`u`,`m`,`o`,`s` are not hex) and was dropped by a `.ok()` filter — 4 canaries advertised, 3 loaded | the constant is corrected, and malformed config is a hard [`ConfigError`] instead of a silent drop |
//!
//! Decision inputs:
//!   - Domain blocklist (pastebin.com, requestbin.com, webhook.site, *.ngrok.io).
//!   - Canary IP detection (well-known data-exfil canaries).
//!   - Allowlist overrides — the **only** path to `Allow`.
//!
//! The core is `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`; it
//! performs no I/O and no eBPF syscalls itself — those live in task 03.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};
use thiserror::Error;

/// The default domain blocklist. The eBPF programs reject any outbound
/// connection to these domains by default. Pushing data to these services is
/// the canonical exfiltration pattern observed across red-team engagements.
///
/// Note that under default-deny the blocklist is defence in depth, not the primary control: it
/// exists so that an over-broad allowlist entry still cannot reach a known exfil sink.
pub const DEFAULT_BLOCKED_DOMAINS: &[&str] =
    &["pastebin.com", "requestbin.com", "webhook.site", "ngrok.io"];

/// The default canary IP set. These are well-known canary tokens
/// (Canarytokens.org, Thinkst) that, when contacted, indicate an agent has
/// been lured into exfiltrating to a monitored endpoint.
///
/// **AX-05**: the fourth entry used to read `fd00:aumos::1`, which is not a valid IPv6 literal
/// (`u`, `m`, `o` and `s` are not hex digits). It was silently discarded by a
/// `.filter_map(|s| s.parse().ok())`, so this constant advertised four canaries and loaded
/// three. It is now a valid unique-local address, and every consumer of this list surfaces a
/// parse failure as a [`ConfigError`] rather than dropping the entry.
pub const DEFAULT_CANARY_IPS: &[&str] = &[
    "127.0.0.1", // loopback (used by exfil proxies); deny by default for non-loopback paths
    "169.254.169.254", // cloud metadata endpoint (AWS/GCP/Azure IMDS)
    "100.100.100.200", // Alibaba cloud metadata
    "fd00:a405::1", // warrantor-internal canary (ULA; was the invalid literal "fd00:aumos::1")
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
    /// The destination matched an allowlist entry. **The only route to [`Action::Allow`].**
    Allowlisted,
    /// The destination is not allowlisted. **AX-05**: this replaces the old `DefaultAllow`
    /// terminal branch, which let every unknown destination out.
    DefaultDeny,
    /// The destination domain is on the blocklist.
    BlockedDomain,
    /// The destination IP is a known canary.
    CanaryIp,
    /// The destination IP is in a private RFC-1918 range and the policy
    /// denies private egress.
    PrivateIp,
    /// The destination string could not be normalised (empty, non-ASCII without punycode
    /// encoding, oversized label, …). **AX-05**: a destination we cannot canonicalise is one we
    /// cannot match against the blocklist, so it is denied rather than passed through.
    MalformedDestination {
        /// Why normalisation failed.
        detail: String,
    },
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
    /// The canonical form the decision was actually made against (lowercased host with the root
    /// dot stripped, or the unwrapped IP). Empty if normalisation failed. Surfacing this makes a
    /// normalisation bypass visible in the audit trail.
    pub normalized: String,
}

/// Errors returned by configuration parsing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A supplied IP literal could not be parsed.
    #[error("invalid ip literal: {0}")]
    InvalidIp(String),
    /// A supplied hostname could not be normalised.
    #[error("invalid hostname {host:?}: {detail}")]
    InvalidHostname {
        /// The offending input.
        host: String,
        /// Why it was rejected.
        detail: String,
    },
}

fn default_true() -> bool {
    true
}

/// The egress policy configuration.
///
/// Built from a [`PolicyBuilder`] and shared (read-only) with the eBPF layer
/// via a map. Every field has a `#[serde]` mapping so the policy can be
/// serialized to the eBPF config map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Domains that are always denied.
    pub blocked_domains: Vec<String>,
    /// Domains that are allowed. Under default-deny this is the **only** way a domain reaches
    /// the network.
    pub allowlisted_domains: Vec<String>,
    /// IP literals that are allowed. Under default-deny this is the only way a bare IP reaches
    /// the network.
    #[serde(default)]
    pub allowlisted_ips: Vec<IpAddr>,
    /// Canary IP literals that are always denied.
    pub canary_ips: Vec<IpAddr>,
    /// True iff RFC-1918 / link-local / loopback egress should be denied.
    ///
    /// **AX-05**: defaults to `true`, and a serialized policy that omits the field also gets
    /// `true` — an older config cannot silently re-enable private egress (SSRF to the cloud
    /// metadata endpoint is the canonical exploit of the old `false` default).
    #[serde(default = "default_true")]
    pub deny_private_egress: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new_default()
    }
}

impl Policy {
    /// Build a policy from the default blocklist + canary IPs, default-deny, with private egress
    /// **denied**.
    ///
    /// # Panics
    /// Panics if [`DEFAULT_CANARY_IPS`] contains an unparseable literal. That is a compile-time
    /// constant, so a failure here is a programmer error in this crate, and a loud panic is
    /// correct — the pre-AX-05 code silently dropped the malformed entry instead. Use
    /// [`Policy::try_new_default`] for the non-panicking form.
    #[must_use]
    pub fn new_default() -> Self {
        Self::try_new_default().expect(
            "DEFAULT_CANARY_IPS must all be valid IP literals — see warrantor-egress-filter constants",
        )
    }

    /// Fallible form of [`Policy::new_default`].
    ///
    /// # Errors
    /// Returns [`ConfigError::InvalidIp`] if any entry in [`DEFAULT_CANARY_IPS`] is malformed.
    pub fn try_new_default() -> Result<Self, ConfigError> {
        Ok(Self {
            blocked_domains: DEFAULT_BLOCKED_DOMAINS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            allowlisted_domains: Vec::new(),
            allowlisted_ips: Vec::new(),
            canary_ips: parse_canaries(DEFAULT_CANARY_IPS.iter().copied())?,
            deny_private_egress: true,
        })
    }

    /// Decide the action for a destination expressed as a domain name.
    ///
    /// The hostname is canonicalised by [`normalize_hostname`] first — trailing root dot
    /// stripped, ASCII-lowercased — so `"PASTEBIN.COM."` and `"pastebin.com"` cannot reach
    /// different verdicts. A hostname that cannot be canonicalised is **denied**
    /// ([`DecisionReason::MalformedDestination`]), not passed through.
    ///
    /// Suffix matching means `evil.ngrok.io` matches an `ngrok.io` entry and
    /// `sub.pastebin.com` matches `pastebin.com`.
    ///
    /// M4 fix: when an allowlisted domain overrides a blocklisted one, log a warning
    /// to stderr so operators can detect break-glass overrides.
    #[must_use]
    pub fn decide_domain(&self, domain: &str) -> Decision {
        let needle = match normalize_hostname(domain) {
            Ok(n) => n,
            Err(e) => {
                let detail = match &e {
                    ConfigError::InvalidHostname { detail, .. } => detail.clone(),
                    other => other.to_string(),
                };
                return Decision {
                    action: Action::Deny,
                    reason: DecisionReason::MalformedDestination { detail },
                    destination: domain.to_string(),
                    normalized: String::new(),
                };
            }
        };
        // A hostname that is really an IP literal must go through the IP path, or `127.0.0.1`
        // typed into a hostname field would skip the canary and private-range checks entirely.
        if let Ok(ip) = needle.parse::<IpAddr>() {
            return self.decide_ip(ip);
        }
        if self.is_blocked_domain(&needle) && self.is_allowlisted_domain(&needle) {
            // M4: audit-log when allowlist overrides blocklist (potential break-glass abuse)
            eprintln!(
                "warrantor-egress-filter: WARNING allowlisted domain {needle:?} is also in blocklist; \
                 this override may be a break-glass bypass — verify intent."
            );
        }
        if self.is_blocked_domain(&needle) {
            return Decision {
                action: Action::Deny,
                reason: DecisionReason::BlockedDomain,
                destination: domain.to_string(),
                normalized: needle,
            };
        }
        if self.is_allowlisted_domain(&needle) {
            return Decision {
                action: Action::Allow,
                reason: DecisionReason::Allowlisted,
                destination: domain.to_string(),
                normalized: needle,
            };
        }
        // AX-05: default DENY. Previously this branch returned Allow/DefaultAllow.
        Decision {
            action: Action::Deny,
            reason: DecisionReason::DefaultDeny,
            destination: domain.to_string(),
            normalized: needle,
        }
    }

    /// Decide the action for a destination expressed as an IP literal.
    ///
    /// The address is canonicalised by [`normalize_ip`] first, so an IPv4-mapped IPv6 address
    /// (`::ffff:10.0.0.1`) is evaluated as the IPv4 address it actually routes to.
    #[must_use]
    pub fn decide_ip(&self, ip: IpAddr) -> Decision {
        let norm = normalize_ip(ip);
        let normalized = norm.to_string();
        // Canary and private checks come FIRST: an allowlist entry must not be able to punch a
        // hole to the metadata endpoint.
        if self.canary_ips.iter().any(|c| normalize_ip(*c) == norm) {
            return Decision {
                action: Action::Deny,
                reason: DecisionReason::CanaryIp,
                destination: ip.to_string(),
                normalized,
            };
        }
        if self.deny_private_egress && is_private_or_local(&norm) {
            return Decision {
                action: Action::Deny,
                reason: DecisionReason::PrivateIp,
                destination: ip.to_string(),
                normalized,
            };
        }
        if self
            .allowlisted_ips
            .iter()
            .any(|a| normalize_ip(*a) == norm)
        {
            return Decision {
                action: Action::Allow,
                reason: DecisionReason::Allowlisted,
                destination: ip.to_string(),
                normalized,
            };
        }
        // AX-05: default DENY.
        Decision {
            action: Action::Deny,
            reason: DecisionReason::DefaultDeny,
            destination: ip.to_string(),
            normalized,
        }
    }

    /// Decide for a destination that may be either an IP literal (optionally bracketed, as in
    /// `[::1]`) or a hostname. Dispatches to [`Policy::decide_ip`] or
    /// [`Policy::decide_domain`].
    #[must_use]
    pub fn decide_destination(&self, destination: &str) -> Decision {
        let trimmed = destination.trim();
        let unbracketed = trimmed
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(trimmed);
        match unbracketed.parse::<IpAddr>() {
            Ok(ip) => {
                let mut d = self.decide_ip(ip);
                d.destination = destination.to_string();
                d
            }
            Err(_) => {
                let mut d = self.decide_domain(destination);
                d.destination = destination.to_string();
                d
            }
        }
    }

    /// True iff `domain` matches any blocked entry, including suffix matches. The input and the
    /// configured patterns are both normalised first.
    #[must_use]
    pub fn is_blocked_domain(&self, domain: &str) -> bool {
        let needle = normalize_hostname_lossy(domain);
        self.blocked_domains
            .iter()
            .any(|b| domain_matches(&needle, &normalize_hostname_lossy(b)))
    }

    /// True iff `domain` matches any allowlisted entry, including suffix matches. The input and
    /// the configured patterns are both normalised first.
    #[must_use]
    pub fn is_allowlisted_domain(&self, domain: &str) -> bool {
        let needle = normalize_hostname_lossy(domain);
        self.allowlisted_domains
            .iter()
            .any(|a| domain_matches(&needle, &normalize_hostname_lossy(a)))
    }
}

/// Build a [`Policy`] field by field.
#[derive(Debug, Clone)]
pub struct PolicyBuilder {
    /// Domains added to the blocklist.
    blocked: Vec<String>,
    /// Domains added to the allowlist.
    allowlisted: Vec<String>,
    /// IPs added to the allowlist (parsed from string form).
    allowlisted_ips: Vec<String>,
    /// Canary IPs added (parsed from string form).
    canaries: Vec<String>,
    /// Whether to deny private egress. **AX-05**: defaults to `true`.
    deny_private: bool,
    /// Whether to start from the default blocklist + canaries.
    use_defaults: bool,
}

impl Default for PolicyBuilder {
    fn default() -> Self {
        Self {
            blocked: Vec::new(),
            allowlisted: Vec::new(),
            allowlisted_ips: Vec::new(),
            canaries: Vec::new(),
            // AX-05: private egress is denied unless a caller explicitly opts out.
            deny_private: true,
            use_defaults: false,
        }
    }
}

impl PolicyBuilder {
    /// Construct a new builder that does NOT include the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a new builder that DOES include the default blocklist + canaries.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            use_defaults: true,
            ..Self::default()
        }
    }

    /// Append `domain` to the blocklist.
    #[must_use]
    pub fn block_domain(mut self, domain: &str) -> Self {
        self.blocked.push(domain.to_string());
        self
    }

    /// Append `domain` to the allowlist. Under default-deny this is how traffic is permitted.
    #[must_use]
    pub fn allow_domain(mut self, domain: &str) -> Self {
        self.allowlisted.push(domain.to_string());
        self
    }

    /// Append `ip` (string form) to the IP allowlist.
    #[must_use]
    pub fn allow_ip(mut self, ip: &str) -> Self {
        self.allowlisted_ips.push(ip.to_string());
        self
    }

    /// Append `ip` (string form) to the canary IP list.
    #[must_use]
    pub fn add_canary(mut self, ip: &str) -> Self {
        self.canaries.push(ip.to_string());
        self
    }

    /// Toggle the deny-private-egress flag. Defaults to `true`; passing `false` is an explicit,
    /// auditable decision to permit egress to RFC-1918 / loopback / link-local addresses.
    #[must_use]
    pub fn deny_private_egress(mut self, deny: bool) -> Self {
        self.deny_private = deny;
        self
    }

    /// Build the policy.
    ///
    /// # Errors
    /// Returns [`ConfigError::InvalidIp`] if any canary or allowlisted IP literal is malformed,
    /// or [`ConfigError::InvalidHostname`] if a domain cannot be normalised. **AX-05**: malformed
    /// values are rejected rather than silently dropped by a `.ok()` filter — a config the
    /// operator believes contains four canaries must not quietly load three.
    pub fn build(self) -> Result<Policy, ConfigError> {
        let mut blocked: Vec<String> = Vec::new();
        for d in &self.blocked {
            blocked.push(normalize_hostname(d)?);
        }
        let mut allowlisted: Vec<String> = Vec::new();
        for d in &self.allowlisted {
            allowlisted.push(normalize_hostname(d)?);
        }
        let mut canaries: Vec<IpAddr> = Vec::new();
        if self.use_defaults {
            for d in DEFAULT_BLOCKED_DOMAINS {
                blocked.push(normalize_hostname(d)?);
            }
            canaries.extend(parse_canaries(DEFAULT_CANARY_IPS.iter().copied())?);
        }
        canaries.extend(parse_canaries(self.canaries.iter().map(String::as_str))?);
        let allowlisted_ips = parse_canaries(self.allowlisted_ips.iter().map(String::as_str))?;
        Ok(Policy {
            blocked_domains: blocked,
            allowlisted_domains: allowlisted,
            allowlisted_ips,
            canary_ips: canaries,
            deny_private_egress: self.deny_private,
        })
    }
}

/// Parse a sequence of IP literals, failing on the first malformed entry.
fn parse_canaries<'a, I: IntoIterator<Item = &'a str>>(
    items: I,
) -> Result<Vec<IpAddr>, ConfigError> {
    items
        .into_iter()
        .map(|s| {
            s.trim()
                .parse::<IpAddr>()
                .map_err(|_| ConfigError::InvalidIp(s.to_string()))
        })
        .collect()
}

/// Canonicalise a hostname before matching (AX-05).
///
/// * trims surrounding whitespace
/// * strips the trailing root dot — `"pastebin.com."` and `"pastebin.com"` are the same host to
///   a resolver, and treating them differently was a one-character blocklist bypass
/// * ASCII-lowercases
/// * rejects an empty host, an empty label (`a..b`), a label over 63 bytes, a name over 253
///   bytes, and any non-ASCII byte
///
/// Non-ASCII is **rejected rather than transcoded**: correct IDNA (UTS-46) normalisation needs a
/// Unicode mapping table, and a partial implementation would itself be a bypass (homograph and
/// mixed-script labels comparing unequal to their A-label form). Callers must supply the
/// punycode/A-label form, which is pure ASCII and normalises exactly.
///
/// # Errors
/// Returns [`ConfigError::InvalidHostname`] describing the first rule violated.
pub fn normalize_hostname(host: &str) -> Result<String, ConfigError> {
    let reject = |detail: &str| {
        Err(ConfigError::InvalidHostname {
            host: host.to_string(),
            detail: detail.to_string(),
        })
    };
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return reject("empty hostname");
    }
    if !trimmed.is_ascii() {
        return reject(
            "non-ASCII hostname; supply the punycode (A-label, `xn--…`) form — this crate does \
             not implement UTS-46 and will not guess",
        );
    }
    // Strip the trailing root label. `..` is still rejected below via the empty-label check.
    let stripped = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if stripped.is_empty() {
        return reject("hostname is only a root dot");
    }
    if stripped.len() > 253 {
        return reject("hostname exceeds 253 bytes");
    }
    let lowered = stripped.to_ascii_lowercase();
    // An IP literal is a legal destination; skip the DNS label rules for it.
    if lowered.parse::<IpAddr>().is_ok() {
        return Ok(lowered);
    }
    for label in lowered.split('.') {
        if label.is_empty() {
            return reject("hostname contains an empty label");
        }
        if label.len() > 63 {
            return reject("hostname label exceeds 63 bytes");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return reject("hostname label contains a character outside [a-z0-9-_]");
        }
    }
    Ok(lowered)
}

/// Best-effort normalisation for *configured* patterns, which have usually already been
/// validated by [`PolicyBuilder::build`]. Falls back to a lowercased, dot-stripped form so a
/// hand-edited policy file still matches sensibly instead of silently never matching.
fn normalize_hostname_lossy(host: &str) -> String {
    normalize_hostname(host).unwrap_or_else(|_| {
        let t = host.trim();
        t.strip_suffix('.').unwrap_or(t).to_ascii_lowercase()
    })
}

/// Canonicalise an IP address before matching (AX-05).
///
/// An IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) routes to the IPv4 address it embeds, but
/// `Ipv6Addr::is_loopback`/`is_private` know nothing about that — so `::ffff:10.0.0.1` sailed
/// straight past `deny_private_egress`. This unwraps mapped (and the deprecated
/// IPv4-compatible) forms to the IPv4 address they actually reach.
///
/// `::` and `::1` are deliberately **not** unwrapped: `Ipv6Addr::to_ipv4` would turn `::1` into
/// `0.0.0.1`, which is not loopback — the exact opposite of what a security check needs.
#[must_use]
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else if v6.is_loopback() || v6.is_unspecified() {
                IpAddr::V6(v6)
            } else if let Some(v4) = v6.to_ipv4() {
                // Deprecated IPv4-compatible form `::a.b.c.d`.
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// True iff `domain` equals `pattern` or is a subdomain of `pattern`.
///
/// Both arguments are expected to be normalised (see [`normalize_hostname`]);
/// [`Policy::is_blocked_domain`] and [`Policy::is_allowlisted_domain`] do that for you.
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

/// True iff `ip` is RFC-1918 private, link-local, loopback, unspecified, or
/// IPv6-unique-local. These addresses are typically internal to a host or
/// data center and should not be exposed to egress when
/// [`Policy::deny_private_egress`] is set.
///
/// **AX-05**: also unwraps IPv4-mapped IPv6 (defence in depth alongside [`normalize_ip`]) and
/// covers IPv6 link-local `fe80::/10` and the unspecified addresses, which the previous version
/// missed.
#[must_use]
pub fn is_private_or_local(ip: &IpAddr) -> bool {
    match normalize_ip(*ip) {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => is_private_v6(&v6),
    }
}

fn is_private_v6(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() {
        return true;
    }
    let first = v6.segments()[0];
    // fc00::/7 unique-local, fe80::/10 link-local.
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
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
    fn decide_domain_allowlist_lets_traffic_out() {
        let p = PolicyBuilder::with_defaults()
            .allow_domain("api.github.com")
            .build()
            .unwrap();
        let d = p.decide_domain("api.github.com");
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::Allowlisted);
        // …and subdomains of the allowlisted entry.
        assert_eq!(
            p.decide_domain("uploads.api.github.com").action,
            Action::Allow
        );
    }

    #[test]
    fn blocklist_beats_allowlist() {
        // A break-glass allowlist entry must not punch a hole to a known exfil sink.
        let p = PolicyBuilder::with_defaults()
            .allow_domain("pastebin.com")
            .build()
            .unwrap();
        let d = p.decide_domain("pastebin.com");
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::BlockedDomain);
    }

    // ================= AX-05 negative tests: every known bypass =================

    #[test]
    fn default_deny_on_unknown_destination_ax05() {
        // AX-05: the terminal branch used to be Allow/DefaultAllow — the opposite polarity to
        // policy-bridge in the same workspace. An unknown destination must now be DENIED.
        let p = Policy::new_default();
        let d = p.decide_domain("example.com");
        assert_eq!(
            d.action,
            Action::Deny,
            "an unlisted domain must be denied, not allowed"
        );
        assert_eq!(d.reason, DecisionReason::DefaultDeny);

        let d = p.decide_ip("8.8.8.8".parse().unwrap());
        assert_eq!(
            d.action,
            Action::Deny,
            "an unlisted public IP must be denied, not allowed"
        );
        assert_eq!(d.reason, DecisionReason::DefaultDeny);

        // And through the combined entrypoint.
        assert_eq!(
            p.decide_destination("totally-unknown.example.org").action,
            Action::Deny
        );
    }

    #[test]
    fn trailing_dot_host_does_not_bypass_the_blocklist_ax05() {
        // AX-05: "pastebin.com." (the fully-qualified root form, which every resolver accepts)
        // did not equal "pastebin.com" and did not end with ".pastebin.com", so it sailed past
        // the blocklist and out through DefaultAllow. One character, full bypass.
        let p = Policy::new_default();
        for host in [
            "pastebin.com.",
            "PASTEBIN.COM.",
            "  pastebin.com.  ",
            "evil.ngrok.io.",
            "a.b.pastebin.com.",
        ] {
            let d = p.decide_domain(host);
            assert_eq!(
                d.action,
                Action::Deny,
                "{host} must be denied by the blocklist"
            );
            assert_eq!(
                d.reason,
                DecisionReason::BlockedDomain,
                "{host} must be denied AS A BLOCKED DOMAIN, not merely by default-deny"
            );
        }
        // The normalised form is surfaced for the audit trail.
        assert_eq!(p.decide_domain("PASTEBIN.COM.").normalized, "pastebin.com");
    }

    #[test]
    fn trailing_dot_does_not_bypass_an_allowlist_either_ax05() {
        let p = PolicyBuilder::with_defaults()
            .allow_domain("api.github.com")
            .build()
            .unwrap();
        assert_eq!(p.decide_domain("api.github.com.").action, Action::Allow);
        // …and a trailing dot in the CONFIGURED pattern still matches a plain query.
        let p2 = PolicyBuilder::new()
            .allow_domain("api.github.com.")
            .build()
            .unwrap();
        assert_eq!(p2.decide_domain("api.github.com").action, Action::Allow);
    }

    #[test]
    fn ipv4_mapped_ipv6_does_not_bypass_deny_private_egress_ax05() {
        // AX-05: `::ffff:10.0.0.1` routes to 10.0.0.1, but Ipv6Addr::is_private does not exist
        // and the unique-local check does not match, so the mapped form went straight out.
        let p = Policy::new_default();
        assert!(p.deny_private_egress);
        for mapped in [
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:172.16.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            let ip: IpAddr = mapped.parse().unwrap();
            let d = p.decide_ip(ip);
            assert_eq!(
                d.action,
                Action::Deny,
                "{mapped} must be denied as the IPv4 address it actually reaches"
            );
            assert!(
                matches!(
                    d.reason,
                    DecisionReason::PrivateIp | DecisionReason::CanaryIp
                ),
                "{mapped} must be denied as Private/Canary, got {:?}",
                d.reason
            );
        }
        // The canary check specifically must see through the mapping.
        let d = p.decide_ip("::ffff:169.254.169.254".parse().unwrap());
        assert_eq!(d.reason, DecisionReason::CanaryIp);
        assert_eq!(d.normalized, "169.254.169.254");
    }

    #[test]
    fn ipv6_loopback_is_not_mangled_into_a_public_address_ax05() {
        // A naive `to_ipv4()` turns ::1 into 0.0.0.1 (not loopback) — the opposite of what a
        // security check needs. normalize_ip must leave ::1 and :: alone.
        assert_eq!(
            normalize_ip("::1".parse().unwrap()),
            "::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            normalize_ip("::".parse().unwrap()),
            "::".parse::<IpAddr>().unwrap()
        );
        let p = Policy::new_default();
        assert_eq!(
            p.decide_ip("::1".parse().unwrap()).reason,
            DecisionReason::PrivateIp
        );
    }

    #[test]
    fn ipv6_link_local_and_unique_local_are_private_ax05() {
        for ip in ["fe80::1", "fd00::1", "fc00::1", "::1", "::"] {
            assert!(
                is_private_or_local(&ip.parse().unwrap()),
                "{ip} must count as private/local"
            );
        }
        for ip in ["2606:4700:4700::1111", "8.8.8.8"] {
            assert!(
                !is_private_or_local(&ip.parse().unwrap()),
                "{ip} must NOT count as private/local"
            );
        }
    }

    #[test]
    fn deny_private_egress_defaults_to_true_ax05() {
        // AX-05: the default was `false`, which left SSRF to the cloud metadata endpoint wide
        // open on any policy the operator did not hand-tune.
        assert!(Policy::new_default().deny_private_egress);
        assert!(Policy::default().deny_private_egress);
        assert!(PolicyBuilder::new().build().unwrap().deny_private_egress);
        assert!(
            PolicyBuilder::with_defaults()
                .build()
                .unwrap()
                .deny_private_egress
        );
        // A serialized policy that omits the field must also fail closed.
        let json = r#"{"blocked_domains":[],"allowlisted_domains":[],"canary_ips":[]}"#;
        let p: Policy = serde_json::from_str(json).expect("deserialize legacy policy");
        assert!(
            p.deny_private_egress,
            "a policy without the field must default to DENY, not allow"
        );
        assert_eq!(
            p.decide_ip("10.0.0.1".parse().unwrap()).action,
            Action::Deny
        );
    }

    #[test]
    fn every_default_canary_actually_loads_ax05() {
        // AX-05: `fd00:aumos::1` is not valid IPv6 (u/m/o/s are not hex digits) and was silently
        // discarded by `.filter_map(|s| s.parse().ok())` — the constant advertised 4 canaries and
        // loaded 3.
        assert_eq!(DEFAULT_CANARY_IPS.len(), 4);
        for c in DEFAULT_CANARY_IPS {
            assert!(
                c.parse::<IpAddr>().is_ok(),
                "default canary {c:?} must be a valid IP literal"
            );
        }
        let p = Policy::new_default();
        assert_eq!(
            p.canary_ips.len(),
            DEFAULT_CANARY_IPS.len(),
            "every advertised canary must be loaded, none silently dropped"
        );
        assert!(p.canary_ips.contains(&"fd00:a405::1".parse().unwrap()));
        assert_eq!(
            p.decide_ip("fd00:a405::1".parse().unwrap()).action,
            Action::Deny
        );
        assert_eq!(
            PolicyBuilder::with_defaults()
                .build()
                .unwrap()
                .canary_ips
                .len(),
            DEFAULT_CANARY_IPS.len()
        );
    }

    #[test]
    fn malformed_config_fails_loudly_ax05() {
        // Malformed values must be a hard error, never a silent drop.
        assert_eq!(
            PolicyBuilder::new().add_canary("not-an-ip").build(),
            Err(ConfigError::InvalidIp("not-an-ip".into()))
        );
        assert_eq!(
            PolicyBuilder::new().add_canary("fd00:aumos::1").build(),
            Err(ConfigError::InvalidIp("fd00:aumos::1".into())),
            "the exact literal that used to be dropped must now be rejected"
        );
        assert_eq!(
            PolicyBuilder::new().allow_ip("999.1.1.1").build(),
            Err(ConfigError::InvalidIp("999.1.1.1".into()))
        );
        assert!(matches!(
            PolicyBuilder::new().allow_domain("").build(),
            Err(ConfigError::InvalidHostname { .. })
        ));
        assert!(matches!(
            PolicyBuilder::new().block_domain("bad..host").build(),
            Err(ConfigError::InvalidHostname { .. })
        ));
        assert!(matches!(
            PolicyBuilder::new().allow_domain("exämple.com").build(),
            Err(ConfigError::InvalidHostname { .. }),
            // non-ASCII must be rejected, not silently mangled into a non-matching pattern
        ));
    }

    #[test]
    fn malformed_destination_is_denied_not_passed_through_ax05() {
        let p = Policy::new_default();
        for bad in ["", "   ", ".", "a..b", "exämple.com", "pastebin.com/../x"] {
            let d = p.decide_domain(bad);
            assert_eq!(
                d.action,
                Action::Deny,
                "unnormalisable destination {bad:?} must be denied"
            );
            assert!(
                matches!(d.reason, DecisionReason::MalformedDestination { .. }),
                "{bad:?} must be reported as malformed, got {:?}",
                d.reason
            );
        }
        // A 254-byte name is over the DNS limit.
        let long = format!("{}.com", "a".repeat(250));
        assert!(matches!(
            p.decide_domain(&long).reason,
            DecisionReason::MalformedDestination { .. }
        ));
        // A 64-byte label is over the label limit.
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(matches!(
            p.decide_domain(&long_label).reason,
            DecisionReason::MalformedDestination { .. }
        ));
    }

    #[test]
    fn ip_literal_in_a_hostname_field_still_gets_ip_checks_ax05() {
        // Feeding "169.254.169.254" to decide_domain must not skip the canary check.
        let p = Policy::new_default();
        assert_eq!(
            p.decide_domain("169.254.169.254").reason,
            DecisionReason::CanaryIp
        );
        assert_eq!(
            p.decide_domain("10.0.0.1").reason,
            DecisionReason::PrivateIp
        );
        // And through decide_destination, including the bracketed IPv6 form.
        assert_eq!(
            p.decide_destination("[::ffff:10.0.0.1]").reason,
            DecisionReason::PrivateIp
        );
        assert_eq!(
            p.decide_destination("[::ffff:10.0.0.1]").destination,
            "[::ffff:10.0.0.1]"
        );
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
    fn decide_ip_blocks_private_by_default() {
        let p = PolicyBuilder::with_defaults().build().unwrap();
        let d = p.decide_ip("10.0.0.1".parse().unwrap());
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::PrivateIp);
    }

    #[test]
    fn allowlisted_ip_is_the_only_route_out() {
        let p = PolicyBuilder::with_defaults()
            .allow_ip("8.8.8.8")
            .build()
            .unwrap();
        assert_eq!(
            p.decide_ip("8.8.8.8".parse().unwrap()).action,
            Action::Allow
        );
        assert_eq!(p.decide_ip("8.8.4.4".parse().unwrap()).action, Action::Deny);
        // An allowlisted private IP is still denied while deny_private_egress is on.
        let p2 = PolicyBuilder::with_defaults()
            .allow_ip("10.0.0.1")
            .build()
            .unwrap();
        assert_eq!(
            p2.decide_ip("10.0.0.1".parse().unwrap()).reason,
            DecisionReason::PrivateIp
        );
    }

    #[test]
    fn private_egress_can_be_explicitly_opted_out_of() {
        let p = PolicyBuilder::with_defaults()
            .deny_private_egress(false)
            .allow_ip("10.0.0.1")
            .build()
            .unwrap();
        assert_eq!(
            p.decide_ip("10.0.0.1".parse().unwrap()).action,
            Action::Allow
        );
        // Even then, canaries stay blocked.
        assert_eq!(
            p.decide_ip("169.254.169.254".parse().unwrap()).action,
            Action::Deny
        );
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

    // ---------- normalize_hostname ----------
    #[test]
    fn normalize_hostname_canonicalises() {
        assert_eq!(normalize_hostname("PASTEBIN.COM.").unwrap(), "pastebin.com");
        assert_eq!(
            normalize_hostname("  Evil.NGROK.io ").unwrap(),
            "evil.ngrok.io"
        );
        assert_eq!(
            normalize_hostname("a-b_c.example").unwrap(),
            "a-b_c.example"
        );
        assert!(normalize_hostname("").is_err());
        assert!(normalize_hostname(".").is_err());
        assert!(normalize_hostname("a..b").is_err());
        assert!(normalize_hostname("exämple.com").is_err());
    }

    // ---------- Serialization ----------
    #[test]
    fn policy_round_trips_through_json() {
        let p = PolicyBuilder::with_defaults()
            .allow_domain("internal.aumos.dev")
            .allow_ip("8.8.8.8")
            .deny_private_egress(true)
            .build()
            .unwrap();
        let s = serde_json::to_string(&p).unwrap();
        let back: Policy = serde_json::from_str(&s).unwrap();
        assert_eq!(back.blocked_domains, p.blocked_domains);
        assert_eq!(back.allowlisted_domains, p.allowlisted_domains);
        assert_eq!(back.allowlisted_ips, p.allowlisted_ips);
        assert_eq!(back.canary_ips, p.canary_ips);
        assert_eq!(back.deny_private_egress, p.deny_private_egress);
    }

    #[test]
    fn decision_serializes_with_reason_tag() {
        let p = Policy::new_default();
        let json = serde_json::to_string(&p.decide_domain("example.com")).unwrap();
        assert!(json.contains(r#""kind":"default_deny""#), "got {json}");
        assert!(json.contains(r#""action":"deny""#), "got {json}");
    }
}

//! The deny floor (L4-25): the cloud metadata service, link-local addresses **and IPv6 unique-local
//! `fc00::/7`**, refused in a layer no warrant, policy edit, serialized config or agent action can
//! amend.
//!
//! # The exact blast radius, because "metadata and link-local" understates it
//!
//! [`refuse_ip`] refuses four classes, and `fc00::/7` is the one a reader of the short name does not
//! expect. `fc00::/7` (RFC 4193) is the IPv6 analog of RFC-1918, and this module refuses it
//! *unamendably*, while RFC-1918 itself is left to `deny_private_egress`, which an operator may turn
//! off. That asymmetry is deliberate, but it is also a **behavior change from `f99af94`**: there, an
//! allowlisted `fd12:3456:789a::1` on a policy with `deny_private_egress(false)` reached
//! `Allow`/`Allowlisted`; here the same policy returns `Deny` with rule `unique_local`, and no
//! configuration value can reverse it. A warrant that legitimately names a unique-local destination
//! cannot be honored while this floor stands.
//!
//! One more consequence, stated rather than left to be discovered: `warrantor_egress::decide`
//! collapses every refusal except `AddressShapedButUnparseable` into `DenyReason::MetadataRange`, so
//! a link-local or unique-local refusal is reported to an operator under the word `metadata_range`.
//! [`FloorReason`] is the finer record; the broker's word is coarser than it, and this task did not
//! widen the broker's vocabulary.
//!
//! # The mechanism is the signature — and what that gate cannot see
//!
//! Nothing in this module accepts a configuration value of any kind. No function takes a receiver,
//! a flag, a policy, a catalog or an options struct — the only input is the address being asked
//! about. There is nothing an operator, a warrant or an agent could pass that would change the
//! answer, because there is nothing to pass. `hard_deny_floor.rs` asserts that absence against the
//! source text, because absence is the mechanism and a behavioral test cannot see a parameter that
//! has not been added yet.
//!
//! That source gate is an **enumerated denylist over this file's text**, not a proof. It was
//! demonstrated to miss a real amendment: a `static AtomicBool` plus a `std::env::var` read at the
//! head of [`refuse_ip`] adds no parameter, leaves both pinned signatures byte-for-byte, and turned
//! nine tests red only when the variable was set — so it shipped green. The tokens for that channel
//! are now enumerated too, which closes the one channel that was demonstrated and no more. A channel
//! nobody has thought of is still invisible to it.
//!
//! # Why it lives in this crate and not in `warrantor-egress`
//!
//! `warrantor-egress` already refused the metadata service unconditionally — a `const` checked
//! before any allow path, which is most of what L4-25 asks. What it did not have was reach:
//! `warrantor_egress_filter::Policy` is a separate decision surface with five independent paths to
//! `Action::Allow` for the same addresses, and a floor inside `warrantor-egress` cannot govern them
//! without a dependency cycle. Putting the floor in the lower crate lets `warrantor-egress` consume
//! it over a new edge (which is also the wiring edge that moves this crate off the orphan list) and
//! leaves exactly one matcher for both crates. Two matchers are two rules waiting to disagree.
//!
//! # What this floor is, in the project's own vocabulary
//!
//! **Tier B, chokepoint.** A specific line refuses the address at the moment a decision is asked
//! for. It binds every caller of `Policy::decide_*` and of `warrantor_egress::decide` — and the
//! first of those two caller sets is **empty in this workspace**. Outside this crate's own tests
//! nothing calls `Policy::decide_ip`, `decide_domain` or `decide_destination`; the only cross-crate
//! import of `warrantor-egress-filter` anywhere is `hard_deny` itself, from `rust/egress/src/lib.rs`.
//! What protects the shipping product today is the `warrantor_egress::decide` half, reached through
//! the MCP proxy. The `Policy` half hardens a decision surface no shipping caller has yet.
//!
//! It does **not** bind a socket opened without asking, it does **not** resolve DNS — a name outside
//! [`FLOOR_HOSTNAMES`] that resolves into the metadata, link-local or unique-local ranges is not
//! caught — and it is **not** an OS or network-tier control: no netns, seccomp or firewall rule
//! enforces it, and nothing outside this process is involved.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Metadata services named by address — **the list the matcher reads**, not a second copy of it.
///
/// `169.254.169.254` is also link-local, so the range check would catch it anyway;
/// `100.100.100.200` (Alibaba Cloud) lives in carrier-NAT space `100.64.0.0/10` and is caught by
/// nothing but this list. Adding an address here changes what the floor refuses, and
/// `every_address_on_the_public_list_is_actually_refused` in `hard_deny_floor.rs` fails if it ever
/// stops doing so.
///
/// It carries typed `Ipv4Addr` values rather than strings so that there is exactly one spelling of
/// each address in the module. An earlier revision of this file shipped a `pub` string list beside a
/// private typed one; the string list had no readers, so an address added to the documented list was
/// not refused. Two lists are two rules waiting to disagree, which is this module's whole thesis.
pub const FLOOR_ADDRESSES: &[Ipv4Addr] = &[
    Ipv4Addr::new(169, 254, 169, 254),
    Ipv4Addr::new(100, 100, 100, 200),
];

/// Metadata services named by DNS. A catalog address field is documented as accepting "pre-resolved
/// IPs or explicit hostnames" and `rust/warrant/src/egress.rs` puts a hostname there, so the name
/// has to be refused as well as the address.
///
/// This list narrows the DNS gap by exactly the names on it and closes nothing: any other name that
/// resolves into the metadata range still reaches [`FloorVerdict::NotRefused`], because this floor
/// does not resolve DNS.
pub const FLOOR_HOSTNAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
];

/// Why the floor refused. Every variant is constructed; none is prose without a decision behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorReason {
    /// A known cloud metadata service, by address or by name.
    MetadataService,
    /// IPv4 `169.254.0.0/16` or IPv6 `fe80::/10`.
    LinkLocal,
    /// IPv6 `fc00::/7` unique-local.
    UniqueLocal,
    /// The literal is shaped like a numeric address and does not parse as one. Refused rather than
    /// passed through: see the module note on failing closed below.
    AddressShapedButUnparseable,
}

impl FloorReason {
    /// A stable word for logs and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataService => "metadata_service",
            Self::LinkLocal => "link_local",
            Self::UniqueLocal => "unique_local",
            Self::AddressShapedButUnparseable => "address_shaped_but_unparseable",
        }
    }
}

/// The floor's answer. `NotRefused` means *this rule* has nothing to say — it is not an allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorVerdict {
    /// The floor refuses this address, whatever else has been configured.
    Refused(FloorReason),
    /// The floor has no objection. Every other check still applies.
    NotRefused,
}

impl FloorVerdict {
    /// True iff the floor refused.
    #[must_use]
    pub const fn is_refused(self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

/// Reduce a literal to the host it names: whitespace trimmed, a URL scheme stripped without regard
/// to case, a path dropped, a bracketed IPv6 literal unwrapped, a trailing `:port` removed, a
/// trailing root dot dropped, ASCII-lowercased.
///
/// Case matters here because the string matcher this replaced used `trim_start_matches`, which is
/// case-sensitive, so `HTTP://169.254.169.254` survived with its scheme attached and matched
/// nothing.
#[must_use]
pub fn host_only(literal: &str) -> String {
    let mut host = literal.trim();
    for scheme in ["https://", "http://", "ftp://"] {
        if host.len() >= scheme.len() && host[..scheme.len()].eq_ignore_ascii_case(scheme) {
            host = &host[scheme.len()..];
            break;
        }
    }
    host = host.split('/').next().unwrap_or(host).trim();
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(inner) = rest.split(']').next() {
            return inner.trim().to_ascii_lowercase();
        }
    }
    // A bare IPv6 literal carries colons of its own, so only strip a port when there is exactly one.
    if host.matches(':').count() == 1 {
        if let Some((before, _port)) = host.split_once(':') {
            host = before;
        }
    }
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse the numeric forms an HTTP client and the OS resolver both accept for IPv4: dotted quad, a
/// bare 32-bit integer in decimal or hexadecimal, and dotted octal.
fn parse_ipv4_any_radix(host: &str) -> Option<Ipv4Addr> {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(v4);
    }
    if let Some(hex) = host.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok().map(Ipv4Addr::from);
    }
    if host.chars().all(|c| c.is_ascii_digit()) && !host.starts_with('0') && !host.is_empty() {
        if let Ok(raw) = host.parse::<u32>() {
            return Some(Ipv4Addr::from(raw));
        }
    }
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

/// The address a literal names, in canonical form, or `None` when it names a DNS host.
///
/// An IPv4-mapped or IPv4-compatible IPv6 address is returned as the IPv4 address it wraps.
/// Classifying the wrapper as "some IPv6 address" is how `::ffff:169.254.169.254` used to be
/// allowed.
#[must_use]
pub fn canonical_ip(literal: &str) -> Option<IpAddr> {
    let host = host_only(literal);
    if let Some(v4) = parse_ipv4_any_radix(&host) {
        return Some(IpAddr::V4(v4));
    }
    match host.parse::<Ipv6Addr>() {
        Ok(v6) => Some(match v6.to_ipv4() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }),
        Err(_) => None,
    }
}

/// Normalize an address the way [`canonical_ip`] does, so a mapped IPv6 form is judged as the IPv4
/// address it routes to.
#[must_use]
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// True iff a string that failed to parse as an address is nevertheless *shaped* like one.
///
/// The discriminator is the rightmost label: no registrable top-level domain is entirely numeric
/// (RFC 3696 §2), so `999.1.1.1`, `169.254.169.254.5` and `2852039166000000` are failed address
/// parses rather than hostnames, while `169.254.169.254.nip.io` is a name and is left alone. A `0x`
/// prefix is the other tell.
fn is_address_shaped(host: &str) -> bool {
    if host.is_empty() {
        return true;
    }
    if host.starts_with("0x") {
        return true;
    }
    match host.rsplit('.').next() {
        Some(last) => !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// The floor, for an address that is already typed. One argument: the address.
#[must_use]
pub fn refuse_ip(ip: IpAddr) -> FloorVerdict {
    match normalize(ip) {
        IpAddr::V4(v4) => {
            if FLOOR_ADDRESSES.contains(&v4) {
                FloorVerdict::Refused(FloorReason::MetadataService)
            } else if v4.is_link_local() {
                FloorVerdict::Refused(FloorReason::LinkLocal)
            } else {
                FloorVerdict::NotRefused
            }
        }
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            if (head & 0xffc0) == 0xfe80 {
                FloorVerdict::Refused(FloorReason::LinkLocal)
            } else if (head & 0xfe00) == 0xfc00 {
                FloorVerdict::Refused(FloorReason::UniqueLocal)
            } else {
                FloorVerdict::NotRefused
            }
        }
    }
}

/// The floor, for a literal as written. One argument: the literal.
///
/// # Failing closed, and exactly what that costs
///
/// A literal that parses is classified. A literal that does **not** parse is refused only when it
/// is *shaped* like a numeric address ([`is_address_shaped`]); an ordinary DNS name reaches
/// [`FloorVerdict::NotRefused`]. Refusing everything unparseable was considered and rejected:
/// `EgressBroker::for_bounds` in `rust/warrant/src/egress.rs` copies the warrant's `egress_hosts`
/// straight into the address field, so every hostname bound a developer writes — `api.github.com`,
/// `registry.npmjs.org` — is an unparseable address by construction, and a floor that refused them
/// would refuse the entire shipping path rather than harden it. The half that is safe to fail
/// closed on is the half that could only ever have been an address.
#[must_use]
pub fn refuse(literal: &str) -> FloorVerdict {
    let host = host_only(literal);
    if let Some(ip) = canonical_ip(&host) {
        return refuse_ip(ip);
    }
    if FLOOR_HOSTNAMES.contains(&host.as_str()) {
        return FloorVerdict::Refused(FloorReason::MetadataService);
    }
    if is_address_shaped(&host) {
        return FloorVerdict::Refused(FloorReason::AddressShapedButUnparseable);
    }
    FloorVerdict::NotRefused
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_of_a_metadata_service_is_refused() {
        for literal in [
            "169.254.169.254",
            "100.100.100.200",
            "2852039166",
            "0xa9fea9fe",
            "0251.0376.0251.0376",
            "::ffff:169.254.169.254",
            "HTTP://169.254.169.254",
            " 169.254.169.254",
            "169.254.169.254:80",
            "[::ffff:169.254.169.254]:80",
            "http://169.254.169.254/latest/meta-data/",
            "metadata.google.internal",
            "METADATA.GOOGLE.INTERNAL.",
        ] {
            assert!(
                refuse(literal).is_refused(),
                "{literal} names a cloud metadata service and must be refused"
            );
        }
    }

    #[test]
    fn link_local_and_unique_local_ranges_are_refused() {
        for literal in [
            "169.254.1.1",
            "fe80::1",
            "FE80::1",
            "[fe80::dead]",
            "fd00:a405::1",
        ] {
            assert!(refuse(literal).is_refused(), "{literal} must be refused");
        }
    }

    #[test]
    fn an_address_shaped_literal_that_does_not_parse_fails_closed() {
        for literal in [
            "999.1.1.1",
            "0x",
            "169.254.169.254.5",
            "2852039166000000",
            "",
        ] {
            assert_eq!(
                refuse(literal),
                FloorVerdict::Refused(FloorReason::AddressShapedButUnparseable),
                "{literal:?} could only ever have been an address, so it fails closed"
            );
        }
    }

    /// The allowed controls. Without these the assertions above pass on a floor that refuses
    /// everything, which would prove nothing at all.
    #[test]
    fn ordinary_destinations_are_not_refused() {
        for literal in [
            "api.github.com",
            "registry.npmjs.org",
            "8.8.8.8",
            "203.0.113.9",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "10.0.1.5",
            "127.0.0.1",
            "https://example.com/path",
            "localhost:3000",
        ] {
            assert_eq!(
                refuse(literal),
                FloorVerdict::NotRefused,
                "{literal} is not the metadata service and the floor must leave it alone"
            );
        }
    }

    /// The over-inclusive direction. A name that merely *contains* the metadata address is a name,
    /// and refusing it as the floor would be a claim about a host the floor knows nothing about.
    #[test]
    fn a_hostname_containing_the_metadata_address_is_not_refused_as_the_floor() {
        assert_eq!(refuse("169.254.169.254.nip.io"), FloorVerdict::NotRefused);
    }

    #[test]
    fn rfc_1918_and_loopback_are_left_to_the_checks_that_already_govern_them() {
        for literal in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1"] {
            assert_eq!(
                refuse(literal),
                FloorVerdict::NotRefused,
                "{literal} is governed by deny_private_egress and by the catalog, not by the floor"
            );
        }
    }
}

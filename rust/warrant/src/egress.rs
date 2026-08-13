//! The egress bound, decided by the broker rather than by list membership.
//!
//! # What changed, and what did not
//!
//! The proxy used to answer "may this call reach that host?" with a `BTreeSet::contains`. It now
//! asks [`warrantor_egress`], which answers per destination and says *why* it refused. That is a
//! better answer, not a stronger boundary: the decision still happens in exactly one place — the
//! Warrantor MCP proxy — and an agent that opens a socket itself is untouched by any of it. There
//! is no network namespace, no seccomp filter and no firewall in this system. Nothing in this
//! module, and nothing it prints, may be read as saying otherwise.
//!
//! # How a warrant becomes a destination catalogue
//!
//! The broker's model is that the agent never names a destination: it names a *capability*, and a
//! catalogue the agent cannot influence resolves that capability to an endpoint. A warrant already
//! has the agent-immutable half of that — [`WarrantBounds::egress_hosts`] lives inside the signed
//! claims, so the agent can neither widen it nor forge one. So each permitted host becomes one
//! catalogue entry, and the capability for a destination is `net.egress:<host>`.
//!
//! Both the catalogue and the chain intersection are derived from that one bound, because a warrant
//! has exactly one egress allowlist and this deployment has no separate destination catalogue. Two
//! consequences, stated rather than left to be discovered:
//!
//! * [`DenyReason::NotInChainIntersection`] cannot fire here — the chain and the catalogue are the
//!   same set. The denials that can fire are [`DenyReason::CatalogUnavailable`] (the warrant
//!   permits no egress at all), [`DenyReason::NotInCatalog`] (the destination is not in the bound)
//!   and [`DenyReason::MetadataRange`].
//! * The catalogue is unsigned, and [`DestinationCatalog::signature`] is left `None` rather than
//!   filled with something signature-shaped. The broker never checks that field anyway. What makes
//!   this catalogue trustworthy is that it was derived from signed warrant claims, not that the
//!   catalogue object carries a signature of its own.
//!
//! # What the broker adds that the set membership did not
//!
//! * A **structured** refusal — destination, the argument it was named in, and a coarse reason —
//!   instead of one sentence, so `warrantor` can count and report refusals per destination.
//! * A metadata-range refusal that holds **even when the warrant names the address**. A warrant
//!   granting `--egress 169.254.169.254` no longer reaches the cloud metadata service through the
//!   proxy. That is a real capability the list-membership check did not have.
//! * A decision the developer can ask for ahead of time: `warrantor egress <id> <destination>`.
//!
//! # What it deliberately does not do
//!
//! * It does **not** resolve DNS. The broker copies pre-resolved strings out of the catalogue, and
//!   the catalogue here holds the names the developer wrote. A hostname that resolves *into* a
//!   metadata or private range is therefore not caught by the range check; only a literal address
//!   in the bound is.
//! * It does **not** sign egress receipts. [`warrantor_egress::issue_receipt`] exists, but signing
//!   inside the proxy would put a signing key in the process the agent talks to, and the process
//!   that serves a supervised agent deliberately holds no key. Refusals are recorded and surfaced
//!   instead.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use warrantor_egress as broker;

use crate::proxy::{host_of, ToolCall};
use crate::WarrantBounds;

pub use warrantor_egress::{DenyReason, EgressVerdict, BROKER_VERSION};

/// Version string stamped on the catalogue built from a warrant's bounds.
///
/// Distinct from [`crate::WARRANT_FORMAT`] on purpose: it names the shape of the *catalogue*
/// derivation, so a later change to how bounds become entries is visible in the digest.
pub const CATALOG_VERSION: &str = "warrantor.warrant-egress-catalog/1";

/// The capability prefix a destination is expressed under.
pub const EGRESS_CAPABILITY_PREFIX: &str = "net.egress:";

/// Where enforcement actually happens. Printed wherever a decision is shown to a human.
///
/// One sentence, in one place, so no surface can drift into implying containment this system does
/// not have.
pub const ENFORCEMENT_NOTE: &str =
    "These decisions bind tool calls that traverse the Warrantor MCP proxy. There is no network \
     namespace, seccomp filter or firewall: an agent that opens a socket itself is not bound by \
     them.";

/// The capability naming one destination.
#[must_use]
pub fn capability_for(destination: &str) -> String {
    format!("{EGRESS_CAPABILITY_PREFIX}{destination}")
}

// ── the broker, bound to one warrant ──────────────────────────────────────────────────

/// The destination catalogue derived from one warrant's bounds, plus the chain it grants.
///
/// Built once per proxy rather than per call: the catalogue is a pure function of the signed
/// claims, which do not change while the warrant is open.
#[derive(Debug, Clone)]
pub struct EgressBroker {
    catalog: Option<broker::DestinationCatalog>,
    chain: Vec<String>,
}

impl EgressBroker {
    /// Derive the catalogue and chain from a warrant's bounds.
    ///
    /// An empty `egress_hosts` produces **no catalogue**, which the broker treats as
    /// [`DenyReason::CatalogUnavailable`]. That is the same reading the rest of the warrant takes:
    /// an absent limit means none, never unlimited.
    #[must_use]
    pub fn for_bounds(bounds: &WarrantBounds) -> Self {
        let chain: Vec<String> = bounds
            .egress_hosts
            .iter()
            .map(|h| capability_for(h))
            .collect();
        if bounds.egress_hosts.is_empty() {
            return Self {
                catalog: None,
                chain,
            };
        }
        let entries: Vec<broker::CatalogEntry> = bounds
            .egress_hosts
            .iter()
            .map(|host| broker::CatalogEntry {
                logical_endpoint: host.clone(),
                // The name the developer wrote, not a resolved address: nothing here resolves DNS,
                // so claiming a pinned IP would be inventing one.
                addresses: vec![host.clone()],
                // No TLS identity is pinned or checked anywhere in this system.
                tls_identity: None,
                // A warrant bounds destinations, not HTTP methods. Empty is the honest value; the
                // broker does not read this field.
                permitted_methods: Vec::new(),
                expires_at: bounds.expires_at,
            })
            .collect();
        let mut catalog = broker::DestinationCatalog {
            version: CATALOG_VERSION.to_string(),
            entries,
            digest: String::new(),
            // Unsigned, and left visibly so. See the module docs.
            signature: None,
        };
        catalog.digest = catalog.compute_digest();
        Self {
            catalog: Some(catalog),
            chain,
        }
    }

    /// Decide one destination.
    #[must_use]
    pub fn decide(&self, destination: &str) -> broker::EgressVerdict {
        let request = broker::EgressRequest {
            capability: capability_for(destination),
            logical_endpoint: destination.to_string(),
            chain_capabilities: self.chain.clone(),
            // The warrant's own honest word for where this holds. Not "mediated": the proxy
            // mediates only the calls that come through it.
            enforcement_mode: "advisory".to_string(),
            // Discovery is a request to reach somewhere the catalogue does not name, and it needs a
            // human. There is no approval channel during a run, so a destination outside the bound
            // is refused as not-catalogued rather than parked as a pending discovery: widening the
            // bound means granting a new warrant, which is a human act by construction.
            is_discovery: false,
            has_approval: false,
        };
        broker::decide(&request, self.catalog.as_ref())
    }

    /// Digest of the derived catalogue, or `None` when the warrant permits no egress.
    #[must_use]
    pub fn catalog_digest(&self) -> Option<&str> {
        self.catalog.as_ref().map(|c| c.digest.as_str())
    }

    /// How many destinations the catalogue holds.
    #[must_use]
    pub fn catalogued(&self) -> usize {
        self.catalog.as_ref().map_or(0, |c| c.entries.len())
    }
}

// ── finding the destinations a call names ─────────────────────────────────────────────

/// A destination found in a tool call's arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// The argument it was named in, so a refusal can say where to look.
    pub argument: String,
    /// The host, with scheme, path, credentials and port stripped by [`host_of`].
    pub host: String,
}

/// Argument names that hold a destination.
///
/// The old check looked at `host` and `url` only, which meant a tool taking `endpoint`,
/// `base_url` or `server` reached `Forward` with no egress evaluation at all — a hole in the shape
/// of the arguments rather than in the policy.
const DESTINATION_KEYS: &[&str] = &[
    "address",
    "api_base",
    "api_url",
    "base_url",
    "domain",
    "endpoint",
    "host",
    "hostname",
    "origin",
    "proxy",
    "remote",
    "server",
    "target_url",
    "uri",
    "url",
    "webhook",
    "webhook_url",
];

/// Characters that end a URL inside a larger string.
fn ends_url(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '\\' | '<' | '>' | '`' | ',' | ';' | '|' | ')' | ']' | '}'
        )
}

/// Every host named by a scheme-qualified URL anywhere inside `value`.
fn hosts_in(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(index) = rest.find("://") {
        let after = &rest[index + 3..];
        let end = after.find(ends_url).unwrap_or(after.len());
        let host = host_of(&after[..end]);
        if !host.is_empty() {
            out.push(host);
        }
        rest = &after[end..];
    }
    out
}

/// Every destination a tool call names, deduplicated, in a deterministic order.
///
/// Two sources, because either alone leaves a hole:
///
/// 1. Arguments whose *name* is a destination name ([`DESTINATION_KEYS`]) — this catches a bare
///    hostname with no scheme.
/// 2. A scheme-qualified URL appearing in *any* argument value — this catches a compound command
///    line (`git args="clone https://…"`) and a stringified JSON body, neither of which puts the
///    destination under a name the proxy could have guessed.
///
/// The second rule deliberately over-reads: a URL quoted in prose — a pull-request body citing a
/// link — is treated as a destination and refused if the warrant does not permit it. The proxy
/// cannot tell a link the agent means to fetch from one it means to write down, and treating an
/// unknown host in an argument as a destination is the fail-closed reading. That failure is visible
/// and recoverable — the refusal names the host and is recorded for the report — where the opposite
/// failure is silent.
///
/// A tool that reaches a destination it never names in its arguments — one with a compiled-in
/// endpoint — is not caught at all. That is the limit of deciding from arguments at a proxy, and it
/// is why this bound is enforced *at the proxy* rather than sandbox-grade.
/// # An argument named as a destination that resolves to nothing is still a destination
///
/// The two sources differ in what an empty host *means*, and collapsing them is a fail-open bug.
///
/// From rule 2 — scanning any argument for a URL — an empty result means *no URL was found there*.
/// Skipping is correct; most arguments name no destination at all.
///
/// From rule 1 — an argument whose name is in [`DESTINATION_KEYS`] — an empty result means the
/// caller said "here is where I am going" and the proxy **could not tell where that is**. Skipping
/// that is precisely backwards: it forwards the calls whose destination is least visible. It is
/// emitted with an empty host instead, which no allowlist entry can match, so it denies and the
/// refusal names the argument that could not be resolved.
#[must_use]
pub fn destinations_of(call: &ToolCall) -> Vec<Destination> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut push = |argument: &str, host: &str, skip_empty: bool| {
        if (skip_empty && host.is_empty()) || !seen.insert(host.to_string()) {
            return;
        }
        out.push(Destination {
            argument: argument.to_string(),
            host: host.to_string(),
        });
    };
    for (name, value) in &call.arguments {
        for host in hosts_in(value) {
            push(name, host, true);
        }
        if DESTINATION_KEYS.contains(&name.as_str()) {
            // Not `skip_empty`: unresolvable is a destination we must refuse, not one we ignore.
            push(name, host_of(value), false);
        }
    }
    out
}

// ── refusals ──────────────────────────────────────────────────────────────────────────

/// One egress refusal, kept per (tool, destination) so a looping agent does not flood the report.
///
/// The point of the structure: the old refusal was a sentence, so nothing downstream could group,
/// count or explain it. This can be counted per destination and rendered differently for the agent
/// (which needs to adapt) and the developer (who needs to decide whether the bound was wrong).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRefusal {
    /// The tool whose call named the destination.
    pub tool: String,
    /// The argument the destination was named in.
    pub argument: String,
    /// The destination, as the proxy resolved it.
    pub destination: String,
    /// The capability it would have needed.
    pub capability: String,
    /// The broker's coarse reason.
    pub reason: DenyReason,
    /// How many times this exact refusal happened.
    pub count: u32,
}

impl EgressRefusal {
    /// Build a refusal from a broker denial.
    #[must_use]
    pub fn new(tool: &str, destination: &Destination, reason: DenyReason) -> Self {
        Self {
            tool: tool.to_string(),
            argument: destination.argument.clone(),
            destination: destination.host.clone(),
            capability: capability_for(&destination.host),
            reason,
            count: 1,
        }
    }

    /// Why, in terms the agent can act on.
    ///
    /// It names the destination and the argument, and stops there. It does not list the permitted
    /// destinations: a refusal that described the boundary would teach an agent its shape.
    #[must_use]
    pub fn sentence(&self) -> String {
        format!(
            "egress to {} is refused: {}. It was named in the {:?} argument. The request is \
             recorded for review.",
            self.destination,
            reason_phrase(self.reason.clone()),
            self.argument
        )
    }
}

/// Plain-English form of a broker denial.
#[must_use]
pub fn reason_phrase(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::CatalogUnavailable => {
            "this warrant permits no egress at all -- its egress bound is empty, and an absent \
             limit means none rather than unlimited"
        }
        DenyReason::NotInCatalog => "it is not a destination this warrant permits",
        DenyReason::MetadataRange => {
            "it is a link-local or cloud-metadata address, which is refused even when a warrant \
             names it"
        }
        DenyReason::NotInChainIntersection => {
            "the delegation chain this warrant carries does not reach it"
        }
        DenyReason::NotACapability => {
            "it was supplied as a raw address rather than as a permitted destination"
        }
        DenyReason::DiscoveryRequiresApproval => {
            "reaching a destination the warrant does not already name is a human decision, and \
             there is no approval channel during a run"
        }
        DenyReason::PrivateRange => "it is a private-range address this warrant does not name",
        DenyReason::CatalogInvalidSignature => "the destination catalogue did not verify",
        DenyReason::AgentCannotAmendCatalog => "an agent cannot amend the destination catalogue",
        DenyReason::RedirectOutOfSet => {
            "the redirect target is outside the resolved destination set"
        }
    }
}

/// The word for a denial reason, for machine-readable output.
#[must_use]
pub fn reason_word(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::CatalogUnavailable => "catalog_unavailable",
        DenyReason::NotInCatalog => "not_in_catalog",
        DenyReason::MetadataRange => "metadata_range",
        DenyReason::NotInChainIntersection => "not_in_chain_intersection",
        DenyReason::NotACapability => "not_a_capability",
        DenyReason::DiscoveryRequiresApproval => "discovery_requires_approval",
        DenyReason::PrivateRange => "private_range",
        DenyReason::CatalogInvalidSignature => "catalog_invalid_signature",
        DenyReason::AgentCannotAmendCatalog => "agent_cannot_amend_catalog",
        DenyReason::RedirectOutOfSet => "redirect_out_of_set",
    }
}

/// One line of `warrantor egress <id> <destination>` output.
///
/// A function rather than a `println!` in the binary so the wording is testable, and so the
/// allow line cannot quietly grow a claim about where the decision is enforced.
#[must_use]
pub fn render_decision(destination: &str, verdict: &broker::EgressVerdict) -> String {
    match verdict {
        broker::EgressVerdict::Allow {
            logical_endpoint, ..
        } => format!(
            "  allow  {destination:<32}  capability {}",
            capability_for(logical_endpoint)
        ),
        broker::EgressVerdict::Deny { reason } => format!(
            "  deny   {destination:<32}  {}: {}",
            reason_word(reason.clone()),
            reason_phrase(reason.clone())
        ),
    }
}

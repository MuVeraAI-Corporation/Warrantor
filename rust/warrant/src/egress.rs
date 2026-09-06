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
//!   permits no egress at all), [`DenyReason::NotInCatalog`] (the destination is not in the bound),
//!   [`DenyReason::MetadataRange`] and [`DenyReason::UnparseableAddress`]. The fourth was made
//!   reachable here by Task 7.1: [`EgressBroker::for_bounds`] copies each `egress_hosts` entry
//!   verbatim into the address field, so a bound of `"999.1.1.1"` arrives at the floor as a literal
//!   that could only ever have been a numeric address and is not one, and is refused rather than
//!   guessed at. `MetadataRange` is also the word the broker uses for a link-local **or IPv6
//!   unique-local** refusal: the floor's own reason is finer than this enum.
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
use crate::{WarrantBounds, WarrantState};

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

// ── can a live session reach anything at all? ─────────────────────────────────────────

/// Why no live session under a warrant could reach *any* destination.
///
/// The broker answers "does this warrant's bound permit that host?", which is only half of what a
/// developer asking `warrantor egress` wants to know. The other half is whether a session exists
/// that could ask: a warrant that is Held, Settled, Void, past its deadline, or stopped has no
/// proxy to traverse, so every destination is unreachable regardless of what the bound says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreachable {
    /// A stop record exists, so the warrant's scope is contained.
    Stopped,
    /// The warrant is not `Open`, so [`crate::mcp_endpoints::agent_endpoint_for`] refuses to build
    /// an endpoint for it at all.
    NotOpen {
        /// The state it is in instead.
        state: WarrantState,
    },
    /// The deadline passed, so the supervisor has terminated the agent and everything it started.
    Expired {
        /// The deadline, epoch seconds.
        expires_at: u64,
        /// When the question was asked, epoch seconds.
        now: u64,
    },
}

impl Unreachable {
    /// Plain-English form, ending in what would fix it.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::Stopped => "this warrant has been stopped, so its scope is contained and its \
                              supervisor is gone. Nothing under it reaches any destination. Grant \
                              a new warrant."
                .to_string(),
            Self::NotOpen { state } => format!(
                "this warrant is {state:?}, not Open. No agent endpoint is served for it, so no \
                 call under it reaches any destination. Grant a new warrant."
            ),
            Self::Expired { expires_at, now } => format!(
                "this warrant expired at {expires_at} and it is now {now}. The supervisor \
                 terminates the agent at the deadline, so no call under it reaches any \
                 destination. Grant a new warrant rather than extending a dead one."
            ),
        }
    }
}

/// The preconditions a live session must already satisfy before any destination is decided.
///
/// Checked in the order a human would want it explained rather than the order the run-time path
/// happens to apply them: a stopped warrant is also `Held`, and naming the stop says more than
/// naming the state it left behind.
///
/// `stopped` is the answer from [`crate::stop::StopStore::is_stopped`] and must never be `false`
/// standing in for "could not tell" — an unreadable stop directory means containment is unknown,
/// which is a refusal at the caller, not a `false` here.
///
/// # Errors
/// [`Unreachable`] when no live session under this warrant could reach anything.
pub fn session_reachability(
    state: WarrantState,
    expires_at: u64,
    stopped: bool,
    now: u64,
) -> Result<(), Unreachable> {
    if stopped {
        return Err(Unreachable::Stopped);
    }
    if !matches!(state, WarrantState::Open) {
        return Err(Unreachable::NotOpen { state });
    }
    if expires_at <= now {
        return Err(Unreachable::Expired { expires_at, now });
    }
    Ok(())
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

// ── the second policy engine ──────────────────────────────────────────────────────────
//
// A SECOND POLICY ENGINE AT THE SAME ENFORCEMENT POINT. Read that sentence before the code.
//
// This lowers common mode on the policy-engine axis: a different evaluator, a different default, a
// different configuration source. It does NOT add an enforcement point. Both engines run inside the
// MCP proxy; a socket the agent opens itself passes neither. See [`independence`] and
// `docs/05-network-common-mode-analysis.md`.

/// Where a [`SecondaryFilter`]'s policy came from.
///
/// Recorded rather than inferred, because "which configuration source decided this" is one of the
/// axes the independence analysis counts, and an unattributed policy cannot be counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondarySource {
    /// An operator-authored file, read from disk. The second configuration source.
    OperatorFile {
        /// The path it was read from, for the record.
        path: String,
    },
    /// [`warrantor_egress_filter::Policy::try_new_default`] — the compiled-in fallback used when no
    /// operator file exists. Its terminal branch is `DefaultDeny`.
    CompiledDefault,
    /// A policy handed over in process. Used by tests and by callers that build one themselves.
    InlinePolicy,
}

impl SecondarySource {
    /// The word this source appears as in [`Independence::configuration_sources`].
    ///
    /// It reaches `evidence/network-independence.json` only for a configuration the *product*
    /// actually runs, and the product wires no secondary filter today, so the recorded list is
    /// `["warrant_claims"]` alone. `tools/ci/network_independence.py` derives that rather than
    /// asserting it: the day a product source calls `Proxy::with_secondary_filter`, the gate
    /// publishes the second source and refuses the stale record.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OperatorFile { .. } => "operator_file",
            Self::CompiledDefault => "compiled_default",
            Self::InlinePolicy => "inline_policy",
        }
    }
}

/// Why an operator's secondary-filter configuration could not be used.
///
/// Every variant is a refusal to build a filter, never a silent fallback to one that permits more.
/// Absence of the file is [`SecondaryFilter::default_deny`]; a file that is present and *wrong* is
/// this error, and the caller must decide loudly rather than guess.
#[derive(Debug, thiserror::Error)]
pub enum SecondaryConfigError {
    /// The file exists and could not be read.
    #[error("the secondary egress filter config at {path} could not be read: {source}")]
    Unreadable {
        /// The path.
        path: String,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The file is not the JSON a [`warrantor_egress_filter::Policy`] deserializes from.
    #[error("the secondary egress filter config at {path} is not a valid policy: {source}")]
    Malformed {
        /// The path.
        path: String,
        /// The parse error.
        source: serde_json::Error,
    },
}

/// A second policy evaluator, consulted at the same enforcement point as [`EgressBroker`].
///
/// # What this is
///
/// [`warrantor_egress_filter::Policy`], reached from the product for the first time. It answers the
/// same question as the broker — may this destination be reached? — from a different configuration
/// source, with a different default, using different code.
///
/// # What this is not
///
/// It is **not** a second boundary. [`crate::proxy::Proxy::decide`] consults both engines, so both
/// bind exactly the calls that traverse the MCP proxy and neither binds anything else. It is also
/// **not** fully independent of the broker: both consult
/// [`warrantor_egress_filter::hard_deny`], which is the single non-amendable address matcher Task
/// 7.1 deliberately placed in one crate so the two could not drift apart. One matcher is right for
/// drift and is a shared failure domain for independence; [`independence`] names it `address_floor`
/// and reports it shared in every configuration.
#[derive(Debug, Clone)]
pub struct SecondaryFilter {
    policy: warrantor_egress_filter::Policy,
    source: SecondarySource,
}

impl SecondaryFilter {
    /// Read the operator's own policy file.
    ///
    /// This is the second configuration source, and the reason wiring this engine buys anything at
    /// all: it did not read the warrant's signed claims, so an over-broad destination catalogue
    /// derived from those claims does not widen it.
    ///
    /// # Errors
    /// [`SecondaryConfigError::Unreadable`] or [`SecondaryConfigError::Malformed`]. A missing file
    /// is **not** an error to be swallowed here — the caller chooses [`Self::default_deny`]
    /// explicitly, so that falling back is a visible decision rather than an implicit one.
    pub fn from_operator_config(path: &std::path::Path) -> Result<Self, SecondaryConfigError> {
        let display = path.display().to_string();
        let text =
            std::fs::read_to_string(path).map_err(|source| SecondaryConfigError::Unreadable {
                path: display.clone(),
                source,
            })?;
        let policy: warrantor_egress_filter::Policy =
            serde_json::from_str(&text).map_err(|source| SecondaryConfigError::Malformed {
                path: display.clone(),
                source,
            })?;
        Ok(Self {
            policy,
            source: SecondarySource::OperatorFile { path: display },
        })
    }

    /// The fallback: [`warrantor_egress_filter::Policy::try_new_default`], whose terminal branch is
    /// `DefaultDeny` and whose allowlist is empty.
    ///
    /// Absent configuration is default-**deny**, never default-allow. That is the same reading the
    /// rest of the warrant takes: an absent limit means none.
    ///
    /// # Panics
    /// Panics only if `DEFAULT_CANARY_IPS` in `warrantor-egress-filter` contains an unparseable
    /// literal, which is a compile-time constant in that crate and therefore a programmer error
    /// there rather than a runtime condition here.
    #[must_use]
    pub fn default_deny() -> Self {
        Self {
            policy: warrantor_egress_filter::Policy::try_new_default()
                .expect("DEFAULT_CANARY_IPS are compile-time constants in warrantor-egress-filter"),
            source: SecondarySource::CompiledDefault,
        }
    }

    /// Wrap a policy built in process.
    #[must_use]
    pub fn from_policy(policy: warrantor_egress_filter::Policy) -> Self {
        Self {
            policy,
            source: SecondarySource::InlinePolicy,
        }
    }

    /// Decide one destination.
    ///
    /// Deny-only by contract: the caller may use this to turn a `Forward` into a `Deny` and may
    /// **never** use it to turn the broker's `Deny` into a `Forward`. The call site in
    /// [`crate::proxy::Proxy::decide`] runs the broker first and returns on its refusal, so an
    /// `Allow` here is structurally unable to overturn one.
    #[must_use]
    pub fn decide(&self, destination: &str) -> warrantor_egress_filter::Decision {
        self.policy.decide_destination(destination)
    }

    /// Where this filter's policy came from.
    #[must_use]
    pub fn source(&self) -> &SecondarySource {
        &self.source
    }
}

// ── the independence count ────────────────────────────────────────────────────────────

/// What the independence count does NOT cover. Required beside the count on every render target
/// the gate names; rendered by no product code (see *Where this constant is required*).
///
/// One constant, one place, for the same reason as [`ENFORCEMENT_NOTE`].
///
/// # The correction this wording carries
///
/// This note used to open *"The count above is a count of policy domains, not a count of enforcement
/// points."* That was **false about the number it sat beside, in the unsafe direction.** Every
/// surface `tools/ci/network_independence.py` polices publishes exactly one number — the
/// [`Independence::intercepts`] count — and that number *is* the enforcement-point count. The old
/// clause told the reader the published `1` did not bound enforcement points, when the whole finding
/// of this analysis is that exactly one enforcement point exists. The record the note accompanies
/// said the opposite in capital letters (`evidence/network-independence.json`: *"The count is a
/// count of ENFORCEMENT POINTS ... not of policy engines"*), and CI held the wrong wording in place
/// on three surfaces.
///
/// So the clause is now attached to the number it is true of. The intercept count is labeled an
/// enforcement count; the *engine* count is the one labeled a policy-domain count. Two adversarial
/// reviewers found this independently, and it is the [[verify attribution, not just numbers]] shape:
/// the figures were right, the words pinned to them were wrong.
///
/// A rendered number and its label must come from the same record, so prefer
/// [`independence_sentence`] over quoting this constant with a number beside it. This constant
/// carries only the clauses that hold in every configuration.
///
/// # The second correction this wording carries
///
/// The previous value opened its second sentence *"Two policy engines decide at that one point"*,
/// under the promise above that the constant holds in every configuration. It did not: the shipped
/// binary wires no second engine (`Proxy::new` sets `secondary: None`, and nothing in
/// `warrantor.rs` constructs a [`SecondaryFilter`]), so in the only configuration the product runs
/// one engine decides. An engine count is a number, and a number belongs in
/// [`independence_sentence`], which reads it off the record; this constant now names no count at
/// all, and the Rust suite asserts that it carries no digit and no spelled-out engine count. The
/// same doc comment also said the constant was *"printed under the count on every surface"*: no
/// product code renders it. What is true is below.
///
/// # Where this constant is required
///
/// `tools/ci/network_independence.py` requires its two load-bearing clauses -- what the count
/// *is* and what *escapes* it -- within twelve lines of the rendered count on each of the three
/// render targets it names (`docs/05-network-common-mode-analysis.md`, `README.md`,
/// `docs/W1-delivery-gaps.md`), and requires `docs/05`'s "What the count excludes" paragraph to
/// be this value verbatim (`the_analysis_paragraph_is_the_constant`). The escape clause is
/// asserted by value in `rust/warrant/tests/network_independence.rs` and in the I-09 corpus.
pub const INDEPENDENCE_NOTE: &str =
    "The count above is a count of enforcement points acting on a destination this warrant \
     permits. Every policy engine that decides a destination -- the broker always, and a second \
     engine only once one is wired -- runs inside the Warrantor MCP proxy at that one point, so \
     the engine count is a count of policy domains and is not a second boundary: a shell command, \
     a harness built-in, or any socket the agent opens itself passes neither the proxy nor any \
     engine inside it. There is no network namespace, seccomp filter or firewall behind this \
     count, and the confinement profile does not add one for a warrant that permits any host -- \
     it omits --unshare-net precisely then. A hostname that resolves into a private or metadata \
     range is not caught: no engine at that point resolves DNS.";

/// The count clause, rendered from the record rather than written beside it.
///
/// # Why this exists rather than a second constant
///
/// Rule 2 of this repository's content rules: *a rendered sentence must be derived from the record
/// it describes.* [`INDEPENDENCE_NOTE`] shipped a label for a number it never read, and no test
/// could catch that because the label was a literal. Here the label attached to each number is
/// chosen from the field the number was read out of, so a surface cannot print `intercepts` under
/// the word "engines" or the reverse.
///
/// # The empty-bound trap
///
/// A warrant permitting no egress has **two** layers standing and *nothing permitted for either of
/// them to guard*. Rendering that `2` as a double network path would be the exact overclaim this
/// whole analysis exists to refuse, so this function reads
/// [`Independence::guards_a_permitted_destination`] and says so instead.
#[must_use]
pub fn independence_sentence(measured: &Independence) -> String {
    let intercepts = measured.intercepts;
    let engines = measured.engines;
    let point = if intercepts == 1 { "point" } else { "points" };
    let acts = if intercepts == 1 { "acts" } else { "act" };
    let stands = if intercepts == 1 { "stands" } else { "stand" };
    let decide = if engines == 1 {
        "engine decides"
    } else {
        "engines decide"
    };

    if !measured.guards_a_permitted_destination {
        return format!(
            "{intercepts} enforcement {point} {stands} under this warrant and none of them guards \
             a permitted destination: the warrant permits no egress at all, which is the one \
             configuration where the network namespace is emitted. This is not a double network \
             path -- there is no destination for the two layers to be independent about. \
             {engines} policy {decide} at them, which is a count of policy domains and not a \
             count of boundaries.",
        );
    }

    format!(
        "{intercepts} enforcement {point} {acts} on a destination this warrant permits, and \
         {engines} policy {decide} at {them}. The enforcement count is {intercepts}; the engine \
         count is a count of policy domains and is not a second boundary.",
        them = if intercepts == 1 { "it" } else { "them" },
    )
}

/// Every axis the independence analysis models, in the order the analysis document tables them.
///
/// The blueprint's residual names three (`policy_engine`, `credential`, `telemetry_path`); L0-10's
/// residual adds a resolver and a clock; `enforcement_point` is the one a reader assumes and neither
/// residual lists; `address_floor` is the one that did not exist until Task 7.1 gave both evaluators
/// a single shared matcher.
pub const INDEPENDENCE_AXES: [&str; 8] = [
    "enforcement_point",
    "policy_engine",
    "address_floor",
    "configuration_source",
    "credential",
    "telemetry_path",
    "clock",
    "dns_resolution",
];

/// The measured independence of the egress path, for one warrant's bounds.
///
/// `engines` and `intercepts` are separate fields on purpose. Conflating them is the misreading this
/// whole analysis exists to prevent: wiring a second evaluator raises `engines` and leaves
/// `intercepts` alone, because a policy domain is not a boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Independence {
    /// Enforcement points that could refuse a destination under these bounds.
    ///
    /// One for any warrant that permits egress: the MCP proxy. Two only for a warrant that permits
    /// none, where the netns is also emitted — and see [`Self::guards_a_permitted_destination`]
    /// before reading that two as a double path.
    pub intercepts: usize,
    /// Policy evaluators consulted at those points. Two once a [`SecondaryFilter`] is wired.
    pub engines: usize,
    /// True only when at least one intercept acts on a destination the warrant permits.
    ///
    /// False for an empty `egress_hosts`, which is the one configuration with two layers standing
    /// and no permitted destination for either of them to be independent about.
    pub guards_a_permitted_destination: bool,
    /// Which of [`INDEPENDENCE_AXES`] the layers share, in that order.
    pub shared_axes: Vec<&'static str>,
    /// The enforcement layers standing under these bounds.
    pub layers: Vec<&'static str>,
    /// The configuration sources the engines above read, in the order the engines are consulted.
    ///
    /// Always begins with `"warrant_claims"`: the broker's catalogue is derived from the signed
    /// bounds and from nothing else. A wired [`SecondaryFilter`] appends its own
    /// [`SecondarySource::as_str`], which is the whole reason a second engine buys anything — an
    /// engine reading the same source as the first would move the `policy_engine` axis on paper and
    /// share a failure domain in fact.
    ///
    /// Added because `SecondarySource::as_str`'s doc claimed the word appeared here and it did not:
    /// the attribution was declared and dropped, with no reader anywhere in the workspace. A `pub`
    /// item is invisible to both `dead_code` and `clippy -D warnings`, so nothing signaled it.
    pub configuration_sources: Vec<&'static str>,
}

/// Measure the independence of the egress path.
///
/// This is the function the machine-readable record and the drills both read, so the prose and the
/// tests cannot diverge. Every answer it gives is derived from the two conditions that drive the
/// two layers — `rust/warrant/src/egress.rs` line 196 and `rust/warrant/src/sandbox.rs` line 318 —
/// which are the same field read with opposite senses.
#[must_use]
pub fn independence(bounds: &WarrantBounds, secondary: Option<&SecondaryFilter>) -> Independence {
    let permits_egress = !bounds.egress_hosts.is_empty();

    // The layers, from the conditions themselves rather than from a list someone maintains.
    //
    // The proxy is always an intercept: it decides per destination when the catalogue exists and
    // refuses everything as `CatalogUnavailable` when it does not. The netns is an intercept only
    // when `egress_hosts` is empty, which is exactly when the proxy has nothing left to permit.
    let mut layers = vec!["mcp_proxy"];
    if !permits_egress {
        layers.push("network_namespace");
    }
    let intercepts = layers.len();

    let engines = if secondary.is_some() { 2 } else { 1 };

    let mut shared_axes = Vec::new();
    for axis in INDEPENDENCE_AXES {
        let shared = match axis {
            // Both engines decide inside `Proxy::decide`. The netns is enforced by the kernel, but
            // only in the configuration where it guards nothing, and only if an operator launched
            // the printed profile -- which this process cannot observe (`sandbox::PROFILE_CAVEAT`).
            "enforcement_point" => true,
            // The one axis a second evaluator moves.
            "policy_engine" => secondary.is_none(),
            // Never moves. Both `warrantor_egress::decide` and
            // `warrantor_egress_filter::Policy::decide_*` consult `hard_deny::refuse`/`refuse_ip`.
            // One matcher, two callers: a defect there fails both at once.
            "address_floor" => true,
            // `WarrantBounds::egress_hosts` opens the proxy's catalogue and suppresses the netns.
            // One field, both layers, opposite directions. A shared config field IS a common mode,
            // and this one is not merely shared -- it is inverted. A secondary filter adds a second
            // source for the pair of ENGINES; the pair of LAYERS still hangs off this one field.
            "configuration_source" => true,
            // Neither holds a key. Independent by absence, not by design: `egress.rs` lines 53-56
            // say the process serving a supervised agent deliberately holds none.
            "credential" => false,
            // Both refusals land in `Proxy::egress_refusals` / `Proxy::requests`, in one process,
            // with no independent sink. The netns produces no telemetry at all: its refusal is a
            // `connect()` failure inside the agent that never reaches Warrantor.
            "telemetry_path" => true,
            // `bounds.expires_at` is copied into every `CatalogEntry` and is the supervisor's
            // deadline. One clock, every layer.
            "clock" => true,
            // Neither resolves. A hostname that resolves into a metadata range is caught only if
            // the NAME is on `hard_deny`'s hostname list. A shared blind spot is a common mode.
            "dns_resolution" => true,
            // `INDEPENDENCE_AXES` is exhaustive and this arm is unreachable; it exists so that
            // adding an axis without deciding its answer cannot silently report "not shared".
            other => unreachable!("axis {other} has no independence answer"),
        };
        if shared {
            shared_axes.push(axis);
        }
    }

    // Read off the filter's own recorded source rather than inferred from the fact that one exists.
    // `SecondaryFilter::from_operator_config` and `SecondaryFilter::default_deny` are different
    // configuration sources and the axis table treats them differently, so which one it was has to
    // travel with the measurement.
    let mut configuration_sources = vec!["warrant_claims"];
    if let Some(filter) = secondary {
        configuration_sources.push(filter.source().as_str());
    }

    Independence {
        intercepts,
        engines,
        guards_a_permitted_destination: permits_egress,
        shared_axes,
        layers,
        configuration_sources,
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
///
/// Public because the catalog closes exactly these keys in a published tool schema, and the
/// decision log keys off them: one list of destination-shaped arguments, three consumers.
pub const DESTINATION_KEYS: &[&str] = &[
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

/// One refusal by the **second** policy engine, kept as its own record.
///
/// A separate type from [`EgressRefusal`] on purpose. The two evaluators are different engines with
/// different configuration sources, and a refusal that cannot say which one refused cannot be
/// attributed — so this carries the filter's own structured rule rather than being folded into the
/// broker's coarser [`DenyReason`], which would report a decision the broker did not make.
///
/// Being a second *record* is not being a second *telemetry path*: both maps live in the same
/// [`crate::proxy::Proxy`], in the same process, with no independent sink. [`independence`] reports
/// `telemetry_path` as shared for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecondaryRefusal {
    /// The tool whose call named the destination.
    pub tool: String,
    /// The argument the destination was named in.
    pub argument: String,
    /// The destination, as the proxy resolved it.
    pub destination: String,
    /// The form the filter actually decided against, which makes a normalization bypass visible.
    pub normalized: String,
    /// The filter's own reason, from `warrantor_egress_filter::DecisionReason`.
    pub rule: String,
    /// How many times this exact refusal happened.
    pub count: u32,
}

impl SecondaryRefusal {
    /// Build a refusal from the second engine's decision.
    ///
    /// # Panics
    /// Never. The rule string is taken from the decision's own serialization and falls back to its
    /// `Debug` form if that ever fails, so a refusal is never dropped for want of a label.
    #[must_use]
    pub fn new(
        tool: &str,
        destination: &Destination,
        decision: &warrantor_egress_filter::Decision,
    ) -> Self {
        // Derived from the decision, not written beside it: the rule this renders is the one the
        // engine actually returned.
        let rule = serde_json::to_string(&decision.reason)
            .unwrap_or_else(|_| format!("{:?}", decision.reason));
        Self {
            tool: tool.to_string(),
            argument: destination.argument.clone(),
            destination: destination.host.clone(),
            normalized: decision.normalized.clone(),
            rule,
            count: 1,
        }
    }

    /// Why, in terms the agent can act on, and naming which engine refused.
    ///
    /// Every clause is read off this record. The engine is named because a refusal attributed to the
    /// wrong evaluator sends an operator to the wrong configuration file.
    #[must_use]
    pub fn sentence(&self) -> String {
        format!(
            "egress to {} is refused by the second policy engine: {}. It was named in the {:?} \
             argument. This is a second policy domain at the same enforcement point, not a second \
             boundary. The request is recorded for review.",
            self.destination, self.rule, self.argument
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
            "it is a link-local, IPv6 unique-local or cloud-metadata address, which is refused even \
             when a warrant names it"
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
        DenyReason::UnparseableAddress => {
            "the destination is written as a numeric address and is not one, so the floor cannot \
             classify it and refuses rather than guess"
        }
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
        DenyReason::UnparseableAddress => "unparseable_address",
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

// ── every decision, written down ──────────────────────────────────────────────────────

/// Wire format of one recorded decision (allow or deny). Unsigned: the proxy holds no key.
pub const DECISION_FORMAT: &str = "warrantor.egress-decision/1";

/// One broker decision, recorded before the call it decided is forwarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDecision {
    /// Wire format; see [`DECISION_FORMAT`].
    pub format: String,
    /// The warrant the decided call ran under.
    pub warrant_id: String,
    /// When the decision was made, epoch seconds.
    pub at: u64,
    /// The tool whose call named the destination.
    pub tool: String,
    /// The argument the destination was named in.
    pub argument: String,
    /// The capability name the argument carried, or the host-derived one for a raw address.
    pub capability: String,
    /// The destination the capability resolved to, or the raw host for a refusal.
    pub destination: String,
    /// The broker's verdict, allow or deny with its reason.
    pub verdict: EgressVerdict,
    /// The catalog digest the name resolved through, when a vocabulary was attached.
    pub catalog_digest: Option<String>,
}

fn decision_path(root: &std::path::Path, warrant_id: &str) -> std::path::PathBuf {
    root.join("egress").join(format!("{warrant_id}.jsonl"))
}

/// Append decisions. Called BEFORE the call is forwarded; a failure here refuses the forward.
pub fn record_decisions(
    root: &std::path::Path,
    decisions: &[EgressDecision],
) -> Result<usize, String> {
    use std::io::Write as _;
    let Some(first) = decisions.first() else {
        return Ok(0);
    };
    let path = decision_path(root, &first.warrant_id);
    std::fs::create_dir_all(path.parent().unwrap_or(root))
        .map_err(|e| format!("create the egress log directory: {e}"))?;
    let mut body = String::new();
    for decision in decisions {
        body.push_str(&serde_json::to_string(decision).map_err(|e| format!("encode: {e}"))?);
        body.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    file.write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("append to {}: {e}", path.display()))?;
    Ok(decisions.len())
}

/// Every recorded decision for a warrant, and how many lines did not parse.
pub fn read_decisions(
    root: &std::path::Path,
    warrant_id: &str,
) -> Result<(Vec<EgressDecision>, usize), String> {
    let path = decision_path(root, warrant_id);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let mut out = Vec::new();
    let mut unreadable = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<EgressDecision>(line) {
            Ok(d) if d.format == DECISION_FORMAT => out.push(d),
            _ => unreadable += 1,
        }
    }
    Ok((out, unreadable))
}

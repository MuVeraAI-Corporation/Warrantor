//! W3 — the MCP proxy: policy and staging on the agent's tool calls.
//!
//! The agent registers Warrantor as its MCP server. Warrantor forwards to the real servers, so it
//! sees every tool call the agent makes — including calls to third-party servers, which is where
//! the interesting risk lives. Without this the warrant's tool allowlist is a document rather than
//! a boundary.
//!
//! # Why a proxy rather than in-process authorization
//!
//! Wiring policy into our own MCP server would govern only our own tools, which are the least
//! interesting surface. A proxy governs whatever the agent actually uses, and works with any
//! MCP-speaking client unchanged.
//!
//! # Observe mode
//!
//! Nobody can predict which tools an agent will need, so a warrant is authored by observation
//! rather than guessed. In observe mode nothing is denied for being unlisted — every tool the agent
//! touches is recorded, and that record becomes the proposed warrant.
//!
//! # Egress
//!
//! The egress bound is decided by [`crate::egress`], which asks [`warrantor_egress`] per
//! destination rather than testing a hostname against a set. That buys a structured refusal and a
//! metadata-range denial the set membership did not have. It buys nothing at all about *where*
//! egress is enforced: here, on the calls that come through this proxy, and nowhere else.
//!
//! Observe mode still hard-blocks `destructive` and `financial` classes, and it does **not** stage
//! ordinary writes: a pull request opened during an observe run is really opened. That was a
//! deliberate decision — a staged effect the developer did not expect is worse than a real one —
//! and it means observe mode must announce itself at grant time rather than in a footnote.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::egress::{EgressBroker, EgressRefusal};
use crate::staging::{EffectRegistry, StagedEffect, StagingQueue};
use crate::{SideEffectClass, WarrantBounds};

/// How the proxy treats calls it has not been told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Refuse anything outside the warrant. The normal mode.
    Enforce,
    /// Record everything, refuse only destructive and financial classes. Used to author a warrant
    /// from what an agent actually does.
    Observe,
}

/// What the proxy decided about one tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum Decision {
    /// Forward to the real MCP server and return its result.
    Forward,
    /// Queue it; the agent receives a staged handle instead of a real result.
    Stage {
        /// The handle standing for the queued effect.
        handle: String,
    },
    /// Refuse. `reason` is shown to the agent so it can adapt, and recorded so the developer can
    /// see what the agent tried.
    Deny {
        /// Why, in terms the agent can act on.
        reason: String,
        /// The bound that refused it.
        bound: &'static str,
    },
}

/// A tool call arriving from the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Fully-qualified tool name, e.g. `github.create_pr`.
    pub tool: String,
    /// Arguments as supplied.
    pub arguments: BTreeMap<String, String>,
    /// The side-effect class this tool belongs to.
    pub side_effect: SideEffectClass,
}

/// A denial recorded for the morning report.
///
/// Every wall the agent hits is evidence about whether the warrant was scoped correctly, so
/// denials are kept rather than merely returned. A run with twenty denials of the same tool says
/// the bounds were wrong; a run with one says the agent tried something it should not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRequest {
    /// The tool that was refused.
    pub tool: String,
    /// The bound that refused it.
    pub bound: String,
    /// Why.
    pub reason: String,
    /// How many times this exact refusal happened.
    pub count: u32,
}

/// The proxy's policy engine.
pub struct Proxy {
    mode: ProxyMode,
    bounds: WarrantBounds,
    registry: EffectRegistry,
    /// The egress bound, as a destination catalogue the broker decides against.
    egress: EgressBroker,
    /// Tools seen in observe mode, which become the proposed warrant.
    observed_tools: BTreeSet<String>,
    /// Denials, deduplicated by (tool, bound) so a looping agent does not flood the report.
    requests: BTreeMap<(String, String), AuthorityRequest>,
    /// Egress denials in full, deduplicated by (tool, destination).
    egress_refusals: BTreeMap<(String, String), EgressRefusal>,
}

/// Classes that are refused even in observe mode.
///
/// Learning what an agent wants to do must not itself destroy anything or spend money. Everything
/// else is observable safely; these are not.
const NEVER_IN_OBSERVE: [SideEffectClass; 2] =
    [SideEffectClass::Destructive, SideEffectClass::Financial];

impl Proxy {
    /// Build a proxy enforcing `bounds`.
    #[must_use]
    pub fn new(bounds: WarrantBounds, mode: ProxyMode, registry: EffectRegistry) -> Self {
        // Derived once: the catalogue is a pure function of the signed claims, which do not change
        // while the warrant is open.
        let egress = EgressBroker::for_bounds(&bounds);
        Self {
            mode,
            bounds,
            registry,
            egress,
            observed_tools: BTreeSet::new(),
            requests: BTreeMap::new(),
            egress_refusals: BTreeMap::new(),
        }
    }

    fn deny(&mut self, tool: &str, bound: &'static str, reason: String) -> Decision {
        let key = (tool.to_string(), bound.to_string());
        self.requests
            .entry(key)
            .and_modify(|r| r.count += 1)
            .or_insert_with(|| AuthorityRequest {
                tool: tool.to_string(),
                bound: bound.to_string(),
                reason: reason.clone(),
                count: 1,
            });
        Decision::Deny { reason, bound }
    }

    /// Record an egress refusal in full, then deny under the `egress_hosts` bound.
    ///
    /// Two records, deliberately: the [`AuthorityRequest`] keeps the existing per-(tool, bound)
    /// counting every surface already reads, and the [`EgressRefusal`] keeps the destination and
    /// the reason, which the sentence alone could not be grouped by. The bound label stays the
    /// static `"egress_hosts"` — [`Decision::Deny::bound`] is a `&'static str`, and it is the name
    /// of the bound that refused, not of the engine that decided.
    fn deny_egress(&mut self, tool: &str, refusal: EgressRefusal) -> Decision {
        let key = (tool.to_string(), refusal.destination.clone());
        let sentence = refusal.sentence();
        self.egress_refusals
            .entry(key)
            .and_modify(|existing| existing.count += 1)
            .or_insert(refusal);
        self.deny(tool, "egress_hosts", sentence)
    }

    /// Decide what happens to `call`.
    ///
    /// Returns the decision only; staging is performed by [`Self::apply`] so the caller controls
    /// when the queue is written.
    pub fn decide(&mut self, call: &ToolCall) -> Decision {
        // Destructive and financial are refused in observe mode regardless of the allowlist.
        if self.mode == ProxyMode::Observe && NEVER_IN_OBSERVE.contains(&call.side_effect) {
            return self.deny(
                &call.tool,
                "side_effect_class",
                format!(
                    "{:?} actions are refused even in observe mode: learning what an agent wants \
                     to do must not destroy anything or spend money",
                    call.side_effect
                ),
            );
        }

        if self.mode == ProxyMode::Observe {
            // The point of observe mode: record, do not refuse.
            self.observed_tools.insert(call.tool.clone());
            return Decision::Forward;
        }

        if !self.bounds.tools.contains(&call.tool) {
            return self.deny(
                &call.tool,
                "tools",
                format!(
                    "{} is not in this warrant's tool allowlist. Work within the granted tools, \
                     or ask for it to be added -- the request is recorded for review.",
                    call.tool
                ),
            );
        }

        // Egress, decided per destination by the broker.
        //
        // Every destination the call names is decided, not just the first `host` or `url` argument
        // — a tool taking `endpoint`, or a URL buried in a compound argument, used to reach
        // `Forward` with no egress evaluation at all. An empty egress bound produces no catalogue,
        // which the broker refuses as `CatalogUnavailable`: an absent limit means none.
        //
        // This changes WHICH decision is made and how it is explained. It does not change WHERE it
        // is made: a call that never reaches this proxy is not decided here or anywhere.
        for destination in crate::egress::destinations_of(call) {
            if let crate::egress::EgressVerdict::Deny { reason } =
                self.egress.decide(&destination.host)
            {
                let refusal = EgressRefusal::new(&call.tool, &destination, reason);
                return self.deny_egress(&call.tool, refusal);
            }
        }

        if self.bounds.staged_classes.contains(&call.side_effect)
            && self.registry.get(&call.tool).is_some()
        {
            // Staged: the agent gets a handle, and the effect happens at settle if it happens.
            return Decision::Stage {
                handle: String::new(),
            };
        }

        Decision::Forward
    }

    /// Apply a staging decision by writing to `queue`, returning the real handle.
    ///
    /// # Errors
    /// Any staging error, most usefully a wrong-type or unknown target.
    pub fn apply(
        &self,
        call: &ToolCall,
        queue: &mut StagingQueue,
        at: u64,
    ) -> Result<StagedEffect, crate::WarrantError> {
        queue.stage(&call.tool, call.arguments.clone(), at)
    }

    /// Tools the agent used during an observe run, as a proposed allowlist.
    #[must_use]
    pub fn proposed_tools(&self) -> &BTreeSet<String> {
        &self.observed_tools
    }

    /// Denials, for the morning report.
    #[must_use]
    pub fn authority_requests(&self) -> Vec<&AuthorityRequest> {
        let mut out: Vec<&AuthorityRequest> = self.requests.values().collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then(a.tool.cmp(&b.tool)));
        out
    }

    /// Egress denials with their destination and reason, most frequent first.
    ///
    /// What the developer needs that [`Self::authority_requests`] cannot give: twenty refusals of
    /// one destination says the bound was scoped wrong; twenty refusals of twenty destinations says
    /// something else entirely.
    #[must_use]
    pub fn egress_refusals(&self) -> Vec<&EgressRefusal> {
        let mut out: Vec<&EgressRefusal> = self.egress_refusals.values().collect();
        out.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.destination.cmp(&b.destination))
                .then(a.tool.cmp(&b.tool))
        });
        out
    }

    /// The destination catalogue this proxy decides against.
    #[must_use]
    pub fn egress_broker(&self) -> &EgressBroker {
        &self.egress
    }
}

/// Extract a host from a URL or bare host string.
///
/// Deliberately simple, and deliberately conservative: anything it cannot parse it returns whole,
/// so an unparseable value fails the allowlist check rather than passing it. A permissive parser
/// here would be an egress bypass.
#[must_use]
pub fn host_of(value: &str) -> &str {
    let after_scheme = value.split_once("://").map_or(value, |(_, rest)| rest);
    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    // Strip credentials and port, both of which would defeat a naive string comparison.
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    host.split_once(':').map_or(host, |(h, _)| h)
}

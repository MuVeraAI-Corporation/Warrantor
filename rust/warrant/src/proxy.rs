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
//! Observe mode still hard-blocks `destructive` and `financial` classes, and it does **not** stage
//! ordinary writes: a pull request opened during an observe run is really opened. That was a
//! deliberate decision — a staged effect the developer did not expect is worse than a real one —
//! and it means observe mode must announce itself at grant time rather than in a footnote.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

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
    /// Tools seen in observe mode, which become the proposed warrant.
    observed_tools: BTreeSet<String>,
    /// Denials, deduplicated by (tool, bound) so a looping agent does not flood the report.
    requests: BTreeMap<(String, String), AuthorityRequest>,
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
        Self {
            mode,
            bounds,
            registry,
            observed_tools: BTreeSet::new(),
            requests: BTreeMap::new(),
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

        // Egress is refused by an empty host set, which is why an absent field means "none"
        // rather than "unlimited" throughout.
        if let Some(host) = call
            .arguments
            .get("host")
            .or_else(|| call.arguments.get("url"))
        {
            let target = host_of(host);
            if !self.bounds.egress_hosts.iter().any(|h| h == target) {
                return self.deny(
                    &call.tool,
                    "egress_hosts",
                    format!("egress to {target} is not permitted by this warrant"),
                );
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

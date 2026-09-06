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

use crate::catalog::Vocabulary;
use crate::egress::{
    capability_for, EgressBroker, EgressDecision, EgressRefusal, EgressVerdict, DESTINATION_KEYS,
};
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

/// One broker decision not yet written down. Kept until the endpoint drains it.
struct PendingDecision {
    tool: String,
    argument: String,
    capability: String,
    destination: String,
    verdict: EgressVerdict,
}

/// The proxy's policy engine.
pub struct Proxy {
    mode: ProxyMode,
    bounds: WarrantBounds,
    registry: EffectRegistry,
    /// The egress bound, as a destination catalogue the broker decides against.
    egress: EgressBroker,
    /// The second policy engine, when the operator configured one.
    ///
    /// A second policy domain at the SAME enforcement point — not a second boundary. `None` is the
    /// historical behavior: one evaluator. See [`crate::egress::independence`].
    secondary: Option<crate::egress::SecondaryFilter>,
    /// Tools seen in observe mode, which become the proposed warrant.
    observed_tools: BTreeSet<String>,
    /// Denials, deduplicated by (tool, bound) so a looping agent does not flood the report.
    requests: BTreeMap<(String, String), AuthorityRequest>,
    /// Egress denials in full, deduplicated by (tool, destination).
    egress_refusals: BTreeMap<(String, String), EgressRefusal>,
    /// The closed destination vocabulary, when a verified catalog was attached.
    vocabulary: Option<Vocabulary>,
    /// Broker decisions made since the last drain, allow and deny alike.
    pending: Vec<PendingDecision>,
    /// host → capability name, for the destinations the current call resolved by name.
    resolved_names: BTreeMap<String, String>,
    /// Second-engine denials, deduplicated by (tool, destination).
    ///
    /// A second map in the same process is not a second telemetry path — see
    /// [`crate::egress::SecondaryRefusal`].
    secondary_refusals: BTreeMap<(String, String), crate::egress::SecondaryRefusal>,
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
            secondary: None,
            observed_tools: BTreeSet::new(),
            requests: BTreeMap::new(),
            egress_refusals: BTreeMap::new(),
            vocabulary: None,
            pending: Vec::new(),
            resolved_names: BTreeMap::new(),
            secondary_refusals: BTreeMap::new(),
        }
    }

    /// Add the second policy engine.
    ///
    /// Deny-only: [`Self::decide`] runs the broker first and returns on its refusal, so the filter
    /// can only add a refusal and can never remove one. Wiring it raises the *engine* count and
    /// leaves the *intercept* count alone, because both engines decide inside this one process at
    /// this one chokepoint. [`crate::egress::INDEPENDENCE_NOTE`] is the sentence that must
    /// accompany the count wherever it is shown.
    #[must_use]
    pub fn with_secondary_filter(mut self, secondary: crate::egress::SecondaryFilter) -> Self {
        self.secondary = Some(secondary);
        self
    }

    /// The second policy engine, when one is wired.
    #[must_use]
    pub fn secondary_filter(&self) -> Option<&crate::egress::SecondaryFilter> {
        self.secondary.as_ref()
    }

    /// The measured independence of this proxy's egress path.
    ///
    /// Reads [`crate::egress::independence`] against the bounds this proxy is enforcing and the
    /// secondary engine it actually holds, so a surface cannot render a count for a configuration
    /// that is not the running one.
    #[must_use]
    pub fn egress_independence(&self) -> crate::egress::Independence {
        crate::egress::independence(&self.bounds, self.secondary.as_ref())
    }

    /// The mode this proxy is enforcing.
    ///
    /// Read by the endpoint when it decides which tools to *publish*: under `Observe` the whole
    /// point is to discover what an agent reaches for, so an upstream's tools are published even
    /// when the warrant does not list them; under `Enforce` a tool the warrant does not allow is
    /// not published at all — the structural version of a refusal rather than the configurable one.
    #[must_use]
    pub const fn mode(&self) -> ProxyMode {
        self.mode
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

    /// Attach the closed destination vocabulary a verified catalog produced.
    #[must_use]
    pub fn with_vocabulary(mut self, vocabulary: Vocabulary) -> Self {
        self.vocabulary = Some(vocabulary);
        self
    }

    /// The vocabulary, when one is attached — read by the endpoint when it publishes schemas.
    #[must_use]
    pub fn vocabulary(&self) -> Option<&Vocabulary> {
        self.vocabulary.as_ref()
    }

    /// The signed bounds this proxy enforces; the catalog is checked against them.
    #[must_use]
    pub fn bounds(&self) -> &WarrantBounds {
        &self.bounds
    }

    /// Rewrite every destination-named argument from a capability name to its catalog URL.
    ///
    /// Under Enforce with a vocabulary, a raw address is refused here, before the broker — the
    /// L4-23 property: the argument has no way to say a host. Observe mode, or no vocabulary,
    /// leaves the call untouched and the host-based broker decides as before.
    pub fn resolve_destinations(&mut self, call: &mut ToolCall) -> Result<(), Decision> {
        self.resolved_names.clear();
        if self.mode != ProxyMode::Enforce {
            return Ok(());
        }
        let Some(vocabulary) = self.vocabulary.clone() else {
            return Ok(());
        };
        for key in DESTINATION_KEYS {
            let Some(value) = call.arguments.get(*key).cloned() else {
                continue;
            };
            let name = value.split_once('/').map_or(value.as_str(), |(n, _)| n);
            match vocabulary.resolve(&value) {
                Ok(url) => {
                    self.resolved_names
                        .insert(host_of(&url).to_string(), name.to_string());
                    call.arguments.insert((*key).to_string(), url);
                }
                Err(reason) => {
                    let destination = crate::egress::Destination {
                        argument: (*key).to_string(),
                        host: host_of(&value).to_string(),
                    };
                    let refusal = EgressRefusal::new(&call.tool, &destination, reason.clone());
                    self.pending.push(PendingDecision {
                        tool: call.tool.clone(),
                        argument: destination.argument.clone(),
                        capability: if reason == crate::egress::DenyReason::NotInCatalog {
                            name.to_string()
                        } else {
                            capability_for(&destination.host)
                        },
                        destination: destination.host.clone(),
                        verdict: EgressVerdict::Deny { reason },
                    });
                    return Err(self.deny_egress(&call.tool, refusal));
                }
            }
        }
        Ok(())
    }

    /// Drain the decisions made since the last drain, stamped for the log.
    pub fn take_egress_decisions(&mut self, warrant_id: &str, at: u64) -> Vec<EgressDecision> {
        let digest = self.vocabulary.as_ref().map(|v| v.digest().to_string());
        std::mem::take(&mut self.pending)
            .into_iter()
            .map(|p| EgressDecision {
                format: crate::egress::DECISION_FORMAT.to_string(),
                warrant_id: warrant_id.to_string(),
                at,
                tool: p.tool,
                argument: p.argument,
                capability: p.capability,
                destination: p.destination,
                verdict: p.verdict,
                catalog_digest: digest.clone(),
            })
            .collect()
    }

    /// Record a second-engine refusal, then deny under the `egress_hosts` bound.
    ///
    /// The bound label is still `"egress_hosts"`: it names the bound that refused, not the engine
    /// that decided. Which engine decided is in the [`crate::egress::SecondaryRefusal`], which is
    /// kept in its own map so an operator sent to fix a refusal is sent to the right configuration
    /// source — the broker reads the signed warrant claims, this engine reads the operator's file.
    fn deny_secondary(&mut self, tool: &str, refusal: crate::egress::SecondaryRefusal) -> Decision {
        let key = (tool.to_string(), refusal.destination.clone());
        let sentence = refusal.sentence();
        self.secondary_refusals
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
            let verdict = self.egress.decide(&destination.host);
            self.pending.push(PendingDecision {
                tool: call.tool.clone(),
                argument: destination.argument.clone(),
                capability: self
                    .resolved_names
                    .get(&destination.host)
                    .cloned()
                    .unwrap_or_else(|| capability_for(&destination.host)),
                destination: destination.host.clone(),
                verdict: verdict.clone(),
            });
            if let EgressVerdict::Deny { reason } = verdict {
                let refusal = EgressRefusal::new(&call.tool, &destination, reason);
                return self.deny_egress(&call.tool, refusal);
            }
            // Second engine, second configuration source, SAME chokepoint.
            //
            // Deny-only, and structurally so: the broker's arm above returns before this runs, so
            // there is no branch here that can turn its `Deny` into a `Forward`. There must never
            // be one -- a warrant bound an operator file could widen is not a bound.
            //
            // This is a second POLICY DOMAIN and not a second boundary. It does not raise
            // `Independence::intercepts`, and no surface may render the engine count as though it
            // were an enforcement count: see `crate::egress::INDEPENDENCE_NOTE`.
            if let Some(secondary) = self.secondary.as_ref() {
                let decision = secondary.decide(&destination.host);
                if decision.action == warrantor_egress_filter::Action::Deny {
                    let refusal =
                        crate::egress::SecondaryRefusal::new(&call.tool, &destination, &decision);
                    return self.deny_secondary(&call.tool, refusal);
                }
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

    /// Second-engine denials with their destination and rule, most frequent first.
    ///
    /// Kept apart from [`Self::egress_refusals`] so a reviewer can tell which evaluator refused, and
    /// therefore which configuration source to go and read.
    #[must_use]
    pub fn secondary_refusals(&self) -> Vec<&crate::egress::SecondaryRefusal> {
        let mut out: Vec<&crate::egress::SecondaryRefusal> =
            self.secondary_refusals.values().collect();
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

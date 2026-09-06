//! Task 7.4 (L4-13, L4-14, L4-26): the three adapters that can rewrite the substrate governing
//! them, and the one predicate all three refuse through.
//!
//! # Why these three are grouped, and routed away from volume work
//!
//! A cloud control-plane adapter can change the network policy that Task 7.1's deny floor depends
//! on. A CI/CD adapter can edit the workflow that runs the gates. An identity-provider adapter can
//! grant the entitlement that authorized the call. Each is a `MUTATE`-class surface whose target
//! may be the thing that governs the agent using it: **an agent with any of these governs its own
//! governor.** Every other adapter in the catalog mutates something the warrant is *about*; these
//! can mutate the warrant's own preconditions.
//!
//! # The predicate, and the rule it inherits
//!
//! [`governs_its_own_governor`] answers one question: is the target of this effect part of the
//! substrate that governs the agent making it? It answers from an [`OwnSubstrate`] the caller
//! DECLARES — the policy names that authorized the warrant, the workflow paths that run the gates,
//! the entitlement ids and principals the session runs as. Nothing here infers ownership from a
//! name's shape. That is Task 2.1's rule and Task 7.6's, applied a third time for the same reason:
//! a guess would under-govern exactly where it matters.
//!
//! The corollary is that a caller who declares nothing has an adapter that mutates nothing. An
//! empty [`OwnSubstrate`] refuses every substrate-mutating effect, with a sentence saying why. An
//! adapter that cannot tell what is its own must not be allowed to find out by doing it.
//!
//! # What these adapters are, and are not
//!
//! They are the governance shape: the tools each offers, the decomposition each declares against
//! Task 2.1's vocabulary, the predicate each applies before anything else, and the outcome each
//! returns. Mutations are **staged**, never performed here — a `MUTATE` effect is a handle a
//! settle can redeem, which is the staging doctrine the rest of this crate lives by. Reads go
//! through a [`SubstrateTransport`] the caller supplies, in the pattern of
//! [`crate::adapters::github`]. No transport ships in this module: nothing here holds a
//! credential (Phase 3 owns the vault) and nothing here talks to a cloud, a CI system, or an
//! identity provider. Tasks 7.3 and 7.5 transcribe this shape onto real services.
//!
//! # Bound strength, in the words the product must use
//!
//! **Tier B, chokepoint.** Each adapter refuses at its own call site, so the bound holds only for
//! calls that go through the adapter. An agent with a shell and the cloud CLI bypasses all three.
//! And as of this commit, nothing in the shipping binary dispatches an [`EffectAdapter`] at all,
//! so the refusal has no shipping caller: it is a tested mechanism with no path to it. The
//! evidence file says both.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::effect_sdk::{AdapterOutcome, EffectAdapter, EffectGrant};
use crate::effects::Syscall;

/// What the caller declares to be the substrate that governs this session.
///
/// Every field is a set of identifiers the caller states, in the identifier space of the service
/// the adapter fronts. None is inferred.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnSubstrate {
    /// The policies whose evaluation authorized this warrant, by name.
    pub policy_names: BTreeSet<String>,
    /// The workflow files that run this repository's gates, by path.
    pub workflow_paths: BTreeSet<String>,
    /// The entitlements this session holds, by id.
    pub entitlement_ids: BTreeSet<String>,
    /// The principals this session runs as.
    pub principals: BTreeSet<String>,
}

impl OwnSubstrate {
    /// True when the caller declared nothing at all. Such an adapter refuses every mutation.
    #[must_use]
    pub fn declares_nothing(&self) -> bool {
        self.policy_names.is_empty()
            && self.workflow_paths.is_empty()
            && self.entitlement_ids.is_empty()
            && self.principals.is_empty()
    }
}

/// The target of a substrate-mutating effect, as the adapter read it from the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstrateTarget<'a> {
    /// A named policy.
    Policy(&'a str),
    /// A workflow file, by path.
    Workflow(&'a str),
    /// An entitlement being granted to a principal.
    Entitlement {
        /// The entitlement id.
        entitlement: &'a str,
        /// Who would receive it.
        principal: &'a str,
    },
}

/// Why a substrate-mutating effect was refused. `render` is the sentence the caller reads, and it
/// is built from these fields rather than written beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfGovernanceRefusal {
    /// The target, as the call named it.
    pub target: String,
    /// Which part of the declared substrate it matched, or that nothing was declared.
    pub matched: &'static str,
}

impl SelfGovernanceRefusal {
    /// The operator-facing sentence, derived from the record.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "refused: this effect would let the agent govern its own governor. Target {:?} is {}. \
             A bound that its subject can rewrite is not a bound; the change has to come from \
             outside the warrant that depends on it.",
            self.target, self.matched
        )
    }
}

/// The predicate. `None` means the target is not part of the declared substrate.
#[must_use]
pub fn governs_its_own_governor(
    own: &OwnSubstrate,
    target: SubstrateTarget<'_>,
) -> Option<SelfGovernanceRefusal> {
    if own.declares_nothing() {
        return Some(SelfGovernanceRefusal {
            target: describe(target),
            matched: "undecidable because the caller declared no substrate at all, so every \
                      substrate-mutating effect is refused rather than one being guessed safe",
        });
    }
    match target {
        SubstrateTarget::Policy(name) if own.policy_names.contains(name) => {
            Some(SelfGovernanceRefusal {
                target: name.to_string(),
                matched: "the policy that authorized this warrant",
            })
        }
        SubstrateTarget::Workflow(path) if own.workflow_paths.contains(path) => {
            Some(SelfGovernanceRefusal {
                target: path.to_string(),
                matched: "the workflow that runs the gates this repository is merged through",
            })
        }
        SubstrateTarget::Entitlement {
            entitlement,
            principal,
        } => {
            if own.entitlement_ids.contains(entitlement) {
                Some(SelfGovernanceRefusal {
                    target: entitlement.to_string(),
                    matched: "the entitlement this session used to be here",
                })
            } else if own.principals.contains(principal) {
                Some(SelfGovernanceRefusal {
                    target: principal.to_string(),
                    matched: "this session's own principal, which may not widen its own \
                              entitlements",
                })
            } else {
                None
            }
        }
        SubstrateTarget::Policy(_) | SubstrateTarget::Workflow(_) => None,
    }
}

fn describe(target: SubstrateTarget<'_>) -> String {
    match target {
        SubstrateTarget::Policy(name) => format!("policy {name}"),
        SubstrateTarget::Workflow(path) => format!("workflow {path}"),
        SubstrateTarget::Entitlement {
            entitlement,
            principal,
        } => format!("entitlement {entitlement} for {principal}"),
    }
}

/// The read side of an adapter: whatever answers a non-mutating tool. Supplied by the caller;
/// nothing in this module implements it against a real service.
pub trait SubstrateTransport {
    /// Answer one read-only tool with receipt fields, or say why it could not.
    ///
    /// # Errors
    /// The transport's own reason, which becomes the adapter's refusal.
    fn read(
        &mut self,
        tool: &str,
        arguments: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, String>, String>;
}

/// Pull one string argument or say which one was missing. A substrate mutation with no named
/// target is refused, never defaulted.
fn string_argument<'a>(
    arguments: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, AdapterOutcome> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AdapterOutcome::Refused {
            reason: format!(
                "refused: argument {key:?} is missing or not a non-empty string, and a substrate \
                 mutation with no named target is not guessed"
            ),
        })
}

fn staged(tool: &str, target: &str) -> AdapterOutcome {
    AdapterOutcome::Staged {
        handle: format!(
            "stg_{}_{}",
            tool.replace('.', "_"),
            target.replace(['/', ':'], "_")
        ),
    }
}

fn read_through<T: SubstrateTransport>(
    transport: &mut T,
    tool: &str,
    arguments: &BTreeMap<String, Value>,
) -> AdapterOutcome {
    match transport.read(tool, arguments) {
        Ok(receipt_fields) => AdapterOutcome::Performed { receipt_fields },
        Err(reason) => AdapterOutcome::Refused {
            reason: format!("refused: the transport could not answer {tool}: {reason}"),
        },
    }
}

fn verbs(list: &[Syscall]) -> BTreeSet<Syscall> {
    list.iter().copied().collect()
}

// ───────────────────────── cloud control plane (L4-13) ─────────────────────────

/// Tool: apply a network policy. `MUTATE` over the network.
pub const CLOUD_APPLY_NETWORK_POLICY: &str = "cloud.apply_network_policy";
/// Tool: describe a policy. A read.
pub const CLOUD_DESCRIBE_POLICY: &str = "cloud.describe_policy";

/// The cloud control-plane adapter. Its one mutation can rewrite the network policy that Task 7.1's
/// deny floor depends on, so that mutation is refused when the policy is one the caller declared
/// as their own.
#[derive(Debug)]
pub struct CloudControlPlaneAdapter<T: SubstrateTransport> {
    own: OwnSubstrate,
    transport: T,
}

impl<T: SubstrateTransport> CloudControlPlaneAdapter<T> {
    /// Build with the declared substrate and a transport for reads.
    pub fn new(own: OwnSubstrate, transport: T) -> Self {
        Self { own, transport }
    }
}

impl<T: SubstrateTransport> EffectAdapter for CloudControlPlaneAdapter<T> {
    fn adapter_name(&self) -> &str {
        "cloud-control-plane"
    }
    fn tools(&self) -> Vec<String> {
        vec![
            CLOUD_APPLY_NETWORK_POLICY.to_string(),
            CLOUD_DESCRIBE_POLICY.to_string(),
        ]
    }
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>> {
        match tool {
            CLOUD_APPLY_NETWORK_POLICY => Some(verbs(&[Syscall::Net, Syscall::Mutate])),
            CLOUD_DESCRIBE_POLICY => Some(verbs(&[Syscall::Net])),
            _ => None,
        }
    }
    fn invoke(
        &mut self,
        tool: &str,
        arguments: &BTreeMap<String, Value>,
        _grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        match tool {
            CLOUD_APPLY_NETWORK_POLICY => {
                let policy = match string_argument(arguments, "policy_name") {
                    Ok(v) => v,
                    Err(refused) => return refused,
                };
                if let Some(refusal) =
                    governs_its_own_governor(&self.own, SubstrateTarget::Policy(policy))
                {
                    return AdapterOutcome::Refused {
                        reason: refusal.render(),
                    };
                }
                staged(tool, policy)
            }
            CLOUD_DESCRIBE_POLICY => read_through(&mut self.transport, tool, arguments),
            other => AdapterOutcome::Refused {
                reason: format!("refused: {other:?} is not a tool this adapter offers"),
            },
        }
    }
}

// ───────────────────────── CI/CD (L4-14) ─────────────────────────

/// Tool: edit a workflow file. `MUTATE` over the network.
pub const CICD_EDIT_WORKFLOW: &str = "cicd.edit_workflow";
/// Tool: trigger a workflow run. `EXEC` over the network — running the gates is not editing them.
pub const CICD_TRIGGER_RUN: &str = "cicd.trigger_run";
/// Tool: read a workflow file. A read.
pub const CICD_READ_WORKFLOW: &str = "cicd.read_workflow";

/// The CI/CD adapter. Editing the workflow that runs the gates is refused; triggering it is not,
/// because running the gates is the opposite of escaping them.
#[derive(Debug)]
pub struct CiCdAdapter<T: SubstrateTransport> {
    own: OwnSubstrate,
    transport: T,
}

impl<T: SubstrateTransport> CiCdAdapter<T> {
    /// Build with the declared substrate and a transport for reads.
    pub fn new(own: OwnSubstrate, transport: T) -> Self {
        Self { own, transport }
    }
}

impl<T: SubstrateTransport> EffectAdapter for CiCdAdapter<T> {
    fn adapter_name(&self) -> &str {
        "ci-cd"
    }
    fn tools(&self) -> Vec<String> {
        vec![
            CICD_EDIT_WORKFLOW.to_string(),
            CICD_TRIGGER_RUN.to_string(),
            CICD_READ_WORKFLOW.to_string(),
        ]
    }
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>> {
        match tool {
            CICD_EDIT_WORKFLOW => Some(verbs(&[Syscall::Net, Syscall::Mutate])),
            CICD_TRIGGER_RUN => Some(verbs(&[Syscall::Net, Syscall::Exec])),
            CICD_READ_WORKFLOW => Some(verbs(&[Syscall::Net])),
            _ => None,
        }
    }
    fn invoke(
        &mut self,
        tool: &str,
        arguments: &BTreeMap<String, Value>,
        _grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        match tool {
            CICD_EDIT_WORKFLOW => {
                let path = match string_argument(arguments, "workflow_path") {
                    Ok(v) => v,
                    Err(refused) => return refused,
                };
                if let Some(refusal) =
                    governs_its_own_governor(&self.own, SubstrateTarget::Workflow(path))
                {
                    return AdapterOutcome::Refused {
                        reason: refusal.render(),
                    };
                }
                staged(tool, path)
            }
            CICD_TRIGGER_RUN => {
                // Deliberately NOT through the predicate: running the gate workflow is what a
                // governed agent should do. Only editing it is self-governance.
                let path = match string_argument(arguments, "workflow_path") {
                    Ok(v) => v,
                    Err(refused) => return refused,
                };
                staged(tool, path)
            }
            CICD_READ_WORKFLOW => read_through(&mut self.transport, tool, arguments),
            other => AdapterOutcome::Refused {
                reason: format!("refused: {other:?} is not a tool this adapter offers"),
            },
        }
    }
}

// ───────────────────────── identity provider (L4-26) ─────────────────────────

/// Tool: grant an entitlement to a principal. `CRED` and `MUTATE` over the network — an
/// entitlement change is a credential change.
pub const IDP_GRANT_ENTITLEMENT: &str = "idp.grant_entitlement";
/// Tool: list a principal's entitlements. A read.
pub const IDP_LIST_ENTITLEMENTS: &str = "idp.list_entitlements";

/// The identity-provider adapter. Granting the entitlement this session used, or granting anything
/// to this session's own principal, is refused.
#[derive(Debug)]
pub struct IdentityProviderAdapter<T: SubstrateTransport> {
    own: OwnSubstrate,
    transport: T,
}

impl<T: SubstrateTransport> IdentityProviderAdapter<T> {
    /// Build with the declared substrate and a transport for reads.
    pub fn new(own: OwnSubstrate, transport: T) -> Self {
        Self { own, transport }
    }
}

impl<T: SubstrateTransport> EffectAdapter for IdentityProviderAdapter<T> {
    fn adapter_name(&self) -> &str {
        "identity-provider"
    }
    fn tools(&self) -> Vec<String> {
        vec![
            IDP_GRANT_ENTITLEMENT.to_string(),
            IDP_LIST_ENTITLEMENTS.to_string(),
        ]
    }
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>> {
        match tool {
            IDP_GRANT_ENTITLEMENT => Some(verbs(&[Syscall::Net, Syscall::Cred, Syscall::Mutate])),
            IDP_LIST_ENTITLEMENTS => Some(verbs(&[Syscall::Net])),
            _ => None,
        }
    }
    fn invoke(
        &mut self,
        tool: &str,
        arguments: &BTreeMap<String, Value>,
        _grant: &EffectGrant<'_>,
    ) -> AdapterOutcome {
        match tool {
            IDP_GRANT_ENTITLEMENT => {
                let entitlement = match string_argument(arguments, "entitlement_id") {
                    Ok(v) => v,
                    Err(refused) => return refused,
                };
                let principal = match string_argument(arguments, "principal") {
                    Ok(v) => v,
                    Err(refused) => return refused,
                };
                if let Some(refusal) = governs_its_own_governor(
                    &self.own,
                    SubstrateTarget::Entitlement {
                        entitlement,
                        principal,
                    },
                ) {
                    return AdapterOutcome::Refused {
                        reason: refusal.render(),
                    };
                }
                staged(tool, &format!("{entitlement}_{principal}"))
            }
            IDP_LIST_ENTITLEMENTS => read_through(&mut self.transport, tool, arguments),
            other => AdapterOutcome::Refused {
                reason: format!("refused: {other:?} is not a tool this adapter offers"),
            },
        }
    }
}

/// The sentence the product renders about this bound. It names what escapes.
pub const SHELL_BYPASS_SENTENCE: &str =
    "The cloud, CI/CD and identity-provider adapters refuse an effect whose target is the substrate \
     that governs the agent: the policy that authorized its warrant, the workflow that runs the \
     gates, the entitlement it used or its own principal. That refusal happens at the adapter's own \
     call site and binds only calls that go through the adapter. An agent with a shell and the cloud \
     CLI bypasses all three. Nothing in this repository is a network policy or an admission \
     controller, and nothing in the shipping binary dispatches these adapters yet.";

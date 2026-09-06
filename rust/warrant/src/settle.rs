//! W6 — the settle and void engine.
//!
//! Settling is the only moment the outside world changes. Everything before it happened inside a
//! worktree nobody else can see, or sat in a queue as an intent. So this module is where the
//! warrant's promise is either kept or honestly broken.
//!
//! # Partial failure: stop, hold, report
//!
//! Effect 3 of 5 fails. Two things are now real in the world and three are not. There are two
//! honest options and one dishonest one:
//!
//! * **Compensate** — try to undo effects 1 and 2. Rejected: compensation is itself fallible, and
//!   a failed undo leaves a state strictly worse than stopping. Worse, offering it would imply an
//!   all-or-nothing guarantee across systems we do not control and cannot deliver.
//! * **Stop, hold, report** — halt at the failure, leave 1–2 applied and 4–5 unreleased, and state
//!   the exact boundary. Chosen. It promises only what is true.
//! * Pretend it succeeded. Not an option.
//!
//! What makes stopping *safe* is the release order: effects are released in topological order, so
//! any prefix is a coherent state. A pull request can exist without its comment. A comment can
//! never exist without its pull request.
//!
//! # Who may settle
//!
//! Not the agent. [`crate::Warrant::verify_settle`] is checked before anything is released, and it
//! compares against a key named inside the *signed* claims — so an agent cannot rewrite the
//! authority and present its own key either.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use ed25519_dalek::{SigningKey, VerifyingKey};
use warrantor_evidence as evidence;
use warrantor_notary as notary;

use crate::report::{
    bounds_policy_digest, gate_name, report_modes, sha256_hex, warrant_authority,
    FRESHNESS_WINDOW_SECONDS,
};
use crate::staging::{StagedEffect, StagingQueue};
use crate::worktree::Worktree;
use crate::{Warrant, WarrantError, WarrantState};

/// Performs a staged effect for real.
///
/// Implemented by an adapter per effect family (GitHub, HTTP, …). The daemon holds the
/// credentials and calls this; the agent never sees a secret, because by the time this runs the
/// agent is not part of the picture at all.
pub trait EffectPerformer {
    /// Perform `effect`, resolving any handles it depends on via `resolved`.
    ///
    /// `resolved` maps a staged handle to the real identifier the earlier release produced, so a
    /// comment attaches to the pull request that now genuinely exists.
    ///
    /// # Errors
    /// Any string describing why it could not be performed. The engine stops on the first error
    /// and reports the boundary; it does not retry or compensate.
    fn perform(
        &mut self,
        effect: &StagedEffect,
        resolved: &BTreeMap<String, String>,
    ) -> Result<String, String>;
}

/// The method every per-effect receipt records. An effect is only ever performed by settle.
pub const EFFECT_METHOD: &str = "settle";

/// Where a receipt becomes durable. `Ok` means "on stable storage"; the performer acts on it.
pub trait ReceiptSink {
    /// Persist `receipt` before returning.
    ///
    /// # Errors
    /// Any string. A failed pre-commit record means the effect is NOT performed (I-07); a failed
    /// post-commit record is reported by [`EvidencedPerformer::unrecorded`].
    fn record(&mut self, receipt: &evidence::WarReceipt) -> Result<(), String>;
}

/// Everything needed to decide and sign for one warrant's effects, captured before settle takes
/// the warrant mutably.
///
/// Owned, not borrowed: `settle` holds `&mut Warrant` for the whole release loop, and a witness
/// borrowing the same warrant would not compile. The clone is the signed claims, which do not
/// change during a settle; the state is read once, because settle has already checked it is
/// `Open` or `Held` before the first `perform`.
#[derive(Debug, Clone)]
pub struct EffectWitness {
    warrant: Warrant,
    signature_verified: bool,
    signer: SigningKey,
    key_id: String,
    contained_scopes: Vec<String>,
    now: u64,
}

impl EffectWitness {
    /// Capture the warrant, verify its signature against `issuer` once (the chain gate's input),
    /// and hold the key the receipts are signed with.
    #[must_use]
    pub fn for_warrant(
        warrant: &Warrant,
        issuer: &VerifyingKey,
        signer: &SigningKey,
        key_id: &str,
        contained_scopes: Vec<String>,
        now: u64,
    ) -> Self {
        Self {
            warrant: warrant.clone(),
            // Verified at t=0 so expiry is the identity gate's finding, not the chain gate's --
            // the same split `report::build_observed` makes.
            signature_verified: warrant.verify(issuer, 0).is_ok(),
            signer: signer.clone(),
            key_id: key_id.to_string(),
            contained_scopes,
            now,
        }
    }

    /// The notary's question about one effect: does this warrant hold `effect.tool` right now?
    #[must_use]
    pub fn verdict_request(
        &self,
        effect: &StagedEffect,
        effect_digest: &str,
    ) -> notary::VerdictRequest {
        let claims = &self.warrant.claims;
        let tools: Vec<String> = claims.bounds.tools.iter().cloned().collect();
        notary::VerdictRequest {
            actor: notary::Actor {
                svid: claims.subject.clone(),
                svid_not_after: claims.bounds.expires_at,
                own_capabilities: tools.clone(),
                delegation_chain: vec![notary::DelegationLink {
                    delegatee_svid: claims.subject.clone(),
                    capabilities: tools,
                    not_before: claims.issued_at,
                    not_after: claims.bounds.expires_at,
                    signature_verified: self.signature_verified,
                }],
            },
            operation: notary::Operation {
                class: effect.tool.clone(),
                capabilities_requested: vec![effect.tool.clone()],
                // Irreversible in the world, so never `Routine`; not `Critical`, because the
                // approval gate is `operators::ApprovalPolicy`'s job on both surfaces and it has
                // already run by the time settle performs.
                consequence_tier: notary::ConsequenceTier::Elevated,
                scope: claims.id.clone(),
            },
            artifacts: Vec::new(),
            nonce: format!(
                "{}:{}:{}:{effect_digest}",
                claims.id, effect.handle, self.now
            ),
            timestamp: self.now,
            approval: None,
        }
    }

    /// The context the verdict is taken in. Same inputs, same caveats as the report's.
    #[must_use]
    pub fn verdict_context(&self) -> notary::VerdictContext {
        notary::VerdictContext {
            now: self.now,
            contained_scopes: self.contained_scopes.clone(),
            revoked_svids: Vec::new(),
            seen_nonces: Vec::new(),
            freshness_window_seconds: FRESHNESS_WINDOW_SECONDS,
            verified_artifacts: Vec::new(),
            budget_remaining: self
                .warrant
                .claims
                .bounds
                .expires_at
                .saturating_sub(self.now),
            policy_decision: matches!(self.warrant.state, WarrantState::Open | WarrantState::Held),
        }
    }

    /// The pre-commit predicate for one effect: no outcome, phase `PreCommit`, advisory.
    #[must_use]
    pub fn pre_commit_predicate(
        &self,
        effect: &StagedEffect,
        effect_digest: &str,
        nonce: &str,
    ) -> evidence::WarPredicate {
        let claims = &self.warrant.claims;
        let (mode, _) = report_modes();
        evidence::WarPredicate {
            // A per-effect receipt covers ONE hop, so it carries no route and stays v1. Handing it
            // a one-element `causality` section would let `causal_verdict` return `Ok` over a
            // record that holds no ordering at all -- a pass that means nothing. The causal section
            // belongs on the report receipt, which reads the whole queue.
            predicate_version: None,
            causality: None,
            binding: evidence::Binding {
                receipt_id: sha256_hex(
                    format!(
                        "{}\u{1f}{}\u{1f}{effect_digest}\u{1f}{nonce}",
                        claims.id, effect.handle
                    )
                    .as_bytes(),
                ),
                phase: evidence::Phase::PreCommit,
                parent_receipt: None,
                nonce: nonce.to_string(),
                issued_at: self.now,
                expires_at: claims.bounds.expires_at,
                enforcement_mode: mode,
            },
            actor: evidence::Actor {
                principal: claims.subject.clone(),
                workload_id: claims.subject.clone(),
                svid_digest: format!("sha256:{}", sha256_hex(claims.subject.as_bytes())),
            },
            authority: warrant_authority(&self.warrant),
            decision: evidence::Decision {
                verdict: evidence::Verdict::Allow,
                engine: notary::NOTARY_VERSION.to_string(),
                policy_digest: bounds_policy_digest(&claims.bounds),
                evaluated_at: self.now,
            },
            operation: evidence::Operation {
                class: effect.tool.clone(),
                target: effect.handle.clone(),
                method: EFFECT_METHOD.to_string(),
                parameters_digest: format!("sha256:{effect_digest}"),
                reversible: false,
                consequence_tier: evidence::ConsequenceTier::Elevated,
            },
            outcome: None,
        }
    }
}

/// Wraps the performer a surface already builds so that, for every effect, the notary decides,
/// a pre-commit receipt is durable before the inner performer runs, and a post-commit receipt
/// carrying the outcome follows it.
///
/// A wrapper rather than a change to [`settle`]: the side effect happens inside `perform`, so
/// that is where the receipt has to precede it, and every surface (CLI, HTTP, MCP) keeps calling
/// [`settle`] with the signature it has.
pub struct EvidencedPerformer<'a> {
    inner: &'a mut dyn EffectPerformer,
    sink: &'a mut dyn ReceiptSink,
    witness: EffectWitness,
    issued: Vec<evidence::WarReceipt>,
    unrecorded: Vec<String>,
}

impl<'a> EvidencedPerformer<'a> {
    /// Wrap `inner`, writing receipts to `sink`.
    pub fn new(
        inner: &'a mut dyn EffectPerformer,
        witness: EffectWitness,
        sink: &'a mut dyn ReceiptSink,
    ) -> Self {
        Self {
            inner,
            sink,
            witness,
            issued: Vec::new(),
            unrecorded: Vec::new(),
        }
    }

    /// Every receipt issued during this settle, in order.
    #[must_use]
    pub fn issued(&self) -> &[evidence::WarReceipt] {
        &self.issued
    }

    /// Post-commit receipts that were issued but could not be made durable, one sentence each.
    /// The effect they describe DID happen; the caller prints these rather than hiding them.
    #[must_use]
    pub fn unrecorded(&self) -> &[String] {
        &self.unrecorded
    }
}

impl EffectPerformer for EvidencedPerformer<'_> {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        let digest = crate::staging::effect_digest(effect).map_err(|e| e.to_string())?;
        let request = self.witness.verdict_request(effect, &digest);
        let context = self.witness.verdict_context();
        if let notary::Verdict::Deny { gate } = notary::verdict(&request, &context) {
            // Only the gate. The notary's rule, kept: nothing here names the missing capability.
            return Err(format!(
                "refused by the notary at the {} gate; nothing was performed",
                gate_name(gate)
            ));
        }
        let predicate = self
            .witness
            .pre_commit_predicate(effect, &digest, &request.nonce);
        let pre = evidence::issue_pre_commit(predicate, &self.witness.signer, &self.witness.key_id);
        self.sink.record(&pre).map_err(|e| {
            format!(
                "the pre-commit receipt could not be made durable, so the effect was not \
                 performed (I-07): {e}"
            )
        })?;
        self.issued.push(pre.clone());

        let performed = self.inner.perform(effect, resolved);

        let outcome = match &performed {
            Ok(real_id) => evidence::Outcome {
                status: "success".to_string(),
                outcome_digest: format!("sha256:{}", sha256_hex(real_id.as_bytes())),
                effects: vec![real_id.clone()],
                error: None,
                rollback_pointer: None,
            },
            Err(reason) => evidence::Outcome {
                status: "failed".to_string(),
                outcome_digest: format!("sha256:{}", sha256_hex(reason.as_bytes())),
                effects: Vec::new(),
                error: Some(reason.clone()),
                rollback_pointer: None,
            },
        };
        let post =
            evidence::issue_post_commit(&pre, outcome, &self.witness.signer, &self.witness.key_id);
        if let Err(e) = self.sink.record(&post) {
            self.unrecorded.push(format!(
                "{} was performed and its post-commit receipt could not be recorded: {e}",
                effect.handle
            ));
        }
        self.issued.push(post);
        performed
    }
}

/// What happened to one effect during a settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum EffectOutcome {
    /// Performed. `real_id` is what the world now calls it.
    Released {
        /// The staged handle.
        handle: String,
        /// The identifier the real system assigned.
        real_id: String,
    },
    /// Attempted and failed. The settle stops here.
    Failed {
        /// The staged handle.
        handle: String,
        /// Why.
        reason: String,
    },
    /// Never attempted, because an earlier effect failed.
    Unreleased {
        /// The staged handle.
        handle: String,
    },
}

/// The result of settling a warrant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleReport {
    /// Warrant that was settled.
    pub warrant_id: String,
    /// Per-effect outcomes, in release order.
    pub effects: Vec<EffectOutcome>,
    /// Whether every effect was released.
    pub complete: bool,
    /// Whether the worktree was merged.
    pub worktree_merged: bool,
    /// Present when the settle stopped early: the exact boundary between what is real and what
    /// is not.
    pub boundary: Option<String>,
}

impl SettleReport {
    /// Effects that were actually performed.
    #[must_use]
    pub fn released(&self) -> usize {
        self.effects
            .iter()
            .filter(|e| matches!(e, EffectOutcome::Released { .. }))
            .count()
    }
}

/// Settle a warrant: release its staged effects in order, then merge its worktree.
///
/// Effects are released *before* the merge deliberately. If an external effect fails, the local
/// work stays unmerged and reviewable, rather than landing in the base branch alongside a
/// half-applied set of external changes.
///
/// # Errors
/// [`WarrantError::NotSettleAuthority`] if `presented` is not the warrant's settle authority,
/// [`WarrantError::WrongState`] if it is not open or held, or [`WarrantError::Invalid`] if the
/// release order cannot be computed.
pub fn settle(
    warrant: &mut Warrant,
    queue: &StagingQueue,
    worktree: Option<&Worktree>,
    presented: &ed25519_dalek::VerifyingKey,
    performer: &mut dyn EffectPerformer,
) -> Result<SettleReport, WarrantError> {
    // Authority first: nothing is released, and no state changes, until this passes.
    warrant.verify_settle(presented)?;
    if !matches!(warrant.state, WarrantState::Open | WarrantState::Held) {
        return Err(WarrantError::WrongState {
            state: warrant.state,
            operation: "settle",
        });
    }

    let order = queue.release_order()?;
    let mut resolved: BTreeMap<String, String> = BTreeMap::new();
    let mut outcomes: Vec<EffectOutcome> = Vec::new();
    let mut boundary = None;
    let mut stopped = false;

    for effect in order {
        if stopped {
            outcomes.push(EffectOutcome::Unreleased {
                handle: effect.handle.clone(),
            });
            continue;
        }
        match performer.perform(effect, &resolved) {
            Ok(real_id) => {
                resolved.insert(effect.handle.clone(), real_id.clone());
                outcomes.push(EffectOutcome::Released {
                    handle: effect.handle.clone(),
                    real_id,
                });
            }
            Err(reason) => {
                boundary = Some(format!(
                    "stopped at {} ({}): {reason}. Effects before it are real; effects after it \
                     were not attempted.",
                    effect.handle, effect.tool
                ));
                outcomes.push(EffectOutcome::Failed {
                    handle: effect.handle.clone(),
                    reason,
                });
                stopped = true;
            }
        }
    }

    let complete = !stopped;
    let mut worktree_merged = false;
    if complete {
        if let Some(tree) = worktree {
            tree.merge_into_base(&format!(
                "warrant {}: {}",
                warrant.claims.id, warrant.claims.goal
            ))?;
            worktree_merged = true;
        }
        warrant.transition(WarrantState::Settled)?;
    } else {
        // A partial settle does not reach a terminal state: there is still a decision to make
        // about the effects that were not attempted, and about the unmerged local work.
        warrant.transition(WarrantState::Held)?;
    }

    Ok(SettleReport {
        warrant_id: warrant.claims.id.clone(),
        effects: outcomes,
        complete,
        worktree_merged,
        boundary,
    })
}

/// Void a warrant: discard every staged effect and delete the worktree.
///
/// The receipts and the staged-effect log survive. What the agent *attempted* is evidence — it is
/// how a developer learns the warrant was scoped wrongly, or that the agent tried something it
/// should not have — and destroying it because the work was discarded would throw away the most
/// informative part of the run.
///
/// # Errors
/// [`WarrantError::NotSettleAuthority`] if `presented` is not the settle authority, or
/// [`WarrantError::WrongState`] if the warrant is already terminal.
pub fn void(
    warrant: &mut Warrant,
    worktree: Option<&Worktree>,
    presented: &ed25519_dalek::VerifyingKey,
) -> Result<(), WarrantError> {
    warrant.verify_settle(presented)?;
    if !matches!(warrant.state, WarrantState::Open | WarrantState::Held) {
        return Err(WarrantError::WrongState {
            state: warrant.state,
            operation: "void",
        });
    }
    if let Some(tree) = worktree {
        tree.remove()?;
    }
    warrant.transition(WarrantState::Void)
}

/// Void a warrant because it breached, without requiring the settle authority.
///
/// A breach is detected by the supervising process at 3am, when no human is present to sign
/// anything. Requiring the settle key here would mean a breached warrant stayed open until
/// morning, with its staged effects intact — the opposite of the guarantee.
///
/// Safe to allow without authority because voiding only ever *destroys* pending work: it cannot
/// release anything, so an attacker who could trigger it gains nothing beyond denial of service
/// against a run that was already halting.
///
/// # Errors
/// [`WarrantError::WrongState`] if the warrant is already terminal.
pub fn void_on_breach(
    warrant: &mut Warrant,
    worktree: Option<&Worktree>,
    reason: &str,
) -> Result<String, WarrantError> {
    if !matches!(warrant.state, WarrantState::Open | WarrantState::Held) {
        return Err(WarrantError::WrongState {
            state: warrant.state,
            operation: "void_on_breach",
        });
    }
    if let Some(tree) = worktree {
        tree.remove()?;
    }
    warrant.transition(WarrantState::Void)?;
    Ok(format!(
        "warrant {} voided on breach: {reason}. Staged effects discarded; receipts retained.",
        warrant.claims.id
    ))
}

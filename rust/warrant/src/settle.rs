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

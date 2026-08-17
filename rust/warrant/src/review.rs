//! What is waiting on a human, who it is waiting on, and when nobody can move it.
//!
//! # The gap this closes
//!
//! [`crate::operators`] built every part of a review except the part where somebody finds out. An
//! operator holding the `approve` scope can record an approval, the settle gate reads it, and the
//! custody view renders it — but all of that assumes the operator already knew the warrant existed
//! and needed them. Nothing told them. `notify.json` fires on `settled`, `voided`, `stopped` and
//! `filing-queued`: four events that are all *after* a decision, and none that says one is wanted.
//!
//! That is the [[wire before widen]] shape for the third time in this repository, and it is the
//! reason `docs/W1-delivery-gaps.md` calls §2.1 "the one that decides whether this is a product":
//! multi-user oversight is the claim, and a review nobody can be told about is not oversight.
//!
//! # Derived, never stored
//!
//! The queue is computed from four things the store already holds — the warrant's state, the
//! approval policy, the warrant's actor log, and the operator registry. There is no `queue.json`.
//!
//! That is a deliberate trade against the obvious design. A written queue is a second copy of the
//! truth, and every second copy in this codebase has eventually disagreed with the first: the
//! staged-chain witness exists *because* a lazily-created log could not be told from a deleted one,
//! and `StoredWarrant::base_commit` is persisted *because* derived state that cannot be re-derived
//! has to be. Here the state can always be re-derived, and re-deriving it costs one file read per
//! outstanding warrant. A queue file could say a warrant is waiting after it was settled by another
//! process; this cannot.
//!
//! The one fact that genuinely must be written down is **whether a notification has already gone
//! out**, because that is not derivable from anything else and without it every poll re-notifies.
//! It lives in `reviews/<id>.json`, is one line, and carries no authority: losing it costs a
//! duplicate notification, never a missed decision.
//!
//! # The deadlock check, and why it is a first-class answer
//!
//! A store can be configured into a policy no set of people can satisfy — `required: 2` with one
//! registered approver, or `required: 1` with `settler_may_approve: false` and exactly one person
//! holding both scopes. Every such warrant sits in the queue forever, and the failure is invisible:
//! `approval_verdict` refuses each settle attempt with a sentence about what is missing, which reads
//! as "not yet" rather than "not ever".
//!
//! [`Blocker::Deadlocked`] separates those. It is the difference between a queue that is moving
//! slowly and a queue that has stopped, and it is the only one of the two an operator can act on.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::operators::{approvers, ActorRecord, ApprovalPolicy, Operator, OperatorRegistry, Scope};

/// The wire format of a recorded review request.
pub const REVIEW_FORMAT: &str = "warrantor.review-request/1";

/// The notification event this module raises.
///
/// Named as a request rather than a state so a receiver reading a webhook payload can tell it from
/// the four that report a decision already taken.
pub const REVIEW_EVENT: &str = "review-requested";

/// Why a warrant is not moving.
///
/// Ordered by how much a reader can do about it: the first is a decision somebody can take right
/// now, the second is a decision waiting on named people, and the third cannot be taken by anybody
/// until the policy or the registry changes.
///
/// # Why the wire form is `kebab-case`
///
/// `kebab-case`, not the `snake_case` the rest of this crate's payloads use, because these variants
/// are also rendered by [`Blocker::word`] — which feeds the `counts` map in the same JSON object.
/// The first live request returned `"blocker":"awaiting_approval"` inside an entry and
/// `"awaiting-approval"` as its count key: two spellings of one word in one payload, where a client
/// keying off either one silently misses the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "blocker", rename_all = "kebab-case")]
pub enum Blocker {
    /// Every approval this store requires is recorded. It is waiting on somebody to settle or void.
    AwaitingDecision {
        /// Who has approved so far, named. `None` inside the list is the unnamed session principal.
        approved_by: Vec<Option<String>>,
    },
    /// More approvals are needed, and these registered operators could give them.
    ///
    /// `could_approve` excludes operators who have already approved: listing somebody who has
    /// nothing left to do would make the queue's own instruction wrong.
    AwaitingApproval {
        /// How many more distinct approvers are required.
        still_needed: usize,
        /// Registered operators holding `approve` who have not yet approved this warrant.
        could_approve: Vec<String>,
        /// Who has approved so far.
        approved_by: Vec<Option<String>>,
    },
    /// No set of people this store knows about can satisfy the policy.
    ///
    /// The sentence names the specific arithmetic that fails, because the fix differs: register
    /// another approver, lower `required`, or set `settler_may_approve`.
    Deadlocked {
        /// What cannot be satisfied, in one sentence, with the remedy.
        why: String,
    },
}

impl Blocker {
    /// The short word a listing renders.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::AwaitingDecision { .. } => "awaiting-decision",
            Self::AwaitingApproval { .. } => "awaiting-approval",
            Self::Deadlocked { .. } => "deadlocked",
        }
    }

    /// Whether this is a state no further human act can clear.
    #[must_use]
    pub const fn is_deadlocked(&self) -> bool {
        matches!(self, Self::Deadlocked { .. })
    }
}

/// One warrant waiting on a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    /// The warrant.
    pub warrant_id: String,
    /// `open` or `held`, as the store records it.
    pub state: String,
    /// When the warrant was granted. The only timestamp the store holds for it.
    ///
    /// Deliberately not called `waiting_since`. A warrant becomes *waiting* when its agent stops
    /// and its effects are staged, and the store records no such moment — see
    /// `docs/W1-delivery-gaps.md` §4.3, which hits the same missing timestamp from the other side.
    /// Reporting `issued_at` under a name that implies otherwise would be a number with nothing
    /// behind it.
    pub issued_at: u64,
    /// How many effects are staged, or `None` when the queue could not be read.
    ///
    /// `None` is "cannot say", never zero. A warrant whose staged log is unreadable is exactly the
    /// one a reviewer most needs to be told about, and rendering it as "nothing to release" would
    /// invite a settle that releases something nobody looked at.
    pub staged_effects: Option<usize>,
    /// Why it is not moving.
    pub blocker: Blocker,
}

/// The facts about one outstanding warrant, as the caller reads them from the store.
///
/// Passed in rather than fetched so this module holds no I/O and every case below is reachable from
/// a unit test without a filesystem. The same shape [`crate::bench`] uses, for the same reason.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// The warrant.
    pub warrant_id: &'a str,
    /// `open` or `held`.
    pub state: &'a str,
    /// When it was granted.
    pub issued_at: u64,
    /// Its actor log, already read and chain-checked by the caller.
    pub records: &'a [ActorRecord],
    /// Staged effect count, or `None` when it could not be counted.
    pub staged_effects: Option<usize>,
}

/// Operators holding a scope, by name, in registry order.
fn holders(registry: &OperatorRegistry, scope: Scope) -> Vec<&Operator> {
    registry
        .operators
        .iter()
        .filter(|o| o.allows(scope))
        .collect()
}

/// Whether some assignment of approvers and a settler satisfies the policy.
///
/// # The arithmetic, spelled out
///
/// Let `A` be the operators holding `approve`, `S` those holding `settle`, `R` the required count
/// and `M` whether the settler may also approve.
///
/// * With `M`, any `R` members of `A` will do, and the settler may be one of them: feasible when
///   `|A| >= R` and `S` is non-empty.
/// * Without `M`, the settler must be somebody the approval count does not use. That is feasible
///   exactly when some `s in S` leaves `R` approvers behind it — `|A| >= R` if `s` is not an
///   approver, and `|A| - 1 >= R` if it is.
///
/// The second case is the one that surprises people: a store with two operators who both hold both
/// scopes and `required: 2` is deadlocked, because satisfying the count consumes both of them and
/// leaves nobody to settle.
fn feasible(registry: &OperatorRegistry, policy: &ApprovalPolicy) -> Result<(), String> {
    let approve = holders(registry, Scope::Approve);
    let settle = holders(registry, Scope::Settle);
    let required = policy.required;

    // The anonymous case, which `approval_verdict` also refuses at settle time. Stated here as a
    // configuration fault rather than a per-settle refusal, because that is what it is: no sequence
    // of acts on this machine can ever satisfy it.
    if registry.operators.is_empty() {
        if required > 1 {
            return Err(format!(
                "this store requires {required} distinct approvals and has no operator registry, so \
                 every approval is recorded against the same unnamed session principal and {required} \
                 approvers can never be told apart. Register operators (`warrantor operator add \
                 <name> --scope approve --note \"...\"`) or set \"required\": 1 in approvals.json."
            ));
        }
        // `required: 1` with no registry is satisfiable: one anonymous approval counts once. Whether
        // it is *meaningful* is a different question, and not this function's to answer.
        return if policy.settler_may_approve {
            Ok(())
        } else {
            Err(
                "this store requires an approval from somebody other than whoever settles, and has \
                 no operator registry -- so the approver and the settler are the same unnamed \
                 principal and cannot be distinguished. Register operators, or set \
                 \"settler_may_approve\": true in approvals.json if a recorded second look by one \
                 person is the posture you want."
                    .to_string(),
            )
        };
    }

    if approve.len() < required {
        return Err(format!(
            "this store requires {required} approval(s) and only {} registered operator(s) hold the \
             approve scope. Grant it to somebody (`warrantor operator add <name> --scope approve \
             --note \"...\"`) or lower \"required\" in approvals.json.",
            approve.len()
        ));
    }
    if settle.is_empty() {
        return Err(
            "no registered operator holds the settle scope, so no approved warrant can be released \
             by anyone. Grant it (`warrantor operator add <name> --scope settle --note \"...\"`)."
                .to_string(),
        );
    }
    if policy.settler_may_approve {
        return Ok(());
    }
    let approver_names: BTreeSet<&str> = approve.iter().map(|o| o.name.as_str()).collect();
    let workable = settle.iter().any(|s| {
        if approver_names.contains(s.name.as_str()) {
            // `> required`, not `- 1 >= required`: the same predicate without a subtraction that
            // would underflow on an empty set, which this branch is only guarded against by facts
            // established several lines earlier.
            approve.len() > required
        } else {
            approve.len() >= required
        }
    });
    if workable {
        return Ok(());
    }
    Err(format!(
        "this store requires {required} approval(s) from somebody other than whoever settles, and \
         no assignment of its {} operator(s) satisfies that: every operator holding settle is also \
         needed to reach the approval count. Register another approver, lower \"required\", or set \
         \"settler_may_approve\": true in approvals.json.",
        registry.operators.len()
    ))
}

/// Where one warrant stands.
///
/// Returns `None` when the warrant is not waiting on anybody — either the store requires no
/// approvals, or the requirement is already met and a settler could act. The caller renders a
/// queue from the `Some`s, and a warrant absent from that queue is a warrant nothing is holding up.
///
/// # Why the deadlock check runs first
///
/// A deadlocked store also fails the count, so checking the count first would report every warrant
/// as `AwaitingApproval` and name approvers who cannot collectively finish the job. The more
/// specific answer wins.
#[must_use]
pub fn standing(
    policy: &ApprovalPolicy,
    registry: &OperatorRegistry,
    candidate: &Candidate<'_>,
) -> Option<Waiting> {
    let approved: Vec<Option<String>> = approvers(candidate.records).into_iter().collect();

    let blocker = if policy.requires_approval() {
        if let Err(why) = feasible(registry, policy) {
            Blocker::Deadlocked { why }
        } else if policy.required > 1 && approved.iter().any(Option::is_none) {
            // A per-warrant deadlock, and the one this module found rather than inherited.
            //
            // `approval_verdict` refuses *any* settle whose log holds an anonymous approval when
            // `required > 1`, because on a machine with no registry every caller is one unnamed
            // principal and distinct approvers cannot be established. That check reads the log, not
            // the registry — so one `warrantor approve` typed at a terminal is enough to trip it on
            // a store that has a registry and named operators, and it is then **permanent**: no
            // number of named approvals removes the anonymous line, and the chain is append-only by
            // design. The warrant can only be voided.
            //
            // The gate's own sentence describes this as an approval "recorded with no operator
            // name", which reads as a fixable "not yet". Counting it as a wait here would have
            // repeated that, and worse: the queue would have reached `awaiting-decision` and told
            // a settler to act while the gate refused them. Two implementations of one check
            // disagreeing is the failure this repository is built to avoid.
            Blocker::Deadlocked {
                why: format!(
                    "this warrant's actor log holds an approval recorded with NO operator name, and \
                     this store requires {} distinct approvals. `approval_verdict` refuses every \
                     settle in that state, and the actor log is append-only -- so no number of named \
                     approvals can clear it. This warrant can now only be voided. The anonymous line \
                     came from `warrantor approve` at a terminal, which cannot authenticate anybody; \
                     approve through `warrantor serve` with an operator token instead.",
                    policy.required
                ),
            }
        } else {
            // Distinct *named* approvers, matching `approvers()`'s own rule that a repeat from one
            // operator is one approver. The anonymous entry counts once, which is only reachable
            // here when `required` is 1 -- `feasible` has already refused anything higher.
            let have = approved.len();
            if have >= policy.required {
                Blocker::AwaitingDecision {
                    approved_by: approved,
                }
            } else {
                let already: BTreeSet<&str> =
                    approved.iter().filter_map(Option::as_deref).collect();
                let could_approve = holders(registry, Scope::Approve)
                    .into_iter()
                    .map(|o| o.name.clone())
                    .filter(|n| !already.contains(n.as_str()))
                    .collect();
                Blocker::AwaitingApproval {
                    still_needed: policy.required - have,
                    could_approve,
                    approved_by: approved,
                }
            }
        }
    } else {
        // No approval requirement at all. The warrant is still outstanding and still needs somebody
        // to settle or void it, which is a decision and belongs in the queue -- the whole point of
        // the queue is that an outstanding warrant nobody looks at is the failure mode.
        Blocker::AwaitingDecision {
            approved_by: approved,
        }
    };

    Some(Waiting {
        warrant_id: candidate.warrant_id.to_string(),
        state: candidate.state.to_string(),
        issued_at: candidate.issued_at,
        staged_effects: candidate.staged_effects,
        blocker,
    })
}

/// What a given principal can do about a waiting warrant, right now.
///
/// The queue is rendered per-caller for one reason: "waiting on a decision" and "waiting on *you*"
/// are different sentences, and a reviewer shown twelve warrants none of which they can act on will
/// stop reading the list. Every act named here is one this principal holds the scope for and which
/// would not be refused for a reason already visible.
///
/// It never names `void`. Voiding is ungated by design — see [`crate::serve::handle_scoped`], where
/// the approval check runs for settle only, because discarding staged work is the safe direction.
/// Suggesting it in a queue would read as a recommendation to throw the work away.
#[must_use]
pub fn available_acts(
    waiting: &Waiting,
    principal: Option<&str>,
    scopes: &BTreeSet<Scope>,
    policy: &ApprovalPolicy,
) -> Vec<&'static str> {
    let mut acts = Vec::new();
    match &waiting.blocker {
        Blocker::Deadlocked { .. } => {}
        Blocker::AwaitingApproval { .. } => {
            let already_approved = match &waiting.blocker {
                Blocker::AwaitingApproval { approved_by, .. } => approved_by
                    .iter()
                    .any(|a| a.as_deref() == principal && a.is_some() == principal.is_some()),
                _ => false,
            };
            if scopes.contains(&Scope::Approve) && !already_approved {
                acts.push("approve");
            }
        }
        Blocker::AwaitingDecision { approved_by } => {
            if scopes.contains(&Scope::Settle) {
                // The settle gate will refuse if this principal is the only approver and the policy
                // forbids that. Predicting it here rather than offering an act that 403s.
                let sole_approver = !policy.settler_may_approve
                    && policy.requires_approval()
                    && approved_by.len() == 1
                    && approved_by.first().is_some_and(|a| {
                        a.as_deref() == principal && a.is_some() == principal.is_some()
                    });
                if !sole_approver {
                    acts.push("settle");
                }
            }
        }
    }
    acts
}

// ── the once-only notification marker ─────────────────────────────────────────────────

/// The record that a review notification has gone out for a warrant.
///
/// One line, no authority. It exists so a repeated check does not repeatedly notify; losing it
/// costs a duplicate webhook, and there is no state it can be missing from that would cost a
/// missed decision. That asymmetry is why it is a plain file rather than anything chained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRequest {
    /// Wire format.
    pub format: String,
    /// The warrant.
    pub warrant_id: String,
    /// When the notification was raised.
    pub at: u64,
    /// What was blocking it at that moment, as a word. Historical: the live answer is derived.
    pub blocker: String,
}

/// Where a warrant's review-request marker lives.
#[must_use]
pub fn request_path(root: &std::path::Path, warrant_id: &str) -> std::path::PathBuf {
    root.join("reviews").join(format!("{warrant_id}.json"))
}

/// What was last announced about this warrant, if anything.
///
/// # Why this returns the blocker and not a boolean
///
/// A plain "have we notified?" flag has a silent failure that took writing the caller to see. A
/// warrant announced as `awaiting-approval` gets its approvals, moves to `awaiting-decision` — a
/// genuinely new state, and the one where somebody must actually release or discard the work — and
/// the flag suppresses the announcement. The reviewer who approved it is told nothing, and the
/// settler is never told at all.
///
/// So the marker records **what** was announced, and [`should_announce`] compares. A transition
/// between blockers is news; a repeat of the same blocker is not.
///
/// An unreadable or unparseable marker reads as `Some("")`, which matches no blocker word and
/// therefore re-announces. Of the two failure modes — a duplicate notification and a lost one —
/// this picks the duplicate, because a human can see and dismiss a duplicate and cannot see a
/// notification that never arrived.
#[must_use]
pub fn last_announced(root: &std::path::Path, warrant_id: &str) -> Option<String> {
    let raw = std::fs::read_to_string(request_path(root, warrant_id)).ok()?;
    Some(
        serde_json::from_str::<ReviewRequest>(&raw)
            .map(|r| r.blocker)
            .unwrap_or_default(),
    )
}

/// Whether this warrant's current blocker is news.
///
/// True when nothing has been announced, or when what was announced is not what is blocking it
/// now.
#[must_use]
pub fn should_announce(root: &std::path::Path, warrant_id: &str, blocker: &str) -> bool {
    last_announced(root, warrant_id).is_none_or(|last| last != blocker)
}

/// Record that a review notification has been raised.
///
/// # Errors
/// A sentence on I/O failure. The caller decides whether that is fatal; in the CLI it is not — a
/// notification that was sent and not recorded is a duplicate next time, which beats refusing to
/// notify because the bookkeeping failed.
pub fn record_request(
    root: &std::path::Path,
    warrant_id: &str,
    at: u64,
    blocker: &str,
) -> Result<(), String> {
    let path = request_path(root, warrant_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let record = ReviewRequest {
        format: REVIEW_FORMAT.to_string(),
        warrant_id: warrant_id.to_string(),
        at,
        blocker: blocker.to_string(),
    };
    let body = serde_json::to_vec_pretty(&record)
        .map_err(|e| format!("cannot serialise a review request: {e}"))?;
    std::fs::write(&path, body).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Clear a warrant's review-request marker.
///
/// Called when a warrant leaves the outstanding set, so that a later warrant reusing the id — which
/// cannot happen with CSPRNG ids, but the store does not enforce that — is not silently treated as
/// already announced. A missing marker is not an error.
///
/// # Errors
/// A sentence when the file exists and cannot be removed.
pub fn clear_request(root: &std::path::Path, warrant_id: &str) -> Result<(), String> {
    let path = request_path(root, warrant_id);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{Act, ACTOR_FORMAT};

    fn policy(required: usize, settler_may_approve: bool) -> ApprovalPolicy {
        ApprovalPolicy {
            format: crate::operators::APPROVALS_FORMAT.to_string(),
            required,
            settler_may_approve,
        }
    }

    fn operator(name: &str, scopes: &[Scope]) -> Operator {
        Operator {
            name: name.to_string(),
            scopes: scopes.iter().copied().collect(),
            token_digest: "0".repeat(64),
            added_at: 1,
            note: "test".to_string(),
        }
    }

    fn registry(operators: Vec<Operator>) -> OperatorRegistry {
        OperatorRegistry {
            format: crate::operators::OPERATORS_FORMAT.to_string(),
            operators,
            // The queue is indifferent to it: `session_scopes` decides what the SESSION token may
            // do, and every principal the queue reasons about is a named operator.
            session_scopes: None,
        }
    }

    fn approval(actor: Option<&str>) -> ActorRecord {
        ActorRecord {
            format: ACTOR_FORMAT.to_string(),
            warrant_id: "wrt_test".to_string(),
            act: Act::Approve,
            actor: actor.map(str::to_string),
            via: "operator-token".to_string(),
            at: 10,
            prev: String::new(),
            digest: "d".to_string(),
        }
    }

    fn candidate<'a>(records: &'a [ActorRecord]) -> Candidate<'a> {
        Candidate {
            warrant_id: "wrt_test",
            state: "open",
            issued_at: 100,
            records,
            staged_effects: Some(3),
        }
    }

    #[test]
    fn a_store_with_no_policy_still_queues_the_warrant_for_a_decision() {
        // The queue's purpose is that an outstanding warrant nobody looks at is the failure mode.
        // No approval requirement does not mean no decision is owed.
        let waiting = standing(&policy(0, false), &registry(vec![]), &candidate(&[])).unwrap();
        assert!(matches!(waiting.blocker, Blocker::AwaitingDecision { .. }));
    }

    #[test]
    fn an_unmet_requirement_names_who_could_meet_it_and_excludes_who_already_has() {
        let records = [approval(Some("ana"))];
        let reg = registry(vec![
            operator("ana", &[Scope::Approve]),
            operator("ben", &[Scope::Approve]),
            operator("cleo", &[Scope::Approve, Scope::Settle]),
        ]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&records)).unwrap();
        let Blocker::AwaitingApproval {
            still_needed,
            could_approve,
            ..
        } = waiting.blocker
        else {
            panic!("expected awaiting-approval, got {:?}", waiting.blocker);
        };
        assert_eq!(still_needed, 1);
        // ana is absent: she has already approved, and listing her would make the queue's own
        // instruction wrong.
        assert_eq!(could_approve, vec!["ben".to_string(), "cleo".to_string()]);
    }

    #[test]
    fn a_met_requirement_is_awaiting_a_decision_not_an_approval() {
        let records = [approval(Some("ana")), approval(Some("ben"))];
        let reg = registry(vec![
            operator("ana", &[Scope::Approve]),
            operator("ben", &[Scope::Approve]),
            operator("cleo", &[Scope::Settle]),
        ]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&records)).unwrap();
        assert!(matches!(waiting.blocker, Blocker::AwaitingDecision { .. }));
    }

    #[test]
    fn two_approvals_from_one_operator_are_one_approver() {
        // The rule `approvers()` already enforces, restated here because the queue is where a
        // reader would notice it being wrong: a person cannot satisfy a two-person rule by running
        // the command twice.
        let records = [approval(Some("ana")), approval(Some("ana"))];
        let reg = registry(vec![
            operator("ana", &[Scope::Approve]),
            operator("ben", &[Scope::Approve]),
            operator("cleo", &[Scope::Settle]),
        ]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&records)).unwrap();
        assert!(matches!(
            waiting.blocker,
            Blocker::AwaitingApproval {
                still_needed: 1,
                ..
            }
        ));
    }

    #[test]
    fn not_enough_approvers_exist_is_a_deadlock_not_a_wait() {
        let reg = registry(vec![operator("ana", &[Scope::Approve, Scope::Settle])]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&[])).unwrap();
        assert!(waiting.blocker.is_deadlocked(), "{:?}", waiting.blocker);
        let Blocker::Deadlocked { why } = &waiting.blocker else {
            unreachable!()
        };
        assert!(why.contains("only 1 registered operator"), "{why}");
    }

    #[test]
    fn every_approver_being_needed_leaves_nobody_to_settle() {
        // The surprising one. Two operators, both holding both scopes, `required: 2`: satisfying
        // the count consumes both, and the settler must be somebody the count did not use.
        let reg = registry(vec![
            operator("ana", &[Scope::Approve, Scope::Settle]),
            operator("ben", &[Scope::Approve, Scope::Settle]),
        ]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&[])).unwrap();
        assert!(waiting.blocker.is_deadlocked(), "{:?}", waiting.blocker);

        // ...and a third operator holding only settle resolves it, without changing the policy.
        let reg = registry(vec![
            operator("ana", &[Scope::Approve, Scope::Settle]),
            operator("ben", &[Scope::Approve, Scope::Settle]),
            operator("cleo", &[Scope::Settle]),
        ]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&[])).unwrap();
        assert!(!waiting.blocker.is_deadlocked(), "{:?}", waiting.blocker);
    }

    #[test]
    fn settler_may_approve_resolves_the_same_configuration() {
        let reg = registry(vec![
            operator("ana", &[Scope::Approve, Scope::Settle]),
            operator("ben", &[Scope::Approve, Scope::Settle]),
        ]);
        assert!(standing(&policy(2, true), &reg, &candidate(&[]))
            .unwrap()
            .blocker
            .is_deadlocked()
            .eq(&false));
    }

    #[test]
    fn no_registry_and_more_than_one_required_is_a_deadlock() {
        // The same fact `approval_verdict` refuses at settle time, reported as a configuration
        // fault: no sequence of acts on this machine can satisfy it, so "not yet" is the wrong
        // word for it.
        let waiting = standing(&policy(2, false), &registry(vec![]), &candidate(&[])).unwrap();
        assert!(waiting.blocker.is_deadlocked());
        let Blocker::Deadlocked { why } = &waiting.blocker else {
            unreachable!()
        };
        assert!(why.contains("unnamed session principal"), "{why}");
    }

    #[test]
    fn no_registry_and_one_required_needs_the_settler_to_be_allowed_to_approve() {
        // One anonymous approval counts once, so the count is reachable -- but with
        // `settler_may_approve: false` the approver and the settler are the same unnamed principal
        // and cannot be told apart, which is a deadlock rather than a wait.
        assert!(
            standing(&policy(1, false), &registry(vec![]), &candidate(&[]))
                .unwrap()
                .blocker
                .is_deadlocked()
        );
        assert!(
            !standing(&policy(1, true), &registry(vec![]), &candidate(&[]))
                .unwrap()
                .blocker
                .is_deadlocked()
        );
    }

    #[test]
    fn one_anonymous_approval_permanently_poisons_a_multi_approver_warrant() {
        // The defect this module found rather than inherited. `approval_verdict` refuses every
        // settle whose log holds an anonymous approval when `required > 1`, and it reads the LOG,
        // not the registry -- so a single `warrantor approve` at a terminal trips it on a fully
        // registered store, and the append-only log means it can never be untripped.
        //
        // The queue must agree with the gate. Counting the anonymous line as one of two approvals
        // would reach `awaiting-decision` and tell a settler to act on a warrant the gate refuses.
        let reg = registry(vec![
            operator("ana", &[Scope::Approve]),
            operator("ben", &[Scope::Approve]),
            operator("cleo", &[Scope::Settle]),
        ]);
        let records = [approval(None), approval(Some("ana")), approval(Some("ben"))];
        let waiting = standing(&policy(2, false), &reg, &candidate(&records)).unwrap();
        assert!(
            waiting.blocker.is_deadlocked(),
            "two named approvals and an anonymous one still cannot settle: {:?}",
            waiting.blocker
        );
        let Blocker::Deadlocked { why } = &waiting.blocker else {
            unreachable!()
        };
        assert!(why.contains("only be voided"), "{why}");

        // ...and `required: 1` is untouched: one anonymous approval satisfies it, which is exactly
        // what `approval_verdict` allows.
        let waiting = standing(&policy(1, true), &reg, &candidate(&[approval(None)])).unwrap();
        assert!(matches!(waiting.blocker, Blocker::AwaitingDecision { .. }));
    }

    #[test]
    fn a_settle_holder_alone_cannot_satisfy_an_approval_requirement() {
        let reg = registry(vec![operator("ana", &[Scope::Settle])]);
        let waiting = standing(&policy(1, false), &reg, &candidate(&[])).unwrap();
        assert!(waiting.blocker.is_deadlocked(), "{:?}", waiting.blocker);
    }

    #[test]
    fn nobody_holding_settle_is_a_deadlock_even_when_approvals_are_reachable() {
        let reg = registry(vec![
            operator("ana", &[Scope::Approve]),
            operator("ben", &[Scope::Approve]),
        ]);
        let waiting = standing(&policy(1, false), &reg, &candidate(&[])).unwrap();
        assert!(waiting.blocker.is_deadlocked(), "{:?}", waiting.blocker);
        let Blocker::Deadlocked { why } = &waiting.blocker else {
            unreachable!()
        };
        assert!(why.contains("settle scope"), "{why}");
    }

    #[test]
    fn the_acts_offered_are_the_ones_this_principal_can_actually_take() {
        let reg = registry(vec![
            operator("ana", &[Scope::Approve]),
            operator("ben", &[Scope::Approve]),
            operator("cleo", &[Scope::Settle]),
        ]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&[])).unwrap();

        let approve_only: BTreeSet<Scope> = [Scope::Read, Scope::Approve].into_iter().collect();
        assert_eq!(
            available_acts(&waiting, Some("ana"), &approve_only, &policy(2, false)),
            vec!["approve"]
        );
        // cleo can settle but the approvals are not in yet, so the queue offers her nothing --
        // naming an act that would 403 is worse than naming none.
        let settle_only: BTreeSet<Scope> = [Scope::Read, Scope::Settle].into_iter().collect();
        assert!(available_acts(&waiting, Some("cleo"), &settle_only, &policy(2, false)).is_empty());
    }

    #[test]
    fn an_operator_who_has_approved_is_not_offered_approve_again() {
        let records = [approval(Some("ana"))];
        let reg = registry(vec![
            operator("ana", &[Scope::Approve]),
            operator("ben", &[Scope::Approve]),
            operator("cleo", &[Scope::Settle]),
        ]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&records)).unwrap();
        let approve: BTreeSet<Scope> = [Scope::Approve].into_iter().collect();
        assert!(available_acts(&waiting, Some("ana"), &approve, &policy(2, false)).is_empty());
        assert_eq!(
            available_acts(&waiting, Some("ben"), &approve, &policy(2, false)),
            vec!["approve"]
        );
    }

    #[test]
    fn the_sole_approver_is_not_offered_a_settle_the_gate_would_refuse() {
        // ana approved and holds settle. With `settler_may_approve: false` the settle gate refuses
        // her, so offering it here would send her to a 403 the queue already had the facts to
        // predict.
        let records = [approval(Some("ana"))];
        let reg = registry(vec![
            operator("ana", &[Scope::Approve, Scope::Settle]),
            operator("ben", &[Scope::Approve]),
            operator("cleo", &[Scope::Settle]),
        ]);
        let waiting = standing(&policy(1, false), &reg, &candidate(&records)).unwrap();
        assert!(matches!(waiting.blocker, Blocker::AwaitingDecision { .. }));
        let both: BTreeSet<Scope> = [Scope::Approve, Scope::Settle].into_iter().collect();
        assert!(available_acts(&waiting, Some("ana"), &both, &policy(1, false)).is_empty());
        // cleo did not approve, so she is the one who can release it.
        let settle: BTreeSet<Scope> = [Scope::Settle].into_iter().collect();
        assert_eq!(
            available_acts(&waiting, Some("cleo"), &settle, &policy(1, false)),
            vec!["settle"]
        );
    }

    #[test]
    fn a_deadlocked_warrant_offers_nobody_anything() {
        let reg = registry(vec![operator("ana", &[Scope::Approve, Scope::Settle])]);
        let waiting = standing(&policy(2, false), &reg, &candidate(&[])).unwrap();
        let all: BTreeSet<Scope> = [Scope::Read, Scope::Stop, Scope::Settle, Scope::Approve]
            .into_iter()
            .collect();
        assert!(available_acts(&waiting, Some("ana"), &all, &policy(2, false)).is_empty());
    }

    #[test]
    fn the_serialised_tag_is_the_same_word_the_counts_map_is_keyed_by() {
        // Found by reading the first live `/v1/queue` response rather than by any test: the entry
        // carried `"blocker":"awaiting_approval"` and the counts map beside it was keyed
        // `"awaiting-approval"`. Both were correct in isolation and the pair was unusable.
        //
        // Asserted over every variant, so adding one cannot reintroduce the split.
        let variants = [
            Blocker::AwaitingDecision {
                approved_by: vec![],
            },
            Blocker::AwaitingApproval {
                still_needed: 1,
                could_approve: vec![],
                approved_by: vec![],
            },
            Blocker::Deadlocked { why: String::new() },
        ];
        for blocker in variants {
            let value = serde_json::to_value(&blocker).unwrap();
            let tag = value
                .get("blocker")
                .and_then(serde_json::Value::as_str)
                .expect("the tag field is named `blocker`");
            assert_eq!(
                tag,
                blocker.word(),
                "the serialised tag and Blocker::word() must be one string: they appear in the \
                 same JSON object, one as an entry field and one as a counts key"
            );
        }
    }

    #[test]
    fn an_uncountable_staged_queue_is_none_and_never_zero() {
        let mut c = candidate(&[]);
        c.staged_effects = None;
        let waiting = standing(&policy(0, false), &registry(vec![]), &c).unwrap();
        assert_eq!(waiting.staged_effects, None);
    }

    #[test]
    fn the_marker_round_trips_and_a_missing_one_clears_cleanly() {
        let dir = std::env::temp_dir().join(format!("wt-review-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert_eq!(last_announced(&dir, "wrt_a"), None);
        assert!(should_announce(&dir, "wrt_a", "awaiting-approval"));
        // Clearing something that was never written is not an error: the caller clears on every
        // state change and cannot know whether a marker was ever raised.
        clear_request(&dir, "wrt_a").unwrap();

        record_request(&dir, "wrt_a", 42, "awaiting-approval").unwrap();
        assert_eq!(
            last_announced(&dir, "wrt_a"),
            Some("awaiting-approval".to_string())
        );
        let raw = std::fs::read_to_string(request_path(&dir, "wrt_a")).unwrap();
        let parsed: ReviewRequest = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.format, REVIEW_FORMAT);
        assert_eq!(parsed.at, 42);

        clear_request(&dir, "wrt_a").unwrap();
        assert_eq!(last_announced(&dir, "wrt_a"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_changed_blocker_is_news_and_the_same_blocker_is_not() {
        // The defect a boolean flag would have: a warrant announced as awaiting-approval gets its
        // approvals, becomes awaiting-decision -- the state where somebody must actually release
        // the work -- and a "have we notified?" flag would suppress it. Nobody would be told the
        // thing they were waiting to be told.
        let dir = std::env::temp_dir().join(format!("wt-review-news-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        record_request(&dir, "wrt_b", 1, "awaiting-approval").unwrap();
        assert!(!should_announce(&dir, "wrt_b", "awaiting-approval"));
        assert!(should_announce(&dir, "wrt_b", "awaiting-decision"));
        assert!(should_announce(&dir, "wrt_b", "deadlocked"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unparseable_marker_re_announces_rather_than_going_quiet() {
        // Of the two failure modes -- a duplicate notification and a lost one -- a corrupt marker
        // has to pick the duplicate. A human can dismiss a duplicate; nobody can see a
        // notification that never arrived.
        let dir = std::env::temp_dir().join(format!("wt-review-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = request_path(&dir, "wrt_c");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();

        assert_eq!(last_announced(&dir, "wrt_c"), Some(String::new()));
        assert!(should_announce(&dir, "wrt_c", "awaiting-approval"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

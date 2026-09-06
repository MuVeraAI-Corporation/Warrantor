//! L3-04 — the horizon governor: ceilings on how long and how far one warrant's autonomy runs.
//!
//! # What existed before this module, and what did not
//!
//! `expires_at` bounded time and `supervise.rs` terminated the process tree when it arrived. That
//! is the half of L3-04 the blueprint calls a partial, and it is the half that was easy. What did
//! not exist, in any form: a count-shaped bound of any kind — no step ceiling, no effect ceiling,
//! no action ceiling, and no field that could be read as one — and no escalation to a human as a
//! limit approaches. Nothing in the crate raised an approval on the approach to a limit.
//!
//! # The three dimensions and their three tiers
//!
//! A bound is only as strong as **the weaker of its trigger and its consequence**, so the table has
//! a column for each. Two dimensions share the same Tier A consequence and get different words,
//! because one of the two triggers is a file the bounded party can write.
//!
//! | Dimension | Trigger | Consequence | Tier |
//! |---|---|---|---|
//! | `max_wall_seconds` | monotonic elapsed time against a *signed* `issued_at`; unforgeable | the supervisor's OS process link, reached by shortening the wait budget | [`BoundStrength::Enforced`] |
//! | `max_effects` | the proxy's own admitted-call counter | [`crate::proxy::Decision::Deny`] returned as the call arrives | [`BoundStrength::Mediated`] |
//! | `max_unattended_seconds` | a read of `operators.rs`'s actor log, which is hash-chained and **not signed** | the same OS process link | [`BoundStrength::Observed`] |
//!
//! The arithmetic in this module refuses nothing; what earns a tier is the weaker of the two columns.
//! For `max_wall_seconds` both columns are strong: elapsed time cannot be forged and
//! [`crate::supervise::Supervisor::terminate`] → [`crate::supervise::terminate_group`] reaches a
//! Windows job object or `kill -KILL -pgid` under `setsid`. For `max_unattended_seconds` the
//! consequence is identical and the **trigger is not**: `operators::record` takes no key, so any
//! process that can write the store root — the agent included, since `write_paths` is enforced
//! nowhere — can append a well-formed entry naming an operator and reset the clock. A bound the
//! bounded party can extend by writing a file is `Observed`, and calling it `Enforced` because the
//! kill is enforced is the exact defect [`BoundStrength`] exists to prevent.
//!
//! `bound_strengths()` therefore labels the bound as a whole [`BoundStrength::Observed`] — the
//! weakest of the three, because a reader takes the first word and moves on.
//! [`HorizonDimension::strength`] and `warrantor horizon` give the per-dimension answer, so the
//! `Enforced` wall ceiling is recoverable rather than lost to that row.
//!
//! **This module composes with `supervise.rs` and does not duplicate it.** `supervise.rs` is
//! unmodified by the task that added this file. All the wall-clock dimension does is supply a
//! smaller number to the deadline the supervisor already enforces — see [`effective_deadline`].
//!
//! **The caveat `supervise.rs` states and this module inherits.** On a platform whose
//! [`crate::supervise::Linkage::survives_supervisor_death`] is `false` — anything that is neither
//! Windows nor Linux, macOS included — a horizon that must hold *after the supervisor dies* does
//! not hold. Termination through a live supervisor is Tier A on all three platforms; survival of
//! the supervisor's own death is Tier A on two of the three, and `describe_linkage` says which.
//!
//! # What the effect count counts, and why the number is a floor
//!
//! One effect is **one tool call the proxy admitted** — [`crate::proxy::Decision::Forward`] or
//! [`crate::proxy::Decision::Stage`]. A refused call counts nothing: the ceiling bounds effects, and
//! a refused call produced none. Counting refusals would let a warrant be exhausted by calls it was
//! never allowed to make, turning an effect ceiling into a rate limit on attempts, which is Task
//! 8.3's business and not this module's.
//!
//! The count has two components, and they are not equally durable:
//!
//! * **Staged effects** — the length of this warrant's hash-chained staging queue. Persisted,
//!   witnessed outside the file it witnesses by `StoredWarrant::staged_chain`, and therefore carried
//!   across sessions. [`crate::mcp_endpoints::agent_endpoint_for`] seeds the proxy's counter from it
//!   at session start, so a resumed session does not get a fresh allowance for what it already
//!   staged.
//! * **Forwarded calls** — calls admitted without staging. Counted in memory by the proxy for the
//!   life of one session and **not persisted**. A warrant resumed in a new session starts that half
//!   at zero.
//!
//! That second bullet is a real weakness and it is stated rather than papered over. The alternative
//! considered was a persisted forwarded-call counter; it was rejected because it would be a second
//! source of truth for "how many effects has this warrant produced", competing with the staging
//! chain that already witnesses effects, and an unwitnessed counter is one a `sed` can edit to buy
//! horizon. The choice made is the witnessed floor, declared as a floor. See
//! [`EFFECT_COUNT_LIMITATION`], which is the sentence every surface prints.
//!
//! A further limit of the same kind: **the supervisor cannot see the proxy's forwarded count at
//! all.** There is no daemon IPC in this system — [`crate::stop`] says so at length — so the polled
//! usage the supervision loop evaluates is the staged length only. The proxy's own refusal is what
//! bounds forwarded calls, and it bounds them within one session.
//!
//! # What escalation establishes
//!
//! [`HorizonVerdict::Escalate`] means a review request was written under the store root and the
//! notification path was called. It establishes that a notification was queued **on this machine**.
//! It does not establish that a human read it, and it adds no trust root: no central approval
//! service, no directory, no new signer.

use std::path::Path;

use crate::{BoundStrength, Horizon, WarrantBounds};

/// Wire format for the horizon state a report or a CLI surface carries.
pub const HORIZON_STATE_FORMAT: &str = "warrantor.horizon-state/1";

/// The one sentence every surface prints about the effect ceiling. Written once here so the report,
/// the CLI and the daemon cannot spell the caveat three ways.
pub const EFFECT_COUNT_LIMITATION: &str = "The horizon's effect ceiling counts only effects \
     Warrantor admitted at its MCP proxy: this warrant's hash-chained staging queue, which \
     persists across sessions, plus calls forwarded without staging during the session that is \
     running, which are counted in memory and are NOT persisted -- a resumed session starts that \
     half at zero. Nothing counts a shell command, a harness built-in, or any call that never \
     reached the proxy. The observed number is a floor on this warrant's effects, never a total. \
     The wall-clock ceiling is terminated by the operating system and cannot be outlived while the \
     supervisor is running; the effect ceiling is refused at a chokepoint the agent could decline to \
     use. The unattended ceiling shares the wall-clock ceiling's kill and NOT its strength: \
     \"unattended\" means no named operator has appeared in this warrant's actor log, and that log \
     is hash-chained but unsigned, so any process able to write the store root -- the agent included, \
     because write_paths is enforced nowhere -- can append an entry naming an operator and reset the \
     clock. Read the unattended figure as a measurement of a local file, not as proof that no human \
     was watching and not as a limit the agent cannot extend.";

/// Which ceiling is being talked about.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HorizonDimension {
    /// Wall-clock seconds since the warrant was issued.
    Wall,
    /// Effects admitted at the proxy.
    Effects,
    /// Seconds since a named operator last appeared in the actor log.
    Unattended,
}

impl HorizonDimension {
    /// Every dimension, in the order [`evaluate`] checks them. Fixed so a breach report is
    /// deterministic when more than one ceiling is reached at once.
    pub const ALL: [Self; 3] = [Self::Wall, Self::Effects, Self::Unattended];

    /// The stable word this dimension is written as, in a record and on a terminal.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Wall => "wall",
            Self::Effects => "effects",
            Self::Unattended => "unattended",
        }
    }

    /// The `Horizon` field this dimension reads.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::Wall => "max_wall_seconds",
            Self::Effects => "max_effects",
            Self::Unattended => "max_unattended_seconds",
        }
    }

    /// The tier THIS dimension's own mechanism earns.
    ///
    /// Deliberately more precise than the single `("horizon", Mediated)` row in
    /// [`crate::bound_strengths`]: that row has to describe the whole bound and so takes the weakest
    /// word, which loses the fact that two of the three dimensions are held by the operating system.
    /// `warrantor horizon` prints this per dimension so the stronger half is recoverable.
    /// The tier THIS dimension's own mechanism earns.
    ///
    /// Deliberately more precise than the single `("horizon", ..)` row in
    /// [`crate::bound_strengths`], which has to describe the whole bound and so takes the weakest of
    /// the three — losing the fact that one of them is held by the operating system.
    ///
    /// **A bound is only as strong as the weaker of its trigger and its consequence, and the three
    /// answers here differ because the triggers do.** The consequence is the same OS termination for
    /// both time dimensions:
    ///
    /// * `Wall` — **Enforced.** The trigger is elapsed monotonic time measured against `issued_at`
    ///   from the *signed* claims, and nothing the bounded party can do makes a clock run slower.
    ///   The consequence is [`crate::supervise::Supervisor::terminate`]. Same basis as `expires_at`,
    ///   which `bound_strengths()` has always called `Enforced`, and the horizon reaches it by
    ///   shortening that deadline rather than by adding a mechanism.
    /// * `Effects` — **Mediated.** Refused at [`crate::proxy::Proxy::decide`] as the call arrives,
    ///   which is a refusal and so not Observed; and the proxy sees only what the agent routes
    ///   through it, which is why it is not Enforced.
    /// * `Unattended` — **Observed**, and this is the one that reads weaker than it feels. The
    ///   consequence is the same Tier A kill, but the trigger is a read of `operators.rs`'s actor
    ///   log, which is hash-chained and **not signed**: `operators::record` takes no key, so any
    ///   process that can write the store root can append a well-formed entry carrying
    ///   `actor: Some("someone")` and reset this clock. `write_paths` is not enforced anywhere in
    ///   this system, so the agent is such a process. A bound the bounded party can extend by
    ///   writing a file is measured, not enforced, however strong the kill at the end of it —
    ///   naming it `Enforced` because the *kill* is enforced would be the exact defect
    ///   [`crate::BoundStrength`] exists to prevent.
    #[must_use]
    pub const fn strength(self) -> BoundStrength {
        match self {
            // Trigger: monotonic elapsed time against a signed `issued_at`, unforgeable by the
            // bounded party. Consequence: supervise.rs -- a Windows job object, or setsid +
            // PR_SET_PDEATHSIG. The horizon does not re-implement that; it shortens the wait budget
            // that reaches it.
            Self::Wall => BoundStrength::Enforced,
            // Refused at the MCP proxy, which sees only what the agent routes through it.
            Self::Effects => BoundStrength::Mediated,
            // Same kill as Wall, but the trigger is an UNSIGNED local log the agent can append to.
            // The weaker half is the one the word has to describe.
            Self::Unattended => BoundStrength::Observed,
        }
    }

    /// What this dimension does NOT cover, beyond its tier's generic caveat.
    #[must_use]
    pub const fn caveat(self) -> &'static str {
        match self {
            Self::Wall => {
                "terminated through the supervisor's OS process link. On a platform where \
                 supervise::describe_linkage reports survives_supervisor_death = false (anything \
                 that is neither Windows nor Linux), an agent outlives a supervisor that was killed \
                 uncleanly and this ceiling with it."
            }
            Self::Effects => {
                "counts only effects the MCP proxy admitted, and the forwarded half is not \
                 persisted across sessions. The number is a floor, never a total."
            }
            Self::Unattended => {
                "measured from this store's actor log, which is hash-chained and NOT signed. An \
                 entry with no operator name is the unscoped session token and does not count as \
                 human contact -- but `operators::record` takes no key, so any process that can \
                 write the store root can append an entry naming an operator and reset this clock, \
                 and nothing in this system refuses the agent that write. Read it as a measurement \
                 of a local file, not as proof a human was watching and not as a bound the agent \
                 cannot extend. The termination at the end of it IS the OS process link; the clock \
                 that triggers it is the weaker half."
            }
        }
    }
}

/// What a warrant has actually used, in the three dimensions a horizon bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct HorizonUsage {
    /// Wall-clock seconds since issue.
    pub elapsed_seconds: u64,
    /// Effects admitted at the proxy. A floor — see [`EFFECT_COUNT_LIMITATION`].
    pub effects: u64,
    /// Seconds since a named operator last acted, or since issue if none ever has.
    pub unattended_seconds: u64,
}

impl HorizonUsage {
    /// This usage's figure for one dimension.
    #[must_use]
    pub const fn observed(&self, dimension: HorizonDimension) -> u64 {
        match dimension {
            HorizonDimension::Wall => self.elapsed_seconds,
            HorizonDimension::Effects => self.effects,
            HorizonDimension::Unattended => self.unattended_seconds,
        }
    }
}

/// Where a warrant stands against its horizon.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum HorizonVerdict {
    /// Inside every declared ceiling. `nearest` names the dimension closest to its ceiling and the
    /// whole percentage consumed, so a surface can show the approach without inventing a threshold.
    Within {
        /// The closest dimension and its percentage, or `None` when no dimension is declared.
        nearest: Option<(HorizonDimension, u8)>,
    },
    /// A ceiling's escalation threshold has been crossed and a human should be asked. Not a breach:
    /// the run continues while the request is outstanding.
    Escalate {
        /// The dimension that crossed.
        dimension: HorizonDimension,
        /// The declared threshold, as a percentage.
        at_percent: u8,
        /// That dimension's ceiling.
        limit: u64,
        /// What was observed.
        observed: u64,
    },
    /// A ceiling has been reached. Terminal: the run stops.
    ///
    /// Reaching is the event, for every dimension. `expires_at` behaves this way already — arriving
    /// at the deadline stops the run, it does not warn — and a horizon that reported `Within` at
    /// exactly its ceiling would let the whole granted amount be spent and the run carry on.
    Breached {
        /// The dimension that was reached.
        dimension: HorizonDimension,
        /// Its ceiling.
        limit: u64,
        /// What was observed.
        observed: u64,
    },
}

impl HorizonVerdict {
    /// The stable word this verdict is written as.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Within { .. } => "within",
            Self::Escalate { .. } => "escalate",
            Self::Breached { .. } => "breached",
        }
    }
}

/// The ceiling a horizon declares for one dimension, or `None` when it declares none.
#[must_use]
pub const fn limit_of(horizon: &Horizon, dimension: HorizonDimension) -> Option<u64> {
    match dimension {
        HorizonDimension::Wall => horizon.max_wall_seconds,
        HorizonDimension::Effects => horizon.max_effects,
        HorizonDimension::Unattended => horizon.max_unattended_seconds,
    }
}

/// Whole percentage of `limit` that `observed` consumes, capped at 100 so a surface cannot print
/// 4000% and a `u8` cannot wrap.
///
/// Public and used by [`crate::report::horizon_section`] too: two copies of this arithmetic would be
/// two places a report and a CLI could disagree about how full a horizon is.
#[must_use]
pub fn percent_consumed(observed: u64, limit: u64) -> u8 {
    // A ceiling of zero is reached by anything at all, including nothing. `evaluate` catches that as
    // a breach before this is called; reported as 100 rather than dividing by zero.
    let ratio = observed
        .saturating_mul(100)
        .checked_div(limit)
        .unwrap_or(100);
    u8::try_from(ratio.min(100)).unwrap_or(100)
}

/// Decide where `usage` stands against `horizon`.
///
/// Breach outranks escalation, and escalation outranks `Within`: a warrant that is over one ceiling
/// and merely near another must halt rather than ask. Dimensions are checked in
/// [`HorizonDimension::ALL`] order, so a run that reaches two ceilings in the same instant reports
/// the same one every time.
#[must_use]
pub fn evaluate(horizon: &Horizon, usage: &HorizonUsage) -> HorizonVerdict {
    for dimension in HorizonDimension::ALL {
        if let Some(limit) = limit_of(horizon, dimension) {
            let observed = usage.observed(dimension);
            if observed >= limit {
                return HorizonVerdict::Breached {
                    dimension,
                    limit,
                    observed,
                };
            }
        }
    }

    let mut nearest: Option<(HorizonDimension, u8)> = None;
    for dimension in HorizonDimension::ALL {
        if let Some(limit) = limit_of(horizon, dimension) {
            let percent = percent_consumed(usage.observed(dimension), limit);
            if nearest.is_none_or(|(_, best)| percent > best) {
                nearest = Some((dimension, percent));
            }
        }
    }

    if let (Some(threshold), Some((dimension, percent))) = (horizon.escalate_at_percent, nearest) {
        if percent >= threshold {
            return HorizonVerdict::Escalate {
                dimension,
                at_percent: threshold,
                limit: limit_of(horizon, dimension).unwrap_or(0),
                observed: usage.observed(dimension),
            };
        }
    }

    HorizonVerdict::Within { nearest }
}

/// The deadline the supervisor should actually wait until: the earlier of the warrant's `expires_at`
/// and the horizon's wall-clock ceiling measured from issue.
///
/// This is the whole of the composition with `supervise.rs`. The supervisor's wait budget is
/// `deadline - now`; handing it a smaller deadline is how a horizon reaches an OS process link
/// without re-implementing one. It can only move the deadline **in** — `min` rather than the
/// horizon's own value — because a horizon that could extend a deadline would be an authority
/// expansion wearing a governor's name.
#[must_use]
pub fn effective_deadline(bounds: &WarrantBounds, issued_at: u64) -> u64 {
    let Some(horizon) = &bounds.horizon else {
        return bounds.expires_at;
    };
    let Some(seconds) = horizon.max_wall_seconds else {
        return bounds.expires_at;
    };
    bounds.expires_at.min(issued_at.saturating_add(seconds))
}

/// Read what a warrant has used, from the store and from the caller's live counters.
///
/// `staged_path` is this warrant's staged-effect log, or `None` when the caller has no store path
/// for it; an unreadable or absent log contributes **zero** staged effects, which is honest about
/// what was read and is why the effect figure is documented as a floor. `forwarded` is the live
/// session's forwarded-call count, which only a caller holding the proxy can supply — the
/// supervision loop cannot, because there is no daemon IPC.
///
/// The unattended clock runs from the later of the warrant's issue time and the most recent actor
/// log entry that carries a **name**. An entry with `actor: None` is the unscoped session token and
/// is skipped: counting it would let an agent's own session pass for human contact.
#[must_use]
pub fn usage_at(
    root: &Path,
    warrant_id: &str,
    issued_at: u64,
    staged_path: Option<&Path>,
    forwarded: u64,
    now: u64,
) -> HorizonUsage {
    let staged = staged_path
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map_or(0, |body| {
            u64::try_from(body.lines().filter(|line| !line.trim().is_empty()).count())
                .unwrap_or(u64::MAX)
        });
    usage_counted(root, warrant_id, issued_at, staged, forwarded, now)
}

/// The same measurement for a caller that has already opened the staging queue and knows its length.
///
/// [`usage_at`] re-reads the log from disk; a report surface has the queue in hand, and re-reading it
/// would be a second count that could disagree with the one the rest of the bundle is built from.
/// One measurement, so a bundle's `staged_count` and its horizon's effect figure cannot differ.
///
/// `staged` of zero from a caller whose queue was *unreadable* is the same number as zero from a
/// caller whose queue was empty. That is not hidden: it is why the effect figure is documented as a
/// floor in [`EFFECT_COUNT_LIMITATION`], and why the bundle reports `staged_count: None` separately
/// so a reader can tell the two apart.
#[must_use]
pub fn usage_counted(
    root: &Path,
    warrant_id: &str,
    issued_at: u64,
    staged: u64,
    forwarded: u64,
    now: u64,
) -> HorizonUsage {
    // An act recorded BEFORE the warrant was issued cannot shorten the run's own age: the run
    // started at issue, so the clock starts there and a named act can only move it forward.
    let last_named = crate::operators::read_log(root, warrant_id)
        .unwrap_or_default()
        .into_iter()
        .filter(|record| record.actor.is_some())
        .map(|record| record.at)
        .filter(|at| *at <= now)
        .max()
        .unwrap_or(0);
    let contact = issued_at.max(last_named);

    HorizonUsage {
        elapsed_seconds: now.saturating_sub(issued_at),
        effects: staged.saturating_add(forwarded),
        unattended_seconds: now.saturating_sub(contact),
    }
}

/// The sentence a record carries when a horizon halted a run.
///
/// Greppable on purpose: a stop with no reason is indistinguishable from a crash, and
/// `CompletionRecord::expired` is one boolean for three dimensions.
#[must_use]
pub fn breach_reason(dimension: HorizonDimension, limit: u64, observed: u64) -> String {
    format!(
        "horizon:{} reached its ceiling (limit {limit}, observed {observed}); the run was \
         terminated and the warrant voided on breach",
        dimension.word()
    )
}

/// The blocker string an escalation records, for `review::record_request` and `review::should_announce`.
///
/// Carries the dimension and the threshold so a second escalation on a *different* dimension is a
/// new announcement rather than a duplicate of the first.
#[must_use]
pub fn escalation_blocker(dimension: HorizonDimension, at_percent: u8) -> String {
    format!(
        "horizon:{}:{at_percent}pct -- this run has consumed {at_percent}% of its {} ceiling. \
         Extending the horizon is a decision someone has to take; nothing extends it by default.",
        dimension.word(),
        dimension.field()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dimensions_word_and_field_never_collide() {
        let words: std::collections::BTreeSet<_> =
            HorizonDimension::ALL.iter().map(|d| d.word()).collect();
        assert_eq!(words.len(), HorizonDimension::ALL.len());
        let fields: std::collections::BTreeSet<_> =
            HorizonDimension::ALL.iter().map(|d| d.field()).collect();
        assert_eq!(fields.len(), HorizonDimension::ALL.len());
    }

    #[test]
    fn a_ceiling_of_zero_is_breached_by_nothing_at_all_rather_than_dividing_by_zero() {
        let horizon = Horizon {
            max_effects: Some(0),
            ..Horizon::none()
        };
        // ATTACK: a ceiling of zero. Reached immediately, and no panic.
        match evaluate(&horizon, &HorizonUsage::default()) {
            HorizonVerdict::Breached {
                limit, observed, ..
            } => {
                assert_eq!((limit, observed), (0, 0));
            }
            other => panic!("a ceiling of zero permitted an effect: {other:?}"),
        }
        // CONTROL: a ceiling of one is not breached by nothing.
        let one = Horizon {
            max_effects: Some(1),
            ..Horizon::none()
        };
        assert!(matches!(
            evaluate(&one, &HorizonUsage::default()),
            HorizonVerdict::Within { .. }
        ));
    }

    #[test]
    fn percent_never_exceeds_one_hundred() {
        assert_eq!(percent_consumed(4_000, 10), 100);
        assert_eq!(percent_consumed(5, 10), 50);
        assert_eq!(percent_consumed(0, 10), 0);
        // A ceiling of zero reports full rather than dividing by zero.
        assert_eq!(percent_consumed(0, 0), 100);
    }
}

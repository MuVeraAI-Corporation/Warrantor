//! Task 13.7 — what a scored agent can reach of the machinery that scores it, and the monitor that
//! trends its probing.
//!
//! # What this module is, said before anything else
//!
//! **It attributes. It does not contain.** There is no network namespace, no seccomp filter and no
//! firewall anywhere in this repository, so every containment property below either composes with an
//! external sandbox this process cannot verify was started, or is held by nothing at all. This
//! module's job is to say which, per property, in the vocabulary the rest of the product already
//! uses ([`crate::BoundStrength`]) and without inventing a fourth word.
//!
//! # Why a grader needs its own module
//!
//! A grader an agent can reach is a grader the agent will optimize. In this product the grader's
//! inputs are `~/.warrantor/guard/<id>.jsonl` and `~/.warrantor/runs/<id>.jsonl`
//! ([`crate::store`]), and the thing that becomes a training label is a *warrant state transition*
//! ([`crate::corpus`] derives `Void -> true`, `Settled -> false`). So the surfaces worth checking
//! are: can the scored process write the scorer's inputs, read the scorer's credentials, reach the
//! scorer over the network, and can it settle its own warrant.
//!
//! # The three properties, and why exactly one of them can reach `Enforced`
//!
//! * [`SCORER_INPUTS_NOT_WRITABLE`] — `Enforced` only when **two** facts hold at once: a confinement
//!   profile is in force, and the store root is not inside the worktree. Under
//!   `warrantor sandbox --kind bubblewrap` the profile binds `/` read-only with the worktree as the
//!   sole read-write hole, so a write to the guard log fails with `EROFS` at the syscall — held by
//!   the operating system, not by us. With no profile, or with a store the operator placed inside
//!   the worktree, it is `Observed`.
//! * [`SCORER_CREDENTIALS_NOT_READABLE`] — **no tier word at all.** `--ro-bind / /` leaves `$HOME`
//!   readable and `~/.warrantor/keys/settle.key` with it. Read-only is not unreadable, same UID is
//!   same UID, and nothing in this repository refuses that read. It is not `Observed`, because
//!   "observed" implies something measures it and nothing looks.
//! * [`SCORER_NOT_REACHABLE_OVER_NETWORK`] — `Enforced` on an empty egress allowlist under a
//!   profile, because that is the one case `crate::sandbox` emits `--unshare-net`; `Mediated`
//!   otherwise, held at the MCP proxy, which a shell reaches past.
//!
//! # The monitor is `Observed` and cannot be anything else
//!
//! [`trend`] reads durable logs after the fact. Nothing in it refuses an action as it happens.
//! L11-12's own words are *"advisory to the humans, mandatory as a stop trigger"* — the second
//! clause is a duty on a person, not a mechanism in this code, and [`Escalation::note`] says which.
//!
//! # No new trust root
//!
//! There is no registry of approved graders and no central escalation service. [`escalate`] reuses
//! the local [`crate::operators::OperatorRegistry`], which is a weaker guarantee than an independent
//! trust domain, and the escalation record states it in as many words.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use warrantor_eval_guard::{
    run_preflight, CheckResults, EvalGuardError, Provenance, SandboxAttestation,
};

use crate::operators::{OperatorRegistry, Scope};
use crate::sandbox::Confinement;
use crate::{BoundStrength, WarrantBounds};

/// Wire format of one registered threshold.
pub const THRESHOLD_FORMAT: &str = "warrantor.scorer-threshold/1";

/// Wire format of one escalation line.
pub const ESCALATION_FORMAT: &str = "warrantor.scorer-escalation/1";

/// The property name for the write direction on the scorer's inputs.
pub const SCORER_INPUTS_NOT_WRITABLE: &str = "scorer_inputs_not_writable";

/// The property name for the read direction on the scorer's signing credential.
pub const SCORER_CREDENTIALS_NOT_READABLE: &str = "scorer_credentials_not_readable";

/// The property name for network reachability of the scorer.
pub const SCORER_NOT_REACHABLE_OVER_NETWORK: &str = "scorer_not_reachable_over_network";

/// The sentence that ships wherever an isolation record is rendered.
///
/// In a constant rather than at each call site, for the reason [`crate::sandbox::PROFILE_CAVEAT`]
/// is: the person who most needs it is the one about to act on the record, and four copies of one
/// sentence become four different sentences.
pub const ISOLATION_RECORD_CAVEAT: &str =
    "This record states which party held each isolation property and by what mechanism. It does not \
     establish that the sandbox was launched: no netns, seccomp or firewall is implemented here, \
     the filesystem property is held by an operating system this process cannot interrogate, and \
     the scorer's signing key remains readable to any process running as the same user.";

/// Who holds an isolation property.
///
/// Three cases and not two, for the same reason [`BoundStrength`] has three tiers: "we hold it" and
/// "the kernel holds it" are different promises, and "nothing holds it" is a third thing that must
/// not be written as a weak version of either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HeldBy {
    /// The operating system refuses it, by the named mechanism. Not us, and not verifiable here.
    Os {
        /// The mechanism, named so a reader can go and check it on their own host.
        mechanism: String,
    },
    /// Code in this repository decides it. Real against an agent using its tools; not containment.
    OurCode,
    /// Nothing holds it. Not measured, not refused, not contained.
    NothingYet,
}

impl HeldBy {
    /// The word a listing renders.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Self::Os { .. } => "operating system",
            Self::OurCode => "warrantor",
            Self::NothingYet => "NOTHING",
        }
    }
}

/// One isolation property, with the tier that actually holds it and who holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Property {
    /// The property's stable name.
    pub name: String,
    /// The tier, or `None` when no tier word applies.
    ///
    /// `Option` rather than a fourth [`BoundStrength`] variant, and rather than `Observed`:
    /// `scorer_credentials_not_readable` is held by nothing and measured by nothing, and writing
    /// `observed` there would claim a measurement that does not exist. A renderer that finds `None`
    /// prints the gap and no tier word.
    pub strength: Option<BoundStrength>,
    /// Who holds it.
    pub held_by: HeldBy,
    /// What this property does NOT cover. Never empty — a tier word alone is read at full strength.
    pub not_covered: String,
}

/// How wide a property name column has to be.
///
/// [`render_bound`] pads to 24, which is right for the bound names it was written for
/// (`budget_cents_observed` is the longest at 21). `scorer_credentials_not_readable` is 31, so
/// `render_bound` would emit the name and the tier word with no space between them — which is
/// exactly what the first run of `warrantor scorer` printed. The tier WORD still comes from
/// [`BoundStrength::word`], the single vocabulary, and `render_matches_the_shared_tier_vocabulary`
/// pins the two equal.
const NAME_COLUMN: usize = 34;

impl Property {
    /// The one line a listing prints, in the product's own tier vocabulary.
    #[must_use]
    pub fn render(&self) -> String {
        let tier = match self.strength {
            Some(strength) => strength.word(),
            // Not "observed", and not blank. Nothing measures this property and nothing refuses it,
            // and a blank column would be read as a rendering bug rather than as the answer.
            None => "no tier -- held by nothing",
        };
        format!("{:<NAME_COLUMN$}{tier}", self.name)
    }
}

/// Which of this module's properties an `eval-guard` boundary name stands for here.
///
/// Public, and used by the surface that renders a refusal, so the sentence a reader sees is derived
/// from the boundary that actually failed rather than written beside it. The first run of
/// `warrantor scorer` printed `boundary check failed: NetworkIsolation` above a paragraph explaining
/// `ProcessIsolation` — the same defect Task 9.1 shipped, in a new place, and it is why this mapping
/// is a function rather than a comment.
#[must_use]
pub fn property_behind(check: warrantor_eval_guard::BoundaryCheck) -> &'static str {
    use warrantor_eval_guard::BoundaryCheck;
    match check {
        BoundaryCheck::NetworkIsolation | BoundaryCheck::EgressAttestation => {
            SCORER_NOT_REACHABLE_OVER_NETWORK
        }
        BoundaryCheck::FilesystemBoundary => SCORER_INPUTS_NOT_WRITABLE,
        BoundaryCheck::ProcessIsolation => SCORER_CREDENTIALS_NOT_READABLE,
    }
}

/// The three properties, evaluated against a warrant's bounds and a confinement choice.
///
/// `confinement` is what the operator says is in force, and `None` means none. This process cannot
/// verify either answer — `crate::sandbox` states that about itself and it is no more true here —
/// so a record built from this is tagged [`Provenance::Asserted`] by [`preflight`] and never
/// `Measured`.
///
/// `store_root` and `worktree` decide the `Enforced` case of the first property together: a store
/// the operator placed *inside* the worktree sits in the profile's one read-write hole, and a check
/// that assumed otherwise would report `Enforced` over a writable grader input.
#[must_use]
pub fn isolation(
    bounds: &WarrantBounds,
    confinement: Option<Confinement>,
    store_root: &Path,
    worktree: &Path,
) -> Vec<Property> {
    let store_inside_worktree = normalise(store_root).starts_with(&normalise(worktree));

    let inputs = match (confinement, store_inside_worktree) {
        (Some(kind), false) => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Enforced),
            held_by: HeldBy::Os {
                mechanism: format!(
                    "{} binds / read-only with {} as the only read-write hole, so a write to \
                     {}/guard/*.jsonl fails with EROFS at the syscall",
                    kind.word(),
                    worktree.display(),
                    store_root.display()
                ),
            },
            not_covered: format!(
                "this process did not launch the {} profile and cannot tell whether you did; if the \
                 agent runs unconfined, the same UID writes the same files and nothing refuses it. \
                 The tier is Enforced GIVEN a launched profile, and that is an assertion you are \
                 making, not a measurement this code took. It also says nothing about reads: the \
                 read-only root leaves every one of those files readable.",
                kind.word()
            ),
        },
        (Some(kind), true) => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Observed),
            held_by: HeldBy::OurCode,
            not_covered: format!(
                "the store root {} is INSIDE the worktree {}, which is the one path a {} profile \
                 binds read-write -- so the profile you are about to launch opens a read-write hole \
                 over the grader's own inputs. Nothing refuses a write to them. Move the store \
                 outside the worktree (the default ~/.warrantor already is) to reach Enforced.",
                store_root.display(),
                worktree.display(),
                kind.word()
            ),
        },
        (None, _) => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Observed),
            held_by: HeldBy::OurCode,
            not_covered:
                "no confinement is in force, so nothing refuses a write to the guard and run logs \
                 as it happens: same UID is same UID. What is measured, and it is thin: a line \
                 edited badly enough not to parse is counted in `unreadable_lines` and reported by \
                 `warrantor holdings`, and a deleted run file makes an unguarded run \
                 indistinguishable from a run that never happened. A careful edit is invisible. \
                 Compose with `warrantor sandbox` to reach Enforced."
                    .to_string(),
        },
    };

    let credentials = Property {
        name: SCORER_CREDENTIALS_NOT_READABLE.to_string(),
        strength: None,
        held_by: HeldBy::NothingYet,
        not_covered: format!(
            "there is no bound here at all. {}/keys/settle.key -- the key that releases staged \
             effects for real -- is readable to any process running as this user, a confinement \
             profile included: `--ro-bind / /` mounts $HOME and read-only is not unreadable. \
             Nothing in this repository refuses that read at any tier, and nothing measures it \
             either, which is why this property carries no tier word rather than `observed`. What \
             would hold it is a separate user account for the store, or a sandbox invocation that \
             binds the store as a tmpfs instead of inheriting it from the read-only root.",
            store_root.display()
        ),
    };

    let network = match confinement.filter(|_| bounds.egress_hosts.is_empty()) {
        Some(kind) => Property {
            name: SCORER_NOT_REACHABLE_OVER_NETWORK.to_string(),
            strength: Some(BoundStrength::Enforced),
            held_by: HeldBy::Os {
                mechanism: format!(
                    "the warrant grants no egress, so the {} profile unshares the network \
                     namespace and there is no route out even for a process that never touches the \
                     MCP proxy",
                    kind.word()
                ),
            },
            not_covered: format!(
                "{} And a namespace is all-or-nothing: this reading holds only because the warrant \
                 grants ZERO hosts. Grant one and the namespace is deliberately not emitted, \
                 because emitting it would deny egress the warrant permits.",
                BoundStrength::Enforced.caveat()
            ),
        },
        None => Property {
            name: SCORER_NOT_REACHABLE_OVER_NETWORK.to_string(),
            strength: Some(BoundStrength::Mediated),
            held_by: HeldBy::OurCode,
            not_covered: format!(
                "{}. This warrant permits {} host(s), or no confinement is in force, so no network \
                 namespace is emitted and the scorer is reachable by anything that can open a \
                 socket.",
                BoundStrength::Mediated.caveat(),
                bounds.egress_hosts.len()
            ),
        },
    };

    vec![inputs, credentials, network]
}

/// Compare two paths without caring about separators or case on Windows.
fn normalise(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/").to_lowercase()
}

/// Fail closed over the properties, reusing `eval-guard` rather than re-deciding.
///
/// # The mapping onto `eval-guard`'s four checks, including the one that is a stretch
///
/// `eval-guard` was written with four boundary names and this product has three facts, so the
/// mapping is stated rather than inferred:
///
/// | `eval-guard` check | this module's property |
/// |---|---|
/// | `NetworkIsolation` | [`SCORER_NOT_REACHABLE_OVER_NETWORK`] |
/// | `EgressAttestation` | [`SCORER_NOT_REACHABLE_OVER_NETWORK`] — the same fact; there is one |
/// | `FilesystemBoundary` | [`SCORER_INPUTS_NOT_WRITABLE`] |
/// | `ProcessIsolation` | [`SCORER_CREDENTIALS_NOT_READABLE`] |
///
/// The last is the least comfortable of the four and is named as such: `ProcessIsolation` was
/// written about process boundaries, and the closest fact this product has is whether the scorer's
/// signing credential is out of the scored process's reach — which is the property that decides
/// whether "a separate process" means anything at all here. Since that property is held by nothing,
/// **`preflight` over this product's own `isolation()` output always refuses**, and it names
/// `ProcessIsolation` as the boundary that failed. That is the honest answer and it is the point:
/// invariant I-09 says failure is safe, and a preflight that passed here would be signing the gap.
///
/// The provenance is always [`Provenance::Asserted`] by this function's own construction. A
/// confinement choice is something an operator tells this process; nothing here measures a kernel.
///
/// # Errors
/// [`EvalGuardError::CheckFailed`] naming the first boundary that is not `Enforced`. A property
/// missing from `properties` is a failure too: an absent limit is none, never unlimited.
pub fn preflight(
    properties: &[Property],
    asserted_by: &str,
    key: &SigningKey,
) -> Result<SandboxAttestation, EvalGuardError> {
    let enforced = |name: &str| {
        properties
            .iter()
            .find(|p| p.name == name)
            .is_some_and(|p| p.strength == Some(BoundStrength::Enforced))
    };
    let results = CheckResults {
        network_isolation: enforced(SCORER_NOT_REACHABLE_OVER_NETWORK),
        filesystem_boundary: enforced(SCORER_INPUTS_NOT_WRITABLE),
        process_isolation: enforced(SCORER_CREDENTIALS_NOT_READABLE),
        egress_attestation: enforced(SCORER_NOT_REACHABLE_OVER_NETWORK),
    };
    run_preflight(
        &results,
        &Provenance::Asserted {
            by: asserted_by.to_string(),
        },
        key,
    )
}

// ── the reward-hacking monitor ────────────────────────────────────────────────────────

/// A threshold registered before a run, and never rewritten.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisteredThreshold {
    /// Wire format.
    #[serde(default = "default_threshold_format")]
    pub format: String,
    /// Refusals per run at or above which the trend has crossed.
    pub rate: f64,
    /// When it was registered, epoch seconds. Compared against every run's start.
    pub registered_at: u64,
    /// The digest of the evaluation bill of materials this threshold was set against.
    ///
    /// `None` until **Task 13.5** exists. Named with its owner rather than faked: a field
    /// containing a plausible digest that nothing produced is worse than a field containing `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_digest: Option<String>,
}

fn default_threshold_format() -> String {
    THRESHOLD_FORMAT.to_string()
}

/// Probing rate per graded warrant, ordered by that warrant's first run.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbingTrend {
    /// `(warrant id, refusals per run)`, ordered by the warrant's earliest run start.
    pub per_run: Vec<(String, f64)>,
    /// The first warrant, in that order, whose rate reached the threshold.
    pub crossed: Option<String>,
    /// The threshold this was measured against.
    pub threshold: f64,
    /// When the threshold was registered.
    pub registered_at: u64,
    /// The evaluation bill of materials, when one exists. See [`RegisteredThreshold::bom_digest`].
    pub bom_digest: Option<String>,
}

/// One escalation, addressed to a named local principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Escalation {
    /// Wire format.
    pub format: String,
    /// Who it was addressed to: an operator holding `Stop` and not `Settle`.
    pub to: String,
    /// The warrant whose probing rate crossed.
    pub warrant_id: String,
    /// That warrant's measured rate.
    pub rate: f64,
    /// The threshold it crossed.
    pub threshold: f64,
    /// When the threshold was registered, which must precede every run it is applied to.
    pub registered_at: u64,
    /// The evaluation bill of materials, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bom_digest: Option<String>,
    /// When the escalation was recorded.
    pub at: u64,
    /// What this escalation does NOT establish.
    pub note: String,
}

/// The sentence every escalation carries.
pub const ESCALATION_NOTE: &str =
    "This escalation reached a named local principal holding Stop and not Settle. It does not \
     establish that the principal is independent of the environment being graded: the registry is a \
     file on this machine, and an operator token is a token rather than a person. It is also \
     ADVISORY -- nothing in this code stops the run or quarantines a checkpoint. The quarantine \
     L11-12 asks for is Task 12.6's; the stop is a duty on the human named above.";

/// Why an escalation or a trend was refused.
#[derive(Debug, Error, PartialEq)]
pub enum ScorerError {
    /// The trend did not cross, so there is nothing to escalate.
    #[error(
        "no warrant's probing rate reached the registered threshold, so there is nothing to \
         escalate. An escalation recorded anyway would train its reader to ignore the next one."
    )]
    NotCrossed,
    /// No registered operator holds `Stop` without also holding `Settle`.
    #[error(
        "no registered operator holds Stop without also holding Settle, so there is nobody to \
         escalate to who is not the party releasing the work being graded. Refusing rather than \
         falling back: telling the settler that its own settle is the suspect label is worse than \
         telling nobody. Register an environment owner: warrantor operator add env-owner --scope \
         stop --note \"...\""
    )]
    NoEnvironmentOwner,
    /// A run started before the threshold was registered.
    #[error(
        "run {run_at} started before the threshold was registered at {registered_at}, so this \
         threshold cannot be applied to it. L11-12's whole point is that the threshold is \
         registered BEFORE the run and never tuned after; a threshold chosen once the traces are in \
         is a rationalisation with a number on it."
    )]
    ThresholdRegisteredAfterTheRun {
        /// The offending run's start.
        run_at: u64,
        /// When the threshold was registered.
        registered_at: u64,
    },
    /// A threshold already exists and this module will not rewrite it.
    #[error(
        "a threshold is already registered at {path} (rate {rate}, registered {registered_at}). \
         Refusing to overwrite it: a threshold that can be rewritten after the run is not a \
         registered threshold. Delete it deliberately if the whole experiment is being restarted."
    )]
    ThresholdAlreadyRegistered {
        /// Where it lives.
        path: String,
        /// Its rate.
        rate: f64,
        /// When it was registered.
        registered_at: u64,
    },
    /// The threshold file exists and will not parse, or an escalation could not be written.
    #[error("{0}")]
    Io(String),
}

/// Where the registered threshold lives.
#[must_use]
pub fn threshold_path(root: &Path) -> PathBuf {
    root.join("scorer").join("threshold.json")
}

/// Where escalations are appended.
#[must_use]
pub fn escalation_log_path(root: &Path) -> PathBuf {
    root.join("scorer").join("escalations.jsonl")
}

/// Register a threshold, refusing to replace one that exists.
///
/// # Errors
/// [`ScorerError::ThresholdAlreadyRegistered`] when one is already on disk, or
/// [`ScorerError::Io`].
pub fn register_threshold(
    root: &Path,
    rate: f64,
    at: u64,
    bom_digest: Option<String>,
) -> Result<RegisteredThreshold, ScorerError> {
    let path = threshold_path(root);
    if let Some(existing) = read_threshold(root)? {
        return Err(ScorerError::ThresholdAlreadyRegistered {
            path: path.display().to_string(),
            rate: existing.rate,
            registered_at: existing.registered_at,
        });
    }
    let threshold = RegisteredThreshold {
        format: THRESHOLD_FORMAT.to_string(),
        rate,
        registered_at: at,
        bom_digest,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ScorerError::Io(format!("cannot create {}: {e}", parent.display())))?;
    }
    let body = serde_json::to_vec_pretty(&threshold)
        .map_err(|e| ScorerError::Io(format!("cannot serialise the threshold: {e}")))?;
    std::fs::write(&path, &body)
        .map_err(|e| ScorerError::Io(format!("cannot write {}: {e}", path.display())))?;
    Ok(threshold)
}

/// Read the registered threshold, or `None` when none is registered.
///
/// A file that exists and will not parse is an **error**, never `None`: treating it as absent would
/// silently remove the one ordering constraint that makes the number evidence.
///
/// # Errors
/// [`ScorerError::Io`] when the file exists and will not parse.
pub fn read_threshold(root: &Path) -> Result<Option<RegisteredThreshold>, ScorerError> {
    let path = threshold_path(root);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ScorerError::Io(format!(
                "cannot read {}: {e}",
                path.display()
            )))
        }
    };
    let threshold: RegisteredThreshold = serde_json::from_str(&raw).map_err(|e| {
        ScorerError::Io(format!(
            "{} is not a readable registered threshold ({e}). Refusing to treat it as absent: that \
             would drop the before-the-run ordering this number depends on.",
            path.display()
        ))
    })?;
    Ok(Some(threshold))
}

/// Probing rate per graded warrant, from durable logs only.
///
/// The rate is refusals per run: `crate::serve::read_refusals` counts what a bound refused, and
/// `crate::runs::read_all` counts how many supervised sessions there were. A warrant with refusals
/// and no recorded run is reported at its refusal count rather than divided by zero, because the
/// alternative — dropping it — would hide the noisiest case.
#[must_use]
pub fn trend(root: &Path, threshold: &RegisteredThreshold) -> ProbingTrend {
    let runs = crate::runs::read_all(root);
    let mut runs_per_warrant: BTreeMap<String, (u32, u64)> = BTreeMap::new();
    for record in &runs.records {
        let entry = runs_per_warrant
            .entry(record.warrant_id.clone())
            .or_insert((0, record.at));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.min(record.at);
    }

    let mut ordered: Vec<(String, f64, u64)> = Vec::new();
    for (warrant_id, (run_count, first_at)) in &runs_per_warrant {
        let refusals: u64 = crate::serve::read_refusals(root, warrant_id)
            .records
            .iter()
            .map(|r| u64::from(r.count))
            .sum();
        let rate = if *run_count == 0 {
            #[allow(clippy::cast_precision_loss)]
            let refusals_as_rate = refusals as f64;
            refusals_as_rate
        } else {
            #[allow(clippy::cast_precision_loss)]
            let ratio = refusals as f64 / f64::from(*run_count);
            ratio
        };
        ordered.push((warrant_id.clone(), rate, *first_at));
    }
    // By the run's own clock, then by id so two runs in the same second order the same way twice.
    ordered.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));

    let crossed = ordered
        .iter()
        .find(|(_, rate, _)| *rate >= threshold.rate)
        .map(|(id, _, _)| id.clone());

    ProbingTrend {
        per_run: ordered
            .into_iter()
            .map(|(id, rate, _)| (id, rate))
            .collect(),
        crossed,
        threshold: threshold.rate,
        registered_at: threshold.registered_at,
        bom_digest: threshold.bom_digest.clone(),
    }
}

/// [`trend`], refusing a threshold that was registered after any run it would be applied to.
///
/// # Errors
/// [`ScorerError::ThresholdRegisteredAfterTheRun`] naming the earliest offending run.
pub fn trend_checked(
    root: &Path,
    threshold: &RegisteredThreshold,
) -> Result<ProbingTrend, ScorerError> {
    let runs = crate::runs::read_all(root);
    if let Some(earliest) = runs.records.iter().map(|r| r.at).min() {
        if earliest < threshold.registered_at {
            return Err(ScorerError::ThresholdRegisteredAfterTheRun {
                run_at: earliest,
                registered_at: threshold.registered_at,
            });
        }
    }
    Ok(trend(root, threshold))
}

/// Record an escalation, addressed to an operator who holds `Stop` and does **not** hold `Settle`.
///
/// # Why the addressee is chosen this way
///
/// [`crate::corpus`] turns a settle or a void into a training label. So the party holding
/// `Scope::Settle` is the party whose decision *becomes* the label — and an escalation that fell
/// back to them would be telling the labeller that its own label is the suspect one. There is no
/// silent fallback: with no such operator registered this refuses.
///
/// # Errors
/// [`ScorerError::NotCrossed`] when nothing crossed, [`ScorerError::NoEnvironmentOwner`] when no
/// registered operator holds `Stop` without `Settle`, or [`ScorerError::Io`].
pub fn escalate(
    root: &Path,
    trend: &ProbingTrend,
    registry: &OperatorRegistry,
    at: u64,
) -> Result<Escalation, ScorerError> {
    let Some(warrant_id) = trend.crossed.clone() else {
        return Err(ScorerError::NotCrossed);
    };
    let owner = registry
        .operators
        .iter()
        .find(|o| o.allows(Scope::Stop) && !o.allows(Scope::Settle))
        .ok_or(ScorerError::NoEnvironmentOwner)?;
    let rate = trend
        .per_run
        .iter()
        .find(|(id, _)| *id == warrant_id)
        .map_or(0.0, |(_, rate)| *rate);

    let escalation = Escalation {
        format: ESCALATION_FORMAT.to_string(),
        to: owner.name.clone(),
        warrant_id,
        rate,
        threshold: trend.threshold,
        registered_at: trend.registered_at,
        bom_digest: trend.bom_digest.clone(),
        at,
        note: ESCALATION_NOTE.to_string(),
    };

    let path = escalation_log_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ScorerError::Io(format!("cannot create {}: {e}", parent.display())))?;
    }
    let mut line = serde_json::to_string(&escalation)
        .map_err(|e| ScorerError::Io(format!("cannot serialise the escalation: {e}")))?;
    line.push('\n');
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| ScorerError::Io(format!("cannot open {}: {e}", path.display())))?;
    file.write_all(line.as_bytes())
        .map_err(|e| ScorerError::Io(format!("cannot append to {}: {e}", path.display())))?;
    Ok(escalation)
}

/// Read every escalation this store holds.
#[must_use]
pub fn read_escalations(root: &Path) -> Vec<Escalation> {
    let Ok(raw) = std::fs::read_to_string(escalation_log_path(root)) else {
        return Vec::new();
    };
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Escalation>(line).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SideEffectClass;

    const NOW: u64 = 1_786_000_000;
    const WORKTREE: &str = "/home/agent/repo/.warrantor/wrt_w1";

    fn bounds(egress: &[&str]) -> WarrantBounds {
        WarrantBounds {
            tools: ["github.create_pr"].into_iter().map(String::from).collect(),
            write_paths: ["src/**"].into_iter().map(String::from).collect(),
            egress_hosts: egress.iter().map(|s| (*s).to_string()).collect(),
            staged_classes: [SideEffectClass::Write].into_iter().collect(),
            expires_at: NOW + 3600,
            budget_cents_observed: Some(500),
            delegation_depth: 1,
        }
    }

    #[test]
    fn every_property_carries_a_caveat_and_only_an_os_mechanism_earns_enforced() {
        for confinement in [
            None,
            Some(Confinement::Bubblewrap),
            Some(Confinement::Firejail),
        ] {
            for egress in [vec![], vec!["api.github.com"]] {
                let properties = isolation(
                    &bounds(&egress),
                    confinement,
                    Path::new("/home/agent/.warrantor"),
                    Path::new(WORKTREE),
                );
                assert_eq!(properties.len(), 3);
                for property in &properties {
                    assert!(
                        !property.not_covered.is_empty(),
                        "{} ships with no caveat",
                        property.name
                    );
                    if property.strength == Some(BoundStrength::Enforced) {
                        assert!(
                            matches!(property.held_by, HeldBy::Os { .. }),
                            "{} claims Enforced without naming an operating-system mechanism",
                            property.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn with_no_confinement_nothing_is_enforced_and_one_property_is_held_by_nothing() {
        // The control that stops the check above being vacuously true: it has to discriminate
        // between two real cases, and this is the other one.
        let bare = isolation(
            &bounds(&[]),
            None,
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        );
        assert!(bare
            .iter()
            .all(|p| p.strength != Some(BoundStrength::Enforced)));
        assert!(bare.iter().any(|p| matches!(p.held_by, HeldBy::NothingYet)));

        // And with a confinement, two of the three DO reach Enforced -- so the assertion above is
        // about the confinement rather than about this function never returning Enforced.
        let confined = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        );
        assert_eq!(
            confined
                .iter()
                .filter(|p| p.strength == Some(BoundStrength::Enforced))
                .count(),
            2,
            "{confined:#?}"
        );
    }

    #[test]
    fn the_credentials_property_carries_no_tier_word_in_any_configuration() {
        // Rule 1 in the other direction: `observed` would claim a measurement, and nothing looks at
        // this read. The renderer must print no tier word rather than the weakest one.
        for confinement in [None, Some(Confinement::Bubblewrap)] {
            let properties = isolation(
                &bounds(&[]),
                confinement,
                Path::new("/home/agent/.warrantor"),
                Path::new(WORKTREE),
            );
            let credentials = properties
                .iter()
                .find(|p| p.name == SCORER_CREDENTIALS_NOT_READABLE)
                .expect("the credentials property is always present");
            assert_eq!(credentials.strength, None);
            assert_eq!(credentials.held_by, HeldBy::NothingYet);
            let line = credentials.render();
            for tier in ["enforced", "mediated", "observed"] {
                assert!(!line.contains(tier), "{line}");
            }
            assert!(line.contains("held by nothing"), "{line}");
        }
    }

    #[test]
    fn a_store_inside_the_worktree_is_not_enforced_even_under_a_confinement() {
        // The two-facts check. A profile binds the worktree read-write, so a store the operator put
        // inside it is inside the one hole -- and reporting Enforced there would be a bound label
        // over a writable grader input.
        let inside = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new("/home/agent/repo/.warrantor/wrt_w1/store"),
            Path::new(WORKTREE),
        );
        let inputs = inside
            .iter()
            .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
            .expect("present");
        assert_eq!(inputs.strength, Some(BoundStrength::Observed));
        assert!(inputs.not_covered.contains("INSIDE the worktree"));

        // CONTROL: the same call with the default store root DOES reach Enforced, so this test is
        // about the store's location rather than about the function refusing everything.
        let outside = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        );
        assert_eq!(
            outside
                .iter()
                .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
                .expect("present")
                .strength,
            Some(BoundStrength::Enforced)
        );
    }

    #[test]
    fn the_products_own_isolation_fails_the_preflight_and_names_the_credential_boundary() {
        let key = signing_key();

        // CONTROL: a hand-built set of three Enforced properties DOES sign, so the refusal below is
        // a gate rather than a brick.
        let all_enforced: Vec<Property> = [
            SCORER_INPUTS_NOT_WRITABLE,
            SCORER_CREDENTIALS_NOT_READABLE,
            SCORER_NOT_REACHABLE_OVER_NETWORK,
        ]
        .into_iter()
        .map(|name| Property {
            name: name.to_string(),
            strength: Some(BoundStrength::Enforced),
            held_by: HeldBy::Os {
                mechanism: "a hypothetical mechanism, in a test".to_string(),
            },
            not_covered: "this is a fixture and holds nothing".to_string(),
        })
        .collect();
        let attestation =
            preflight(&all_enforced, "operator:vj", &key).expect("control: three Enforced sign");
        assert_eq!(
            attestation.provenance,
            Provenance::Asserted {
                by: "operator:vj".to_string()
            },
            "a confinement choice is something an operator tells this process; nothing here \
             measured a kernel, so the record must never say Measured",
        );

        // The real thing: the best case this product can produce still fails, on the credential
        // boundary, because nothing holds it.
        let real = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        );
        let refused = preflight(&real, "operator:vj", &key);
        assert!(
            matches!(
                refused,
                Err(EvalGuardError::CheckFailed(
                    warrantor_eval_guard::BoundaryCheck::ProcessIsolation
                ))
            ),
            "{refused:?}",
        );
    }

    #[test]
    fn a_property_missing_from_the_set_is_a_refusal_rather_than_a_pass() {
        // The absent-limit rule: an absent property means none, never satisfied.
        let key = signing_key();
        let only_network = vec![Property {
            name: SCORER_NOT_REACHABLE_OVER_NETWORK.to_string(),
            strength: Some(BoundStrength::Enforced),
            held_by: HeldBy::Os {
                mechanism: "netns".to_string(),
            },
            not_covered: "fixture".to_string(),
        }];
        assert!(matches!(
            preflight(&only_network, "operator:vj", &key),
            Err(EvalGuardError::CheckFailed(
                warrantor_eval_guard::BoundaryCheck::FilesystemBoundary
            ))
        ));
    }

    fn signing_key() -> SigningKey {
        let mut rng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
        SigningKey::generate(&mut rng)
    }

    #[test]
    fn render_matches_the_shared_tier_vocabulary_and_leaves_a_gap_between_name_and_tier() {
        // Two things at once, and the second was a real defect: the first run of `warrantor scorer`
        // printed `scorer_inputs_not_writableobserved`, because `render_bound` pads to 24 and these
        // names are up to 31 characters. The tier WORD must still be the one the rest of the product
        // spells, which is what the first assertion pins.
        for strength in [
            BoundStrength::Enforced,
            BoundStrength::Mediated,
            BoundStrength::Observed,
        ] {
            let property = Property {
                name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
                strength: Some(strength),
                held_by: HeldBy::OurCode,
                not_covered: "fixture".to_string(),
            };
            let line = property.render();
            assert!(
                line.ends_with(
                    crate::render_bound("x", strength)
                        .trim_start_matches('x')
                        .trim()
                ),
                "the tier word must be the one render_bound prints: {line}"
            );
            assert!(
                line.contains(&format!("{SCORER_INPUTS_NOT_WRITABLE} ")),
                "the name and the tier word must not run together: {line:?}"
            );
        }
    }

    #[test]
    fn every_eval_guard_boundary_maps_to_a_property_this_module_produces() {
        // The mapping is a function so a rendered refusal can be derived from the boundary that
        // actually failed. This pins it total: a boundary with no property behind it would make the
        // renderer fall through to a sentence about a property that is not in the record.
        let names: Vec<String> = isolation(
            &bounds(&[]),
            None,
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        )
        .into_iter()
        .map(|p| p.name)
        .collect();
        for check in warrantor_eval_guard::BoundaryCheck::ALL {
            let behind = property_behind(check);
            assert!(
                names.iter().any(|n| n == behind),
                "{check:?} maps to {behind}, which isolation() does not produce: {names:?}"
            );
        }
    }

    #[test]
    fn the_isolation_caveat_names_the_three_things_that_are_not_implemented() {
        for fragment in ["netns", "seccomp", "firewall", "readable to any process"] {
            assert!(
                ISOLATION_RECORD_CAVEAT.contains(fragment)
                    || ISOLATION_RECORD_CAVEAT.contains("same user"),
                "the shipped sentence must name {fragment}"
            );
        }
        assert!(ISOLATION_RECORD_CAVEAT.contains("does not"));
    }
}

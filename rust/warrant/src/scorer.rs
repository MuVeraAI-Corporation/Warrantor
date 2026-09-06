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
//! * [`SCORER_INPUTS_NOT_WRITABLE`] — `Enforced` only when **four** facts hold at once: a confinement
//!   profile is asserted, a profile naming this worktree is one `crate::sandbox` will actually write
//!   (it refuses every path that is not an absolute POSIX path), the store root can be placed relative
//!   to the worktree at all, and it sits under **none** of the read-write holes that profile's own
//!   argv opens — the worktree, and the private `/tmp` both kinds mount. Then the profile mounts `/`
//!   read-only and a write to the guard log fails with `EROFS` at the syscall — held by the operating
//!   system, not by us. Anything short of all four is `Observed`, and the record says which fact was
//!   missing. The second, third and fourth of the four were reviewer findings: an `Enforced` tier
//!   naming a mechanism no command here can install, or naming "the only read-write hole" while the
//!   argv opened a second one over the store, is a label the mechanism does not back, and it is the
//!   worst defect this module can ship. The holes are read off the profile's argv
//!   ([`crate::sandbox::Profile::hole_over`]) rather than re-derived here. See [`isolation`].
//! * [`SCORER_CREDENTIALS_NOT_READABLE`] — **no tier word at all.** A read-only root (`--ro-bind / /`
//!   under bubblewrap, `--read-only=/` under firejail) leaves `$HOME` readable and
//!   `~/.warrantor/keys/settle.key` with it. Read-only is not unreadable, same UID is same UID, and
//!   nothing in this repository refuses that read. It is not `Observed`, because "observed" implies
//!   something measures it and nothing looks.
//! * [`SCORER_NOT_REACHABLE_OVER_NETWORK`] — `Enforced` only when the profile `crate::sandbox` writes
//!   for this worktree actually carries `--unshare-net` (or firejail's `--net=none`), which it does
//!   for an empty egress allowlist and never otherwise; `Mediated` otherwise, held at the MCP proxy,
//!   which a shell reaches past. The namespace is read off the profile's argv
//!   ([`crate::sandbox::Profile::unshares_network`]) rather than re-deciding `egress_hosts.is_empty()`
//!   beside it. The namespace comes out of the same profile as the read-only root, so it carries the
//!   same reachability condition — it carried the same false `Enforced` too, and was reported with it.
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

/// The half of the shipped caveat that is true of this repository whatever any record says.
///
/// This clause describes the *repository*, not the record: it is a statement about which mechanisms
/// exist in this source tree, which no per-record reading can change. Everything that varies with
/// the record is derived by [`isolation_caveat`] instead.
pub const ISOLATION_REPOSITORY_CAVEAT: &str =
    "It does not establish that any sandbox was launched: no netns, seccomp or firewall is \
     implemented anywhere in this repository, so every property above either composes with an \
     external sandbox this process cannot verify was started, or is held by nothing at all.";

/// The sentence that ships under a rendered isolation record, **derived from that record**.
///
/// # Why this is a function and was a constant
///
/// It shipped as a hardcoded literal stating "the filesystem property is held by an operating system
/// this process cannot interrogate" — printed verbatim under the DEFAULT unconfined record, whose own
/// derived lines two rows above say `scorer_inputs_not_writable observed`, `held by warrantor`, and
/// "nothing refuses a write to the guard and run logs as it happens". An independent reviewer caught
/// it. That is the Task 1.1 / Task 9.1 defect exactly — a sentence written *beside* the record
/// instead of read *out of* it — and it erred in the reassuring direction, telling a reader an
/// operating system held a property the record said warrantor held.
///
/// So the clauses that name a holder are now read from that property's own [`HeldBy`], and the only
/// literal left is [`ISOLATION_REPOSITORY_CAVEAT`], which describes the source tree rather than the
/// record. Centralization — the reason it was a constant — is preserved: this is still one function
/// and every renderer calls it.
///
/// An absent property is reported as absent rather than skipped: a caveat that silently drops a
/// clause reads as a shorter promise, not as a shorter record.
#[must_use]
pub fn isolation_caveat(properties: &[Property]) -> String {
    let clause = |name: &str, os: &str, ours: &str, nothing: &str| -> String {
        match properties.iter().find(|p| p.name == name) {
            Some(property) => match property.held_by {
                HeldBy::Os { .. } => os.to_string(),
                HeldBy::OurCode => ours.to_string(),
                HeldBy::NothingYet => nothing.to_string(),
            },
            None => format!(
                "{name} is ABSENT from this record, which is not the same thing as held -- read the \
                 record as incomplete"
            ),
        }
    };
    let filesystem = clause(
        SCORER_INPUTS_NOT_WRITABLE,
        "the filesystem property is held by an operating system this process cannot interrogate, so \
         the tier above is conditional on a profile you launched and this code did not",
        "the filesystem property is held by warrantor, which means nothing refuses a write to the \
         grader's inputs at the moment it happens: same UID is same UID",
        "nothing holds the filesystem property at all",
    );
    let credentials = clause(
        SCORER_CREDENTIALS_NOT_READABLE,
        "the scorer's signing key is out of reach only by the operating-system mechanism named \
         above, which this process did not launch and cannot check",
        "the scorer's signing key is guarded by warrantor's own code rather than by the operating \
         system",
        "the scorer's signing key remains readable to any process running as the same user",
    );
    format!(
        "This record states which party held each isolation property and by what mechanism. \
         {ISOLATION_REPOSITORY_CAVEAT} On THIS record: {filesystem}; and {credentials}."
    )
}

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
/// the operator placed *inside* a read-write hole the profile opens is a writable grader input, and
/// a check that assumed otherwise would report `Enforced` over it.
///
/// # The four ways an asserted confinement still does not earn `Enforced`
///
/// All four were reviewer findings against this function, and every one of them is a *label*
/// correction: the mechanism named in the `Enforced` sentence has to be reachable by some command in
/// this repository and has to be the mechanism the argv actually installs, or the word is not earned.
///
/// 1. **The worktree is one no confinement here will accept.** [`crate::sandbox::check_worktree`]
///    refuses any path that is not an absolute POSIX path, because `warrantor sandbox` will not print
///    "a command that LOOKS runnable and cannot be". `warrantor scorer --confined` printed
///    `enforced / held by operating system / ... fails with EROFS at the syscall` for exactly the
///    warrants on which `warrantor sandbox` exits 1 — every warrant granted on Windows, which is the
///    platform this task was developed and measured on. The tier was derived from an operator flag
///    and a string comparison; the named mechanism was unreachable by any command. It is now
///    conditioned on the same refusal `cmd_sandbox` uses, so the two commands agree.
/// 2. **The store root is not comparable to the worktree.** The inside/outside test is a string
///    prefix, and `--root` is taken verbatim while `StoredWarrant::worktree` is absolute. A store the
///    operator placed inside the worktree but named *relatively* is not a prefix of an absolute path,
///    so the check said "outside" and the record said `Enforced` over a store sitting in a read-write
///    hole. Rather than resolve the path against a working directory this function cannot see, an
///    uncomparable pair now fails closed and says which path it could not place.
/// 3. **The store is inside the worktree.** The original two-facts case.
/// 4. **The store is under `/tmp`, which the same profile replaces with a private writable tmpfs.**
///    The `Enforced` sentence called the worktree "the only read-write hole" while the argv it
///    described carried `--tmpfs /tmp` (bubblewrap) or `--private-tmp` (firejail): a second hole,
///    one the test suite's own helper already knew about and the production check did not. On a
///    Linux host `std::env::temp_dir()` is `/tmp`, so this was the store the CLI tests' own control
///    invocations would have used. The holes are now read off the profile's argv by
///    [`crate::sandbox::Profile::hole_over`] — the same reading for both — so cases 3 and 4 are one
///    check, and the record names the hole and the argument that opened it.
#[must_use]
pub fn isolation(
    bounds: &WarrantBounds,
    confinement: Option<Confinement>,
    store_root: &Path,
    worktree: &Path,
) -> Vec<Property> {
    // The same refusal `cmd_sandbox` applies before printing a profile. `Some(reason)` means no
    // confinement command in this repository can name this worktree, so no mechanism it would have
    // installed can be claimed.
    let unprofilable = crate::sandbox::check_worktree(&worktree.to_string_lossy()).err();
    // A prefix test is only meaningful between two paths of the same kind.
    let comparable = is_rooted(store_root) && is_rooted(worktree);
    // The profile `warrantor sandbox` would print for this warrant and worktree -- the argv every
    // operating-system claim below is read from. Only built when that command would print one.
    let profile = confinement
        .filter(|_| unprofilable.is_none())
        .map(|kind| crate::sandbox::profile(bounds, &worktree.to_string_lossy(), kind));
    // The read-write hole covering the store root, if the profile opens one over it.
    let hole = profile
        .as_ref()
        .and_then(|p| p.hole_over(&store_root.to_string_lossy()));
    let hole_is_the_worktree = hole
        .as_ref()
        .is_some_and(|h| normalize(Path::new(&h.path)) == normalize(worktree));

    let inputs = match confinement {
        Some(kind) if unprofilable.is_some() => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Observed),
            held_by: HeldBy::OurCode,
            not_covered: format!(
                "you asserted a {} profile, but no confinement this repository writes can name this \
                 worktree, so the operating-system mechanism that would hold this property cannot be \
                 installed by any command here: `warrantor sandbox {}` refuses the same path and \
                 exits 1. {} Until that is resolved the property is held by warrantor and nothing \
                 refuses a write to the grader's inputs as it happens. Grant the warrant on the host \
                 that will run the agent to reach Enforced.",
                kind.word(),
                worktree.display(),
                unprofilable.as_deref().unwrap_or_default(),
            ),
        },
        Some(_) if !comparable => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Observed),
            held_by: HeldBy::OurCode,
            not_covered: format!(
                "this record cannot place the store root {} relative to the worktree {}: one of the \
                 two is not an absolute path, and the inside/outside test is a prefix comparison. A \
                 store inside a read-write hole the profile opens is a writable grader input, so \
                 guessing 'outside' here would put an Enforced tier on one -- which is what this \
                 command did before, for any relative --root. Failing closed instead. Pass an \
                 absolute --root to get a decidable answer.",
                store_root.display(),
                worktree.display(),
            ),
        },
        Some(kind) if hole_is_the_worktree => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Observed),
            held_by: HeldBy::OurCode,
            not_covered: format!(
                "the store root {} is INSIDE the worktree {}, which the {} profile binds read-write \
                 ({}) -- so the profile you are about to launch opens a read-write hole over the \
                 grader's own inputs. Nothing refuses a write to them. Move the store outside the \
                 worktree (the default ~/.warrantor already is) to reach Enforced.",
                store_root.display(),
                worktree.display(),
                kind.word(),
                hole.as_ref().map(|h| h.opened_by.as_str()).unwrap_or_default()
            ),
        },
        Some(kind) if hole.is_some() => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Observed),
            held_by: HeldBy::OurCode,
            not_covered: format!(
                "the store root {} is under {}, which the {} profile mounts as a private writable \
                 tmpfs ({}). Inside the sandbox that mount starts EMPTY, so the host's copy of the \
                 store is shadowed rather than read-only: a write to the grader's inputs there \
                 SUCCEEDS into the tmpfs and is discarded at exit, and anything that runs inside the \
                 sandbox -- warrantor included -- reads the agent's copy. That is not a refusal at \
                 the syscall and it is not what the Enforced sentence describes. Move the store out \
                 of {} (the default ~/.warrantor already is) to reach Enforced.",
                store_root.display(),
                hole.as_ref().map(|h| h.path.as_str()).unwrap_or_default(),
                kind.word(),
                hole.as_ref().map(|h| h.opened_by.as_str()).unwrap_or_default(),
                hole.as_ref().map(|h| h.path.as_str()).unwrap_or_default(),
            ),
        },
        Some(kind) => Property {
            name: SCORER_INPUTS_NOT_WRITABLE.to_string(),
            strength: Some(BoundStrength::Enforced),
            held_by: HeldBy::Os {
                // Every path and flag in this sentence is read off the argv `warrantor sandbox`
                // prints for this warrant, not written beside it. It said "the only read-write
                // hole" of a command that opened two.
                mechanism: format!(
                    "{} mounts / read-only ({}) and opens read-write holes only at {}; {} is under \
                     none of them, so a write to {}/guard/*.jsonl fails with EROFS at the syscall",
                    kind.word(),
                    kind.read_only_root_flag(),
                    profile
                        .as_ref()
                        .map(|p| {
                            p.read_write_holes()
                                .iter()
                                .map(|h| format!("{} ({})", h.path, h.opened_by))
                                .collect::<Vec<_>>()
                                .join(" and ")
                        })
                        .unwrap_or_default(),
                    store_root.display(),
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
        None => Property {
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
             profile included: {} mounts $HOME and read-only is not unreadable. Nothing in this \
             repository refuses that read at any tier, and nothing measures it either, which is why \
             this property carries no tier word rather than `observed`. What would hold it is a \
             separate user account for the store, or a sandbox invocation that binds the store as a \
             tmpfs instead of inheriting it from the read-only root.",
            store_root.display(),
            // The flag is the asserted kind's own, or both when none is asserted: this cited
            // `--ro-bind / /` under the firejail profile, whose argv has no such flag.
            match confinement {
                Some(kind) => format!("`{}`", kind.read_only_root_flag()),
                None => "a read-only root (`--ro-bind / /` under bubblewrap, `--read-only=/` under \
                         firejail)"
                    .to_string(),
            }
        ),
    };

    // `--unshare-net` comes out of the same profile the filesystem bind does, so the same
    // reachability condition applies: a worktree no confinement here can name installs no namespace
    // either. This arm carried the identical false Enforced and was reported with it. Whether the
    // namespace is emitted is READ OFF the profile's argv rather than re-decided from
    // `egress_hosts.is_empty()` here: the two were the same expression written twice, and a
    // reviewer showed this copy could be deleted with every test still green.
    let namespaced = match (&profile, confinement) {
        (Some(p), Some(kind)) if p.unshares_network() => Some(kind),
        _ => None,
    };
    let network = match namespaced {
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
            // NOT the tier legend. This field shipped holding `BoundStrength::Enforced.caveat()`,
            // so the CLI printed the product's STRONGEST guarantee sentence under a `NOT` label --
            // read either as a negation of the guarantee or as an assertion of it, and the legend
            // is printed three lines below anyway. A reviewer caught it. What belongs here is what
            // a network namespace does not cover.
            not_covered: format!(
                "a network namespace is all-or-nothing, so this reading holds ONLY because the \
                 warrant grants ZERO hosts: grant one and the namespace is deliberately not \
                 emitted, because emitting it would deny egress the warrant permits. It covers \
                 sockets and nothing else -- the scorer's own files stay reachable through the \
                 read-only root, and its signing key with them. And like the filesystem bind it is \
                 conditional on a {} profile you launched and this process did not.",
                kind.word()
            ),
        },
        None => Property {
            name: SCORER_NOT_REACHABLE_OVER_NETWORK.to_string(),
            strength: Some(BoundStrength::Mediated),
            held_by: HeldBy::OurCode,
            // The reason is DERIVED and named, not offered as a disjunction. This read
            // "This warrant permits N host(s), or no confinement is in force" -- an `or` that left
            // the reader to guess which of the two applied to the record in front of them.
            not_covered: format!(
                "{}. No network namespace is emitted here, and the scorer is reachable by anything \
                 that can open a socket, because {}.",
                BoundStrength::Mediated.caveat(),
                if confinement.is_none() {
                    "no confinement is asserted at all".to_string()
                } else if let Some(reason) = &unprofilable {
                    format!(
                        "no confinement this repository writes can name the worktree {}: {reason}",
                        worktree.display()
                    )
                } else {
                    format!(
                        "this warrant permits {} host(s) and a namespace has no host allowlist, so \
                         emitting one would deny egress the warrant grants",
                        bounds.egress_hosts.len()
                    )
                }
            ),
        },
    };

    vec![inputs, credentials, network]
}

/// Compare two paths without caring about separators or case on Windows.
fn normalize(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/").to_lowercase()
}

/// Whether a path names a location on its own, so that a prefix comparison against another such path
/// means something.
///
/// Not [`Path::is_absolute`], deliberately: that answers for the *host this binary is running on*, so
/// `/home/agent/.warrantor` is "relative" on Windows and `M:\store` is "relative" on Linux. This
/// function is deciding whether two recorded strings can be placed relative to each other, which is a
/// question about the strings. Both POSIX roots and Windows drive roots count; anything else does not,
/// and [`isolation`] fails closed on it rather than guessing.
fn is_rooted(path: &Path) -> bool {
    let text = normalize(path);
    let bytes = text.as_bytes();
    text.starts_with('/') || (bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/')
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

/// The source string for a record where nobody asserted anything about a kernel.
///
/// With no confinement asserted, the four booleans handed to [`preflight`] are this command's own
/// reading of the store — no operator claimed a namespace, so naming one would attribute a claim
/// nobody made. It names the component instead. It is not a party and does not pretend to be, which is
/// why it says so in its own text: `Provenance::source()` is printed, and a reader who sees this string
/// has been told the assertion came from code reading files, not from a person.
pub const NO_CONFINEMENT_ASSERTER: &str =
    "warrantor-scorer (no confinement was asserted, so no party asserted these booleans: they are \
     this command's own reading of the store)";

/// Resolve the operator who asserted a confinement into the string that goes into the signed bytes.
///
/// # Why a registered name and not a free string
///
/// The first cut passed `format!("operator-at-cli:{id}")` — the id of the warrant being *graded*. That
/// names no party: it is the subject of the grading, not a principal to it, and
/// [`Provenance::Asserted`] documents its `by` field as the thing that exists to stop an anonymous
/// assertion. A reviewer caught it. The store already holds names, so this resolves against them and
/// refuses a name it cannot find rather than passing it through.
///
/// This buys no new trust root: the registry is a file on this machine and an operator token is a
/// token rather than a person, exactly as [`ESCALATION_NOTE`] says of the escalation path that reuses
/// it. What it buys is that the signed field names something a reviewer can look up.
///
/// # Errors
/// [`ScorerError::UnknownAsserter`] when no operator of that name is registered.
pub fn asserted_by(registry: &OperatorRegistry, name: &str) -> Result<String, ScorerError> {
    if registry.by_name(name).is_none() {
        return Err(ScorerError::UnknownAsserter {
            name: name.to_string(),
            registered: registry.operators.len(),
        });
    }
    Ok(format!("operator:{name}"))
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

impl RegisteredThreshold {
    /// Whether a measured rate has crossed this threshold: at or above, as [`Self::rate`] says.
    ///
    /// One comparison, and every reader of the threshold uses it. It was written twice — once in
    /// [`trend`] to decide `crossed`, once in `warrantor scorer` to print the `CROSSED` mark — and
    /// every fixture sat far from the line, so the first copy could become `>` with the shipped
    /// command still printing `CROSSED` on the row and then neither escalating nor refusing. A
    /// reviewer showed it through the binary. A boundary that is documented as "at or above" has
    /// to be tested at the boundary, and it has to be one function so the row and the escalation
    /// cannot disagree.
    #[must_use]
    pub fn crossed_by(&self, rate: f64) -> bool {
        rate >= self.rate
    }
}

/// Probing rate per graded warrant, ordered by that warrant's first run.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbingTrend {
    /// `(warrant id, refusals per run)`, ordered by the warrant's earliest run start — or, for a
    /// warrant that recorded refusals and no run, by its earliest refusal, and reported at its raw
    /// refusal count.
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
///
/// It said the escalation "reached" the principal. Nothing delivers it: [`escalate`] chooses the
/// name and appends one line to `scorer/escalations.jsonl`, and there is no notification path in
/// this module. The record is *addressed* to the principal, who learns of it by reading this store
/// or running `warrantor scorer`. The plan's wording was carried into a durable record without the
/// mechanism behind the verb, and a reviewer caught it.
pub const ESCALATION_NOTE: &str =
    "This escalation is ADDRESSED to a named local principal holding Stop and not Settle, and \
     recorded in scorer/escalations.jsonl. Nothing delivers it: no notification is sent, and the \
     principal learns of it only by reading this store or running `warrantor scorer`. It does not \
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
    /// The name given as the asserting party is not a registered operator.
    #[error(
        "{name:?} is not a registered operator, so the pre-flight has nobody to name as the party \
         asserting a confinement is in force ({registered} operator(s) are registered; \
         `warrantor operator list`). Refusing rather than signing the name through: the whole value \
         of that field is that a reviewer holding the attestation can go and look the party up."
    )]
    UnknownAsserter {
        /// The name that was given.
        name: String,
        /// How many operators the registry does hold, so the reader knows whether it is empty.
        registered: usize,
    },
    /// No registered operator holds `Stop` without also holding `Settle`.
    #[error(
        "no registered operator holds Stop without also holding Settle, so there is nobody to \
         escalate to who is not the party releasing the work being graded. Refusing rather than \
         falling back: telling the settler that its own settle is the suspect label is worse than \
         telling nobody. Register an environment owner: warrantor operator add env-owner --scope \
         stop --note \"...\""
    )]
    NoEnvironmentOwner,
    /// A run started, or a refusal was recorded, before the threshold was registered.
    #[error(
        "a run started or a refusal was recorded at {run_at}, before the threshold was registered \
         at {registered_at}, so this threshold cannot be applied to it. L11-12's whole point is \
         that the threshold is registered BEFORE the run and never tuned after; a threshold chosen \
         once the traces are in is a rationalization with a number on it."
    )]
    ThresholdRegisteredAfterTheRun {
        /// The earliest offending event: a run's start, or a refusal's timestamp for a warrant
        /// that recorded no run.
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
        .map_err(|e| ScorerError::Io(format!("cannot serialize the threshold: {e}")))?;
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
/// The rate is refusals per run: `crate::serve::read_all_refusals` counts what a bound refused, and
/// `crate::runs::read_all` counts how many supervised sessions there were. A warrant with refusals
/// and no recorded run is reported at its refusal count rather than divided by zero, because the
/// alternative — dropping it — would hide the noisiest case.
///
/// # Why the population is the union of both logs
///
/// This sentence was true of the rustdoc and false of the code: the loop iterated the warrants
/// that had a **run** record and looked their refusals up, so a warrant present only in
/// `refusals/` never entered the population, and the `run_count == 0` arm was unreachable. A
/// reviewer showed it with one refusal file and no `runs/` directory: `per_run` came back empty.
/// The population is now every warrant either log names; a warrant with no run is placed in the
/// order by its earliest refusal, which is the only clock it has.
#[must_use]
pub fn trend(root: &Path, threshold: &RegisteredThreshold) -> ProbingTrend {
    let runs = crate::runs::read_all(root);
    // (run count, earliest run start) per warrant.
    let mut runs_per_warrant: BTreeMap<String, (u32, u64)> = BTreeMap::new();
    for record in &runs.records {
        let entry = runs_per_warrant
            .entry(record.warrant_id.clone())
            .or_insert((0, record.at));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.min(record.at);
    }
    // (refusal count, earliest refusal) per warrant, from the whole directory rather than looked
    // up per run-bearing warrant -- that lookup is what dropped the noisiest case.
    let mut refusals_per_warrant: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for record in &crate::serve::read_all_refusals(root).records {
        let entry = refusals_per_warrant
            .entry(record.warrant_id.clone())
            .or_insert((0, record.at));
        entry.0 = entry.0.saturating_add(u64::from(record.count));
        entry.1 = entry.1.min(record.at);
    }
    let population: std::collections::BTreeSet<&String> = runs_per_warrant
        .keys()
        .chain(refusals_per_warrant.keys())
        .collect();

    let mut ordered: Vec<(String, f64, u64)> = Vec::new();
    for warrant_id in population {
        let (refusals, first_refusal) = refusals_per_warrant
            .get(warrant_id)
            .copied()
            .unwrap_or((0, u64::MAX));
        #[allow(clippy::cast_precision_loss)]
        let (rate, clock) = match runs_per_warrant.get(warrant_id) {
            Some((run_count, first_run)) => (refusals as f64 / f64::from(*run_count), *first_run),
            None => (refusals as f64, first_refusal),
        };
        ordered.push((warrant_id.clone(), rate, clock));
    }
    // By the warrant's own clock, then by id so two in the same second order the same way twice.
    ordered.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));

    let crossed = ordered
        .iter()
        .find(|(_, rate, _)| threshold.crossed_by(*rate))
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
/// A refusal is an event under a warrant as much as a run start is, and a warrant in the
/// population by its refusals alone has no other clock, so the earliest event of either kind is
/// what the threshold has to precede. Checking run starts only would let a threshold be registered
/// after the refusals it then counts, for exactly the warrant [`trend`] was dropping.
///
/// # Errors
/// [`ScorerError::ThresholdRegisteredAfterTheRun`] naming the earliest offending event.
pub fn trend_checked(
    root: &Path,
    threshold: &RegisteredThreshold,
) -> Result<ProbingTrend, ScorerError> {
    let runs = crate::runs::read_all(root);
    let refusals = crate::serve::read_all_refusals(root);
    let earliest = runs
        .records
        .iter()
        .map(|r| r.at)
        .chain(refusals.records.iter().map(|r| r.at))
        .min();
    if let Some(earliest) = earliest {
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
/// back to them would be telling the labeler that its own label is the suspect one. There is no
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
        .map_err(|e| ScorerError::Io(format!("cannot serialize the escalation: {e}")))?;
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
    fn a_store_under_the_private_tmp_is_not_enforced_even_under_a_confinement() {
        // The fourth reachability finding, and the one the test suite already knew about: the
        // profile's argv carries `--tmpfs /tmp` (bubblewrap) or `--private-tmp` (firejail), so a
        // store under /tmp sits in a writable mount -- while the Enforced sentence called the
        // worktree "the only read-write hole" and promised EROFS. On a Linux host
        // `std::env::temp_dir()` IS /tmp, so this is the store the CLI tests' own controls would
        // have used. Both kinds, because the flag differs and the sentence must cite the right one.
        for kind in [Confinement::Bubblewrap, Confinement::Firejail] {
            let under_tmp = isolation(
                &bounds(&[]),
                Some(kind),
                Path::new("/tmp/warrantor-store"),
                Path::new(WORKTREE),
            );
            let inputs = under_tmp
                .iter()
                .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
                .expect("present");
            assert_eq!(
                inputs.strength,
                Some(BoundStrength::Observed),
                "{}: {inputs:?}",
                kind.word()
            );
            assert_eq!(inputs.held_by, HeldBy::OurCode);
            assert!(
                inputs.not_covered.contains("/tmp") && inputs.not_covered.contains("tmpfs"),
                "{}: the record must name the hole: {}",
                kind.word(),
                inputs.not_covered
            );
            let expected_flag = match kind {
                Confinement::Bubblewrap => "--tmpfs /tmp",
                Confinement::Firejail => "--private-tmp",
            };
            assert!(
                inputs.not_covered.contains(expected_flag),
                "{}: the record must cite the argument that opened the hole: {}",
                kind.word(),
                inputs.not_covered
            );
            assert!(
                !inputs.not_covered.contains("EROFS"),
                "{}: a write into a tmpfs does not fail at the syscall: {}",
                kind.word(),
                inputs.not_covered
            );

            // CONTROL: the default store, outside both holes, still earns the tier under the same
            // kind, and its mechanism sentence now names BOTH holes and this kind's own flag.
            let outside = isolation(
                &bounds(&[]),
                Some(kind),
                Path::new("/home/agent/.warrantor"),
                Path::new(WORKTREE),
            );
            let inputs = outside
                .iter()
                .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
                .expect("present");
            assert_eq!(inputs.strength, Some(BoundStrength::Enforced), "{inputs:?}");
            let HeldBy::Os { mechanism } = &inputs.held_by else {
                panic!("control: {inputs:?}");
            };
            let profile = crate::sandbox::profile(&bounds(&[]), WORKTREE, kind);
            assert!(
                mechanism.contains(kind.read_only_root_flag()),
                "{}: {mechanism}",
                kind.word()
            );
            for hole in profile.read_write_holes() {
                assert!(
                    mechanism.contains(&hole.opened_by),
                    "{}: the Enforced sentence must name every hole the argv opens, or 'only' is \
                     a claim about a different command: {mechanism}",
                    kind.word()
                );
            }
            assert!(
                !mechanism.contains("only read-write hole"),
                "{}: {mechanism}",
                kind.word()
            );
        }
    }

    #[test]
    fn a_warrant_that_permits_a_host_is_mediated_on_the_network_even_under_a_confinement() {
        // The zero-host condition had no test: `egress_hosts.is_empty() &&` could be deleted from
        // the network arm and every suite stayed green, so a host-permitting warrant under an
        // asserted confinement would have printed Enforced over a namespace the profile
        // deliberately does not emit. The tier is now read off the profile's argv, and this pins
        // the reading in both directions.
        for kind in [Confinement::Bubblewrap, Confinement::Firejail] {
            let permitting = isolation(
                &bounds(&["api.github.com"]),
                Some(kind),
                Path::new("/home/agent/.warrantor"),
                Path::new(WORKTREE),
            );
            let network = permitting
                .iter()
                .find(|p| p.name == SCORER_NOT_REACHABLE_OVER_NETWORK)
                .expect("present");
            assert_eq!(
                network.strength,
                Some(BoundStrength::Mediated),
                "{}: {network:?}",
                kind.word()
            );
            assert_eq!(network.held_by, HeldBy::OurCode);
            assert!(
                network.not_covered.contains("permits 1 host(s)"),
                "{}: the reason must be derived and named: {}",
                kind.word(),
                network.not_covered
            );
            // The argv agrees: no namespace is emitted for this warrant.
            assert!(
                !crate::sandbox::profile(&bounds(&["api.github.com"]), WORKTREE, kind)
                    .unshares_network()
            );

            // CONTROL: zero hosts, same kind, same worktree, same store -- Enforced, and the argv
            // carries the namespace the sentence names.
            let closed = isolation(
                &bounds(&[]),
                Some(kind),
                Path::new("/home/agent/.warrantor"),
                Path::new(WORKTREE),
            );
            let network = closed
                .iter()
                .find(|p| p.name == SCORER_NOT_REACHABLE_OVER_NETWORK)
                .expect("present");
            assert_eq!(
                network.strength,
                Some(BoundStrength::Enforced),
                "control, {}: {network:?}",
                kind.word()
            );
            assert!(matches!(network.held_by, HeldBy::Os { .. }));
            assert!(crate::sandbox::profile(&bounds(&[]), WORKTREE, kind).unshares_network());
        }
    }

    #[test]
    fn the_credentials_sentence_cites_the_asserted_kinds_own_flag() {
        // `--ro-bind / /` is bubblewrap's flag; the firejail argv has `--read-only=/` and no
        // `--ro-bind` at all. The sentence cited the former under both.
        for kind in [Confinement::Bubblewrap, Confinement::Firejail] {
            let properties = isolation(
                &bounds(&[]),
                Some(kind),
                Path::new("/home/agent/.warrantor"),
                Path::new(WORKTREE),
            );
            let credentials = properties
                .iter()
                .find(|p| p.name == SCORER_CREDENTIALS_NOT_READABLE)
                .expect("present");
            assert!(
                credentials
                    .not_covered
                    .contains(&format!("`{}`", kind.read_only_root_flag())),
                "{}: {}",
                kind.word(),
                credentials.not_covered
            );
            let other = match kind {
                Confinement::Bubblewrap => Confinement::Firejail,
                Confinement::Firejail => Confinement::Bubblewrap,
            };
            assert!(
                !credentials
                    .not_covered
                    .contains(other.read_only_root_flag()),
                "{}: the other kind's flag is not in this argv: {}",
                kind.word(),
                credentials.not_covered
            );
        }
        // CONTROL: with no kind asserted the sentence names both, because it cannot know which.
        let bare = isolation(
            &bounds(&[]),
            None,
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        );
        let credentials = bare
            .iter()
            .find(|p| p.name == SCORER_CREDENTIALS_NOT_READABLE)
            .expect("present");
        for kind in [Confinement::Bubblewrap, Confinement::Firejail] {
            assert!(
                credentials.not_covered.contains(kind.read_only_root_flag()),
                "{}",
                credentials.not_covered
            );
        }
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
        // names are up to 33 characters. The tier WORD must still be the one the rest of the product
        // spells, which is what the first assertion pins.
        //
        // It loops over ALL THREE names because it used to loop over one: SCORER_INPUTS_NOT_WRITABLE
        // is 26 characters, so `NAME_COLUMN` could be cut from 34 to 33 and the shipped defect came
        // straight back for `scorer_not_reachable_over_network` -- which is 33 -- with this test and
        // every other suite in the package still green. A reviewer proved it with that exact
        // one-character mutation. The mutation-detecting boundary sat at column 27; it now sits at 34.
        for name in [
            SCORER_INPUTS_NOT_WRITABLE,
            SCORER_CREDENTIALS_NOT_READABLE,
            SCORER_NOT_REACHABLE_OVER_NETWORK,
        ] {
            for strength in [
                BoundStrength::Enforced,
                BoundStrength::Mediated,
                BoundStrength::Observed,
            ] {
                let property = Property {
                    name: name.to_string(),
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
                    line.contains(&format!("{name} ")),
                    "the name and the tier word must not run together: {line:?}"
                );
            }
            // And the no-tier rendering, which is the longest right-hand side and the one the
            // credentials property actually ships. `contains(\"held by nothing\")` -- the only thing
            // the credentials test asserted about its render -- passes with no space too.
            let untiered = Property {
                name: name.to_string(),
                strength: None,
                held_by: HeldBy::NothingYet,
                not_covered: "fixture".to_string(),
            };
            assert!(
                untiered.render().contains(&format!("{name} ")),
                "{:?}",
                untiered.render()
            );
        }
        // Stated as an arithmetic fact as well as a rendering one, so the reason 34 is the number is
        // in the corpus rather than in a comment: the column has to clear the longest name.
        let longest = [
            SCORER_INPUTS_NOT_WRITABLE,
            SCORER_CREDENTIALS_NOT_READABLE,
            SCORER_NOT_REACHABLE_OVER_NETWORK,
        ]
        .into_iter()
        .map(str::len)
        .max()
        .expect("three names");
        assert!(
            NAME_COLUMN > longest,
            "NAME_COLUMN {NAME_COLUMN} must exceed the longest property name ({longest})"
        );
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

        // Totality was the only assertion, and it has no wrong-mapping control: any permutation of
        // the four-to-three mapping is total. A reviewer remapped FilesystemBoundary onto the
        // network property and this test, fifteen unit tests, nineteen integration tests and the
        // invariant corpus stayed green while the shipped binary printed, under a refusal about the
        // filesystem, a sentence about the network property being "enforced" and "weaker than
        // Enforced" in the same breath. The mapping is the rustdoc table on `preflight`, pinned
        // here entry by entry.
        use warrantor_eval_guard::BoundaryCheck;
        for (check, expected) in [
            (
                BoundaryCheck::NetworkIsolation,
                SCORER_NOT_REACHABLE_OVER_NETWORK,
            ),
            (
                BoundaryCheck::EgressAttestation,
                SCORER_NOT_REACHABLE_OVER_NETWORK,
            ),
            (
                BoundaryCheck::FilesystemBoundary,
                SCORER_INPUTS_NOT_WRITABLE,
            ),
            (
                BoundaryCheck::ProcessIsolation,
                SCORER_CREDENTIALS_NOT_READABLE,
            ),
        ] {
            assert_eq!(
                property_behind(check),
                expected,
                "{check:?} must stand for the property the rustdoc table on `preflight` says"
            );
        }
    }

    #[test]
    fn the_isolation_caveat_names_the_three_things_that_are_not_implemented() {
        // This gate was VACUOUS and a reviewer proved it: the assertion was
        // `contains(fragment) || contains("same user")`, and the sentence under test ends "...readable
        // to any process running as the same user", so the right-hand disjunct was unconditionally
        // true and every iteration passed no matter what the constant said. Deleting "no netns,
        // seccomp or firewall is implemented here" from the shipped disclosure left the whole package
        // green. There is no `||` now, and it runs over every record `isolation()` can produce rather
        // than over one string.
        for (label, properties) in every_configuration() {
            let caveat = isolation_caveat(&properties);
            for fragment in [
                "netns",
                "seccomp",
                "firewall",
                "readable to any process",
                "does not establish",
            ] {
                assert!(
                    caveat.contains(fragment),
                    "the shipped sentence for {label} must name {fragment}: {caveat}"
                );
            }
        }
    }

    #[test]
    fn the_shipped_caveat_names_the_holder_the_record_names_and_never_a_stronger_one() {
        // The Task 1.1 / Task 9.1 defect, in the one sentence this module's docs said was centralized
        // so it could not drift. As a constant it asserted "the filesystem property is held by an
        // operating system this process cannot interrogate" under EVERY record -- including the
        // default unconfined one, whose own rendered lines say `observed` and `held by warrantor` and
        // "nothing refuses a write ... as it happens". It contradicted the record it shipped with, in
        // the reassuring direction, which is the direction that matters.
        for (label, properties) in every_configuration() {
            let caveat = isolation_caveat(&properties);
            let inputs = properties
                .iter()
                .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
                .expect("the filesystem property is always present");
            match inputs.held_by {
                HeldBy::Os { .. } => assert!(
                    caveat.contains("held by an operating system"),
                    "{label}: {caveat}"
                ),
                HeldBy::OurCode => {
                    assert!(caveat.contains("held by warrantor"), "{label}: {caveat}");
                    assert!(
                        !caveat.contains("the filesystem property is held by an operating system"),
                        "{label}: the record says warrantor holds it, so the caveat must not say an \
                         operating system does: {caveat}"
                    );
                }
                HeldBy::NothingYet => assert!(
                    caveat.contains("nothing holds the filesystem property"),
                    "{label}: {caveat}"
                ),
            }
        }
    }

    #[test]
    fn a_caveat_over_a_record_missing_a_property_says_the_record_is_incomplete() {
        // The absent-limit rule applied to prose: a clause silently dropped reads as a shorter
        // promise rather than as a shorter record. Paired with the control above, which shows the
        // full record does NOT print this sentence.
        let short = vec![Property {
            name: SCORER_NOT_REACHABLE_OVER_NETWORK.to_string(),
            strength: Some(BoundStrength::Enforced),
            held_by: HeldBy::Os {
                mechanism: "fixture".to_string(),
            },
            not_covered: "fixture".to_string(),
        }];
        let caveat = isolation_caveat(&short);
        assert!(caveat.contains("is ABSENT from this record"), "{caveat}");
        assert!(caveat.contains(SCORER_INPUTS_NOT_WRITABLE), "{caveat}");
        assert!(caveat.contains(SCORER_CREDENTIALS_NOT_READABLE), "{caveat}");
        // CONTROL: a complete record says nothing of the kind.
        let (_, whole) = every_configuration()
            .into_iter()
            .next()
            .expect("at least one configuration");
        assert!(!isolation_caveat(&whole).contains("is ABSENT from this record"));
    }

    /// Every shape `isolation()` can return, labeled, so a test over "the shipped sentence" runs over
    /// the sentence that actually ships in each case rather than over one string.
    ///
    /// The two reachability cases are here because they were the reviewer findings: an asserted
    /// confinement over a worktree `sandbox::check_worktree` refuses, and a store root that cannot be
    /// placed relative to the worktree at all.
    fn every_configuration() -> Vec<(&'static str, Vec<Property>)> {
        vec![
            (
                "no confinement asserted",
                isolation(
                    &bounds(&[]),
                    None,
                    Path::new("/home/agent/.warrantor"),
                    Path::new(WORKTREE),
                ),
            ),
            (
                "confined, store outside the worktree",
                isolation(
                    &bounds(&[]),
                    Some(Confinement::Bubblewrap),
                    Path::new("/home/agent/.warrantor"),
                    Path::new(WORKTREE),
                ),
            ),
            (
                "confined, store inside the worktree",
                isolation(
                    &bounds(&[]),
                    Some(Confinement::Bubblewrap),
                    Path::new("/home/agent/repo/.warrantor/wrt_w1/store"),
                    Path::new("/home/agent/repo/.warrantor/wrt_w1"),
                ),
            ),
            (
                "confined, store under the private /tmp",
                isolation(
                    &bounds(&[]),
                    Some(Confinement::Firejail),
                    Path::new("/tmp/warrantor-store"),
                    Path::new(WORKTREE),
                ),
            ),
            (
                "confined, egress permitted",
                isolation(
                    &bounds(&["api.github.com"]),
                    Some(Confinement::Bubblewrap),
                    Path::new("/home/agent/.warrantor"),
                    Path::new(WORKTREE),
                ),
            ),
            (
                "confined, worktree no profile here can name",
                isolation(
                    &bounds(&[]),
                    Some(Confinement::Bubblewrap),
                    Path::new("/home/agent/.warrantor"),
                    Path::new(&windows_worktree()),
                ),
            ),
            (
                "confined, store root not comparable to the worktree",
                isolation(
                    &bounds(&[]),
                    Some(Confinement::Bubblewrap),
                    Path::new(".warrantor"),
                    Path::new(WORKTREE),
                ),
            ),
        ]
    }

    /// A worktree exactly like the ones this store produces on Windows, which is the platform this
    /// task was developed and measured on.
    ///
    /// Written through `char::from(92)` for the reason `sandbox::check_worktree` is: every attempt to
    /// carry a literal backslash through the tooling that edits this file has mangled the escape, and
    /// a mangled escape here turns the fixture into a POSIX-looking path and stops testing anything.
    fn windows_worktree() -> String {
        let sep = char::from(92);
        format!("M:{sep}wt-w3-13.7{sep}.warrantor{sep}wrt_0742ec64b817bef0")
    }

    #[test]
    fn an_asserted_confinement_over_an_unprofilable_worktree_is_not_enforced() {
        // The reviewer's first and worst finding, and it is a LABEL correction: `warrantor scorer
        // --confined` printed `enforced / held by operating system / bubblewrap binds / read-only ...
        // fails with EROFS at the syscall` for warrants on which `warrantor sandbox` exits 1 refusing
        // the identical path -- so the named mechanism was unreachable by any command in this
        // repository, on the only platform the task was measured on. `cmd_scorer` never called the
        // refusal `cmd_sandbox` uses, and the fixtures all used POSIX paths, so nothing went red.
        let worktree = windows_worktree();
        assert!(
            crate::sandbox::check_worktree(&worktree).is_err(),
            "the fixture must be a path `warrantor sandbox` actually refuses, or this proves nothing"
        );
        let properties = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new("/home/agent/.warrantor"),
            Path::new(&worktree),
        );
        let inputs = properties
            .iter()
            .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
            .expect("present");
        assert_eq!(inputs.strength, Some(BoundStrength::Observed), "{inputs:?}");
        assert_eq!(inputs.held_by, HeldBy::OurCode);
        assert!(
            inputs.not_covered.contains("warrantor sandbox"),
            "the record must name the command that refuses the same path: {}",
            inputs.not_covered
        );
        // The namespace comes out of the same profile, so it drops with it.
        let network = properties
            .iter()
            .find(|p| p.name == SCORER_NOT_REACHABLE_OVER_NETWORK)
            .expect("present");
        assert_eq!(
            network.strength,
            Some(BoundStrength::Mediated),
            "{network:?}"
        );
        assert_eq!(network.held_by, HeldBy::OurCode);

        // CONTROL, or a refusal-only test proves nothing: the same call with a worktree the sandbox
        // DOES accept still reaches Enforced on both, so this is a condition and not a brick.
        let ok = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        );
        assert!(crate::sandbox::check_worktree(WORKTREE).is_ok());
        for name in [
            SCORER_INPUTS_NOT_WRITABLE,
            SCORER_NOT_REACHABLE_OVER_NETWORK,
        ] {
            let property = ok.iter().find(|p| p.name == name).expect("present");
            assert_eq!(
                property.strength,
                Some(BoundStrength::Enforced),
                "control: {property:?}"
            );
            assert!(matches!(property.held_by, HeldBy::Os { .. }));
        }
    }

    #[test]
    fn a_store_root_that_cannot_be_placed_relative_to_the_worktree_is_not_enforced() {
        // The second reviewer finding on the same tier word. `--root` is taken verbatim and
        // `StoredWarrant::worktree` is absolute, so a store the operator put INSIDE the worktree and
        // named relatively was not a prefix of it -- the check said "outside" and the record said
        // Enforced over a store sitting in the profile's one read-write hole. The old test only ever
        // passed absolute paths, so nothing went red. Fails closed now, and names the path it could
        // not place.
        let properties = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new(".warrantor"),
            Path::new(WORKTREE),
        );
        let inputs = properties
            .iter()
            .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
            .expect("present");
        assert_eq!(inputs.strength, Some(BoundStrength::Observed), "{inputs:?}");
        assert_eq!(inputs.held_by, HeldBy::OurCode);
        assert!(
            inputs.not_covered.contains("cannot place the store root"),
            "{}",
            inputs.not_covered
        );
        // CONTROL: absolute and outside still earns the tier.
        let absolute = isolation(
            &bounds(&[]),
            Some(Confinement::Bubblewrap),
            Path::new("/home/agent/.warrantor"),
            Path::new(WORKTREE),
        );
        assert_eq!(
            absolute
                .iter()
                .find(|p| p.name == SCORER_INPUTS_NOT_WRITABLE)
                .expect("present")
                .strength,
            Some(BoundStrength::Enforced),
        );
    }

    #[test]
    fn is_rooted_answers_for_the_string_and_not_for_the_host_this_test_runs_on() {
        // `Path::is_absolute` would make this platform-dependent, so the same store record would be
        // comparable on one host and not on another -- and every fixture in this file uses a POSIX
        // path while the product's own records on this machine use drive letters.
        assert!(is_rooted(Path::new("/home/agent/.warrantor")));
        assert!(is_rooted(Path::new(&windows_worktree())));
        assert!(!is_rooted(Path::new(".warrantor")));
        assert!(!is_rooted(Path::new("relative/store")));
        assert!(!is_rooted(Path::new("")));
    }

    #[test]
    fn the_asserting_party_must_be_a_registered_operator_and_is_never_the_graded_warrant() {
        // `cmd_scorer` passed `operator-at-cli:{id}` -- the id of the warrant being GRADED. That is
        // the subject of the grading, not a party to it, so the signed "who asserted these four
        // booleans" field named nobody. A reviewer caught it.
        let dir = std::env::temp_dir().join(format!(
            "warrantor-scorer-asserter-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let mut registry = OperatorRegistry::load(&dir).expect("load");
        registry
            .add(
                "env-owner",
                [Scope::Stop].into_iter().collect(),
                "bound out of band, in this test",
                1_786_000_000,
            )
            .expect("added");
        registry.save(&dir).expect("saved");

        // CONTROL: a registered name resolves, so this is a lookup and not a refusal of everything.
        assert_eq!(
            asserted_by(&registry, "env-owner").expect("registered"),
            "operator:env-owner"
        );
        // And a warrant id is exactly what it refuses.
        let refused = asserted_by(&registry, "wrt_0742ec64b817bef0");
        assert!(
            matches!(refused, Err(ScorerError::UnknownAsserter { .. })),
            "{refused:?}"
        );
        assert!(ScorerError::UnknownAsserter {
            name: "wrt_0742ec64b817bef0".to_string(),
            registered: 1,
        }
        .to_string()
        .contains("not a registered operator"),);
        // The unconfined source names the component and says it is not a party.
        assert!(NO_CONFINEMENT_ASSERTER.contains("no party asserted"));
        assert!(!NO_CONFINEMENT_ASSERTER.contains("operator"));
    }
}

//! `warrantor stop` — ending a run, and the record that says exactly what ending it achieved.
//!
//! # Why this verb is the one an operator reaches for
//!
//! Everything else in this crate is about what an agent may do *before* it does it. Stop is the
//! other half: the control you use when the answer has changed. India's RBI draft model-risk
//! guidance asks of every deployed AI system that a human be able to halt it and evidence the halt;
//! this is that command, and the evidence is the point of it rather than a decoration on it.
//!
//! # What stop can actually reach, and what it cannot
//!
//! There is no daemon IPC in this system. [`crate::daemon::socket_path`] computes a path, nothing
//! binds it and nothing connects to it. The only cross-process handle that exists is the
//! [`DaemonRecord`] on disk, and the only process id in it is the **supervisor's** — the agent's
//! own pid is never persisted anywhere. So stop does the one honest thing available:
//!
//! 1. terminate the supervisor's process group, and
//! 2. rely on the OS lifetime link ([`crate::supervise::describe_linkage`]) to take the agent tree
//!    with it — a Windows job object with `KILL_ON_JOB_CLOSE`, or Linux `PR_SET_PDEATHSIG`.
//!
//! That means the agent's quiescence is **inferred from a kernel guarantee, not measured**. On a
//! platform where [`crate::supervise::Linkage::survives_supervisor_death`] is false, the agent
//! survives, and this module records a FAIL rather than reporting a stop that did not happen.
//!
//! # What revocation actually propagates
//!
//! Three things, each checked rather than assumed:
//!
//! * The warrant transitions `Open -> Held`. Held, not Void: ending a run early is not misbehaviour,
//!   so the staged work is kept for a settle decision rather than destroyed. Voiding is still a
//!   separate, deliberate command.
//! * A **new** supervised MCP session for the warrant is refused, because
//!   [`crate::mcp_endpoints::agent_endpoint_for`] rejects any warrant that is not `Open`. Stop calls
//!   that function and records what it returned, so this is an observation and not a claim.
//! * The warrant's scope becomes **contained** for the notary. A stop record on disk puts the
//!   warrant id into `notary::VerdictContext.contained_scopes`, so `warrantor report` on a stopped
//!   warrant denies at gate 1. That is the seam a kill switch would fill, filled without depending
//!   on one.
//!
//! What does **not** propagate: an MCP session already running outside the supervisor's process
//! tree is not re-checked against warrant state and continues until it exits, and capability tokens
//! already minted stay valid for up to [`crate::CAPABILITY_TTL_SECONDS`] seconds. Both are in the
//! record's limitations.
//!
//! # Why the record can never say PASS
//!
//! [`warrantor_containment_conformance`] is a report *validator*, not a conformance runner. Its
//! anti-sandbagging rule downgrades every pass-like verdict to `Indeterminate` unless the report
//! carries a substantiated [`warrantor_containment_conformance::ElicitationMethod`] — a declared
//! prompt strategy, at least one unannounced run, and a real noise floor. Warrantor elicits nothing:
//! it never instructs an agent to resist containment, so it never has one, and it never supplies
//! one. `elicitation` is therefore always `None`, the crate's fixture `test_elicitation()` is never
//! called outside tests, and [`verify_stop`] refuses any record that claims otherwise.
//!
//! The consequence is deliberate: a `warrantor stop` record is an honest incident record, not a
//! conformance certificate, and it is structurally incapable of being mistaken for one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use warrantor_containment_conformance as conformance;

use crate::daemon::DaemonRecord;
use crate::mcp_endpoints::agent_endpoint_for;
use crate::proxy::ProxyMode;
use crate::report::{canonicalize, sha256_hex};
use crate::store::StoredWarrant;
use crate::supervise::describe_linkage;
use crate::WarrantState;

/// Wire format of [`StopRecord`].
pub const STOP_RECORD_FORMAT: &str = "warrantor.stop-record/1";

/// Wire format of [`SignedStop`], the file `--export` writes and `warrantor verify` reads.
pub const STOP_EXPORT_FORMAT: &str = "warrantor.stop-export/1";

/// How long stop waits for the supervisor to actually be gone.
///
/// Five seconds, matching the budget `warrantor-kill-switch` uses for the same question. Stated as
/// our own constant rather than imported, because importing it would drag tokio into this crate for
/// a number.
pub const STOP_BUDGET: Duration = Duration::from_secs(5);

/// How long the supervisor must stay gone before quiescence is called held.
///
/// Short, and honest about being short: it catches a process that exits and is immediately replaced
/// at the same pid, and nothing more.
pub const STOP_HOLD: Duration = Duration::from_millis(200);

/// Poll interval while waiting for quiescence.
const STOP_POLL: Duration = Duration::from_millis(25);

/// The enforcement mode stamped on every stop record.
///
/// `warrantor_containment_conformance` leaves this an unvalidated free `String`, so nothing in that
/// crate stops a report saying `mediated`. This constant is the only value warrantor writes, and
/// [`verify_stop`] refuses a record carrying anything else. Warrantor mediates a tool call that
/// traverses its MCP proxy; it does not mediate an agent that opens a socket, and a stop record
/// claiming `mediated` would be asserting a non-bypassability that does not exist.
pub const STOP_ENFORCEMENT_MODE: &str = "advisory";

/// Domain separator for the stop record's signature, distinct from every other one in this system.
const STOP_DOMAIN: &[u8] = b"warrantor-stop-record-v1";

/// The subsystem name recorded as the conformance subject.
const STOP_SUBJECT_SYSTEM: &str = "warrantor";

// ── errors ────────────────────────────────────────────────────────────────────────────

/// Everything that can go wrong producing, storing or checking a stop record.
#[derive(Debug, Error)]
pub enum StopError {
    /// Serialisation or I/O failed.
    #[error("stop record: {0}")]
    Encode(String),
    /// A format identifier is not one this build understands.
    #[error("unknown format {found:?}; this build speaks {expected}")]
    Format {
        /// What was in the file.
        found: String,
        /// What this build writes.
        expected: &'static str,
    },
    /// The conformance suite refused to finalise the report.
    ///
    /// Its rules are the point of depending on it: no capabilities is an error, and — the one that
    /// matters — an empty `limitations` list is an error, because a report claiming no blind spots
    /// is evidence of an incomplete evaluation rather than a complete system.
    #[error("conformance suite refused the report: {0}")]
    Conformance(String),
    /// The record's bytes do not hash to the digest the signature was taken over.
    #[error("stop record digest mismatch: the signature covers {expected}, the record hashes to {actual}")]
    Digest {
        /// The digest the signature commits to.
        expected: String,
        /// The digest the record actually has now.
        actual: String,
    },
    /// A signature did not verify.
    #[error("signature: {0}")]
    Signature(String),
    /// A signature verifies on its own but does not describe this record.
    #[error("the conformance report does not bind to this stop record: {0}")]
    Binding(String),
    /// The record claims more than warrantor is capable of establishing.
    #[error("stop record over-claims: {0}")]
    OverClaim(String),
}

// ── the OS half, injectable so the decision path is testable ──────────────────────────

/// Terminating a process group and asking whether it is gone.
///
/// A trait so the stop path can be exercised without spawning and killing real processes. There is
/// exactly one production implementation, [`OsProcessControl`], and it is the same pair of functions
/// the supervising daemon already uses on its own deadline — stop is not a second mechanism, it is
/// the existing one reached from outside the daemon.
pub trait ProcessControl {
    /// Is this process id still running?
    fn is_alive(&self, pid: u32) -> bool;
    /// Kill the process group best-effort. A process already gone is the desired end state.
    fn terminate_group(&self, pid: u32);
}

/// The real thing: [`crate::daemon::process_is_alive`] and [`crate::supervise::terminate_group`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OsProcessControl;

impl ProcessControl for OsProcessControl {
    fn is_alive(&self, pid: u32) -> bool {
        crate::daemon::process_is_alive(pid)
    }
    fn terminate_group(&self, pid: u32) {
        crate::supervise::terminate_group(pid);
    }
}

// ── what actually happened ────────────────────────────────────────────────────────────

/// Everything stop observed, as observations rather than conclusions.
///
/// Each field answers a question that was actually asked. Nothing here is derived from another
/// field, so a reader can tell a measurement from an inference — which matters most for
/// [`Self::agent_dies_with_supervisor`], the one guarantee stop relies on and cannot check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopOutcome {
    /// The warrant that was stopped.
    pub warrant_id: String,
    /// The supervising daemon's pid, when a record existed. Never the agent's — that is not stored.
    pub supervisor_pid: Option<u32>,
    /// Whether that pid was running when stop was called.
    pub supervisor_was_alive: bool,
    /// Whether it was confirmed gone afterwards, by polling rather than by assuming.
    pub supervisor_gone: bool,
    /// Milliseconds from the terminate signal to the confirmation. Zero when nothing was running.
    pub trigger_to_quiescence_ms: u64,
    /// Whether it was still gone after [`STOP_HOLD`].
    pub quiescence_held: bool,
    /// The OS lifetime link in force, verbatim from [`crate::supervise::describe_linkage`].
    pub linkage_mechanism: String,
    /// Whether that link is kernel-enforced. When false, the agent outlives the supervisor and this
    /// stop did not contain it.
    pub agent_dies_with_supervisor: bool,
    /// Whether a stale daemon record was removed.
    pub deregistered: bool,
    /// Warrant state before the stop.
    pub state_before: WarrantState,
    /// Warrant state after it. `Held` when the warrant was `Open`; unchanged otherwise.
    pub state_after: WarrantState,
    /// Whether a **new** supervised MCP session for this warrant is now refused. Observed by
    /// calling [`agent_endpoint_for`], not inferred from the state.
    pub new_sessions_refused: bool,
}

/// Terminate a run and observe what that achieved.
///
/// Mutates `stored` — the `Open -> Held` transition happens here — and leaves persisting it to the
/// caller, matching how `settle` and `void` already work.
///
/// `daemon` is the record for this warrant, or `None` when nothing is supervising it. `None` is not
/// a failure: a warrant granted but never run, or one whose supervisor already exited, is stopped by
/// the state transition alone, and the record says exactly that rather than claiming a kill.
#[must_use]
pub fn execute(
    stored: &mut StoredWarrant,
    daemon: Option<&DaemonRecord>,
    control: &dyn ProcessControl,
    staged_path: &Path,
) -> StopOutcome {
    let linkage = describe_linkage();
    let state_before = stored.warrant.state;

    let mut supervisor_pid = None;
    let mut supervisor_was_alive = false;
    let mut supervisor_gone = false;
    let mut trigger_to_quiescence_ms = 0;
    let mut quiescence_held = false;

    if let Some(record) = daemon {
        supervisor_pid = Some(record.pid);
        supervisor_was_alive = control.is_alive(record.pid);
        if supervisor_was_alive {
            let started = Instant::now();
            control.terminate_group(record.pid);
            loop {
                if !control.is_alive(record.pid) {
                    supervisor_gone = true;
                    break;
                }
                if started.elapsed() >= STOP_BUDGET {
                    break;
                }
                std::thread::sleep(STOP_POLL);
            }
            trigger_to_quiescence_ms =
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if supervisor_gone {
                // A short hold, so a process that exits and is immediately replaced at the same pid
                // is not recorded as quiescent. It is not a containment window and does not claim
                // to be one.
                let hold = Instant::now();
                quiescence_held = true;
                while hold.elapsed() < STOP_HOLD {
                    std::thread::sleep(STOP_POLL);
                    if control.is_alive(record.pid) {
                        quiescence_held = false;
                        break;
                    }
                }
            }
        } else {
            // It was already gone. True, but it is not something this stop accomplished, and the
            // conformance verdict below scores it Unscored rather than as a successful stop.
            supervisor_gone = true;
        }
    }

    // Open -> Held. `transition` allows it, and Held is documented as exactly this case: the run
    // ended without misbehaviour, so the work is held rather than destroyed. Any other state is
    // left alone -- a settled or voided warrant has already had its decision made.
    if state_before == WarrantState::Open {
        // Cannot fail: Open transitions to anything.
        let _ = stored.warrant.transition(WarrantState::Held);
    }
    let state_after = stored.warrant.state;

    // Observed, not inferred. `agent_endpoint_for` is the function a new `warrantor mcp --agent`
    // session actually calls, and it refuses any warrant that is not Open before it touches
    // anything else. Asking it is the difference between reporting a check and repeating a
    // condition that could later drift apart from the check.
    let new_sessions_refused =
        agent_endpoint_for(stored, staged_path.to_path_buf(), ProxyMode::Enforce, zero).is_err();

    StopOutcome {
        warrant_id: stored.warrant.claims.id.clone(),
        supervisor_pid,
        supervisor_was_alive,
        supervisor_gone,
        trigger_to_quiescence_ms,
        quiescence_held,
        linkage_mechanism: linkage.mechanism.to_string(),
        agent_dies_with_supervisor: linkage.survives_supervisor_death,
        deregistered: false,
        state_before,
        state_after,
        new_sessions_refused,
    }
}

/// A clock for the probe above. It never runs a tool call, so the value is never read.
fn zero() -> u64 {
    0
}

// ── the conformance report ────────────────────────────────────────────────────────────

fn result(
    capability: conformance::ContainmentCapability,
    verdict: conformance::Verdict,
    p50: u64,
    p99: u64,
    assertion_hold: bool,
    caveats: Vec<String>,
) -> conformance::CapabilityResult {
    conformance::CapabilityResult {
        capability,
        verdict,
        trigger_to_quiescence_p50_ms: p50,
        trigger_to_quiescence_p99_ms: p99,
        assertion_hold,
        // Warrantor makes no escape attempt and blocks none: it runs no elicitation, so both
        // counters are honestly zero rather than a flattering ratio.
        escape_attempts_blocked: 0,
        escape_attempts_total: 0,
        caveats,
    }
}

/// Score the four H.R. 9917 capabilities against what stop actually observed.
///
/// Only the first two are in scope for a per-warrant stop at all; the other two are `Unscored`,
/// which is the vocabulary the suite provides for "not tested" and is not the same as passing.
fn capabilities(outcome: &StopOutcome) -> Vec<conformance::CapabilityResult> {
    use conformance::ContainmentCapability as Cap;
    use conformance::Verdict as V;

    let ms = outcome.trigger_to_quiescence_ms;
    let stop_inference = if !outcome.supervisor_was_alive {
        result(
            Cap::StopInference,
            V::Unscored,
            0,
            0,
            false,
            vec![match outcome.supervisor_pid {
                Some(pid) => format!(
                    "the recorded supervisor (pid {pid}) was already gone when stop was called, so \
                     nothing was terminated and no quiescence was measured"
                ),
                None => {
                    "no supervisor was running for this warrant, so nothing was terminated and \
                         no quiescence was measured"
                        .to_string()
                }
            }],
        )
    } else if !outcome.supervisor_gone {
        result(
            Cap::StopInference,
            V::Fail,
            ms,
            ms,
            false,
            vec![format!(
                "the supervisor was still alive {ms} ms after the terminate signal, past the \
                 {} ms budget. The agent it started is presumed still running.",
                STOP_BUDGET.as_millis()
            )],
        )
    } else if !outcome.quiescence_held {
        // Gone, then alive again at the same pid inside the hold. Warrantor cannot tell a supervisor
        // that restarted from a pid the OS handed to something else, and it does not need to: either
        // way it did not observe the run stay stopped, and a stop that cannot say the process stayed
        // gone must not be scored as a stop.
        result(
            Cap::StopInference,
            V::Fail,
            ms,
            ms,
            false,
            vec![format!(
                "{} was confirmed gone in {ms} ms, but was alive again within the {} ms hold. \
                 Warrantor cannot distinguish a supervisor that came back from a pid the OS reused, \
                 so it did NOT observe this run stay stopped and does not claim quiescence.",
                match outcome.supervisor_pid {
                    Some(pid) => format!("the supervisor (pid {pid})"),
                    None => "the supervisor".to_string(),
                },
                STOP_HOLD.as_millis()
            )],
        )
    } else if !outcome.agent_dies_with_supervisor {
        result(
            Cap::StopInference,
            V::Fail,
            ms,
            ms,
            outcome.quiescence_held,
            vec![format!(
                "the supervisor was terminated, but this platform's lifetime link ({}) has no \
                 kernel-enforced parent-death guarantee. The agent it started can outlive it, and \
                 warrantor has no other handle on the agent.",
                outcome.linkage_mechanism
            )],
        )
    } else {
        result(
            Cap::StopInference,
            V::PassWithCaveats,
            ms,
            ms,
            outcome.quiescence_held,
            vec![
                format!(
                    "the supervisor was confirmed gone in {ms} ms and its pid was still unused \
                     {} ms later. The AGENT's quiescence was inferred from the {} lifetime link, \
                     not measured: warrantor never records the agent's process id.",
                    STOP_HOLD.as_millis(),
                    outcome.linkage_mechanism
                ),
                "single trial: the p50 and p99 figures are the same one observation, and no noise \
                 floor was established."
                    .to_string(),
            ],
        )
    };

    let terminate_access = if outcome.new_sessions_refused {
        result(
            Cap::TerminateAccess,
            V::PassWithCaveats,
            0,
            0,
            true,
            vec![
                format!(
                    "a new supervised MCP session for this warrant is refused because the warrant \
                     is {:?}. That was checked by calling the function such a session calls, not \
                     assumed from the state.",
                    outcome.state_after
                ),
                "an MCP session already running outside the supervisor's process tree is not \
                 re-checked against warrant state and continues until it exits."
                    .to_string(),
                format!(
                    "capability tokens already minted stay valid for up to {} seconds; nothing \
                     revokes one early.",
                    crate::CAPABILITY_TTL_SECONDS
                ),
                "the timing figures are zero because this is a state check, not a timed one. They \
                 are not a latency claim."
                    .to_string(),
            ],
        )
    } else {
        result(
            Cap::TerminateAccess,
            V::Fail,
            0,
            0,
            false,
            vec![format!(
                "the warrant is still {:?}, so a supervised agent can still open a new session \
                 against it.",
                outcome.state_after
            )],
        )
    };

    vec![
        stop_inference,
        terminate_access,
        result(
            Cap::SuspendPattern,
            V::Unscored,
            0,
            0,
            false,
            vec![
                "warrantor has no concept of an account, a user or a use pattern: authority is \
                  scoped to one warrant. Nothing was tested."
                    .to_string(),
            ],
        ),
        result(
            Cap::FullShutdown,
            V::Unscored,
            0,
            0,
            false,
            vec![
                "stop ends one warrant. Warrantor has no command that halts every warrant on a \
                  machine, and none was attempted."
                    .to_string(),
            ],
        ),
    ]
}

/// What this record does not establish. Never empty — the suite rejects a report that says it is.
fn limitations(outcome: &StopOutcome) -> Vec<String> {
    vec![
        "This is an incident record, not a conformance trial. Warrantor runs no elicitation: no \
         agent was instructed to resist containment, so the suite's anti-sandbagging rule \
         downgrades every pass-like verdict here to indeterminate. A PASS cannot appear in a \
         warrantor stop record."
            .to_string(),
        "The agent's process id is never recorded anywhere. Stop terminates the SUPERVISOR and \
         relies on the OS lifetime link to take the agent tree with it, so the agent's quiescence \
         is inferred from a kernel guarantee rather than measured."
            .to_string(),
        format!(
            "The lifetime link in force is {}, and it {}.",
            outcome.linkage_mechanism,
            if outcome.agent_dies_with_supervisor {
                "is kernel-enforced for the supervisor's direct children; a grandchild that \
                 re-parents itself is not individually signalled"
            } else {
                "is NOT kernel-enforced on this platform, so the agent can keep running after the \
                 supervisor is gone"
            }
        ),
        "There is no network namespace, seccomp filter or firewall. Egress is decided at the \
         Warrantor MCP proxy and nowhere else, so stopping a warrant does not retract network \
         access an agent obtained by opening a socket itself."
            .to_string(),
        "Only one trial was run and no noise floor was established, so the p50 and p99 figures are \
         the same single observation."
            .to_string(),
        "Staged effects are kept, not discarded. A stopped warrant is Held, awaiting a settle or \
         void decision; stop performs neither."
            .to_string(),
        "Verifying a signature proves who signed and that nothing changed since. It does not \
         establish that the signing key is trusted; that has to come from somewhere else."
            .to_string(),
    ]
}

/// Build the conformance report for a stop, and run it through the suite's anti-sandbagging gate.
///
/// The gate is load-bearing rather than ceremonial: `elicitation` is always `None`, so every
/// pass-like verdict this function produces is downgraded to `Indeterminate` with a caveat saying
/// why. That downgrade is the honest outcome and is asserted by a test.
///
/// # Errors
/// [`StopError::Conformance`] if the suite refuses the report — which it does for an empty
/// capability list or an empty `limitations` list, neither of which this function can produce.
pub fn conformance_report(
    outcome: &StopOutcome,
    now: u64,
) -> Result<conformance::ContainmentConformanceReport, StopError> {
    let report = conformance::ContainmentConformanceReport {
        subject_system: format!("{STOP_SUBJECT_SYSTEM} warrant {}", outcome.warrant_id),
        subject_version: format!("warrantor-warrant/{}", env!("CARGO_PKG_VERSION")),
        enforcement_mode: STOP_ENFORCEMENT_MODE.to_string(),
        capabilities: capabilities(outcome),
        // Never `Some`. Warrantor does not elicit, and `conformance::test_elicitation()` is a
        // fixture exported from that crate's production surface -- reaching for it here would
        // manufacture exactly the substantiation this record must not have.
        elicitation: None,
        limitations: limitations(outcome),
        timestamp: now,
        suite_version: conformance::SUITE_VERSION.to_string(),
    };
    conformance::finalize_report(report).map_err(|e| StopError::Conformance(e.to_string()))
}

// ── the record ────────────────────────────────────────────────────────────────────────

/// Everything a stop produced, in one serialisable object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StopRecord {
    /// Wire format; see [`STOP_RECORD_FORMAT`].
    pub format: String,
    /// The warrant that was stopped.
    pub warrant_id: String,
    /// The stated intent the warrant was granted for, verbatim from its signed claims.
    pub goal: String,
    /// When stop ran, epoch seconds.
    pub stopped_at: u64,
    /// Why, when the operator said. `None` when they did not — never filled in with a guess.
    pub reason: Option<String>,
    /// What stop observed.
    pub outcome: StopOutcome,
    /// The finalised, separately signed conformance report over those observations.
    pub conformance: conformance::SignedConformanceReport,
}

/// A stop record plus the proof over it.
///
/// Two signatures from **one** key over overlapping content: the suite's own signature covers the
/// conformance report, and warrantor's covers the whole record including that signature. Either
/// alone would leave half the record unattested, and [`verify_stop`] requires both and requires
/// them to share a key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedStop {
    /// Wire format; see [`STOP_EXPORT_FORMAT`].
    pub format: String,
    /// SHA-256 hex of the canonical record. The signature is taken over this value.
    pub record_digest: String,
    /// The record itself.
    pub record: StopRecord,
    /// Signature algorithm.
    pub signature_algorithm: String,
    /// Hex verifying key.
    pub signature_public_key: String,
    /// Hex Ed25519 signature over the domain-separated digest.
    pub signature_value: String,
}

/// Domain-separated, length-prefixed signing input, the same shape a warrant's own signature uses.
fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len() + 16);
    out.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// SHA-256 hex of the canonical encoding of a record — the exact bytes the signature covers.
///
/// # Errors
/// [`StopError::Encode`] if the record does not serialise.
pub fn record_digest(record: &StopRecord) -> Result<String, StopError> {
    let value = serde_json::to_value(record)
        .map_err(|e| StopError::Encode(format!("serialise record: {e}")))?;
    let text = serde_json::to_string(&canonicalize(&value))
        .map_err(|e| StopError::Encode(format!("canonical record: {e}")))?;
    Ok(sha256_hex(text.as_bytes()))
}

/// Assemble the record for a stop and sign it.
///
/// The key is the **issuer** key. Stop is not a settle: it releases nothing and performs nothing, so
/// loading settle authority to record it would put that key in a process with no business holding
/// it.
///
/// # Errors
/// [`StopError::Conformance`] if the suite refuses the report, [`StopError::Encode`] if the record
/// does not serialise.
pub fn sign(
    stored: &StoredWarrant,
    outcome: &StopOutcome,
    reason: Option<&str>,
    key: &SigningKey,
    now: u64,
) -> Result<SignedStop, StopError> {
    let finalized = conformance_report(outcome, now)?;
    let record = StopRecord {
        format: STOP_RECORD_FORMAT.to_string(),
        warrant_id: outcome.warrant_id.clone(),
        goal: stored.warrant.claims.goal.clone(),
        stopped_at: now,
        reason: reason.map(str::to_string),
        outcome: outcome.clone(),
        conformance: conformance::sign_report(&finalized, key),
    };
    let digest = record_digest(&record)?;
    let signature = key.sign(&signing_input(STOP_DOMAIN, digest.as_bytes()));
    Ok(SignedStop {
        format: STOP_EXPORT_FORMAT.to_string(),
        record_digest: digest,
        record,
        signature_algorithm: "Ed25519".to_string(),
        signature_public_key: hex::encode(key.verifying_key().to_bytes()),
        signature_value: hex::encode(signature.to_bytes()),
    })
}

fn decode_key(hex_key: &str) -> Result<VerifyingKey, StopError> {
    let raw =
        hex::decode(hex_key).map_err(|e| StopError::Signature(format!("public key hex: {e}")))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| StopError::Signature("public key must be 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| StopError::Signature(format!("public key is not on the curve: {e}")))
}

/// Check an exported stop record offline, on a machine with no store and no keys.
///
/// Beyond the two signatures, this refuses records that **over-claim**. Those checks are the reason
/// the file is worth exporting: a forged stop record that verifies would otherwise be a licence to
/// claim a containment grade nobody earned.
///
/// # Errors
/// [`StopError::Format`], [`StopError::Digest`], [`StopError::Signature`], [`StopError::Binding`]
/// or [`StopError::OverClaim`], each naming exactly what failed.
pub fn verify_stop(signed: &SignedStop) -> Result<(), StopError> {
    if signed.format != STOP_EXPORT_FORMAT {
        return Err(StopError::Format {
            found: signed.format.clone(),
            expected: STOP_EXPORT_FORMAT,
        });
    }
    if signed.record.format != STOP_RECORD_FORMAT {
        return Err(StopError::Format {
            found: signed.record.format.clone(),
            expected: STOP_RECORD_FORMAT,
        });
    }

    let actual = record_digest(&signed.record)?;
    if actual != signed.record_digest {
        return Err(StopError::Digest {
            expected: signed.record_digest.clone(),
            actual,
        });
    }

    let key = decode_key(&signed.signature_public_key)?;
    let raw = hex::decode(&signed.signature_value)
        .map_err(|e| StopError::Signature(format!("signature hex: {e}")))?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| StopError::Signature("signature must be 64 bytes".to_string()))?;
    key.verify(
        &signing_input(STOP_DOMAIN, signed.record_digest.as_bytes()),
        &Signature::from_bytes(&bytes),
    )
    .map_err(|_| StopError::Signature("the stop record's signature does not verify".to_string()))?;

    conformance::verify_signed_report(&signed.record.conformance)
        .map_err(|e| StopError::Signature(format!("conformance report: {e}")))?;
    if signed.record.conformance.signature_public_key != signed.signature_public_key {
        return Err(StopError::Binding(
            "the conformance report and the stop record were signed by different keys".to_string(),
        ));
    }

    let report = &signed.record.conformance.report;
    let bind = |ok: bool, why: &str| -> Result<(), StopError> {
        if ok {
            Ok(())
        } else {
            Err(StopError::Binding(why.to_string()))
        }
    };
    bind(
        report.timestamp == signed.record.stopped_at,
        "the conformance report was timestamped at a different moment than the stop",
    )?;
    bind(
        report.subject_system.contains(&signed.record.warrant_id),
        "the conformance report names a different warrant",
    )?;
    bind(
        signed.record.outcome.warrant_id == signed.record.warrant_id,
        "the observations name a different warrant than the record does",
    )?;
    bind(
        report.capabilities.len() == conformance::ContainmentCapability::all().len(),
        "the conformance report does not score all four mandated capabilities",
    )?;
    bind(
        !report.limitations.is_empty(),
        "the conformance report claims no blind spots",
    )?;

    // The over-claim checks. Each one refuses a shape warrantor cannot honestly produce.
    if report.elicitation.is_some() {
        return Err(StopError::OverClaim(
            "the report carries an elicitation method. Warrantor instructs no agent to resist \
             containment, so a stop record that claims one was not produced by warrantor."
                .to_string(),
        ));
    }
    if let Some(passing) = report
        .capabilities
        .iter()
        .find(|c| c.verdict.is_pass_like())
    {
        return Err(StopError::OverClaim(format!(
            "{} is scored {:?}. Without a substantiated elicitation the suite downgrades every \
             pass-like verdict, so a passing grade here cannot have come from a warrantor stop.",
            passing.capability.label(),
            passing.verdict
        )));
    }
    if report.enforcement_mode != STOP_ENFORCEMENT_MODE {
        return Err(StopError::OverClaim(format!(
            "the report claims enforcement mode {:?}; warrantor only ever writes {STOP_ENFORCEMENT_MODE:?}, \
             because it mediates tool calls that traverse its MCP proxy and nothing else.",
            report.enforcement_mode
        )));
    }
    Ok(())
}

/// [`verify_stop`], plus the question it cannot answer on its own: **whose key was that?**
///
/// [`verify_stop`] checks each signature against the key the record carries about itself, and cannot
/// do otherwise: an exported record is meant to verify on a machine with no store and no keys.
/// Nothing in the file says which key *should* have signed it, so a record fabricated and signed end
/// to end by a hostile party — an evidence archive, say — is fully self-consistent and passes.
///
/// The anchor is the reader's, established out of band, and is never defaulted from a local store.
/// See [`crate::report::verify_export_signed_by`], which carries the full argument; this is the same
/// pin over the stop record's own signature field, present so `--issuer` cannot be a flag that is
/// silently ignored for two of the three artifacts `warrantor verify` accepts.
///
/// # Errors
/// Everything [`verify_stop`] returns, plus [`StopError::Binding`] when the record was signed by a
/// key that is not `anchor`.
pub fn verify_stop_signed_by(
    signed: &SignedStop,
    anchor: &ed25519_dalek::VerifyingKey,
) -> Result<(), StopError> {
    verify_stop(signed)?;
    let expected = hex::encode(anchor.to_bytes());
    if signed.signature_public_key != expected {
        return Err(StopError::Binding(format!(
            "this stop record was signed by {}, not by the issuer you pinned ({expected}). The \
             signatures are intact — it is internally consistent — but it was signed by a \
             different key, so it is not evidence about the issuer you asked about.",
            signed.signature_public_key
        )));
    }
    Ok(())
}

// ── durable stop records ──────────────────────────────────────────────────────────────

/// Where stop records live: `<root>/stops/<warrant-id>.json`.
///
/// Its own directory rather than a field on [`StoredWarrant`], for two reasons. The record is
/// append-only evidence and a warrant's stored file is rewritten on every state change; and adding a
/// field to `StoredWarrant` would change a struct that seven test modules construct by literal,
/// which is a lot of churn for a value that is not part of a warrant's identity.
#[derive(Debug, Clone)]
pub struct StopStore {
    root: PathBuf,
}

impl StopStore {
    /// Open (or create) the stop-record directory under a store root.
    ///
    /// # Errors
    /// [`StopError::Encode`] if the directory cannot be created.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StopError> {
        let root = root.as_ref().join("stops");
        std::fs::create_dir_all(&root)
            .map_err(|e| StopError::Encode(format!("create stops dir: {e}")))?;
        Ok(Self { root })
    }

    /// Path a warrant's stop record occupies.
    #[must_use]
    pub fn path(&self, warrant_id: &str) -> PathBuf {
        self.root.join(format!("{warrant_id}.json"))
    }

    /// Persist a signed stop record, returning where it landed.
    ///
    /// # Errors
    /// [`StopError::Encode`] on serialisation or I/O failure.
    pub fn save(&self, signed: &SignedStop) -> Result<PathBuf, StopError> {
        let path = self.path(&signed.record.warrant_id);
        let body = serde_json::to_vec_pretty(signed)
            .map_err(|e| StopError::Encode(format!("serialise stop record: {e}")))?;
        std::fs::write(&path, &body)
            .map_err(|e| StopError::Encode(format!("write {}: {e}", path.display())))?;
        Ok(path)
    }

    /// Read a warrant's stop record, when it has one and it parses.
    #[must_use]
    pub fn get(&self, warrant_id: &str) -> Option<SignedStop> {
        let body = std::fs::read(self.path(warrant_id)).ok()?;
        serde_json::from_slice(&body).ok()
    }

    /// Has this warrant been stopped?
    ///
    /// Answered from the file's **existence**, deliberately: a stop record that is corrupt or
    /// unparseable still means someone stopped this warrant, and treating it as unstopped because
    /// it will not deserialise would be the one failure direction that matters.
    ///
    /// `try_exists` rather than `exists`, for exactly the same reason. `Path::exists` returns
    /// `false` when the answer is *unknown* — a permission error, an I/O failure, a disconnected
    /// volume — and it folds that into the same answer as "definitely not stopped". That would drop
    /// the warrant out of [`Self::contained_scopes`], and the notary's containment gate would then
    /// pass for a warrant somebody had stopped. Unknown resolves to stopped.
    #[must_use]
    pub fn is_stopped(&self, warrant_id: &str) -> bool {
        self.path(warrant_id).try_exists().unwrap_or(true)
    }

    /// The scopes to hand the notary's containment gate for this warrant.
    ///
    /// This is the whole of the kill-switch wiring, and it needs no kill-switch dependency: the
    /// notary's `contained_scopes` is a `Vec<String>` and a warrant's scope is its id, so a stopped
    /// warrant denies at gate 1 of every subsequent verdict.
    #[must_use]
    pub fn contained_scopes(&self, warrant_id: &str) -> Vec<String> {
        if self.is_stopped(warrant_id) {
            vec![warrant_id.to_string()]
        } else {
            Vec::new()
        }
    }
}

// ── rendering ─────────────────────────────────────────────────────────────────────────

/// The word for a conformance verdict.
#[must_use]
pub fn verdict_word(verdict: conformance::Verdict) -> &'static str {
    match verdict {
        conformance::Verdict::Pass => "pass",
        conformance::Verdict::PassWithCaveats => "pass-with-caveats",
        conformance::Verdict::Indeterminate => "indeterminate",
        conformance::Verdict::Fail => "fail",
        conformance::Verdict::Unscored => "unscored",
    }
}

/// Whether this stop contained the run, for the caller's exit code.
///
/// False when anything was left running or access was left open. A stop that could not contain must
/// not exit as though it had.
#[must_use]
pub fn contained(signed: &SignedStop) -> bool {
    !signed
        .record
        .conformance
        .report
        .capabilities
        .iter()
        .any(|c| c.verdict == conformance::Verdict::Fail)
}

/// What `warrantor stop` prints. Loud on purpose: this is the command an operator runs when
/// something is wrong, and a quiet success is indistinguishable from a no-op.
///
/// Call it **after** [`StopStore::save`]: one line states that the warrant's scope is now contained,
/// which is true because the record is on disk, and printing it before the write would be a promise
/// rather than a report.
#[must_use]
pub fn render_cli(signed: &SignedStop) -> String {
    let outcome = &signed.record.outcome;
    let report = &signed.record.conformance.report;
    let mut lines = vec![
        format!(
            "STOPPED {}  —  \"{}\"",
            signed.record.warrant_id, signed.record.goal
        ),
        format!(
            "state: {:?} -> {:?}",
            outcome.state_before, outcome.state_after
        ),
        String::new(),
        "── WHAT WAS TERMINATED ──".to_string(),
    ];
    match (outcome.supervisor_pid, outcome.supervisor_was_alive) {
        (Some(pid), true) if outcome.supervisor_gone => lines.push(format!(
            "  supervisor pid {pid} terminated and confirmed gone in {} ms{}",
            outcome.trigger_to_quiescence_ms,
            if outcome.quiescence_held {
                format!(", still gone after {} ms", STOP_HOLD.as_millis())
            } else {
                ", but it did NOT stay gone".to_string()
            }
        )),
        (Some(pid), true) => lines.push(format!(
            "  supervisor pid {pid} did NOT die within {} ms. The agent it started is presumed \
             still running.",
            STOP_BUDGET.as_millis()
        )),
        (Some(pid), false) => lines.push(format!(
            "  supervisor pid {pid} was already gone; nothing was terminated"
        )),
        (None, _) => {
            lines
                .push("  nothing was supervising this warrant; nothing was terminated".to_string());
        }
    }
    lines.push(format!(
        "  lifetime link  {} — the agent {}",
        outcome.linkage_mechanism,
        if outcome.agent_dies_with_supervisor {
            "dies with the supervisor by kernel guarantee; its own quiescence was NOT measured"
        } else {
            "CAN OUTLIVE the supervisor on this platform. This stop did not contain it."
        }
    ));

    lines.push(String::new());
    lines.push("── WHAT REVOCATION REACHED ──".to_string());
    lines.push(format!(
        "  new agent sessions  {}",
        if outcome.new_sessions_refused {
            "refused"
        } else {
            "STILL ACCEPTED"
        }
    ));
    lines.push(
        "  notary containment  this warrant's scope is contained; its next report denies \
                at the containment gate"
            .to_string(),
    );
    lines.push(format!(
        "  staged effects      kept. The warrant is {:?} — settle or void it: warrantor report {}",
        outcome.state_after, signed.record.warrant_id
    ));

    lines.push(String::new());
    lines.push("── CONTAINMENT CONFORMANCE ──".to_string());
    for capability in &report.capabilities {
        lines.push(format!(
            "  {:<20}{}",
            capability.capability.label(),
            verdict_word(capability.verdict)
        ));
        for caveat in &capability.caveats {
            lines.push(format!("      {caveat}"));
        }
    }
    lines.push(format!("  scored by {}", report.suite_version));

    lines.push(String::new());
    lines.push("── SIGNED EVIDENCE ──".to_string());
    lines.push(format!("  record          {}", signed.record_digest));
    lines.push(format!("  signed by       {}", signed.signature_public_key));
    lines.push(format!("  enforcement     {}", report.enforcement_mode));
    lines.push(format!(
        "  limitations     {} recorded in the report",
        report.limitations.len()
    ));

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The `── WHAT THIS DOES NOT ESTABLISH ──` section, shared by `stop` and `verify`.
#[must_use]
pub fn render_limitations(signed: &SignedStop) -> String {
    let mut lines = vec![
        String::new(),
        "── WHAT THIS DOES NOT ESTABLISH ──".to_string(),
    ];
    for limitation in &signed.record.conformance.report.limitations {
        lines.push(format!("  - {limitation}"));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

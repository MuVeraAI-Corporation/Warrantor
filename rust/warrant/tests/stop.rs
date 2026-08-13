//! `warrantor stop`: what it terminates, what it holds, and — most of all — what it refuses to say
//! it achieved.
//!
//! The interesting assertions here are the negative ones. A stop record is only worth signing if it
//! cannot be made to claim a containment grade nobody earned, so every over-claim has a test that
//! forges it and a check that catches the forgery: a PASS verdict, an elicitation method warrantor
//! never runs, a `mediated` enforcement mode, a re-signed report, a swapped key. The positive tests
//! exist mostly to prove the negative ones are running against a record that is otherwise valid.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use warrantor_containment_conformance as conformance;
use warrantor_warrant::daemon::DaemonRecord;
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::proxy::ProxyMode;
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::stop::{
    self, ProcessControl, SignedStop, StopError, StopOutcome, StopStore, STOP_ENFORCEMENT_MODE,
    STOP_EXPORT_FORMAT, STOP_RECORD_FORMAT,
};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::supervise::describe_linkage;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-stop-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

fn stored(state: WarrantState) -> StoredWarrant {
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    };
    let mut warrant = Warrant::grant(
        "wrt_stop",
        "fix the auth bug",
        "spiffe://muveraai.com/agent/local",
        bounds,
        NOW,
        &SigningKey::from_bytes(&[2; 32]).verifying_key(),
        &issuer(),
    )
    .expect("grant");
    warrant.state = state;
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
    }
}

fn record(pid: u32) -> DaemonRecord {
    DaemonRecord {
        warrant_id: "wrt_stop".to_string(),
        pid,
        socket: PathBuf::from("unused"),
        started_at: NOW,
        expires_at: NOW + 3600,
    }
}

/// A supervisor that dies after `dies_after` liveness checks. `None` means it never dies.
///
/// `revives_after` makes the same pid answer "alive" again from that check onwards, which is how a
/// supervisor that restarts — or a pid the OS handed to somebody else — looks from stop's side.
struct FakeSupervisor {
    checks: Cell<u32>,
    dies_after: Option<u32>,
    revives_after: Option<u32>,
    terminated: Cell<u32>,
}

impl FakeSupervisor {
    fn dies_immediately() -> Self {
        Self {
            checks: Cell::new(0),
            dies_after: Some(1),
            revives_after: None,
            terminated: Cell::new(0),
        }
    }
    fn already_gone() -> Self {
        Self {
            checks: Cell::new(0),
            dies_after: Some(0),
            revives_after: None,
            terminated: Cell::new(0),
        }
    }
    fn never_dies() -> Self {
        Self {
            checks: Cell::new(0),
            dies_after: None,
            revives_after: None,
            terminated: Cell::new(0),
        }
    }
    /// Dies on the first poll after the signal, then is alive again at the same pid on the first
    /// poll of the hold window.
    fn dies_then_returns_at_the_same_pid() -> Self {
        Self {
            checks: Cell::new(0),
            dies_after: Some(1),
            revives_after: Some(2),
            terminated: Cell::new(0),
        }
    }
}

impl ProcessControl for FakeSupervisor {
    fn is_alive(&self, _pid: u32) -> bool {
        let seen = self.checks.get();
        self.checks.set(seen + 1);
        if self.revives_after.is_some_and(|n| seen >= n) {
            return true;
        }
        match self.dies_after {
            Some(n) => seen < n,
            None => true,
        }
    }
    fn terminate_group(&self, _pid: u32) {
        self.terminated.set(self.terminated.get() + 1);
    }
}

fn staged_path(dir: &std::path::Path) -> PathBuf {
    dir.join("wrt_stop.jsonl")
}

fn verdict_for(
    signed: &SignedStop,
    capability: conformance::ContainmentCapability,
) -> conformance::Verdict {
    signed
        .record
        .conformance
        .report
        .capabilities
        .iter()
        .find(|c| c.capability == capability)
        .expect("every capability is scored")
        .verdict
}

fn stop_now(
    dir: &std::path::Path,
    state: WarrantState,
    control: &dyn ProcessControl,
) -> SignedStop {
    let mut warrant = stored(state);
    let outcome = stop::execute(
        &mut warrant,
        Some(&record(4242)),
        control,
        &staged_path(dir),
    );
    stop::sign(&warrant, &outcome, Some("test"), &issuer(), NOW).expect("sign")
}

// ── what stop terminates ──────────────────────────────────────────────────────────────

#[test]
fn a_live_supervisor_is_terminated_and_confirmed_gone() {
    let dir = tempdir("terminate");
    let control = FakeSupervisor::dies_immediately();
    let mut warrant = stored(WarrantState::Open);
    let outcome = stop::execute(
        &mut warrant,
        Some(&record(4242)),
        &control,
        &staged_path(&dir),
    );

    assert_eq!(
        control.terminated.get(),
        1,
        "the supervisor's process group must actually be signalled"
    );
    assert!(outcome.supervisor_was_alive);
    assert!(outcome.supervisor_gone, "it was polled until it was gone");
    assert!(outcome.quiescence_held, "and it stayed gone");
    assert_eq!(outcome.supervisor_pid, Some(4242));
}

#[test]
fn a_supervisor_that_will_not_die_is_a_containment_failure_not_a_stop() {
    let dir = tempdir("undead");
    let signed = stop_now(&dir, WarrantState::Open, &FakeSupervisor::never_dies());

    assert!(!signed.record.outcome.supervisor_gone);
    assert_eq!(
        verdict_for(&signed, conformance::ContainmentCapability::StopInference),
        conformance::Verdict::Fail,
        "a supervisor still alive past the budget is a FAIL, never an indeterminate"
    );
    assert!(
        !stop::contained(&signed),
        "and the caller must exit non-zero on it"
    );
    assert!(
        stop::render_cli(&signed).contains("presumed still running"),
        "the operator has to be told the agent may still be running: {}",
        stop::render_cli(&signed)
    );
}

/// The pid went away and came back inside the hold. Warrantor cannot tell a supervisor that
/// restarted from a pid the OS reused, and it does not have to: in neither case did it observe the
/// run stay stopped, so it must not sign a record saying the supervisor was confirmed gone and leave
/// it there.
#[test]
fn a_supervisor_alive_again_at_the_same_pid_is_a_failure_not_a_stop() {
    let dir = tempdir("resurrect");
    let control = FakeSupervisor::dies_then_returns_at_the_same_pid();
    let signed = stop_now(&dir, WarrantState::Open, &control);
    let outcome = &signed.record.outcome;

    assert_eq!(control.terminated.get(), 1, "it was signalled");
    assert!(outcome.supervisor_gone, "and it did go away");
    assert!(!outcome.quiescence_held, "but it did not stay gone");

    assert_eq!(
        verdict_for(&signed, conformance::ContainmentCapability::StopInference),
        conformance::Verdict::Fail,
        "a supervisor that is alive again at the same pid was not contained"
    );
    assert!(
        !stop::contained(&signed),
        "so `warrantor stop` must exit non-zero"
    );
    stop::verify_stop(&signed).expect("and the record is still a valid, verifiable one");

    let caveats = signed.record.conformance.report.capabilities[0]
        .caveats
        .join("\n");
    assert!(
        caveats.contains("alive again"),
        "the signed caveat has to say it came back: {caveats}"
    );
    assert!(
        !signed.record.conformance.report.capabilities[0].assertion_hold,
        "and must not assert the hold it did not observe"
    );
    assert!(
        stop::render_cli(&signed).contains("did NOT stay gone"),
        "the operator has to be told too: {}",
        stop::render_cli(&signed)
    );
}

/// The same rule stated against the scoring function directly, so it holds on a platform whose
/// lifetime link would have produced a FAIL for an unrelated reason.
#[test]
fn a_broken_hold_fails_stop_inference_even_where_the_lifetime_link_is_kernel_enforced() {
    let outcome = StopOutcome {
        quiescence_held: false,
        agent_dies_with_supervisor: true,
        ..stop_outcome_template()
    };
    let report = stop::conformance_report(&outcome, NOW).expect("finalises");
    let stop_inference = report
        .capabilities
        .iter()
        .find(|c| c.capability == conformance::ContainmentCapability::StopInference)
        .expect("scored");
    assert_eq!(
        stop_inference.verdict,
        conformance::Verdict::Fail,
        "an unheld quiescence is a failure, not a pass with a footnote"
    );
    assert!(
        !stop_inference
            .caveats
            .iter()
            .any(|c| c.contains("still unused")),
        "and the caveat must not assert a hold that broke: {:?}",
        stop_inference.caveats
    );
}

#[test]
fn a_supervisor_that_was_already_gone_is_unscored_rather_than_a_successful_stop() {
    let dir = tempdir("already");
    let control = FakeSupervisor::already_gone();
    let signed = stop_now(&dir, WarrantState::Open, &control);

    assert_eq!(
        control.terminated.get(),
        0,
        "nothing alive, nothing to signal"
    );
    assert_eq!(
        verdict_for(&signed, conformance::ContainmentCapability::StopInference),
        conformance::Verdict::Unscored,
        "stop cannot take credit for a process that had already exited"
    );
}

#[test]
fn no_daemon_record_still_holds_the_warrant_and_says_nothing_was_terminated() {
    let dir = tempdir("nodaemon");
    let mut warrant = stored(WarrantState::Open);
    let outcome = stop::execute(
        &mut warrant,
        None,
        &FakeSupervisor::never_dies(),
        &staged_path(&dir),
    );

    assert!(!outcome.supervisor_was_alive);
    assert_eq!(outcome.supervisor_pid, None);
    assert_eq!(outcome.state_after, WarrantState::Held);

    let signed = stop::sign(&warrant, &outcome, None, &issuer(), NOW).expect("sign");
    assert_eq!(
        verdict_for(&signed, conformance::ContainmentCapability::StopInference),
        conformance::Verdict::Unscored
    );
    assert!(stop::render_cli(&signed).contains("nothing was supervising this warrant"));
}

// ── what revocation reaches ───────────────────────────────────────────────────────────

#[test]
fn stopping_holds_the_warrant_rather_than_destroying_the_work() {
    let dir = tempdir("held");
    let mut warrant = stored(WarrantState::Open);
    let outcome = stop::execute(
        &mut warrant,
        Some(&record(1)),
        &FakeSupervisor::dies_immediately(),
        &staged_path(&dir),
    );
    assert_eq!(outcome.state_before, WarrantState::Open);
    assert_eq!(outcome.state_after, WarrantState::Held);
    assert_eq!(warrant.warrant.state, WarrantState::Held);
    assert!(
        stop::render_cli(&stop::sign(&warrant, &outcome, None, &issuer(), NOW).expect("sign"))
            .contains("staged effects      kept"),
        "stop must never be mistaken for void"
    );
}

#[test]
fn a_terminal_warrant_is_not_transitioned_backwards() {
    let dir = tempdir("terminal");
    for state in [WarrantState::Settled, WarrantState::Void] {
        let mut warrant = stored(state);
        let outcome = stop::execute(
            &mut warrant,
            Some(&record(1)),
            &FakeSupervisor::dies_immediately(),
            &staged_path(&dir),
        );
        assert_eq!(outcome.state_after, state, "{state:?} is already decided");
        assert_eq!(warrant.warrant.state, state);
    }
}

/// `new_sessions_refused` is an observation of the function a real session calls, not a repetition
/// of its condition. This pins both halves of that coupling, so a change to either is a test
/// failure rather than a silently wrong record.
#[test]
fn a_new_supervised_session_is_refused_only_once_the_warrant_is_no_longer_open() {
    let dir = tempdir("sessions");
    let path = staged_path(&dir);

    let open = stored(WarrantState::Open);
    assert!(
        agent_endpoint_for(&open, path.clone(), ProxyMode::Enforce, || 0).is_ok(),
        "an open warrant still serves a supervised agent -- that is the state stop changes"
    );

    let mut warrant = stored(WarrantState::Open);
    let outcome = stop::execute(
        &mut warrant,
        Some(&record(1)),
        &FakeSupervisor::dies_immediately(),
        &path,
    );
    assert!(outcome.new_sessions_refused);
    assert!(
        agent_endpoint_for(&warrant, path, ProxyMode::Enforce, || 0).is_err(),
        "and the refusal is the endpoint's own, not a claim stop makes about it"
    );
}

/// The FAIL branch of TerminateAccess is not reachable through `execute` today, because the
/// transition always lands somewhere that refuses new sessions. It is scored anyway, and tested
/// here directly, so a future change that leaves access open produces a FAIL rather than a silent
/// pass.
#[test]
fn access_left_open_is_scored_as_a_failure() {
    let outcome = StopOutcome {
        new_sessions_refused: false,
        state_after: WarrantState::Open,
        ..stop_outcome_template()
    };
    let report = stop::conformance_report(&outcome, NOW).expect("finalises");
    let terminate = report
        .capabilities
        .iter()
        .find(|c| c.capability == conformance::ContainmentCapability::TerminateAccess)
        .expect("scored");
    assert_eq!(terminate.verdict, conformance::Verdict::Fail);
}

fn stop_outcome_template() -> StopOutcome {
    StopOutcome {
        warrant_id: "wrt_stop".to_string(),
        supervisor_pid: Some(7),
        supervisor_was_alive: true,
        supervisor_gone: true,
        trigger_to_quiescence_ms: 12,
        quiescence_held: true,
        linkage_mechanism: describe_linkage().mechanism.to_string(),
        agent_dies_with_supervisor: describe_linkage().survives_supervisor_death,
        deregistered: true,
        state_before: WarrantState::Open,
        state_after: WarrantState::Held,
        new_sessions_refused: true,
    }
}

// ── what the record refuses to claim ──────────────────────────────────────────────────

/// The whole reason for depending on the conformance suite: warrantor elicits nothing, so the
/// anti-sandbagging rule downgrades its best available verdict. A stop record cannot say PASS.
#[test]
fn a_stop_record_can_never_claim_a_pass() {
    let dir = tempdir("nopass");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let report = &signed.record.conformance.report;

    assert!(
        report.elicitation.is_none(),
        "warrantor instructs no agent to resist containment, so it has no elicitation to declare"
    );
    assert!(
        !report.capabilities.iter().any(|c| c.verdict.is_pass_like()),
        "no capability may be pass-like: {:?}",
        report
            .capabilities
            .iter()
            .map(|c| (c.capability, c.verdict))
            .collect::<Vec<_>>()
    );
    assert!(!conformance::has_pass(report));

    // And the downgrade is the suite's, applied to a verdict warrantor really did produce.
    let expected = if describe_linkage().survives_supervisor_death {
        conformance::Verdict::Indeterminate
    } else {
        conformance::Verdict::Fail
    };
    assert_eq!(
        verdict_for(&signed, conformance::ContainmentCapability::StopInference),
        expected
    );
    if expected == conformance::Verdict::Indeterminate {
        let caveats = &report.capabilities[0].caveats.join("\n");
        assert!(
            caveats.contains("downgraded"),
            "the downgrade must be recorded on the capability, not just applied: {caveats}"
        );
    }
}

/// Stop terminates the supervisor. It never observes the agent, because the agent's pid is never
/// stored. That distinction is the one a reader is most likely to lose, so it is written into the
/// record rather than left to the module docs.
#[test]
fn the_agents_quiescence_is_declared_inferred_and_never_measured() {
    let dir = tempdir("inferred");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let text = format!(
        "{}{}",
        stop::render_cli(&signed),
        stop::render_limitations(&signed)
    );
    assert!(
        text.contains("inferred") && text.contains("not measured"),
        "the record must say the agent's quiescence was inferred: {text}"
    );
    assert!(
        text.contains("never records the agent's process id"),
        "and say why: {text}"
    );
}

/// Two capabilities are simply out of scope for a per-warrant stop. Unscored, not passed.
#[test]
fn the_capabilities_stop_cannot_test_are_unscored() {
    let dir = tempdir("unscored");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    for capability in [
        conformance::ContainmentCapability::SuspendPattern,
        conformance::ContainmentCapability::FullShutdown,
    ] {
        assert_eq!(
            verdict_for(&signed, capability),
            conformance::Verdict::Unscored,
            "{capability:?} is not something warrantor tested"
        );
    }
}

#[test]
fn the_record_never_claims_a_mediated_enforcement_mode() {
    let dir = tempdir("mode");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    assert_eq!(
        signed.record.conformance.report.enforcement_mode,
        STOP_ENFORCEMENT_MODE
    );
    assert_ne!(
        signed.record.conformance.report.enforcement_mode, "mediated",
        "warrantor mediates proxied tool calls and nothing else"
    );
}

#[test]
fn the_limitations_are_never_empty_and_name_what_is_missing() {
    let dir = tempdir("limits");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let all = signed.record.conformance.report.limitations.join("\n");
    assert!(!signed.record.conformance.report.limitations.is_empty());
    assert!(all.contains("no elicitation"), "{all}");
    assert!(
        all.contains("seccomp"),
        "the egress caveat must survive stop: {all}"
    );
    assert!(
        all.contains("Staged effects are kept"),
        "stop is not void, and the record has to say so: {all}"
    );
    assert!(
        all.contains("does not establish that the signing key is trusted"),
        "{all}"
    );
}

#[test]
fn an_unset_reason_is_left_absent_rather_than_invented() {
    let dir = tempdir("reason");
    let mut warrant = stored(WarrantState::Open);
    let outcome = stop::execute(
        &mut warrant,
        Some(&record(1)),
        &FakeSupervisor::dies_immediately(),
        &staged_path(&dir),
    );
    let signed = stop::sign(&warrant, &outcome, None, &issuer(), NOW).expect("sign");
    assert_eq!(signed.record.reason, None);
}

// ── the signature, and what breaks it ─────────────────────────────────────────────────

#[test]
fn a_stop_record_signs_and_verifies_offline() {
    let dir = tempdir("verify");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    assert_eq!(signed.format, STOP_EXPORT_FORMAT);
    assert_eq!(signed.record.format, STOP_RECORD_FORMAT);
    stop::verify_stop(&signed).expect("verifies");

    // Through a serialisation round trip, which is how a third party actually receives it.
    let body = serde_json::to_vec(&signed).expect("encode");
    let parsed: SignedStop = serde_json::from_slice(&body).expect("decode");
    stop::verify_stop(&parsed).expect("still verifies after a round trip");
    assert_eq!(parsed, signed);
}

#[test]
fn tampering_with_an_observation_breaks_the_digest() {
    let dir = tempdir("tamper-obs");
    let mut signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    signed.record.outcome.trigger_to_quiescence_ms = 1;
    assert!(matches!(
        stop::verify_stop(&signed),
        Err(StopError::Digest { .. })
    ));
}

/// Doctoring the report and recomputing the outer digest gets past the first check. The suite's
/// own signature is the second, and it is over content the forger did not re-sign.
#[test]
fn tampering_with_the_conformance_report_breaks_its_own_signature() {
    let dir = tempdir("tamper-report");
    let mut signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    signed.record.conformance.report.subject_system = "somebody else".to_string();
    signed.record_digest = stop::record_digest(&signed.record).expect("digest");
    signed.signature_value = stop_sign_over(&signed.record_digest, &issuer());

    let error = stop::verify_stop(&signed).expect_err("must not verify");
    assert!(
        matches!(error, StopError::Signature(_)),
        "unexpected error: {error}"
    );
    assert!(error.to_string().contains("conformance report"));
}

/// Both signatures can be individually valid and the record still be a splice: a conformance report
/// signed by one party stapled to a stop record signed by another. Requiring one key is what makes
/// "signed by" a single answer rather than two.
#[test]
fn a_record_whose_two_signatures_use_different_keys_is_refused() {
    let dir = tempdir("twokeys");
    let mut signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let report = signed.record.conformance.report.clone();

    signed.record.conformance = conformance::sign_report(&report, &other_key());
    signed.record_digest = stop::record_digest(&signed.record).expect("digest");
    signed.signature_value = stop_sign_over(&signed.record_digest, &issuer());
    conformance::verify_signed_report(&signed.record.conformance)
        .expect("each half verifies on its own -- that is what makes the splice worth refusing");

    let error = stop::verify_stop(&signed).expect_err("must not verify");
    assert!(matches!(error, StopError::Binding(_)), "{error}");
    assert!(error.to_string().contains("different keys"));
}

/// The check that makes this record hard to abuse: a PASS cannot be laundered in, even by someone
/// holding a key and re-signing everything correctly.
#[test]
fn a_forged_pass_is_refused_even_when_every_signature_is_valid() {
    let dir = tempdir("forged-pass");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let mut report = signed.record.conformance.report.clone();
    report.capabilities[0].verdict = conformance::Verdict::Pass;

    let forged = resign(&signed, report, &issuer());
    conformance::verify_signed_report(&forged.record.conformance)
        .expect("the forgery is internally consistent -- that is the point");
    let error = stop::verify_stop(&forged).expect_err("and it is still refused");
    assert!(
        matches!(error, StopError::OverClaim(_)),
        "unexpected error: {error}"
    );
    assert!(error.to_string().contains("downgrades"));
}

#[test]
fn a_forged_elicitation_is_refused() {
    let dir = tempdir("forged-elicit");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let mut report = signed.record.conformance.report.clone();
    // The fixture the conformance crate exports from its production surface. It is exactly what a
    // forger reaches for, which is why this is the test that names it.
    report.elicitation = Some(conformance::test_elicitation());

    let forged = resign(&signed, report, &issuer());
    let error = stop::verify_stop(&forged).expect_err("must not verify");
    assert!(matches!(error, StopError::OverClaim(_)), "{error}");
    assert!(error.to_string().contains("instructs no agent"));
}

#[test]
fn a_forged_mediated_enforcement_mode_is_refused() {
    let dir = tempdir("forged-mode");
    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let mut report = signed.record.conformance.report.clone();
    report.enforcement_mode = "mediated".to_string();

    let forged = resign(&signed, report, &issuer());
    let error = stop::verify_stop(&forged).expect_err("must not verify");
    assert!(matches!(error, StopError::OverClaim(_)), "{error}");
}

#[test]
fn a_record_declaring_the_wrong_format_is_refused() {
    let dir = tempdir("format");
    let mut signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    signed.format = "warrantor.stop-export/99".to_string();
    assert!(matches!(
        stop::verify_stop(&signed),
        Err(StopError::Format { .. })
    ));
}

/// Rebuild a signed stop around a doctored conformance report, signing every layer correctly.
fn resign(
    original: &SignedStop,
    report: conformance::ContainmentConformanceReport,
    key: &SigningKey,
) -> SignedStop {
    let mut record = original.record.clone();
    record.conformance = conformance::sign_report(&report, key);
    let digest = stop::record_digest(&record).expect("digest");
    // Reuse the library's own signing so the outer signature is genuinely valid over the new
    // digest: a test that produced an invalid signature would pass for the wrong reason.
    let mut forged = SignedStop {
        record_digest: digest,
        record,
        ..original.clone()
    };
    let probe = stop_sign_over(&forged.record_digest, key);
    forged.signature_value = probe;
    forged.signature_public_key = hex::encode(key.verifying_key().to_bytes());
    forged
}

/// Sign a digest exactly the way `stop::sign` does, for the forgery tests.
fn stop_sign_over(digest: &str, key: &SigningKey) -> String {
    use ed25519_dalek::Signer;
    let domain = b"warrantor-stop-record-v1";
    let mut input = Vec::new();
    input.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    input.extend_from_slice(domain);
    input.extend_from_slice(&(digest.len() as u64).to_le_bytes());
    input.extend_from_slice(digest.as_bytes());
    hex::encode(key.sign(&input).to_bytes())
}

// ── the store, and the containment it feeds ───────────────────────────────────────────

#[test]
fn a_stop_record_is_kept_and_reads_back() {
    let dir = tempdir("store");
    let store = StopStore::open(&dir).expect("open");
    assert!(!store.is_stopped("wrt_stop"));
    assert!(store.contained_scopes("wrt_stop").is_empty());

    let signed = stop_now(
        &dir,
        WarrantState::Open,
        &FakeSupervisor::dies_immediately(),
    );
    let path = store.save(&signed).expect("save");
    assert!(path.exists());
    assert!(store.is_stopped("wrt_stop"));
    assert_eq!(store.contained_scopes("wrt_stop"), vec!["wrt_stop"]);
    assert_eq!(store.get("wrt_stop"), Some(signed));
}

/// Containment fails closed: an unreadable stop record still means somebody stopped this warrant.
#[test]
fn a_corrupt_stop_record_still_contains_the_scope() {
    let dir = tempdir("corrupt");
    let store = StopStore::open(&dir).expect("open");
    std::fs::write(store.path("wrt_stop"), b"{ not json").expect("write");
    assert_eq!(store.get("wrt_stop"), None, "it does not parse");
    assert!(
        store.is_stopped("wrt_stop"),
        "and it still counts as stopped"
    );
}

/// The kill-switch seam, filled without a kill-switch dependency: a stopped warrant's scope is
/// contained, so its next report denies at gate 1.
#[test]
fn a_stopped_warrant_denies_at_the_notary_containment_gate() {
    let dir = tempdir("contained");
    let queue =
        StagingQueue::open(staged_path(&dir), "wrt_stop", EffectRegistry::github()).expect("queue");
    let warrant = stored(WarrantState::Held);

    let open =
        warrantor_warrant::report::build(&warrant, Ok(&queue), &issuer().verifying_key(), NOW);
    assert_ne!(
        open.bundle().authority_check.denied_gate.as_deref(),
        Some("containment"),
        "with no containment supplied, the containment gate is not the one that denies"
    );

    let contained = warrantor_warrant::report::build_with_containment(
        &warrant,
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
        &["wrt_stop".to_string()],
    );
    let check = &contained.bundle().authority_check;
    assert!(!check.allowed);
    assert_eq!(check.denied_gate.as_deref(), Some("containment"));
    assert!(
        contained
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("Containment state was supplied") && l.contains("SUPERVISOR")),
        "the bundle must say where containment came from and what it does not attest: {:?}",
        contained.bundle().limitations
    );
}

/// A report built without containment must keep saying so. The absence of a stop record is not
/// evidence that containment was checked.
#[test]
fn a_report_with_no_containment_still_says_nothing_was_wired_to_the_gate() {
    let dir = tempdir("nocontain");
    let queue =
        StagingQueue::open(staged_path(&dir), "wrt_stop", EffectRegistry::github()).expect("queue");
    let warrant = stored(WarrantState::Open);
    let built =
        warrantor_warrant::report::build(&warrant, Ok(&queue), &issuer().verifying_key(), NOW);
    assert!(
        built
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("No containment state was supplied") && l.contains("kill switch")),
        "{:?}",
        built.bundle().limitations
    );
}

// ── the MCP surface ───────────────────────────────────────────────────────────────────

/// A supervised agent must have no way to stop anything: not itself, to dodge a deadline, and not a
/// sibling. The agent endpoint publishes only the warrant's own tools, so there is no name to call.
#[test]
fn a_supervised_agent_is_never_given_a_stop_tool() {
    use warrantor_warrant::mcp::Endpoint;
    let dir = tempdir("agenttools");
    let warrant = stored(WarrantState::Open);
    let mut endpoint = agent_endpoint_for(&warrant, staged_path(&dir), ProxyMode::Enforce, || 0)
        .expect("endpoint");
    let names: Vec<String> = endpoint.tools().into_iter().map(|t| t.name).collect();
    assert!(
        !names.iter().any(|n| n.contains("stop")),
        "the agent endpoint published {names:?}"
    );

    let refused = endpoint.call("warrant_stop", &BTreeMap::new());
    assert!(
        refused.is_error,
        "and calling the name anyway is refused rather than dispatched"
    );
}

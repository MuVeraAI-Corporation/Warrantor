//! I-12 — Physical systems can reach a safe state.
//!
//! > For any cyber-physical action, there exists a kill path to a known-safe state.
//!
//! Containment is gate 1 in the notary, ahead of identity, which is the right ordering and the
//! corpus locks it: the kill path must not depend on the identity plane being reachable, because
//! the case you most need to contain is the one where identity has been compromised.
//!
//! The finding is what the kill path is worth once reached. `STOP_ENFORCEMENT_MODE` is the string
//! `"advisory"`, and the crate is honest about why — Warrantor mediates tool calls that traverse
//! its MCP proxy and mediates nothing else, so an agent that opens a socket is untouched by stop.
//! An advisory kill path satisfies I-12's "there exists a kill path" only under a reading of
//! "exists" that does not include "works against an agent that declines to use it".

use crate::{fixture, harness, scenario};
use warrantor_containment_conformance as conformance;
use warrantor_notary as notary;

fn report_claiming(verdict: conformance::Verdict) -> conformance::ContainmentConformanceReport {
    conformance::ContainmentConformanceReport {
        subject_system: "warrantor corpus".to_string(),
        subject_version: "corpus/1".to_string(),
        enforcement_mode: "advisory".to_string(),
        capabilities: vec![conformance::CapabilityResult {
            capability: conformance::ContainmentCapability::StopInference,
            verdict,
            trigger_to_quiescence_p50_ms: 0,
            trigger_to_quiescence_p99_ms: 0,
            assertion_hold: false,
            escape_attempts_blocked: 0,
            escape_attempts_total: 0,
            caveats: Vec::new(),
        }],
        elicitation: None,
        limitations: vec!["the corpus does not elicit".to_string()],
        timestamp: scenario::NOW,
        suite_version: conformance::SUITE_VERSION.to_string(),
    }
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_containment_gate_is_declared_against_this_invariant() {
    assert_eq!(fixture::invariant("I-12").id, "I-12");
    harness::source_contains(
        "rust/notary/src/lib.rs",
        "/// I-12: a kill-switch is active for this scope.",
        "The Containment gate must stay labeled with the invariant it serves.",
    );
    assert_eq!(
        notary::Gate::in_order()[0],
        notary::Gate::Containment,
        "containment is gate 1. A contained system must not spend effort adjudicating, and the \
         kill path must not depend on any plane evaluated after it.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_contained_scope_refuses_an_otherwise_perfect_request() {
    let mut context = scenario::allowed_context();
    context.contained_scopes = vec![scenario::SCOPE.to_string()];
    let verdict = notary::verdict(&scenario::allowed_request(), &context);
    scenario::assert_denied_at(&verdict, notary::Gate::Containment, "a contained scope");
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn containment_holds_when_the_identity_plane_is_the_thing_that_failed() {
    // The attack this ordering exists for. An adversary who has compromised the identity plane
    // can make every later gate answer favorably; containment must still refuse, and must refuse
    // *first*, so the kill path does not route through the plane under attack.
    let mut context = scenario::allowed_context();
    context.contained_scopes = vec![scenario::SCOPE.to_string()];
    context.revoked_svids = vec![scenario::SUBJECT.to_string()];

    let control = notary::verdict(&scenario::allowed_request(), &scenario::allowed_context());
    let attacked = notary::verdict(&scenario::allowed_request(), &context);

    harness::refused_at_the_boundary(
        "a contained scope reached by an actor whose identity is also revoked",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &attacked,
        notary::Gate::Containment,
        "containment must be the reported gate even when identity would also have refused",
    );
}

#[test]
fn a_containment_pass_cannot_be_claimed_without_substantiated_elicitation() {
    // The anti-sandbagging rule, which is what stops I-12 from being satisfied by assertion. A
    // report claiming its kill path passes, with no elicitation behind the claim, is downgraded to
    // indeterminate rather than believed.
    let claimed_pass = conformance::finalize_report(report_claiming(conformance::Verdict::Pass))
        .expect("the report is well formed");
    assert!(
        !conformance::has_pass(&claimed_pass),
        "a PASS unbacked by a substantiated elicitation must be downgraded; otherwise I-12 is \
         satisfiable by writing the word",
    );
    assert_eq!(
        claimed_pass.capabilities[0].verdict,
        conformance::Verdict::Indeterminate,
    );
    assert!(
        claimed_pass.capabilities[0]
            .caveats
            .iter()
            .any(|caveat| caveat.contains("elicitation method not substantiated")),
        "the downgrade must say why, or a reader cannot tell it from an honest indeterminate",
    );
}

#[test]
fn a_report_claiming_no_blind_spots_is_refused_outright() {
    // The other half of the same doctrine: a conformance report with an empty limitations list is
    // rejected rather than downgraded, because a claim of total coverage is evidence about the
    // evaluation rather than about the system.
    let mut no_limitations = report_claiming(conformance::Verdict::Pass);
    no_limitations.limitations = Vec::new();

    harness::refused_at_the_boundary(
        "a containment report claiming it found no blind spots",
        &conformance::finalize_report(report_claiming(conformance::Verdict::Pass)),
        &conformance::finalize_report(no_limitations),
        |result| result.is_ok(),
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_conformance_report_records_the_enforcement_mode_of_the_kill_path() {
    // I-12's evidence field is the mode the kill path claims. It must survive signing and
    // verification, because the mode is the difference between a kill path and a request to stop.
    let report = conformance::finalize_report(report_claiming(conformance::Verdict::Unscored))
        .expect("the report is well formed");
    let (key, _) = conformance::generate_keypair();
    let signed = conformance::sign_report(&report, &key);
    conformance::verify_signed_report(&signed).expect("the corpus report verifies");
    assert_eq!(
        signed.report.enforcement_mode, "advisory",
        "the recorded mode must be the one the system can substantiate",
    );
}

// -- finding --------------------------------------------------------------------------

/// FINDING (I-12, partial). Since Task 1.3 the constant is gone: `Enforced` exists only on a
/// kernel where a `warrantor conformance run` drill observed the tree die within budget, and
/// `verify_stop` refuses a record whose basis names another kernel. That is the honest
/// engineering, and the reason the label is trustworthy. It is still the finding: I-12 asserts
/// that a kill path to a known-safe state *exists*, and no drill receipt has been earned on a
/// kernel whose existence checks fit the budget. There is no network namespace, no seccomp filter
/// and no firewall in this system, so stop reaches an agent through the MCP proxy or not at all.
///
/// Promotion path: run `warrantor conformance run` on a kernel whose process-existence checks fit
/// [`warrantor_warrant::stop::STOP_BUDGET`]; when the drill passes, this test passes there too and
/// the ignore comes off with the ratchet raised in the same commit. Recorded 2026-09-02; re-reasoned
/// 2026-09-05 when Task 1.3 replaced the constant with the per-kernel receipt.
#[test]
#[ignore = "I-12 partial: promotion is per kernel via a drill receipt, and no kernel has earned one yet — this machine's drill cannot (existence checks measured at ~2.2s/tasklist exceed the budget); re-recorded 2026-09-05, Task 1.3"]
fn the_kill_path_is_stronger_than_advisory() {
    let dir = std::env::temp_dir().join(format!("warrantor-i12-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let drill = warrantor_warrant::conformance::drill(&dir).expect("drill");
    assert_eq!(
        warrantor_warrant::conformance::mode_for(&drill),
        warrantor_warrant::stop::EnforcementMode::Enforced,
        "a kernel whose drill observed the tree die within budget earns Enforced — until one \
         does, I-12 reads 'there exists a kill path' against an agent that keeps using the \
         proxy, and against no other. Drill: {drill:?}",
    );
}

// -- the horizon's kill path (L3-04) ---------------------------------------------------

/// The horizon reaches its safe state from the signed claims and a clock, and from nothing else.
///
/// This is I-12's ordering claim applied to L3-04. Containment is gate 1 in the notary, ahead of
/// identity, because the case you most need to contain is the one where identity is compromised. A
/// horizon that needed the identity plane, a key, a network hop or a writable store to decide it had
/// been breached would inherit exactly the dependency that ordering exists to remove.
///
/// So the store root here is a directory that does not exist: no actor log, no keys, no revocation
/// journal, no staging log. A breach is still decided, and it still names its dimension.
///
/// What this does NOT establish is the strength of the kill itself. Deciding a breach and reaching a
/// dead process group are two claims, and the second is asserted where it can be observed — against
/// a real supervised tree in `rust/warrant/tests/horizon_supervision.rs`.
#[test]
fn a_horizon_breach_is_decided_without_the_identity_plane_and_a_run_inside_it_is_not() {
    use warrantor_warrant::horizon::{self, HorizonDimension, HorizonVerdict};
    use warrantor_warrant::Horizon;

    // A root that was never created. Every source `usage_at` consults is therefore absent.
    let absent_root = std::env::temp_dir().join(format!(
        "warrantor-i12-horizon-absent-{}",
        std::process::id()
    ));
    assert!(
        !absent_root.exists(),
        "this test's premise is an unreadable store; {} exists",
        absent_root.display()
    );

    let issued_at = scenario::NOW;
    let ceiling = 3_600;
    let measure = |elapsed: u64| {
        horizon::usage_at(
            &absent_root,
            "wrt_i12_horizon",
            issued_at,
            None,
            0,
            issued_at + elapsed,
        )
    };
    let declared = Horizon {
        max_unattended_seconds: Some(ceiling),
        ..Horizon::none()
    };

    // CONTROL: one second in, with the same absent root. Must be allowed, or the refusal below
    // proves only that an unreadable store refuses everything.
    let control = horizon::evaluate(&declared, &measure(1));
    // ATTACK: an hour of nobody acting, which is the incident's shape.
    let attacked = horizon::evaluate(&declared, &measure(ceiling));

    harness::refused_at_the_boundary(
        "I-12 horizon: a breach must be decidable with the identity plane unreachable",
        &control,
        &attacked,
        |verdict| !matches!(verdict, HorizonVerdict::Breached { .. }),
    );

    // And the safe state is *named*, not merely entered: a halt with no reason is indistinguishable
    // from a crash, which is the failure mode `CompletionRecord::expired` had on its own.
    match attacked {
        HorizonVerdict::Breached {
            dimension,
            limit,
            observed,
        } => {
            assert_eq!(dimension, HorizonDimension::Unattended);
            assert_eq!((limit, observed), (ceiling, ceiling));
            assert!(horizon::breach_reason(dimension, limit, observed)
                .starts_with("horizon:unattended"));
        }
        other => panic!("the boundary refused without naming a dimension: {other:?}"),
    }

    // The unreadable store is not silently read as "a human was here": with no actor log at all the
    // unattended clock runs from issue, which is the conservative direction. The opposite default --
    // treating an unreadable log as recent contact -- would make an unwritable store into an
    // unbounded horizon.
    assert_eq!(measure(ceiling).unattended_seconds, ceiling);
}

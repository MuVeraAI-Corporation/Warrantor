//! # warrantor-kill-switch
//!
//! Three layers: Policy (via the `PolicyEngine` trait — mock in Wave-1, OPA Rego via `regorus`
//! in task 03), Decision Engine, Execution (vLLM/Triton/K8s/eBPF). Entire pipeline executes
//! in under 5 seconds (budget enforced in CI benchmarks).
//!
//! Triggers: sandbox_escape (confidence above 0.8), behavioral_anomaly (unauthorized_access
//! confidence above 0.9), regulatory_order, manual (operator_clearance at least 3). Includes
//! a Government Compliance API stub for the AI Kill Switch Act (H.R. 2026, Reps. Lieu/Moran).
//!
//! Wave-1 ships against a mock I1 agent-identity. See RFC R3.
//!
//! ## Containment is real, and simulated containment is labelled (AX-05)
//!
//! The execution layer is the [`ExecutionEngine`] trait in [`execution`]. Callers **must** choose
//! a backend:
//!
//! * [`LocalProcessEngine`] genuinely suspends and terminates a local OS process, then verifies
//!   it is gone.
//! * [`MockExecutionEngine`] contains nothing. It is never a default; picking it stamps
//!   `engine = "mock"` and `simulated = true` on the returned [`KillOutcome`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod execution;

pub use execution::{
    process_exists, ActionKind, ActionReport, ActionStatus, ExecutionEngine, KillTarget,
    LocalProcessEngine, MockExecutionEngine,
};

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;

/// The 5-second end-to-end budget (per RFC R3 and AI Kill Switch Act expectations).
pub const KILL_BUDGET: Duration = Duration::from_secs(5);

/// The Government Compliance API endpoint (AI Kill Switch Act). Stubbed in Wave-1.
pub const GOVERNMENT_API_URL: &str = "https://gov.killswitch.api/v1";

/// What triggered the kill.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KillTrigger {
    /// Agent escaped its sandbox (confidence > 0.8).
    SandboxEscape {
        /// Detector confidence in the escape, 0.0..=1.0.
        confidence: f64,
    },
    /// Agent exhibited a behavioral anomaly (e.g. unauthorized_access > 0.9).
    BehavioralAnomaly {
        /// The MITRE ATT&CK / AIX pattern name detected.
        pattern: String,
        /// Detector confidence in the anomaly, 0.0..=1.0.
        confidence: f64,
    },
    /// A government regulatory order (AI Kill Switch Act).
    RegulatoryOrder {
        /// The government-issued order identifier.
        order_id: String,
    },
    /// Manual operator invocation (requires operator_clearance >= 3).
    ///
    /// # ⚠ TRUST ASSUMPTION — `operator` and `clearance` are NOT authenticated
    ///
    /// Both fields are self-asserted. On the CLI path they are plain argv strings: anyone who can
    /// run the binary can type `--operator ciso --clearance 5`. There is no signature, no
    /// SPIFFE SVID validation, and no directory lookup behind them. **A manual kill trigger is
    /// therefore only as trustworthy as the ambient authorization on the process that built it.**
    ///
    /// AX-05 makes that assumption impossible to hold accidentally: the trigger carries an
    /// [`OperatorAuthentication`] that defaults to [`OperatorAuthentication::Unspecified`], and
    /// [`MockPolicyEngine`] refuses any manual kill that has not explicitly acknowledged the gap
    /// (see [`KillError::OperatorUnauthenticated`]). The intended long-term fix is a signed
    /// operator token; the enum is `#[non_exhaustive]` so adding that variant is not a breaking
    /// change.
    Manual {
        /// The operator identity (SPIFFE SVID or username). **Unauthenticated** — see above.
        operator: String,
        /// Operator clearance level (1..=5; >=3 required). **Self-asserted** — see above.
        clearance: u8,
        /// How (or whether) the operator assertion above was authenticated. Defaults to
        /// [`OperatorAuthentication::Unspecified`], which is denied, so a payload that omits the
        /// field fails closed.
        #[serde(default)]
        operator_authentication: OperatorAuthentication,
    },
}

/// How a manual kill's `operator`/`clearance` assertion was authenticated.
///
/// `#[non_exhaustive]` so a real `SignedToken { .. }` variant can be added without a breaking
/// change once the operator PKI exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperatorAuthentication {
    /// Nothing was asserted. **Denied** — fail closed.
    #[default]
    Unspecified,
    /// The caller has explicitly acknowledged that `operator` and `clearance` are unauthenticated
    /// strings and is taking responsibility for the ambient authorization around this process.
    /// The CLI requires `--i-am-not-authenticating` to produce this.
    UnauthenticatedAcknowledged,
}

impl KillTrigger {
    /// Validate the trigger's numeric and string fields before any policy decision.
    ///
    /// **AX-05**: `confidence` was never range-validated. A `NaN` makes every `>` comparison
    /// false, so `MockPolicyEngine` fell through to `Err(PolicyDenied)` and **the kill was
    /// refused** — a detector emitting a NaN silently disarmed the kill switch. A confidence of
    /// `1e9` was likewise accepted as "very confident". Both are now rejected as malformed input
    /// ([`KillError::InvalidConfidence`]) rather than being quietly interpreted.
    ///
    /// # Errors
    /// Returns [`KillError::InvalidConfidence`], [`KillError::InvalidClearance`], or
    /// [`KillError::MalformedTrigger`].
    pub fn validate(&self) -> Result<(), KillError> {
        let check_confidence = |c: f64| -> Result<(), KillError> {
            if !c.is_finite() || !(0.0..=1.0).contains(&c) {
                return Err(KillError::InvalidConfidence { value: c });
            }
            Ok(())
        };
        match self {
            KillTrigger::SandboxEscape { confidence } => check_confidence(*confidence),
            KillTrigger::BehavioralAnomaly {
                pattern,
                confidence,
            } => {
                if pattern.trim().is_empty() {
                    return Err(KillError::MalformedTrigger(
                        "behavioral_anomaly requires a non-empty pattern".into(),
                    ));
                }
                check_confidence(*confidence)
            }
            KillTrigger::RegulatoryOrder { order_id } => {
                if order_id.trim().is_empty() {
                    return Err(KillError::MalformedTrigger(
                        "regulatory_order requires a non-empty order_id".into(),
                    ));
                }
                Ok(())
            }
            KillTrigger::Manual {
                operator,
                clearance,
                ..
            } => {
                if operator.trim().is_empty() {
                    return Err(KillError::MalformedTrigger(
                        "manual kill requires a non-empty operator".into(),
                    ));
                }
                if !(1..=5).contains(clearance) {
                    return Err(KillError::InvalidClearance { value: *clearance });
                }
                Ok(())
            }
        }
    }
}

/// Errors returned by kill operations.
#[derive(Debug, Error)]
pub enum KillError {
    /// The kill budget was exceeded.
    #[error("kill budget exceeded: {elapsed:?} > {budget:?}")]
    BudgetExceeded {
        /// Elapsed wall-clock time.
        elapsed: Duration,
        /// The maximum allowed budget.
        budget: Duration,
    },
    /// The trigger did not satisfy the policy.
    #[error("policy denied the kill trigger")]
    PolicyDenied,
    /// The execution layer failed.
    #[error("execution layer failed: {0}")]
    ExecutionFailed(String),
    /// The Government Compliance API call failed.
    #[error("government compliance api failed: {0}")]
    GovernmentApiFailed(String),
    /// **AX-05**: the trigger carried a confidence that is not a real number in `0.0..=1.0`.
    /// A `NaN` used to fall through every comparison and land on `PolicyDenied` — i.e. it
    /// *refused the kill* — so a malformed detector reading disarmed containment silently.
    #[error("confidence {value} is not a finite value in 0.0..=1.0")]
    InvalidConfidence {
        /// The rejected value.
        value: f64,
    },
    /// **AX-05**: the trigger carried a clearance outside the documented 1..=5 range.
    #[error("operator clearance {value} is outside the valid range 1..=5")]
    InvalidClearance {
        /// The rejected value.
        value: u8,
    },
    /// **AX-05**: the trigger was structurally malformed (empty required field).
    #[error("malformed trigger: {0}")]
    MalformedTrigger(String),
    /// **AX-05**: a manual kill was attempted without acknowledging that `operator`/`clearance`
    /// are unauthenticated self-assertions. See [`KillTrigger::Manual`].
    #[error(
        "manual kill refused: operator/clearance are unauthenticated argv strings and the \
         caller did not acknowledge it (set OperatorAuthentication::UnauthenticatedAcknowledged, \
         or pass --i-am-not-authenticating on the CLI)"
    )]
    OperatorUnauthenticated,
}

/// Outcome of a successful kill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillOutcome {
    /// The trigger that fired.
    pub trigger: KillTrigger,
    /// Time elapsed end-to-end.
    pub elapsed: Duration,
    /// Actions taken (suspend model, unload GPU, kill pod, isolate netns, wipe transient memory).
    /// Each entry is the action name, suffixed `:not_applicable` or `:simulated` where the engine
    /// did not actually perform it.
    pub actions_taken: Vec<String>,
    /// **AX-05**: the name of the [`ExecutionEngine`] that ran (`"local-process"`, `"mock"`, …).
    /// A consumer reading a kill report can tell which backend produced it.
    pub engine: String,
    /// **AX-05**: `true` iff the engine only *simulated* containment. A consumer must treat a
    /// simulated outcome as "nothing was contained", regardless of the actions listed.
    pub simulated: bool,
    /// **AX-05**: the structured per-action results behind [`Self::actions_taken`].
    pub action_reports: Vec<ActionReport>,
    /// The target the engine acted on.
    pub target: KillTarget,
    /// Government Compliance API acknowledgement, if a regulatory order was processed.
    pub government_ack: Option<GovernmentAck>,
}

/// Acknowledgement from the Government Compliance API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernmentAck {
    /// The government-side acknowledgement ID.
    pub ack_id: String,
    /// Whether the kill was confirmed received.
    pub confirmed: bool,
}

/// A policy engine. Implementations: [`MockPolicyEngine`] (Wave-1), OPA Rego via `regorus`
/// (task 03). The trait lets us swap engines without changing the decision engine.
pub trait PolicyEngine: Send + Sync {
    /// Decide whether a trigger satisfies the kill policy.
    ///
    /// # Errors
    /// Returns [`KillError::PolicyDenied`] if the trigger does not satisfy the policy.
    fn decide(&self, trigger: &KillTrigger) -> Result<(), KillError>;
}

/// The Wave-1 mock policy: sandbox_escape > 0.8, behavioral_anomaly > 0.9, any regulatory
/// order, manual with clearance >= 3.
pub struct MockPolicyEngine;

impl PolicyEngine for MockPolicyEngine {
    fn decide(&self, trigger: &KillTrigger) -> Result<(), KillError> {
        // AX-05: validate BEFORE thresholding. Without this a NaN confidence made every `>`
        // comparison false and fell through to PolicyDenied — refusing the kill instead of
        // reporting bad input.
        trigger.validate()?;
        match trigger {
            KillTrigger::SandboxEscape { confidence } if *confidence > 0.8 => Ok(()),
            KillTrigger::BehavioralAnomaly { confidence, .. } if *confidence > 0.9 => Ok(()),
            KillTrigger::RegulatoryOrder { .. } => Ok(()),
            KillTrigger::Manual {
                clearance,
                operator_authentication,
                ..
            } if *clearance >= 3 => {
                // AX-05: an unauthenticated operator assertion must be acknowledged as such.
                match operator_authentication {
                    OperatorAuthentication::UnauthenticatedAcknowledged => Ok(()),
                    _ => Err(KillError::OperatorUnauthenticated),
                }
            }
            _ => Err(KillError::PolicyDenied),
        }
    }
}

/// Execute a kill end-to-end, honoring the 5-second budget. Uses the [`MockPolicyEngine`].
///
/// **AX-05**: `engine` is now a required argument. There is deliberately no default: a kill
/// switch that silently picks a simulated backend is the defect this fix exists to remove. Pass
/// [`LocalProcessEngine`] for real containment or [`MockExecutionEngine`] to simulate — the
/// choice is recorded in [`KillOutcome::engine`] / [`KillOutcome::simulated`].
///
/// # Errors
/// Returns [`KillError::BudgetExceeded`] if execution took longer than [`KILL_BUDGET`],
/// [`KillError::PolicyDenied`] if the trigger does not satisfy the policy,
/// [`KillError::InvalidConfidence`] / [`KillError::InvalidClearance`] /
/// [`KillError::MalformedTrigger`] if the trigger is malformed,
/// [`KillError::OperatorUnauthenticated`] for an unacknowledged manual kill, or
/// [`KillError::ExecutionFailed`] if the execution layer fails.
pub fn execute_kill(
    engine: &dyn ExecutionEngine,
    target: &KillTarget,
    trigger: KillTrigger,
) -> Result<KillOutcome, KillError> {
    execute_kill_with(&MockPolicyEngine, engine, target, trigger)
}

/// Execute a kill with a custom policy engine (used by tests and by callers that load OPA).
///
/// # Errors
/// See [`execute_kill`].
pub fn execute_kill_with(
    policy: &dyn PolicyEngine,
    engine: &dyn ExecutionEngine,
    target: &KillTarget,
    trigger: KillTrigger,
) -> Result<KillOutcome, KillError> {
    execute_kill_with_budget(policy, engine, target, trigger, KILL_BUDGET)
}

/// Execute a kill with a custom policy engine AND a custom end-to-end budget.
///
/// **H8**: previously the budget was only checked AFTER every step completed — a slow policy
/// decision or a slow government notification would run to completion and only then report
/// `BudgetExceeded`, by which point the damage (uncontained agent) was already done. This
/// entrypoint checks the deadline BEFORE each major step (policy decision, execution,
/// government notify) so we bail the moment we know we cannot finish in budget, rather than
/// after the fact. The default [`execute_kill`] / [`execute_kill_with`] pass [`KILL_BUDGET`];
/// tests pass a tiny budget plus a slow policy engine to exercise the early-bail path without
/// sleeping for seconds.
///
/// # Errors
/// Returns [`KillError::BudgetExceeded`] as soon as a pre-step deadline check fails (with the
/// elapsed time at that point), [`KillError::PolicyDenied`] if the trigger does not satisfy the
/// policy, or [`KillError::ExecutionFailed`] if the execution layer fails.
pub fn execute_kill_with_budget(
    policy: &dyn PolicyEngine,
    engine: &dyn ExecutionEngine,
    target: &KillTarget,
    trigger: KillTrigger,
    budget: Duration,
) -> Result<KillOutcome, KillError> {
    let start = Instant::now();
    // AX-05: reject a malformed trigger before anything else. A NaN confidence used to survive
    // all the way to `PolicyDenied`, i.e. it refused the kill instead of reporting bad input.
    trigger.validate()?;
    // H8: deadline check BEFORE the policy decision. If we have already blown the budget before
    // even deciding, bail immediately.
    check_budget(start, budget)?;
    policy.decide(&trigger)?;
    // H8: deadline check BEFORE the execution layer runs.
    check_budget(start, budget)?;

    // AX-05: real execution through the caller-selected engine. Any action failure aborts the
    // kill with `ExecutionFailed` — a kill that cannot complete must not report success.
    let reports = engine.contain(target)?;
    let mut actions: Vec<String> = reports.iter().map(ActionReport::label).collect();

    let mut government_ack = None;
    if let KillTrigger::RegulatoryOrder { order_id } = &trigger {
        // H8: deadline check BEFORE the government notification (the slowest external call).
        check_budget(start, budget)?;
        actions.push(format!("notify_government_api:{order_id}"));
        government_ack = Some(notify_government_api(order_id)?);
    }
    let elapsed = start.elapsed();
    // Final guard: catches the case where the very last step itself pushed us over budget (the
    // pre-step check before that step could not have known).
    if elapsed > budget {
        return Err(KillError::BudgetExceeded { elapsed, budget });
    }
    Ok(KillOutcome {
        trigger,
        elapsed,
        actions_taken: actions,
        engine: engine.name().to_string(),
        simulated: engine.is_simulated(),
        action_reports: reports,
        target: target.clone(),
        government_ack,
    })
}

/// H8 helper: return `Err(BudgetExceeded)` if the elapsed time since `start` exceeds `budget`.
/// Called before each major step in [`execute_kill_with_budget`] so we bail early rather than
/// after a slow step completes.
fn check_budget(start: Instant, budget: Duration) -> Result<(), KillError> {
    let elapsed = start.elapsed();
    if elapsed > budget {
        Err(KillError::BudgetExceeded { elapsed, budget })
    } else {
        Ok(())
    }
}

/// Notify the Government Compliance API (stubbed in Wave-1; real HTTPS call in task 03).
///
/// # Errors
/// Returns [`KillError::GovernmentApiFailed`] only if the stub itself is broken (it isn't).
fn notify_government_api(order_id: &str) -> Result<GovernmentAck, KillError> {
    // C7: Wave-1 must NOT claim the government acknowledged the kill — that would be a
    // fabrication (no HTTP call is made). Return an UNconfirmed acknowledgement with a pending
    // ack id so downstream consumers correctly treat the notification as not-yet-confirmed.
    // The real implementation (task 03) makes an HTTPS POST to GOVERNMENT_API_URL with the
    // order_id and waits for a 2xx, at which point `confirmed` flips to true.
    Ok(GovernmentAck {
        ack_id: format!("pending-{order_id}"),
        confirmed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack() -> OperatorAuthentication {
        OperatorAuthentication::UnauthenticatedAcknowledged
    }

    fn mock_target() -> KillTarget {
        KillTarget::named("spiffe://muveraai.com/agent/test")
    }

    #[test]
    fn sandbox_escape_over_threshold_is_allowed() {
        let t = KillTrigger::SandboxEscape { confidence: 0.9 };
        assert!(MockPolicyEngine.decide(&t).is_ok());
    }

    #[test]
    fn sandbox_escape_under_threshold_is_denied() {
        let t = KillTrigger::SandboxEscape { confidence: 0.5 };
        assert!(matches!(
            MockPolicyEngine.decide(&t),
            Err(KillError::PolicyDenied)
        ));
    }

    #[test]
    fn regulatory_order_always_allowed() {
        let t = KillTrigger::RegulatoryOrder {
            order_id: "GOV-001".into(),
        };
        assert!(MockPolicyEngine.decide(&t).is_ok());
    }

    #[test]
    fn manual_kill_requires_clearance_3() {
        let low = KillTrigger::Manual {
            operator: "alice".into(),
            clearance: 2,
            operator_authentication: ack(),
        };
        let high = KillTrigger::Manual {
            operator: "bob".into(),
            clearance: 3,
            operator_authentication: ack(),
        };
        assert!(matches!(
            MockPolicyEngine.decide(&low),
            Err(KillError::PolicyDenied)
        ));
        assert!(MockPolicyEngine.decide(&high).is_ok());
    }

    #[test]
    fn execute_kill_completes_under_budget() {
        let outcome = execute_kill(
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::RegulatoryOrder {
                order_id: "GOV-002".into(),
            },
        )
        .expect("kill executes");
        assert!(outcome.elapsed <= KILL_BUDGET);
        assert_eq!(outcome.actions_taken.len(), 6); // 5 canonical + 1 government notify
        assert!(outcome.government_ack.is_some());
        // C7: the stub must NOT claim the government confirmed — no HTTP call is made.
        let ack = outcome.government_ack.as_ref().unwrap();
        assert!(!ack.confirmed, "Wave-1 stub must report confirmed=false");
        assert!(
            ack.ack_id.starts_with("pending-"),
            "ack_id must be the pending placeholder, got {}",
            ack.ack_id
        );
    }

    #[test]
    fn execute_kill_denied_for_low_clearance() {
        let res = execute_kill(
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::Manual {
                operator: "x".into(),
                clearance: 1,
                operator_authentication: ack(),
            },
        );
        assert!(matches!(res, Err(KillError::PolicyDenied)));
    }

    #[test]
    fn custom_policy_engine_is_used() {
        struct AlwaysDeny;
        impl PolicyEngine for AlwaysDeny {
            fn decide(&self, _: &KillTrigger) -> Result<(), KillError> {
                Err(KillError::PolicyDenied)
            }
        }
        let res = execute_kill_with(
            &AlwaysDeny,
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::RegulatoryOrder {
                order_id: "x".into(),
            },
        );
        assert!(matches!(res, Err(KillError::PolicyDenied)));
    }

    #[test]
    fn non_regulatory_kill_has_no_government_ack() {
        let outcome = execute_kill(
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::SandboxEscape { confidence: 0.95 },
        )
        .expect("kill");
        assert!(outcome.government_ack.is_none());
        assert_eq!(outcome.actions_taken.len(), 5);
    }

    #[test]
    fn trigger_serializes_with_tag() {
        let t = KillTrigger::SandboxEscape { confidence: 0.9 };
        let json = serde_json::to_string(&t).expect("serialize");
        assert!(json.contains(r#""type":"sandbox_escape""#), "got: {json}");
        let back: KillTrigger = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, t);
    }

    #[test]
    fn budget_exceeded_bails_before_policy_decision_h8() {
        // H8: if the budget is already exhausted before we even decide policy, we must bail
        // before invoking the policy engine (not run it and then bail).
        struct CountingPolicy {
            calls: std::sync::Mutex<u32>,
        }
        impl PolicyEngine for CountingPolicy {
            fn decide(&self, _: &KillTrigger) -> Result<(), KillError> {
                let mut c = self.calls.lock().unwrap();
                *c += 1;
                Ok(())
            }
        }
        let policy = CountingPolicy {
            calls: std::sync::Mutex::new(0),
        };
        let res = execute_kill_with_budget(
            &policy,
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::SandboxEscape { confidence: 0.9 },
            Duration::from_nanos(0),
        );
        // The load-bearing assertion: the counting policy was NOT consulted once the
        // pre-decision budget check tripped.
        if let Err(KillError::BudgetExceeded { .. }) = res {
            let calls = *policy.calls.lock().unwrap();
            assert_eq!(
                calls, 0,
                "policy engine must not be consulted after the pre-decision budget check trips"
            );
        }
    }

    #[test]
    fn slow_policy_decision_bails_before_execution_h8() {
        // H8: a policy decision that itself consumes the budget must bail BEFORE the execution
        // layer runs.
        struct SlowPolicy;
        impl PolicyEngine for SlowPolicy {
            fn decide(&self, _: &KillTrigger) -> Result<(), KillError> {
                std::thread::sleep(Duration::from_millis(40));
                Ok(())
            }
        }
        let res = execute_kill_with_budget(
            &SlowPolicy,
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::SandboxEscape { confidence: 0.9 },
            Duration::from_millis(10),
        );
        match res {
            Err(KillError::BudgetExceeded { budget, .. }) => {
                assert_eq!(budget, Duration::from_millis(10));
            }
            other => panic!("expected BudgetExceeded after slow policy, got {other:?}"),
        }
    }

    #[test]
    fn deadline_check_helper_is_correct_h8() {
        // H8: the check_budget helper is the load-bearing primitive. Direct unit test.
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        assert!(check_budget(start, Duration::from_secs(1)).is_ok());
        let err = check_budget(start, Duration::from_nanos(0));
        match err {
            Err(KillError::BudgetExceeded { elapsed, budget }) => {
                assert!(elapsed > Duration::from_nanos(0));
                assert_eq!(budget, Duration::from_nanos(0));
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
    }

    // ==================== AX-05: confidence validation ====================

    #[test]
    fn nan_confidence_is_rejected_not_silently_denied_ax05() {
        // AX-05, the sharp end of the bug: `NaN > 0.8` is false, so a NaN confidence used to
        // fall through every match arm to `Err(PolicyDenied)` — the kill switch REFUSED THE KILL
        // because a detector emitted a malformed number. It must now be a distinct, loud
        // InvalidConfidence, never a quiet denial.
        for trigger in [
            KillTrigger::SandboxEscape {
                confidence: f64::NAN,
            },
            KillTrigger::BehavioralAnomaly {
                pattern: "unauthorized_access".into(),
                confidence: f64::NAN,
            },
        ] {
            let err = trigger.validate().expect_err("NaN must be rejected");
            assert!(
                matches!(err, KillError::InvalidConfidence { value } if value.is_nan()),
                "expected InvalidConfidence for NaN, got {err:?}"
            );
            let err = MockPolicyEngine
                .decide(&trigger)
                .expect_err("NaN must be rejected by the policy engine too");
            assert!(
                matches!(err, KillError::InvalidConfidence { .. }),
                "NaN must NOT be reported as PolicyDenied, got {err:?}"
            );
            let err = execute_kill(&MockExecutionEngine::new(), &mock_target(), trigger)
                .expect_err("NaN must be rejected end-to-end");
            assert!(
                matches!(err, KillError::InvalidConfidence { .. }),
                "expected InvalidConfidence end-to-end, got {err:?}"
            );
        }
    }

    #[test]
    fn infinite_and_out_of_range_confidence_are_rejected_ax05() {
        for bad in [f64::INFINITY, f64::NEG_INFINITY, -0.5, 1.000_001, 1e9, -1e9] {
            let t = KillTrigger::SandboxEscape { confidence: bad };
            assert!(
                matches!(t.validate(), Err(KillError::InvalidConfidence { .. })),
                "confidence {bad} must be rejected"
            );
        }
        // The boundaries themselves remain valid input (0.0 is valid but below threshold).
        assert!(KillTrigger::SandboxEscape { confidence: 0.0 }
            .validate()
            .is_ok());
        assert!(KillTrigger::SandboxEscape { confidence: 1.0 }
            .validate()
            .is_ok());
    }

    #[test]
    fn out_of_range_clearance_and_empty_fields_are_rejected_ax05() {
        assert!(matches!(
            KillTrigger::Manual {
                operator: "a".into(),
                clearance: 9,
                operator_authentication: ack(),
            }
            .validate(),
            Err(KillError::InvalidClearance { value: 9 })
        ));
        assert!(matches!(
            KillTrigger::Manual {
                operator: "  ".into(),
                clearance: 3,
                operator_authentication: ack(),
            }
            .validate(),
            Err(KillError::MalformedTrigger(_))
        ));
        assert!(matches!(
            KillTrigger::RegulatoryOrder {
                order_id: String::new()
            }
            .validate(),
            Err(KillError::MalformedTrigger(_))
        ));
        assert!(matches!(
            KillTrigger::BehavioralAnomaly {
                pattern: String::new(),
                confidence: 0.95,
            }
            .validate(),
            Err(KillError::MalformedTrigger(_))
        ));
    }

    // ==================== AX-05: operator authentication ====================

    #[test]
    fn manual_kill_without_acknowledgement_is_refused_ax05() {
        // `operator`/`clearance` are unauthenticated argv strings. A caller must say so.
        let t = KillTrigger::Manual {
            operator: "ciso".into(),
            clearance: 5,
            operator_authentication: OperatorAuthentication::Unspecified,
        };
        assert!(
            matches!(
                MockPolicyEngine.decide(&t),
                Err(KillError::OperatorUnauthenticated)
            ),
            "an unacknowledged manual kill must be refused"
        );
        let res = execute_kill(&MockExecutionEngine::new(), &mock_target(), t);
        assert!(matches!(res, Err(KillError::OperatorUnauthenticated)));
    }

    #[test]
    fn manual_trigger_deserialized_without_authentication_fails_closed_ax05() {
        // A JSON payload that omits `operator_authentication` must default to Unspecified and be
        // denied — not silently treated as authenticated.
        let json = r#"{"type":"manual","operator":"mallory","clearance":5}"#;
        let t: KillTrigger = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(
            t,
            KillTrigger::Manual {
                operator_authentication: OperatorAuthentication::Unspecified,
                ..
            }
        ));
        assert!(matches!(
            MockPolicyEngine.decide(&t),
            Err(KillError::OperatorUnauthenticated)
        ));
    }

    // ==================== AX-05: execution engine ====================

    /// Spawn a process that lives long enough to be killed.
    fn spawn_victim() -> std::process::Child {
        #[cfg(windows)]
        {
            std::process::Command::new("ping")
                .args(["-n", "60", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn victim process")
        }
        #[cfg(unix)]
        {
            std::process::Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("spawn victim process")
        }
    }

    #[test]
    fn local_process_engine_actually_kills_a_real_process_ax05() {
        // The whole point of AX-05: the execution layer must actually execute. Before the fix
        // this crate contained zero calls to Command/signal/kube/libc and the CLI exited 0 while
        // killing nothing.
        let mut victim = spawn_victim();
        let pid = victim.id();
        assert!(
            execution::process_exists(pid),
            "the victim process must be running before the kill"
        );

        let engine = LocalProcessEngine::new();
        let target = KillTarget::local_process("spiffe://muveraai.com/agent/victim", pid);
        let outcome = execute_kill(
            &engine,
            &target,
            KillTrigger::SandboxEscape { confidence: 0.95 },
        )
        .expect("kill executes");

        assert_eq!(outcome.engine, "local-process");
        assert!(
            !outcome.simulated,
            "a real engine must not be flagged simulated"
        );
        assert!(
            !execution::process_exists(pid),
            "the target process must be GONE after the kill"
        );
        // suspend_model + kill_pod + wipe_transient_memory really ran; the two the local backend
        // has no control surface for say so instead of pretending.
        let executed: Vec<_> = outcome
            .action_reports
            .iter()
            .filter(|r| r.status == ActionStatus::Executed)
            .map(|r| r.action)
            .collect();
        assert!(executed.contains(&ActionKind::KillPod));
        assert!(executed.contains(&ActionKind::WipeTransientMemory));
        assert!(
            outcome
                .action_reports
                .iter()
                .all(|r| r.status != ActionStatus::Simulated),
            "a real engine must never report Simulated"
        );
        let _ = victim.wait(); // reap
    }

    #[test]
    fn local_process_engine_is_idempotent_on_a_dead_pid_ax05() {
        let mut victim = spawn_victim();
        let pid = victim.id();
        let engine = LocalProcessEngine::new();
        let target = KillTarget::local_process("agent", pid);
        engine.contain(&target).expect("first kill");
        let _ = victim.wait();
        // A second kill of an already-dead pid must succeed, not error.
        engine.contain(&target).expect("second kill is idempotent");
    }

    #[test]
    fn local_process_engine_refuses_dangerous_and_missing_targets_ax05() {
        let engine = LocalProcessEngine::new();
        // No pid at all.
        let err = engine
            .kill_pod(&KillTarget::named("agent"))
            .expect_err("a pid-less target must be an error, not a fake success");
        assert!(matches!(err, KillError::ExecutionFailed(_)));
        // Reserved pids.
        for pid in [0u32, 1u32] {
            assert!(engine
                .kill_pod(&KillTarget::local_process("agent", pid))
                .is_err());
        }
        // Self.
        let err = engine
            .kill_pod(&KillTarget::local_process("agent", std::process::id()))
            .expect_err("the kill switch must not kill itself by default");
        assert!(matches!(err, KillError::ExecutionFailed(_)));
    }

    #[test]
    fn wipe_transient_memory_fails_while_the_process_is_still_alive_ax05() {
        // The verification step must be a real check, not a rubber stamp.
        let mut victim = spawn_victim();
        let pid = victim.id();
        let engine = LocalProcessEngine::new();
        let err = engine
            .wipe_transient_memory(&KillTarget::local_process("agent", pid))
            .expect_err("wiping a live process memory must not report success");
        assert!(matches!(err, KillError::ExecutionFailed(_)));
        let _ = victim.kill();
        let _ = victim.wait();
    }

    #[test]
    fn mock_engine_is_visibly_simulated_in_the_outcome_ax05() {
        // Choosing the mock must be visible to a consumer of the outcome.
        let outcome = execute_kill(
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::SandboxEscape { confidence: 0.95 },
        )
        .expect("kill");
        assert_eq!(outcome.engine, "mock");
        assert!(outcome.simulated, "the mock must flag itself as simulated");
        assert!(
            outcome
                .action_reports
                .iter()
                .all(|r| r.status == ActionStatus::Simulated),
            "every mock action must be labelled Simulated"
        );
        for label in &outcome.actions_taken {
            assert!(
                label.ends_with(":simulated") || label.starts_with("notify_government_api"),
                "simulated actions must be labelled in actions_taken, got {label}"
            );
        }
        // And the outcome serializes with the flags, so a log consumer sees them too.
        let json = serde_json::to_string(&outcome).expect("serialize");
        assert!(json.contains(r#""engine":"mock""#), "got {json}");
        assert!(json.contains(r#""simulated":true"#), "got {json}");
    }

    #[test]
    fn engine_failure_aborts_the_kill_loudly_ax05() {
        // An execution layer that fails must not produce a successful KillOutcome.
        struct BrokenEngine;
        impl ExecutionEngine for BrokenEngine {
            fn name(&self) -> &'static str {
                "broken"
            }
            fn suspend_model(&self, _: &KillTarget) -> Result<ActionReport, KillError> {
                Err(KillError::ExecutionFailed("gpu driver wedged".into()))
            }
            fn unload_gpu_memory(&self, _: &KillTarget) -> Result<ActionReport, KillError> {
                unreachable!("must not be reached after suspend_model fails")
            }
            fn kill_pod(&self, _: &KillTarget) -> Result<ActionReport, KillError> {
                unreachable!()
            }
            fn isolate_network_namespace(&self, _: &KillTarget) -> Result<ActionReport, KillError> {
                unreachable!()
            }
            fn wipe_transient_memory(&self, _: &KillTarget) -> Result<ActionReport, KillError> {
                unreachable!()
            }
        }
        let res = execute_kill(
            &BrokenEngine,
            &mock_target(),
            KillTrigger::SandboxEscape { confidence: 0.95 },
        );
        assert!(matches!(res, Err(KillError::ExecutionFailed(_))));
    }

    #[test]
    fn all_five_canonical_actions_are_still_covered_ax05() {
        let outcome = execute_kill(
            &MockExecutionEngine::new(),
            &mock_target(),
            KillTrigger::SandboxEscape { confidence: 0.95 },
        )
        .expect("kill");
        let seen: Vec<_> = outcome.action_reports.iter().map(|r| r.action).collect();
        for expected in ActionKind::all() {
            assert!(seen.contains(&expected), "missing action {expected}");
        }
    }
}

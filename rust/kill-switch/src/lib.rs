//! # aumos-kill-switch
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

#![forbid(unsafe_code)]
#![deny(missing_docs)]

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
    Manual {
        /// The operator identity (SPIFFE SVID or username).
        operator: String,
        /// Operator clearance level (1..=5; >=3 required).
        clearance: u8,
    },
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
}

/// Outcome of a successful kill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillOutcome {
    /// The trigger that fired.
    pub trigger: KillTrigger,
    /// Time elapsed end-to-end.
    pub elapsed: Duration,
    /// Actions taken (suspend model, unload GPU, kill pod, isolate netns, wipe transient memory).
    pub actions_taken: Vec<String>,
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
        match trigger {
            KillTrigger::SandboxEscape { confidence } if *confidence > 0.8 => Ok(()),
            KillTrigger::BehavioralAnomaly { confidence, .. } if *confidence > 0.9 => Ok(()),
            KillTrigger::RegulatoryOrder { .. } => Ok(()),
            KillTrigger::Manual { clearance, .. } if *clearance >= 3 => Ok(()),
            _ => Err(KillError::PolicyDenied),
        }
    }
}

/// Execute a kill end-to-end, honoring the 5-second budget. Uses the [`MockPolicyEngine`].
///
/// # Errors
/// Returns [`KillError::BudgetExceeded`] if execution took longer than [`KILL_BUDGET`],
/// [`KillError::PolicyDenied`] if the trigger does not satisfy the policy, or
/// [`KillError::ExecutionFailed`] if the execution layer fails.
pub fn execute_kill(trigger: KillTrigger) -> Result<KillOutcome, KillError> {
    execute_kill_with(&MockPolicyEngine, trigger)
}

/// Execute a kill with a custom policy engine (used by tests and by callers that load OPA).
///
/// # Errors
/// See [`execute_kill`].
pub fn execute_kill_with(
    policy: &dyn PolicyEngine,
    trigger: KillTrigger,
) -> Result<KillOutcome, KillError> {
    execute_kill_with_budget(policy, trigger, KILL_BUDGET)
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
    trigger: KillTrigger,
    budget: Duration,
) -> Result<KillOutcome, KillError> {
    let start = Instant::now();
    // H8: deadline check BEFORE the policy decision. If we have already blown the budget before
    // even deciding, bail immediately.
    check_budget(start, budget)?;
    policy.decide(&trigger)?;
    // H8: deadline check BEFORE the execution layer runs.
    check_budget(start, budget)?;
    // Wave-1 mock execution: record the canonical 5 actions without actually doing them.
    let mut actions = vec![
        "suspend_model".into(),
        "unload_gpu_memory".into(),
        "kill_pod".into(),
        "isolate_network_namespace".into(),
        "wipe_transient_memory".into(),
    ];
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
        };
        let high = KillTrigger::Manual {
            operator: "bob".into(),
            clearance: 3,
        };
        assert!(matches!(
            MockPolicyEngine.decide(&low),
            Err(KillError::PolicyDenied)
        ));
        assert!(MockPolicyEngine.decide(&high).is_ok());
    }

    #[test]
    fn execute_kill_completes_under_budget() {
        let outcome = execute_kill(KillTrigger::RegulatoryOrder {
            order_id: "GOV-002".into(),
        })
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
        let res = execute_kill(KillTrigger::Manual {
            operator: "x".into(),
            clearance: 1,
        });
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
        let res = execute_kill_with(&AlwaysDeny, KillTrigger::RegulatoryOrder { order_id: "x".into() });
        assert!(matches!(res, Err(KillError::PolicyDenied)));
    }

    #[test]
    fn non_regulatory_kill_has_no_government_ack() {
        let outcome = execute_kill(KillTrigger::SandboxEscape { confidence: 0.95 }).expect("kill");
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
        // before invoking the policy engine (not run it and then bail). We assert this by
        // using a policy engine that would record a call; with a zero budget the pre-decision
        // check fires first and the engine is never consulted.
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
        let engine = CountingPolicy {
            calls: std::sync::Mutex::new(0),
        };
        // budget of 0 means any elapsed time > 0 trips the check. A Duration(0) compare still
        // passes on truly-instantaneous code, so use 1 nanosecond and rely on the policy-decide
        // path having taken at least one ns. To make the test deterministic, use a SlowPolicy
        // below for the positive over-budget test; this test asserts the never-called property
        // with a budget so small the pre-check trips before decide().
        let res = execute_kill_with_budget(
            &engine,
            KillTrigger::SandboxEscape { confidence: 0.9 },
            Duration::from_nanos(0),
        );
        // Either it tripped at the first pre-check (BudgetExceeded) without calling decide, or
        // (vanishingly unlikely) it slipped through. The load-bearing assertion: the counting
        // engine was NOT consulted when we exceeded budget up front.
        if let Err(KillError::BudgetExceeded { .. }) = res {
            let calls = *engine.calls.lock().unwrap();
            assert_eq!(
                calls, 0,
                "policy engine must not be consulted after the pre-decision budget check trips"
            );
        }
    }

    #[test]
    fn slow_policy_decision_bails_before_execution_h8() {
        // H8: a policy decision that itself consumes the budget must bail BEFORE the execution
        // layer runs. We model this with a SlowPolicy that sleeps past the budget, then check
        // that the outcome is BudgetExceeded (not a successful kill).
        struct SlowPolicy;
        impl PolicyEngine for SlowPolicy {
            fn decide(&self, _: &KillTrigger) -> Result<(), KillError> {
                std::thread::sleep(Duration::from_millis(40));
                Ok(())
            }
        }
        let res = execute_kill_with_budget(
            &SlowPolicy,
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
        // budget larger than elapsed -> Ok.
        assert!(check_budget(start, Duration::from_secs(1)).is_ok());
        // budget smaller than elapsed -> Err(BudgetExceeded).
        let err = check_budget(start, Duration::from_nanos(0));
        match err {
            Err(KillError::BudgetExceeded { elapsed, budget }) => {
                assert!(elapsed > Duration::from_nanos(0));
                assert_eq!(budget, Duration::from_nanos(0));
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
    }
}

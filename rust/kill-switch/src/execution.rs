//! The kill switch's **execution layer** (AX-05).
//!
//! # Why this module exists
//!
//! Before AX-05 the entire "execution layer" was five string literals pushed onto a `Vec` and an
//! `Ok`. A grep for `Command|signal|kube|libc|process::` across the crate returned **zero hits**.
//! The in-code comment was honest ("Wave-1 mock execution … without actually doing them") but the
//! CLI exited 0 reporting success while killing nothing, and — the actual defect — there was **no
//! seam a real implementation could be plugged into**.
//!
//! This module is that seam:
//!
//! * [`ExecutionEngine`] — the trait, with the five canonical containment actions as methods.
//! * [`LocalProcessEngine`] — a **real** backend that suspends and terminates an OS process via
//!   `std::process` and signals, and then *verifies* the process is gone.
//! * [`MockExecutionEngine`] — an explicitly-named test double. It is **never** the default on
//!   any non-test path: the caller must pass it by name, and
//!   [`ExecutionEngine::is_simulated`] plus [`crate::KillOutcome::engine`] make its use visible
//!   in the returned outcome, so a consumer can always tell simulated containment from real
//!   containment.
//!
//! # `forbid(unsafe_code)` is preserved
//!
//! Signalling a process would normally mean `libc::kill`, which is `unsafe`. Instead the local
//! backend shells out to the platform's own process-control tool (`kill(1)` on Unix,
//! `taskkill`/`tasklist` on Windows) through [`std::process::Command`]. That keeps the crate-wide
//! `#![forbid(unsafe_code)]` intact for a security-critical component, at the cost of one process
//! spawn per action — irrelevant against the 5-second budget.

use serde::{Deserialize, Serialize};

use crate::KillError;

/// The existence check the rails and the actions share, re-exported so `lib.rs`'s
/// `pub use execution::{ process_exists, … }` is unchanged by the extraction.
pub use warrantor_kill_switch_core::process_exists;

/// What a core termination observed, in the words the action reports have always used.
fn describe(terminated: warrantor_kill_switch_core::Terminated) -> String {
    if terminated.already_gone {
        format!("pid {} was already gone", terminated.pid)
    } else {
        format!(
            "pid {} terminated and verified gone in {:?}",
            terminated.pid, terminated.confirmed_after
        )
    }
}

/// What the kill switch is being asked to contain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillTarget {
    /// The agent identity (SPIFFE SVID or logical name). Informational.
    pub agent_id: String,
    /// The OS process id of the agent, if it runs as a local process. Required by
    /// [`LocalProcessEngine`].
    pub pid: Option<u32>,
    /// The Kubernetes pod name, if the agent runs in one. Out of scope for
    /// [`LocalProcessEngine`].
    pub pod: Option<String>,
    /// The network namespace to isolate, if any. Out of scope for [`LocalProcessEngine`].
    pub netns: Option<String>,
}

impl KillTarget {
    /// A target that is a local OS process.
    #[must_use]
    pub fn local_process(agent_id: impl Into<String>, pid: u32) -> Self {
        Self {
            agent_id: agent_id.into(),
            pid: Some(pid),
            pod: None,
            netns: None,
        }
    }

    /// A target identified only by name (no process/pod handle). Useful with
    /// [`MockExecutionEngine`] and with engines that resolve the handle themselves.
    #[must_use]
    pub fn named(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            ..Self::default()
        }
    }
}

/// One of the five canonical containment actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Stop the model from producing further output.
    SuspendModel,
    /// Release the accelerator memory the agent holds.
    UnloadGpuMemory,
    /// Terminate the agent's execution unit.
    KillPod,
    /// Cut the agent off from the network.
    IsolateNetworkNamespace,
    /// Destroy the agent's in-flight state.
    WipeTransientMemory,
    /// **I-05**: revoke every credential the agent holds, within the &lt;1s budget. Performed by a
    /// [`CredentialRevoker`], not the [`ExecutionEngine`] &mdash; the engine contains the process;
    /// the revoker contains the authority the process was using. Without this action a killed
    /// agent's tokens stay valid until their TTL expires, which is the exact gap invariant I-05
    /// exists to close.
    RevokeCredentials,
}

impl ActionKind {
    /// The canonical wire name (the same strings the pre-AX-05 mock emitted).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::SuspendModel => "suspend_model",
            ActionKind::UnloadGpuMemory => "unload_gpu_memory",
            ActionKind::KillPod => "kill_pod",
            ActionKind::IsolateNetworkNamespace => "isolate_network_namespace",
            ActionKind::WipeTransientMemory => "wipe_transient_memory",
            ActionKind::RevokeCredentials => "revoke_credentials",
        }
    }

    /// The five canonical actions, in execution order.
    #[must_use]
    pub fn all() -> [ActionKind; 5] {
        [
            ActionKind::SuspendModel,
            ActionKind::UnloadGpuMemory,
            ActionKind::KillPod,
            ActionKind::IsolateNetworkNamespace,
            ActionKind::WipeTransientMemory,
        ]
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether an action actually did something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// The engine performed the action against the target.
    Executed,
    /// The engine has no control surface for this action, and says so rather than pretending.
    /// Containment for this dimension must come from another action or another engine.
    NotApplicable,
    /// The engine only *simulated* the action. Produced by [`MockExecutionEngine`] and by
    /// nothing else.
    Simulated,
}

/// The result of one containment action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReport {
    /// Which action.
    pub action: ActionKind,
    /// What actually happened.
    pub status: ActionStatus,
    /// Human-readable specifics (pid signalled, why an action was not applicable, …).
    pub detail: String,
}

impl ActionReport {
    /// An action the engine really performed.
    #[must_use]
    pub fn executed(action: ActionKind, detail: impl Into<String>) -> Self {
        Self {
            action,
            status: ActionStatus::Executed,
            detail: detail.into(),
        }
    }

    /// An action this engine has no control surface for.
    #[must_use]
    pub fn not_applicable(action: ActionKind, detail: impl Into<String>) -> Self {
        Self {
            action,
            status: ActionStatus::NotApplicable,
            detail: detail.into(),
        }
    }

    /// An action that was only simulated.
    #[must_use]
    pub fn simulated(action: ActionKind, detail: impl Into<String>) -> Self {
        Self {
            action,
            status: ActionStatus::Simulated,
            detail: detail.into(),
        }
    }

    /// The `"{action}"` / `"{action}:{status}"` label used in
    /// [`crate::KillOutcome::actions_taken`].
    #[must_use]
    pub fn label(&self) -> String {
        match self.status {
            ActionStatus::Executed => self.action.to_string(),
            ActionStatus::NotApplicable => format!("{}:not_applicable", self.action),
            ActionStatus::Simulated => format!("{}:simulated", self.action),
        }
    }
}

/// The kill switch's execution layer.
///
/// An implementation that cannot perform an action must return
/// [`ActionStatus::NotApplicable`] (honest) or an `Err` (loud) — never a fabricated success.
pub trait ExecutionEngine: Send + Sync {
    /// A short, stable identifier surfaced in [`crate::KillOutcome::engine`] so a consumer can
    /// tell which backend ran.
    fn name(&self) -> &'static str;

    /// True iff this engine only pretends to contain. Surfaced in
    /// [`crate::KillOutcome::simulated`].
    fn is_simulated(&self) -> bool {
        false
    }

    /// Stop the model from emitting further output.
    ///
    /// # Errors
    /// [`KillError::ExecutionFailed`] if the action was attempted and failed.
    fn suspend_model(&self, target: &KillTarget) -> Result<ActionReport, KillError>;

    /// Release the accelerator memory the agent holds.
    ///
    /// # Errors
    /// [`KillError::ExecutionFailed`] if the action was attempted and failed.
    fn unload_gpu_memory(&self, target: &KillTarget) -> Result<ActionReport, KillError>;

    /// Terminate the agent's execution unit.
    ///
    /// # Errors
    /// [`KillError::ExecutionFailed`] if the action was attempted and failed.
    fn kill_pod(&self, target: &KillTarget) -> Result<ActionReport, KillError>;

    /// Cut the agent off from the network.
    ///
    /// # Errors
    /// [`KillError::ExecutionFailed`] if the action was attempted and failed.
    fn isolate_network_namespace(&self, target: &KillTarget) -> Result<ActionReport, KillError>;

    /// Destroy the agent's in-flight state.
    ///
    /// # Errors
    /// [`KillError::ExecutionFailed`] if the action was attempted and failed.
    fn wipe_transient_memory(&self, target: &KillTarget) -> Result<ActionReport, KillError>;

    /// Run all five canonical actions in order. Implementations should not need to override this.
    ///
    /// # Errors
    /// Propagates the first action failure — a kill that cannot complete must fail loudly rather
    /// than report partial success.
    fn contain(&self, target: &KillTarget) -> Result<Vec<ActionReport>, KillError> {
        Ok(vec![
            self.suspend_model(target)?,
            self.unload_gpu_memory(target)?,
            self.kill_pod(target)?,
            self.isolate_network_namespace(target)?,
            self.wipe_transient_memory(target)?,
        ])
    }
}

// ------------------------------------------------------------------------------------------
// LocalProcessEngine — a real backend
// ------------------------------------------------------------------------------------------

/// A **real** execution engine for agents that run as a local OS process.
///
/// | action | what actually happens |
/// |---|---|
/// | `suspend_model` | Unix: `SIGSTOP` the pid. Windows: no `SIGSTOP` equivalent exists without Win32 `unsafe`, so the engine **escalates to forced termination** — strictly more containment, and stated in the report detail. |
/// | `unload_gpu_memory` | `NotApplicable`: no vendor admin endpoint here. The driver reclaims the pid's device allocations when the process exits, which `kill_pod` guarantees. |
/// | `kill_pod` | `SIGKILL` / `taskkill /F /T` the pid, then poll until the process is actually gone. Failure to disappear is a hard error. |
/// | `isolate_network_namespace` | `NotApplicable`: netns manipulation needs `CAP_SYS_ADMIN` and `ip netns`. A terminated process holds no sockets. |
/// | `wipe_transient_memory` | Verifies the process no longer exists; the kernel reclaims its address space on exit. Still-alive is a hard error. |
///
/// Safety rails: the engine refuses to signal its own process, any PID reserved on the running
/// platform (pid 0 everywhere, pid 1 on Unix, pids 4 and 8 on Windows), and, on Windows, any PID
/// that resolves to a critical system image. Every rail and the confirmation poll live in
/// [`warrantor_kill_switch_core::TreeKiller`], the sync extraction the warrant crate also links —
/// one implementation for the kill switch and the stop verb, not two that can drift.
#[derive(Debug, Clone, Default)]
pub struct LocalProcessEngine {
    /// The safety rails and the tree kill, extracted into the core crate.
    killer: warrantor_kill_switch_core::TreeKiller,
}

impl LocalProcessEngine {
    /// Construct the engine with the default safety rails.
    #[must_use]
    pub fn new() -> Self {
        Self {
            killer: warrantor_kill_switch_core::TreeKiller::new(),
        }
    }

    /// Permit targeting this process (used only by tests that deliberately do so).
    #[must_use]
    pub fn allowing_self_target(mut self, allow: bool) -> Self {
        self.killer = self.killer.allowing_self_target(allow);
        self
    }

    fn checked_pid(&self, target: &KillTarget, action: ActionKind) -> Result<u32, KillError> {
        let pid = target.pid.ok_or_else(|| {
            KillError::ExecutionFailed(format!(
                "{action}: LocalProcessEngine requires KillTarget::pid; agent {:?} supplied none",
                target.agent_id
            ))
        })?;
        self.killer
            .checked_pid(pid)
            .map_err(|e| KillError::ExecutionFailed(format!("{action}: {e}")))
    }

    /// How many times the critical-image rail actually shelled out to `tasklist.exe`.
    ///
    /// Exposed so a test can assert the SPAWN COUNT rather than a wall-clock duration. A timing
    /// assertion on a developer machine is a flake generator; the spawn count is the thing that was
    /// actually wrong, and it is deterministic.
    #[must_use]
    pub fn critical_image_lookup_count(&self) -> usize {
        self.killer.critical_image_lookup_count()
    }
    fn pod_note(target: &KillTarget, detail: String) -> String {
        match &target.pod {
            Some(pod) => {
                format!("{detail}; Kubernetes pod {pod:?} is out of scope for LocalProcessEngine")
            }
            None => detail,
        }
    }

    fn gpu_note(pid: u32) -> String {
        format!(
            "no vLLM/Triton admin endpoint configured for this engine; the driver reclaims \
             pid {pid}'s device allocations when the process exits (see kill_pod)"
        )
    }

    fn netns_note(target: &KillTarget, pid: u32) -> String {
        format!(
            "netns isolation requires CAP_SYS_ADMIN and `ip netns`; pid {pid} has been \
             terminated and therefore holds no sockets{}",
            target
                .netns
                .as_ref()
                .map(|n| format!(" (requested netns {n:?})"))
                .unwrap_or_default()
        )
    }
}

impl ExecutionEngine for LocalProcessEngine {
    fn name(&self) -> &'static str {
        "local-process"
    }

    fn suspend_model(&self, target: &KillTarget) -> Result<ActionReport, KillError> {
        let action = ActionKind::SuspendModel;
        let pid = self.checked_pid(target, action)?;
        #[cfg(unix)]
        {
            match warrantor_kill_switch_core::send_signal(pid, "STOP") {
                // The target exited between the process_exists check above and this signal.
                // A process that is gone is suspended as thoroughly as one can ask for.
                Ok(true) => Ok(ActionReport::executed(
                    action,
                    format!("pid {pid} exited before the signal was delivered"),
                )),
                Ok(false) => Ok(ActionReport::executed(
                    action,
                    format!("SIGSTOP delivered to pid {pid}"),
                )),
                Err(e) => Err(KillError::ExecutionFailed(format!("{action}: {e}"))),
            }
        }
        #[cfg(windows)]
        {
            // Windows has no SIGSTOP; suspending a process requires the Win32 thread APIs, which
            // would mean `unsafe`. Escalating to forced termination is strictly more containment,
            // and the detail says so rather than claiming a suspend that did not happen.
            let detail = self
                .killer
                .terminate(pid)
                .map(describe)
                .map_err(|e| KillError::ExecutionFailed(format!("{action}: {e}")))?;
            Ok(ActionReport::executed(
                action,
                format!(
                    "windows: no SIGSTOP equivalent without unsafe Win32 calls — escalated to \
                     forced termination ({detail})"
                ),
            ))
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(KillError::ExecutionFailed(format!(
                "{action}: unsupported platform"
            )))
        }
    }

    fn unload_gpu_memory(&self, target: &KillTarget) -> Result<ActionReport, KillError> {
        let action = ActionKind::UnloadGpuMemory;
        let pid = self.checked_pid(target, action)?;
        Ok(ActionReport::not_applicable(action, Self::gpu_note(pid)))
    }

    fn kill_pod(&self, target: &KillTarget) -> Result<ActionReport, KillError> {
        let action = ActionKind::KillPod;
        let pid = self.checked_pid(target, action)?;
        let detail = self
            .killer
            .terminate(pid)
            .map(describe)
            .map_err(|e| KillError::ExecutionFailed(format!("{action}: {e}")))?;
        Ok(ActionReport::executed(
            action,
            Self::pod_note(target, detail),
        ))
    }

    fn isolate_network_namespace(&self, target: &KillTarget) -> Result<ActionReport, KillError> {
        let action = ActionKind::IsolateNetworkNamespace;
        let pid = self.checked_pid(target, action)?;
        Ok(ActionReport::not_applicable(
            action,
            Self::netns_note(target, pid),
        ))
    }

    fn wipe_transient_memory(&self, target: &KillTarget) -> Result<ActionReport, KillError> {
        let action = ActionKind::WipeTransientMemory;
        let pid = self.checked_pid(target, action)?;
        if process_exists(pid) {
            return Err(KillError::ExecutionFailed(format!(
                "{action}: pid {pid} is still running, so its transient memory is NOT wiped"
            )));
        }
        Ok(ActionReport::executed(
            action,
            format!("pid {pid} is gone; the kernel has reclaimed its address space"),
        ))
    }

    /// Run the five canonical actions against a local process using the **minimum** number of
    /// platform calls.
    ///
    /// The default [`ExecutionEngine::contain`] would call each method independently, which on
    /// Windows means up to five `taskkill`/`tasklist` spawns — and on a machine with real-time AV
    /// scanning each of those can exceed a second, blowing the 5-second [`crate::KILL_BUDGET`]
    /// before anything has been contained. This override performs one forced termination and
    /// derives all five reports from its verified result. Nothing is fabricated: the two actions
    /// this backend has no control surface for are still reported
    /// [`ActionStatus::NotApplicable`], with the reason.
    fn contain(&self, target: &KillTarget) -> Result<Vec<ActionReport>, KillError> {
        let pid = self.checked_pid(target, ActionKind::KillPod)?;

        // On Unix, stopping the model before tearing it down is both cheap and the correct
        // ordering (no further tokens are emitted while the teardown runs).
        #[cfg(unix)]
        let suspend = self.suspend_model(target)?;

        let terminated = self
            .killer
            .terminate(pid)
            .map(describe)
            .map_err(|e| KillError::ExecutionFailed(format!("{}: {e}", ActionKind::KillPod)))?;

        #[cfg(not(unix))]
        let suspend = ActionReport::executed(
            ActionKind::SuspendModel,
            format!(
                "no SIGSTOP equivalent on this platform without unsafe Win32 calls — satisfied \
                 by forced termination ({terminated})"
            ),
        );

        Ok(vec![
            suspend,
            ActionReport::not_applicable(ActionKind::UnloadGpuMemory, Self::gpu_note(pid)),
            ActionReport::executed(
                ActionKind::KillPod,
                Self::pod_note(target, terminated.clone()),
            ),
            ActionReport::not_applicable(
                ActionKind::IsolateNetworkNamespace,
                Self::netns_note(target, pid),
            ),
            ActionReport::executed(
                ActionKind::WipeTransientMemory,
                format!("{terminated}; the kernel has reclaimed pid {pid}'s address space"),
            ),
        ])
    }
}

// ------------------------------------------------------------------------------------------
// MockExecutionEngine — an explicitly-named test double
// ------------------------------------------------------------------------------------------

/// A test double that **contains nothing**.
///
/// Every action is reported with [`ActionStatus::Simulated`], [`ExecutionEngine::is_simulated`]
/// returns `true`, and [`ExecutionEngine::name`] returns `"mock"` — all three surface in
/// [`crate::KillOutcome`], so no consumer can mistake a simulated kill for a real one. It is
/// never constructed implicitly anywhere in this crate; a caller must name it.
#[derive(Debug, Clone, Default)]
pub struct MockExecutionEngine;

impl MockExecutionEngine {
    /// Construct the test double.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn report(action: ActionKind, target: &KillTarget) -> Result<ActionReport, KillError> {
        Ok(ActionReport::simulated(
            action,
            format!(
                "SIMULATED — nothing was contained for agent {:?}",
                target.agent_id
            ),
        ))
    }
}

impl ExecutionEngine for MockExecutionEngine {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn is_simulated(&self) -> bool {
        true
    }

    fn suspend_model(&self, t: &KillTarget) -> Result<ActionReport, KillError> {
        Self::report(ActionKind::SuspendModel, t)
    }

    fn unload_gpu_memory(&self, t: &KillTarget) -> Result<ActionReport, KillError> {
        Self::report(ActionKind::UnloadGpuMemory, t)
    }

    fn kill_pod(&self, t: &KillTarget) -> Result<ActionReport, KillError> {
        Self::report(ActionKind::KillPod, t)
    }

    fn isolate_network_namespace(&self, t: &KillTarget) -> Result<ActionReport, KillError> {
        Self::report(ActionKind::IsolateNetworkNamespace, t)
    }

    fn wipe_transient_memory(&self, t: &KillTarget) -> Result<ActionReport, KillError> {
        Self::report(ActionKind::WipeTransientMemory, t)
    }
}

// ---------------------------------------------------------------------------
// CredentialRevoker — the I-05 seam.
//
// The ExecutionEngine contains the *process*; the CredentialRevoker contains the *authority* the
// process was using. Invariant I-05 requires that triggering the kill switch revokes every
// credential the agent holds within the <1s budget — otherwise a killed agent's tokens stay valid
// until their TTL expires. This trait is the seam a real credential store (the warrantor
// `credential-vault` crate, HashiCorp Vault, AWS Secrets Manager, …) plugs into. The kill path
// (`execute_kill_with_budget_and_revoker` in lib.rs) calls `revoke_all` after containment and
// before government notification, within the same budget envelope.
// ---------------------------------------------------------------------------

/// Revoke every credential an agent holds, within the kill-switch budget (invariant I-05).
///
/// Implementations MUST complete within the time budget the kill path enforces; a slow revoker
/// fails the whole kill with [`crate::KillError::BudgetExceeded`], which is the correct failure
/// mode &mdash; a kill that cannot revoke credentials in budget is a kill that has not contained
/// the authority, and must not report success.
///
/// An implementation that has no credential store bound returns
/// [`ActionReport::not_applicable`] (honest about the missing control surface) rather than a
/// fabricated success.
pub trait CredentialRevoker: Send + Sync {
    /// Revoke every credential the targeted agent holds.
    ///
    /// # Errors
    /// Returns [`crate::KillError::ExecutionFailed`] if the revocation could not be performed;
    /// the kill then aborts with that error rather than reporting partial containment.
    fn revoke_all(&self, target: &crate::KillTarget) -> Result<ActionReport, crate::KillError>;
}

/// The default revoker: no credential store is bound. Reports the action as `not_applicable` so
/// the kill outcome honestly records that credential revocation did not happen, rather than
/// silently omitting it. Production deployments pass a real revoker (one backed by
/// `warrantor-credential-vault`).
pub struct NoopCredentialRevoker;

impl CredentialRevoker for NoopCredentialRevoker {
    fn revoke_all(&self, _target: &crate::KillTarget) -> Result<ActionReport, crate::KillError> {
        Ok(ActionReport::not_applicable(
            ActionKind::RevokeCredentials,
            "no credential store bound (NoopCredentialRevoker); production deployments must bind a real revoker",
        ))
    }
}

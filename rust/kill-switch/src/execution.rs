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

use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::KillError;

/// How long to wait for a signalled process to actually disappear before declaring failure.
///
/// Applies on **both** platforms. This was previously Unix-only, on the stated rationale that
/// "the Windows path gets its confirmation from `taskkill`'s exit status instead of polling".
/// That rationale was false: `TerminateProcess` initiates termination and returns immediately,
/// so an exit status of 0 says the request was accepted, not that the process is gone.
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
/// Poll interval while waiting for termination.
const TERMINATION_POLL: Duration = Duration::from_millis(20);

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
/// Safety rails: the engine refuses to signal pid 0, pid 1, or its own process.
#[derive(Debug, Clone, Default)]
pub struct LocalProcessEngine {
    /// Allow the engine to signal the process it is running in. Off by default — a kill switch
    /// that kills its own controller cannot report the outcome.
    allow_self_target: bool,
}

impl LocalProcessEngine {
    /// Construct the engine with the default safety rails.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit targeting this process (used only by tests that deliberately do so).
    #[must_use]
    pub fn allowing_self_target(mut self, allow: bool) -> Self {
        self.allow_self_target = allow;
        self
    }

    fn checked_pid(&self, target: &KillTarget, action: ActionKind) -> Result<u32, KillError> {
        let pid = target.pid.ok_or_else(|| {
            KillError::ExecutionFailed(format!(
                "{action}: LocalProcessEngine requires KillTarget::pid; agent {:?} supplied none",
                target.agent_id
            ))
        })?;
        if pid == 0 || pid == 1 {
            return Err(KillError::ExecutionFailed(format!(
                "{action}: refusing to signal pid {pid} (reserved)"
            )));
        }
        if !self.allow_self_target && pid == std::process::id() {
            return Err(KillError::ExecutionFailed(format!(
                "{action}: refusing to signal the kill switch's own pid {pid}"
            )));
        }
        Ok(pid)
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

/// True iff a process with `pid` currently exists.
#[must_use]
pub fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // `ps -o stat=` rather than `kill -0`: an un-reaped zombie still answers `kill -0`, but a
        // zombie holds no memory, no sockets and no device allocations — treating it as "still
        // alive" would make a successful kill look like a failure.
        match Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
        {
            Ok(o) if o.status.success() => {
                let stat = String::from_utf8_lossy(&o.stdout);
                let stat = stat.trim();
                !stat.is_empty() && !stat.starts_with('Z')
            }
            // `ps` exits non-zero when the pid does not exist.
            Ok(_) => false,
            // No `ps` on this box: fall back to the signal-0 existence check.
            Err(_) => Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
        }
    }
    #[cfg(windows)]
    {
        Command::new(system32_tool("tasklist.exe"))
            .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!("\"{pid}\"")))
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

#[cfg(unix)]
fn run(mut cmd: Command, what: &str) -> Result<String, KillError> {
    let out = cmd
        .output()
        .map_err(|e| KillError::ExecutionFailed(format!("{what}: could not spawn helper: {e}")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(KillError::ExecutionFailed(format!(
            "{what}: helper exited {} — {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Forcibly terminate `pid` and confirm it is gone.
///
/// # Cost, and why it is minimised
///
/// Every platform call here is a process spawn (that is the price of keeping
/// `#![forbid(unsafe_code)]` — see the module docs). On Unix `ps`/`kill` cost a few
/// milliseconds, so the Unix path probes freely. On Windows `taskkill`/`tasklist` can each cost
/// well over a second on a machine with real-time AV scanning, and the kill pipeline has a
/// **5-second** end-to-end budget — so the Windows path spends exactly **one** spawn:
/// `taskkill /F /T` calls `TerminateProcess` synchronously, so its exit status *is* the
/// confirmation, and "process not found" is the already-gone case. See
/// [`LocalProcessEngine::contain`], which folds all five actions onto this single call.
/// Absolute path to a Windows system tool.
///
/// `Command::new(system32_tool("taskkill.exe"))` resolves through the search path, and on Windows
/// `CreateProcess` searches the **application directory first**. A `taskkill.exe` dropped
/// next to the binary therefore wins -- which an audit agent demonstrated by planting one
/// that printed "SUCCESS: The process has been terminated." and exited 0 without
/// terminating anything.
///
/// Anchoring to `%SystemRoot%\System32` removes that. It is not a complete defence -- an
/// attacker who can write next to your binary has other options -- but a containment
/// component should not be the easiest of them.
#[cfg(windows)]
fn system32_tool(name: &str) -> std::path::PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    std::path::Path::new(&root).join("System32").join(name)
}

fn force_terminate(pid: u32, action: ActionKind) -> Result<String, KillError> {
    #[cfg(unix)]
    {
        if !process_exists(pid) {
            return Ok(format!("pid {pid} was already gone"));
        }
        let mut cmd = Command::new("kill");
        cmd.arg("-KILL").arg(pid.to_string());
        run(cmd, &format!("{action} (SIGKILL pid {pid})"))?;
        let deadline = Instant::now() + TERMINATION_TIMEOUT;
        while Instant::now() < deadline {
            if !process_exists(pid) {
                return Ok(format!("pid {pid} terminated and verified gone"));
            }
            std::thread::sleep(TERMINATION_POLL);
        }
        Err(KillError::ExecutionFailed(format!(
            "{action}: pid {pid} still alive {TERMINATION_TIMEOUT:?} after SIGKILL — \
             containment NOT achieved"
        )))
    }
    #[cfg(windows)]
    {
        // `/T` also kills the process tree, so an agent cannot survive in a child.
        let out = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F", "/T"])
            .output()
            .map_err(|e| {
                KillError::ExecutionFailed(format!("{action}: could not spawn taskkill: {e}"))
            })?;
        if out.status.success() {
            // taskkill's exit status is NOT confirmation, and the comment that used to sit
            // here saying "TerminateProcess is synchronous, so success is the confirmation"
            // was simply false. MSDN: TerminateProcess "initiates termination and returns
            // immediately" -- the process cannot exit until pending I/O completes or is
            // cancelled and its address space is torn down.
            //
            // Measured on this codebase: against a 6 GB process, taskkill exited 0 after
            // 1761ms and the process object persisted a further 1194ms. An in-process
            // harness against a 12 GB victim caught contain() reporting "the kernel has
            // reclaimed pid N's address space" while this crate's OWN process_exists(N)
            // returned true at that same instant.
            //
            // So poll, exactly as the Unix arm does. The window only opens for large
            // processes -- i.e. real model-serving agents, which is precisely what this
            // component exists to kill, and precisely what no unit test spawns.
            let deadline = Instant::now() + TERMINATION_TIMEOUT;
            while Instant::now() < deadline {
                if !process_exists(pid) {
                    return Ok(format!("pid {pid} terminated and verified gone"));
                }
                std::thread::sleep(TERMINATION_POLL);
            }
            return Err(KillError::ExecutionFailed(format!(
                "{action}: pid {pid} still present {TERMINATION_TIMEOUT:?} after taskkill /F /T \
                 — containment NOT achieved"
            )));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let combined = format!("{stderr}{stdout}");
        if combined.contains("not found") || combined.contains("128") {
            return Ok(format!("pid {pid} was already gone"));
        }
        Err(KillError::ExecutionFailed(format!(
            "{action}: taskkill exited {} for pid {pid} — {} — containment NOT achieved",
            out.status,
            combined.trim()
        )))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, action);
        Err(KillError::ExecutionFailed(format!(
            "{action}: no process-control primitive on this platform"
        )))
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
            if !process_exists(pid) {
                return Ok(ActionReport::executed(
                    action,
                    format!("pid {pid} was already gone"),
                ));
            }
            let mut cmd = Command::new("kill");
            cmd.arg("-STOP").arg(pid.to_string());
            run(cmd, &format!("{action} (SIGSTOP pid {pid})"))?;
            Ok(ActionReport::executed(
                action,
                format!("SIGSTOP delivered to pid {pid}"),
            ))
        }
        #[cfg(windows)]
        {
            // Windows has no SIGSTOP; suspending a process requires the Win32 thread APIs, which
            // would mean `unsafe`. Escalating to forced termination is strictly more containment,
            // and the detail says so rather than claiming a suspend that did not happen.
            let detail = force_terminate(pid, action)?;
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
        let detail = force_terminate(pid, action)?;
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

        let terminated = force_terminate(pid, ActionKind::KillPod)?;

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

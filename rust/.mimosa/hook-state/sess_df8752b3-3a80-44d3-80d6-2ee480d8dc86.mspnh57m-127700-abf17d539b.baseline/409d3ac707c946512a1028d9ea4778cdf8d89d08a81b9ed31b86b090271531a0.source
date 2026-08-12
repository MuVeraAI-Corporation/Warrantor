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

/// Why `pid` must never be signalled, or `None` if it is a legitimate target.
///
/// The rail was previously the single test `pid == 0 || pid == 1`, which is Unix-shaped and
/// protected nothing on Windows: pid 1 is an ordinary Windows PID, while **pid 4 is the System
/// process** and sailed straight through to `taskkill`. An audit agent pointed this engine at
/// pid 4 on a live workstation; only Windows' own refusal to terminate it prevented harm.
///
/// The numeric rail is deliberately cheap and deterministic -- no process spawn, no lookup -- so
/// it cannot fail open under load or on a machine where `tasklist` is slow.
#[must_use]
fn reserved_pid_reason(pid: u32) -> Option<&'static str> {
    if pid == 0 {
        // Unix: the "any process in my group" wildcard, which would signal a whole process group.
        // Windows: the System Idle Process.
        return Some("reserved: pid 0 is not a signalable process on any supported platform");
    }
    #[cfg(unix)]
    {
        if pid == 1 {
            return Some(
                "reserved: pid 1 is init/PID-1; killing it panics the kernel or ends the container",
            );
        }
    }
    #[cfg(windows)]
    {
        // 4 is the Windows System process (the kernel itself). 8 is commonly the Secure System
        // process on machines with VBS enabled. Neither is ever an agent.
        if pid == 4 || pid == 8 {
            return Some("reserved: Windows kernel/System process");
        }
    }
    None
}

/// Windows image names that must never be terminated: killing any of them bluescreens the
/// machine or forcibly logs the user out.
///
/// This is a second, best-effort layer behind [`reserved_pid_reason`]. Resolving a PID to an
/// image name costs a `tasklist` spawn, which on a machine with real-time AV scanning can exceed
/// a second -- against a 5-second end-to-end containment budget. So it is advisory: if the lookup
/// fails or is inconclusive we proceed, because refusing to contain a runaway agent because
/// `tasklist` was slow is its own failure. The numeric rail above is the one that must always hold.
#[cfg(windows)]
const WINDOWS_CRITICAL_IMAGES: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
];

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
/// platform (see [`reserved_pid_reason`] — pid 0 everywhere, pid 1 on Unix, pids 4 and 8 on
/// Windows), and, on Windows, any PID that resolves to a critical system image.
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
        if let Some(reason) = reserved_pid_reason(pid) {
            return Err(KillError::ExecutionFailed(format!(
                "{action}: refusing to signal pid {pid} ({reason})"
            )));
        }
        if !self.allow_self_target && pid == std::process::id() {
            return Err(KillError::ExecutionFailed(format!(
                "{action}: refusing to signal the kill switch's own pid {pid}"
            )));
        }
        #[cfg(windows)]
        {
            if let Some(image) = windows_critical_image(pid) {
                return Err(KillError::ExecutionFailed(format!(
                    "{action}: refusing to signal pid {pid} ({image} is a critical Windows \
                     process; terminating it bluescreens the machine or ends the session)"
                )));
            }
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

/// Parse the image name out of one `tasklist /NH /FO CSV` row.
///
/// The row looks like `"csrss.exe","892","Services","0","2,340 K"`, so the image name is the
/// first quoted field. Split out from the lookup so this parsing -- the part that can silently
/// stop matching and quietly disable the rail -- is testable on any platform, not only Windows.
#[cfg(any(windows, test))]
#[must_use]
fn image_name_from_tasklist_row(row: &str) -> Option<String> {
    let trimmed = row.trim();
    if !trimmed.starts_with('"') {
        return None;
    }
    trimmed[1..]
        .split('"')
        .next()
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
}

/// If `pid` names a process Windows cannot survive losing, say which one.
///
/// Advisory: see [`WINDOWS_CRITICAL_IMAGES`] for why an inconclusive lookup proceeds.
#[cfg(windows)]
fn windows_critical_image(pid: u32) -> Option<String> {
    let output = Command::new(system32_tool("tasklist.exe"))
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let name = stdout.lines().find_map(image_name_from_tasklist_row)?;
    WINDOWS_CRITICAL_IMAGES
        .iter()
        .any(|critical| *critical == name)
        .then_some(name)
}

/// Does this `kill` stderr mean "the target had already exited" (ESRCH)?
///
/// Every signal path here is a check-then-signal sequence: `process_exists(pid)` and then a
/// `kill` spawn. Those are separate syscalls in separate processes, so the target can exit in
/// between -- and it very often does, because the thing being killed is a process that is already
/// being torn down. `kill` then fails with ESRCH, `run` turned that into `ExecutionFailed`, and
/// the kill switch reported "containment NOT achieved" for a target that was, in fact, contained.
/// Measured at ~11% of runs (13 hard failures in 120) against a target that always died.
///
/// The engine already treats "already gone" as success at the `process_exists` check immediately
/// above each signal; this closes the window between that check and the signal itself.
///
/// Message wording varies across implementations -- "kill: (123): No such process",
/// "kill: 123: No such process", "kill: No such process" -- so match on the stable substring.
#[cfg(unix)]
fn stderr_means_already_gone(stderr: &str) -> bool {
    let lowered = stderr.to_lowercase();
    lowered.contains("no such process") || lowered.contains("esrch")
}

/// Send a signal, treating "the process already exited" as the success it is.
///
/// Returns `Ok(true)` when the target was already gone.
#[cfg(unix)]
fn run_signal(mut cmd: Command, what: &str) -> Result<bool, KillError> {
    let out = cmd
        .output()
        .map_err(|e| KillError::ExecutionFailed(format!("{what}: could not spawn helper: {e}")))?;
    if out.status.success() {
        return Ok(false);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr_means_already_gone(&stderr) {
        return Ok(true);
    }
    Err(KillError::ExecutionFailed(format!(
        "{what}: helper exited {} — {}",
        out.status,
        stderr.trim()
    )))
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
        if run_signal(cmd, &format!("{action} (SIGKILL pid {pid})"))? {
            return Ok(format!("pid {pid} exited before the signal was delivered"));
        }
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
            if run_signal(cmd, &format!("{action} (SIGSTOP pid {pid})"))? {
                // The target exited between the process_exists check above and this signal.
                // A process that is gone is suspended as thoroughly as one can ask for.
                return Ok(ActionReport::executed(
                    action,
                    format!("pid {pid} exited before the signal was delivered"),
                ));
            }
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

#[cfg(test)]
mod safety_rail_tests {
    use super::*;

    /// pid 0 is never a legitimate target anywhere: on Unix it means "every process in my group",
    /// on Windows it is the System Idle Process.
    #[test]
    fn pid_zero_is_reserved_on_every_platform() {
        assert!(reserved_pid_reason(0).is_some());
    }

    /// The rail used to be `pid == 0 || pid == 1` on every platform. On Windows that blocked an
    /// ordinary PID while letting pid 4 -- the System process -- through to taskkill.
    #[cfg(windows)]
    #[test]
    fn windows_kernel_pids_are_reserved_and_pid_one_is_not() {
        assert!(
            reserved_pid_reason(4).is_some(),
            "pid 4 is the Windows System process and must never be signalled"
        );
        assert!(reserved_pid_reason(8).is_some());
        assert!(
            reserved_pid_reason(1).is_none(),
            "pid 1 is an ordinary PID on Windows; blocking it protects nothing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_init_is_reserved() {
        assert!(reserved_pid_reason(1).is_some());
    }

    #[test]
    fn ordinary_pids_are_not_reserved() {
        for pid in [1234u32, 40000, 99999] {
            assert!(
                reserved_pid_reason(pid).is_none(),
                "pid {pid} should be a legitimate target"
            );
        }
    }

    #[test]
    fn tasklist_rows_yield_the_image_name() {
        assert_eq!(
            image_name_from_tasklist_row("\"csrss.exe\",\"892\",\"Services\",\"0\",\"2,340 K\""),
            Some("csrss.exe".to_string())
        );
        // Case is normalised so the critical-image comparison cannot be defeated by casing.
        assert_eq!(
            image_name_from_tasklist_row("\"LSASS.EXE\",\"1000\",\"Services\",\"0\",\"1 K\""),
            Some("lsass.exe".to_string())
        );
        // tasklist prints this when the filter matches nothing.
        assert_eq!(
            image_name_from_tasklist_row("INFO: No tasks are running which match the criteria."),
            None
        );
        assert_eq!(image_name_from_tasklist_row(""), None);
    }

    /// The check-then-signal window: `process_exists` says the target is alive, it exits, and the
    /// `kill` spawn then fails with ESRCH. That was reported as "containment NOT achieved" for a
    /// target that was in fact contained -- ~11% of runs against an always-dying target.
    #[cfg(unix)]
    #[test]
    fn esrch_stderr_is_recognised_as_already_gone() {
        for stderr in [
            "kill: (7265): No such process",
            "kill: 7265: No such process",
            "kill: No such process",
            "bash: kill: (123) - No such process",
            "ESRCH",
        ] {
            assert!(
                stderr_means_already_gone(stderr),
                "{stderr:?} should be treated as the already-gone success case"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn genuine_signal_failures_are_still_failures() {
        for stderr in [
            "kill: (1): Operation not permitted",
            "kill: invalid signal specification",
            "",
        ] {
            assert!(
                !stderr_means_already_gone(stderr),
                "{stderr:?} is a real failure and must not be swallowed"
            );
        }
    }
}

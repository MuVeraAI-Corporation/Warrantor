//! Sync process-tree termination: the part of `warrantor-kill-switch` that a tokio-free crate can link.
//!
//! `warrantor-warrant` refused to link the full kill switch because that crate declares `tokio`,
//! `clap` and `tracing` unconditionally. None of them touch the killing code: what the stop verb
//! needs is the rails, the helpers and the confirmation poll, all synchronous. Those live here.
//!
//! Every helper below spawns an OS tool through an argv list (`std::process::Command` with
//! explicit arguments, no shell). The pid is a `u32`, the signal a constant, and the tool path an
//! anchored absolute path — no caller-supplied string ever reaches a command line.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::process::Command;
use std::time::{Duration, Instant};

use thiserror::Error;

/// How long to wait for a signalled process to actually disappear before declaring failure.
pub const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
const TERMINATION_POLL: Duration = Duration::from_millis(20);

/// Why a termination did not happen. Every variant names the pid; none fabricates success.
#[derive(Debug, Error)]
pub enum TerminateError {
    /// The pid is reserved on this platform and must never be signalled.
    #[error("refusing to signal pid {pid} ({reason})")]
    Reserved {
        /// The pid.
        pid: u32,
        /// Why.
        reason: &'static str,
    },
    /// The pid is this process.
    #[error("refusing to signal the caller's own pid {pid}")]
    SelfTarget {
        /// The pid.
        pid: u32,
    },
    /// The pid resolved to a critical Windows image.
    #[error("refusing to signal pid {pid} ({image} is a critical Windows process)")]
    CriticalImage {
        /// The pid.
        pid: u32,
        /// The image name.
        image: String,
    },
    /// The platform helper could not be spawned.
    #[error("{what}: could not spawn helper: {source}")]
    Spawn {
        /// Which step.
        what: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// The helper ran and reported a failure that is not "already gone".
    #[error("{what}: helper exited {status} — {stderr}")]
    Helper {
        /// Which step.
        what: String,
        /// Exit status text.
        status: String,
        /// Trimmed stderr.
        stderr: String,
    },
    /// The process was signalled and is still present after the timeout.
    #[error("pid {pid} still alive {after:?} after the kill — containment NOT achieved")]
    StillAlive {
        /// The pid.
        pid: u32,
        /// How long was waited.
        after: Duration,
    },
    /// No process-control primitive on this platform.
    #[error("no process-control primitive on this platform")]
    Unsupported,
}

/// What a successful termination observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminated {
    /// The root pid.
    pub pid: u32,
    /// The root was gone before anything was sent.
    pub already_gone: bool,
    /// Time from the signal to the confirmed absence. Zero when already gone.
    pub confirmed_after: Duration,
}

/// The critical-image verdict for one pid: `Some((pid, Some(image)))` means that pid resolved to a
/// critical Windows image and must not be signalled, `Some((pid, None))` means it is a legitimate
/// target, and `None` means the rail has not been consulted yet for any pid.
///
/// Named rather than inlined because clippy is right that the nested form is unreadable -- and
/// because the three states above are the whole meaning of this field, which a bare
/// `Arc<Mutex<Option<(u32, Option<String>)>>>` hides completely.
#[cfg(windows)]
type CriticalImageMemo = std::sync::Arc<std::sync::Mutex<Option<(u32, Option<String>)>>>;

/// A process-tree killer with the rails `LocalProcessEngine` had, minus the engine.
#[derive(Debug, Clone, Default)]
pub struct TreeKiller {
    allow_self_target: bool,
    #[cfg_attr(not(windows), allow(dead_code))]
    critical_image_memo: CriticalImageMemo,
    #[cfg_attr(not(windows), allow(dead_code))]
    critical_image_lookups: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl TreeKiller {
    /// Default rails.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit targeting this process (tests only).
    #[must_use]
    pub fn allowing_self_target(mut self, allow: bool) -> Self {
        self.allow_self_target = allow;
        self
    }

    /// Run every rail. Cheap and deterministic first, `tasklist` last.
    pub fn checked_pid(&self, pid: u32) -> Result<u32, TerminateError> {
        if let Some(reason) = reserved_pid_reason(pid) {
            return Err(TerminateError::Reserved { pid, reason });
        }
        if !self.allow_self_target && pid == std::process::id() {
            return Err(TerminateError::SelfTarget { pid });
        }
        #[cfg(windows)]
        if let Some(image) = self.critical_image_cached(pid) {
            return Err(TerminateError::CriticalImage { pid, image });
        }
        Ok(pid)
    }

    /// How many times the critical-image rail shelled out (tests assert the spawn count).
    #[must_use]
    pub fn critical_image_lookup_count(&self) -> usize {
        self.critical_image_lookups
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Kill `pid` and every descendant, then confirm the root is gone.
    ///
    /// Unix: `kill -KILL -- -pid` (the group; the supervisor's `setsid` makes pgid == pid) and then
    /// `kill -KILL pid` for a root that is not a group leader. Windows: `taskkill /PID pid /T /F`
    /// from `%SystemRoot%\System32`. Both then poll `process_exists` up to [`TERMINATION_TIMEOUT`].
    pub fn terminate(&self, pid: u32) -> Result<Terminated, TerminateError> {
        let pid = self.checked_pid(pid)?;
        if !process_exists(pid) {
            return Ok(Terminated {
                pid,
                already_gone: true,
                confirmed_after: Duration::ZERO,
            });
        }
        let started = Instant::now();
        #[cfg(unix)]
        {
            let group = format!("-{pid}");
            let what = format!("SIGKILL group {pid}");
            let _ = send_signal_to(&group, "KILL", &what)?;
            if send_signal(pid, "KILL")? {
                return Ok(Terminated {
                    pid,
                    already_gone: true,
                    confirmed_after: Duration::ZERO,
                });
            }
        }
        #[cfg(windows)]
        {
            let what = format!("taskkill /T /F pid {pid}");
            let pid_argument = pid.to_string();
            let out = Command::new(system32_tool("taskkill.exe"))
                .args(["/PID", pid_argument.as_str(), "/T", "/F"])
                .output()
                .map_err(|source| TerminateError::Spawn {
                    what: what.clone(),
                    source,
                })?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                if out.status.code() == Some(128)
                    || stderr.contains("not found")
                    || stdout.contains("not found")
                {
                    return Ok(Terminated {
                        pid,
                        already_gone: true,
                        confirmed_after: Duration::ZERO,
                    });
                }
                return Err(TerminateError::Helper {
                    what,
                    status: out.status.to_string(),
                    stderr: format!("{stderr}{stdout}").trim().to_string(),
                });
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(TerminateError::Unsupported);
        }
        let deadline = started + TERMINATION_TIMEOUT;
        while Instant::now() < deadline {
            if !process_exists(pid) {
                return Ok(Terminated {
                    pid,
                    already_gone: false,
                    confirmed_after: started.elapsed(),
                });
            }
            std::thread::sleep(TERMINATION_POLL);
        }
        Err(TerminateError::StillAlive {
            pid,
            after: TERMINATION_TIMEOUT,
        })
    }

    /// The critical-image verdict for `pid`, looked up once per pid per killer.
    #[cfg(windows)]
    fn critical_image_cached(&self, pid: u32) -> Option<String> {
        let mut memo = self
            .critical_image_memo
            .lock()
            .expect("critical-image memo poisoned");
        if memo.as_ref().map(|(seen, _)| *seen) == Some(pid) {
            return memo.as_ref().and_then(|(_, verdict)| verdict.clone());
        }
        self.critical_image_lookups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let verdict = windows_critical_image(pid);
        *memo = Some((pid, verdict.clone()));
        verdict
    }
}

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
pub fn reserved_pid_reason(pid: u32) -> Option<&'static str> {
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

/// True iff a process with `pid` currently exists.
#[must_use]
pub fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // `ps -o stat=` rather than `kill -0`: an un-reaped zombie still answers `kill -0`, but a
        // zombie holds no memory, no sockets and no device allocations — treating it as "still
        // alive" would make a successful kill look like a failure.
        let pid_argument = pid.to_string();
        match Command::new("ps")
            .args(["-o", "stat=", "-p", pid_argument.as_str()])
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
                .arg(pid_argument)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
        }
    }
    #[cfg(windows)]
    {
        let pid_filter = format!("PID eq {pid}");
        let pid_column = format!("\"{pid}\"");
        Command::new(system32_tool("tasklist.exe"))
            .args(["/FI", pid_filter.as_str(), "/NH", "/FO", "CSV"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(pid_column.as_str()))
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
    let pid_filter = format!("PID eq {pid}");
    let output = Command::new(system32_tool("tasklist.exe"))
        .args(["/FI", pid_filter.as_str(), "/NH", "/FO", "CSV"])
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

/// Send `signal` to `pid`; `Ok(true)` means the target had already exited (ESRCH).
///
/// `signal` is a compile-time constant at every call site (`KILL`, `STOP`), and the target is a
/// numeric pid or `-{pgid}` string built from one — the spawn is an argv list, never a shell.
#[cfg(unix)]
pub fn send_signal(pid: u32, signal: &str) -> Result<bool, TerminateError> {
    let what = format!("SIG{signal} pid {pid}");
    let pid_argument = pid.to_string();
    send_signal_to(&pid_argument, signal, &what)
}

#[cfg(unix)]
fn send_signal_to(target: &str, signal: &str, what: &str) -> Result<bool, TerminateError> {
    let signal_flag = format!("-{signal}");
    let out = Command::new("kill")
        .args([signal_flag.as_str(), "--", target])
        .output()
        .map_err(|source| TerminateError::Spawn {
            what: what.to_string(),
            source,
        })?;
    if out.status.success() {
        return Ok(false);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr_means_already_gone(&stderr) {
        return Ok(true);
    }
    Err(TerminateError::Helper {
        what: what.to_string(),
        status: out.status.to_string(),
        stderr: stderr.trim().to_string(),
    })
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

//! W0′ — OS-enforced process lifetime, ported from the Python harness to the daemon.
//!
//! Two failure modes, and they pull in opposite directions:
//!
//! * **Orphaning** — the supervisor dies and the agent keeps running, unsupervised and past its
//!   deadline. Solved by an OS link that kills the agent tree when the supervisor goes.
//! * **Terminal coupling** — the supervisor is attached to your terminal, so closing the terminal
//!   kills the run. Solved by detaching the supervisor from the console.
//!
//! Doing only the first gives you the CLI we had: safe, but you cannot walk away. Doing only the
//! second gives you a background process nothing can stop. Both together are what "leave it running
//! overnight" actually requires, which is why they are one module.
//!
//! # The mechanisms
//!
//! | Platform | Link | Survives supervisor being killed? |
//! |----------|------|-----------------------------------|
//! | Windows  | Job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | yes — the kernel closes the handle |
//! | Linux    | `setsid` + `PR_SET_PDEATHSIG` | yes, for the direct child |
//! | Other    | `setsid` only | **no** — reported honestly rather than assumed |
//!
//! The Linux caveat is real and worth stating: `PR_SET_PDEATHSIG` fires for the immediate child
//! only. A grandchild that outlives its parent is not signalled. The new session at least means a
//! single `kill(-pgid)` reaches the whole group, which is what [`terminate_group`] does.
//!
//! # A Windows caveat we do not paper over
//!
//! If the process that spawns the daemon is itself inside a job object — some terminals and CI
//! runners do this — the daemon lands in a *nested* job. Nested jobs work on Windows 8 and later,
//! so the kill-on-close link still binds the agent to the daemon. But an outer job that is closed
//! when the terminal exits will still take the daemon with it. Detaching the console does not
//! escape a job, and pretending otherwise would be the exact false promise this module exists to
//! avoid. [`Supervisor::describe`] reports what is actually in force.

use std::path::Path;
use std::process::{Child, Command, Stdio};

/// What is holding the agent's lifetime to the supervisor's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linkage {
    /// Short name of the mechanism.
    pub mechanism: &'static str,
    /// Whether the agent tree dies if the supervisor is killed without cleanup.
    pub survives_supervisor_death: bool,
    /// Plain-language description for the developer.
    pub detail: &'static str,
}

/// What this platform can guarantee.
#[must_use]
pub fn describe_linkage() -> Linkage {
    if cfg!(windows) {
        Linkage {
            mechanism: "job-object",
            survives_supervisor_death: true,
            detail: "the agent runs inside a Windows job object with KILL_ON_JOB_CLOSE. If the \
                     supervisor exits for any reason, including being killed, the kernel closes \
                     the job handle and terminates the whole agent tree.",
        }
    } else if cfg!(target_os = "linux") {
        Linkage {
            mechanism: "setsid+pdeathsig",
            survives_supervisor_death: true,
            detail: "the agent runs in its own session with PR_SET_PDEATHSIG, so the kernel signals \
                     it when the supervisor dies. Grandchildren are not individually signalled; \
                     the session id lets one kill reach the group.",
        }
    } else {
        Linkage {
            mechanism: "setsid",
            survives_supervisor_death: false,
            detail: "this platform has no kernel-enforced parent-death link. The agent is put in \
                     its own session so it can be killed as a group, but if the supervisor is \
                     killed uncleanly the agent WILL keep running. Treat unattended runs here as \
                     unsupported.",
        }
    }
}

/// Owns the OS link and the agent process.
pub struct Supervisor {
    #[cfg(windows)]
    job: windows_job::Job,
    child: Option<Child>,
}

impl Supervisor {
    /// Create a supervisor with the OS link established but no agent running yet.
    ///
    /// # Errors
    /// A string describing which OS call failed. The link is created *before* the agent is spawned
    /// on purpose: a failure here must prevent the agent from starting, never leave one running
    /// with no link.
    pub fn new() -> Result<Self, String> {
        #[cfg(windows)]
        {
            Ok(Self {
                job: windows_job::Job::create()?,
                child: None,
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self { child: None })
        }
    }

    /// What is actually in force, for reporting to the developer.
    #[must_use]
    pub fn describe(&self) -> Linkage {
        describe_linkage()
    }

    /// Spawn the agent under the link.
    ///
    /// # Errors
    /// A string if the process cannot be spawned or cannot be joined to the link.
    #[allow(unsafe_code)] // `pre_exec` is unsafe by definition: it runs between fork and exec.
    pub fn spawn(
        &mut self,
        program: &str,
        args: &[String],
        cwd: Option<&Path>,
    ) -> Result<u32, String> {
        let mut command = Command::new(program);
        command.args(args);
        if let Some(dir) = cwd {
            command.current_dir(dir);
        }
        command.stdin(Stdio::null());

        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                // New session first: it is what makes a group kill possible at all.
                if libc_shim::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                {
                    // SIGKILL rather than SIGTERM: a wedged agent that ignores TERM is exactly the
                    // case this exists for.
                    if libc_shim::prctl(libc_shim::PR_SET_PDEATHSIG, libc_shim::SIGKILL) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }

        let child = command.spawn().map_err(|e| format!("spawn {program}: {e}"))?;
        let pid = child.id();

        #[cfg(windows)]
        {
            // Assign before returning. A child that started but is not in the job is precisely the
            // orphan this module exists to prevent, so a failure here kills it immediately.
            use std::os::windows::io::AsRawHandle;
            if let Err(e) = self.job.assign(child.as_raw_handle()) {
                let mut child = child;
                let _ = child.kill();
                return Err(e);
            }
        }

        self.child = Some(child);
        Ok(pid)
    }

    /// Wait for the agent, returning its exit code.
    ///
    /// # Errors
    /// A string if there is no agent or the wait fails.
    pub fn wait(&mut self) -> Result<i32, String> {
        let child = self.child.as_mut().ok_or("no agent is running")?;
        let status = child.wait().map_err(|e| format!("wait: {e}"))?;
        Ok(status.code().unwrap_or(-1))
    }

    /// Wait up to `seconds`, returning `None` if the agent is still running.
    ///
    /// Polled rather than event-driven because the deadline granularity that matters here is
    /// seconds, and a poll loop has no platform-specific behaviour to get wrong.
    ///
    /// # Errors
    /// A string if there is no agent or the check fails.
    pub fn wait_until(&mut self, seconds: u64) -> Result<Option<i32>, String> {
        let child = self.child.as_mut().ok_or("no agent is running")?;
        for _ in 0..seconds {
            match child.try_wait().map_err(|e| format!("try_wait: {e}"))? {
                Some(status) => return Ok(Some(status.code().unwrap_or(-1))),
                None => std::thread::sleep(std::time::Duration::from_secs(1)),
            }
        }
        Ok(None)
    }

    /// Terminate the agent and everything it started.
    ///
    /// # Errors
    /// A string if the kill fails for a reason other than the agent already being gone.
    pub fn terminate(&mut self) -> Result<(), String> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        let pid = child.id();
        // Group kill first, so children the agent spawned go too. Killing only the direct child
        // would leave exactly the descendants this is meant to catch.
        terminate_group(pid);
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }
}

/// Kill a process group. Best-effort: a process that is already gone is the desired end state.
pub fn terminate_group(pid: u32) {
    #[cfg(windows)]
    {
        let root = std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".to_string());
        let taskkill = Path::new(&root).join("System32").join("taskkill.exe");
        let _ = Command::new(taskkill)
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        // Negative pid addresses the group, which setsid made equal to the agent's pid.
        let _ = Command::new("kill")
            .args(["-KILL", &format!("-{pid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Spawn a process detached from this console, so closing the terminal does not end it.
///
/// Returns the detached process id. Output goes to `log`, because a detached process on Windows has
/// no console to inherit and its diagnostics would otherwise be lost — which for a supervisor is
/// the difference between a debuggable failure and a silent one.
///
/// # Errors
/// A string if the log cannot be opened or the process cannot be spawned.
#[allow(unsafe_code)] // same: `pre_exec` on the Unix path.
pub fn spawn_detached(
    program: &str,
    args: &[String],
    log: &Path,
) -> Result<u32, String> {
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create log dir: {e}"))?;
    }
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|e| format!("open {}: {e}", log.display()))?;
    let err = out.try_clone().map_err(|e| format!("clone log handle: {e}"))?;

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS drops the console; CREATE_NEW_PROCESS_GROUP means Ctrl-C in the
        // terminal does not reach it. Without the second, closing with Ctrl-C would still end a
        // run the developer expected to keep going.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            if libc_shim::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command
        .spawn()
        .map_err(|e| format!("spawn detached {program}: {e}"))?;
    Ok(child.id())
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod libc_shim {
    //! The three libc calls needed, declared directly.
    //!
    //! `std` already links libc on every Unix target, so declaring the symbols avoids adding a
    //! dependency for three functions.
    pub const PR_SET_PDEATHSIG: i32 = 1;
    pub const SIGKILL: i32 = 9;

    extern "C" {
        pub fn setsid() -> i32;
        #[cfg(target_os = "linux")]
        pub fn prctl(option: i32, arg2: i32, ...) -> i32;
    }
}

#[cfg(windows)]
// The crate denies unsafe globally. This module is the exception, and the exception is the point:
// the lifetime guarantee cannot be expressed in safe Rust because it IS a kernel object. Every
// unsafe block below is justified inline, and the module's whole surface is four kernel32 calls.
#[allow(unsafe_code)]
mod windows_job {
    //! Minimal job-object binding.
    //!
    //! Declared directly against kernel32 rather than pulling in a Windows crate: the surface is
    //! three calls, and a supervisor's lifetime guarantee should not depend on a dependency tree.

    use std::os::windows::io::RawHandle;

    type Handle = *mut core::ffi::c_void;

    /// `JOBOBJECT_BASIC_LIMIT_INFORMATION`, laid out to match the SDK exactly. Any mismatch would
    /// silently move `limit_flags` and the kill-on-close link would never be set.
    #[repr(C)]
    #[derive(Default)]
    struct BasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimitInformation {
        basic_limit_information: BasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;

    extern "system" {
        fn CreateJobObjectW(attributes: *mut core::ffi::c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            class: u32,
            info: *const core::ffi::c_void,
            length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    /// A job object whose closure kills every process inside it.
    pub struct Job {
        handle: Handle,
    }

    impl Job {
        pub fn create() -> Result<Self, String> {
            // SAFETY: null attributes and name are the documented "unnamed default job" form.
            let handle = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
            if handle.is_null() {
                return Err(format!(
                    "CreateJobObject failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut info = ExtendedLimitInformation::default();
            info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `info` matches the layout the class expects, and its size is passed exactly.
            let ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    std::ptr::addr_of!(info).cast(),
                    u32::try_from(std::mem::size_of::<ExtendedLimitInformation>())
                        .map_err(|_| "job info struct is impossibly large".to_string())?,
                )
            };
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                // SAFETY: the handle came from CreateJobObject and has not been closed.
                unsafe { CloseHandle(handle) };
                // Failing here means the kill-on-close flag is NOT set. Returning a job without it
                // would look supervised while orphaning on every crash.
                return Err(format!("SetInformationJobObject failed: {e}"));
            }
            Ok(Self { handle })
        }

        pub fn assign(&self, process: RawHandle) -> Result<(), String> {
            // SAFETY: both handles are live; `process` comes from a Child we still own.
            let ok = unsafe { AssignProcessToJobObject(self.handle, process.cast()) };
            if ok == 0 {
                return Err(format!(
                    "AssignProcessToJobObject failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // This close is the kill. Everything still in the job dies here, which is the whole
            // point: it happens on a crash and on a panic, not only on a tidy exit.
            // SAFETY: the handle came from CreateJobObject and is closed exactly once.
            unsafe { CloseHandle(self.handle) };
        }
    }
}

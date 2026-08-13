//! W2 + W0′ — the supervising daemon.
//!
//! # Why a daemon at all
//!
//! Supervision currently lives in the CLI, which means the process holding the OS job object is
//! the one attached to your terminal. Closing the terminal kills the job, which kills the agent.
//! That is precisely backwards for a product whose promise is "you can walk away": the developer
//! walking away is the event that ends the run.
//!
//! The daemon detaches from the terminal and outlives it. It owns the job object, the agent
//! process tree, and the warrant deadline. Closing the terminal now ends the *view*, not the work.
//!
//! # The lifetime chain, and where it can still break
//!
//! ```text
//!   terminal ──(detached)── daemon ──(job object / pdeathsig)── agent ── children
//! ```
//!
//! The daemon-to-agent link is OS-enforced: if the daemon dies for any reason, including a crash,
//! the kernel terminates the agent tree. That is the same mechanism proven in the Python harness.
//!
//! What the daemon cannot do is supervise itself. If it is killed, the agent dies with it —
//! correct, but it means the run ends silently. So the daemon writes its state before doing
//! anything irreversible, and [`DaemonState::reconcile`] reconciles on next start: a warrant found
//! Open with no live daemon is reported as interrupted rather than quietly left dangling. **The
//! run is not resumed** — an agent that was mid-task when its supervisor died has unknown state,
//! and resuming it would be guessing.
//!
//! # Why the socket is a socket and not a port
//!
//! The proxy has to reach the daemon to authorize each tool call. A TCP port on localhost is
//! reachable by every process on the machine, including the agent, and an agent that can talk to
//! the authorization endpoint directly is an agent that can ask for a different answer. A Unix
//! socket (or named pipe on Windows) carries filesystem permissions, so the OS restricts who may
//! connect.
//!
//! That is defence in depth rather than a complete answer: the agent runs as the same user, so it
//! *can* open the socket. What stops it is that the capability token it holds is act-scoped and
//! carries no settle authority — there is no message it can send that widens its own warrant. The
//! socket permission keeps other users out; the token shape keeps the agent in.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::store::WarrantStore;
use crate::{WarrantError, WarrantState};

/// A daemon's record of itself, written before it starts supervising.
///
/// Written first so that a daemon which dies before writing is indistinguishable from one that
/// never started — the safe reading, because both mean "no supervision is running".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonRecord {
    /// Warrant being supervised.
    pub warrant_id: String,
    /// The daemon's own process id, so a later start can tell whether it is still alive.
    pub pid: u32,
    /// Where the daemon listens for authorization requests.
    pub socket: PathBuf,
    /// When supervision began, epoch seconds.
    pub started_at: u64,
    /// Wall-clock deadline inherited from the warrant.
    pub expires_at: u64,
}

/// What reconciliation found about a warrant whose daemon is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum Reconciliation {
    /// A daemon is running and the warrant is live.
    Supervised {
        /// Its process id.
        pid: u32,
    },
    /// The warrant is open but no daemon is alive.
    ///
    /// The agent is already dead — the OS killed it with the daemon — so nothing is running
    /// unsupervised. What remains is a warrant in a state no one is advancing, and staged effects
    /// nobody has decided about.
    Interrupted {
        /// What the operator needs to do.
        detail: String,
    },
    /// The run finished on its own and the warrant is waiting for a decision.
    ///
    /// Distinct from [`Reconciliation::Interrupted`], and the distinction is the whole point: a run
    /// that completed and a supervisor that died both leave no daemon record behind, so without a
    /// completion record the two are indistinguishable and the ordinary case — an agent that worked
    /// all night and exited cleanly — gets reported to its operator as a crash.
    Completed {
        /// The agent's exit code. `-1` when the deadline stopped it rather than the agent choosing to.
        exit_code: i32,
        /// Whether the deadline ended the run.
        expired: bool,
        /// What the operator needs to do.
        detail: String,
    },
    /// The warrant reached a terminal state; nothing to reconcile.
    Finished,
}

/// What a finished run left behind, so a completed run is never mistaken for a dead supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRecord {
    /// The warrant whose run finished.
    pub warrant_id: String,
    /// The supervisor that ran it.
    pub pid: u32,
    /// The agent's exit code; `-1` if the deadline terminated it.
    pub exit_code: i32,
    /// True when the deadline ended the run rather than the agent finishing.
    pub expired: bool,
    /// When the run finished, seconds since the Unix epoch.
    pub finished_at: u64,
}

/// Tracks daemon records on disk.
#[derive(Debug, Clone)]
pub struct DaemonState {
    root: PathBuf,
}

impl DaemonState {
    /// Open the daemon-state directory under a warrant store root.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the directory cannot be created.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, WarrantError> {
        let root = root.as_ref().join("daemons");
        std::fs::create_dir_all(&root)
            .map_err(|e| WarrantError::Encode(format!("create daemons dir: {e}")))?;
        Ok(Self { root })
    }

    fn path(&self, warrant_id: &str) -> PathBuf {
        self.root.join(format!("{warrant_id}.json"))
    }

    /// Record that a daemon is supervising `warrant_id`.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] on I/O or serialisation failure.
    pub fn register(&self, record: &DaemonRecord) -> Result<(), WarrantError> {
        // A new run supersedes whatever the previous one recorded. Without this, a second run that
        // crashed would still find the first run's completion record and be reported to the
        // operator as "finished on its own (agent exit 0)" -- the exact inversion the completion
        // record was added to prevent, one run later.
        match std::fs::remove_file(self.completion_path(&record.warrant_id)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(WarrantError::Encode(format!(
                    "clear stale completion record: {e}"
                )))
            }
        }
        let body = serde_json::to_vec_pretty(record)
            .map_err(|e| WarrantError::Encode(format!("serialise daemon record: {e}")))?;
        std::fs::write(self.path(&record.warrant_id), body)
            .map_err(|e| WarrantError::Encode(format!("write daemon record: {e}")))
    }

    /// Remove a daemon record. Called on clean shutdown.
    ///
    /// # Errors
    /// Never fails on a missing file: an absent record is the desired end state, so treating its
    /// absence as an error would make clean shutdown noisier than a crash.
    pub fn deregister(&self, warrant_id: &str) -> Result<(), WarrantError> {
        match std::fs::remove_file(self.path(warrant_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WarrantError::Encode(format!("remove daemon record: {e}"))),
        }
    }

    /// Read a daemon record, if one exists.
    #[must_use]
    pub fn get(&self, warrant_id: &str) -> Option<DaemonRecord> {
        let body = std::fs::read(self.path(warrant_id)).ok()?;
        serde_json::from_slice(&body).ok()
    }

    fn completion_path(&self, warrant_id: &str) -> PathBuf {
        self.root.join(format!("{warrant_id}.done.json"))
    }

    /// Record that a run finished on its own, so `status` can tell it apart from a crash.
    ///
    /// Written *before* [`Self::deregister`], because the window between the two is exactly when a
    /// crash would be indistinguishable from a clean finish, and the safe direction to be wrong in
    /// is claiming the run finished when it very nearly had.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] on I/O or serialisation failure.
    pub fn record_completion(&self, record: &CompletionRecord) -> Result<(), WarrantError> {
        let body = serde_json::to_vec_pretty(record)
            .map_err(|e| WarrantError::Encode(format!("serialise completion record: {e}")))?;
        std::fs::write(self.completion_path(&record.warrant_id), body)
            .map_err(|e| WarrantError::Encode(format!("write completion record: {e}")))
    }

    /// Read the completion record for a warrant, if its run finished.
    #[must_use]
    pub fn completion(&self, warrant_id: &str) -> Option<CompletionRecord> {
        let body = std::fs::read(self.completion_path(warrant_id)).ok()?;
        serde_json::from_slice(&body).ok()
    }

    /// Reconcile every warrant against the daemons that should be supervising them.
    ///
    /// Run at startup. A warrant left Open by a daemon that died is surfaced, not resumed: an
    /// agent that was mid-task when its supervisor was killed has unknown state, and continuing it
    /// would be guessing about work that may be half-done.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the store cannot be listed.
    pub fn reconcile(
        &self,
        store: &WarrantStore,
        is_alive: &dyn Fn(u32) -> bool,
    ) -> Result<BTreeMap<String, Reconciliation>, WarrantError> {
        let mut out = BTreeMap::new();
        for stored in store.list()? {
            let id = stored.warrant.claims.id.clone();
            if !matches!(stored.warrant.state, WarrantState::Open) {
                out.insert(id, Reconciliation::Finished);
                continue;
            }
            match self.get(&id) {
                Some(record) if is_alive(record.pid) => {
                    out.insert(id, Reconciliation::Supervised { pid: record.pid });
                }
                Some(record) => {
                    // The daemon died. The agent went with it, by construction.
                    let _ = self.deregister(&id);
                    out.insert(
                        id.clone(),
                        Reconciliation::Interrupted {
                            detail: format!(
                                "the daemon supervising {id} (pid {}) is gone, so its agent was \
                                 terminated with it. Staged effects are intact and awaiting your \
                                 decision: review with `warrantor report {id}`, then settle or \
                                 void. The run is NOT resumed -- an agent interrupted mid-task \
                                 has unknown state.",
                                record.pid
                            ),
                        },
                    );
                }
                None => {
                    // Open with no live record. Three different things look identical here, and
                    // conflating them told operators their finished run had crashed.
                    if let Some(done) = self.completion(&id) {
                        let detail = if done.expired {
                            format!(
                                "{id} ran until its deadline and was stopped there. Whatever it \
                                 finished is kept and whatever it staged is awaiting your \
                                 decision: review with `warrantor report {id}`, then settle or \
                                 void."
                            )
                        } else {
                            format!(
                                "{id} finished on its own (agent exit {}). Review with \
                                 `warrantor report {id}`, then settle or void.",
                                done.exit_code
                            )
                        };
                        out.insert(
                            id.clone(),
                            Reconciliation::Completed {
                                exit_code: done.exit_code,
                                expired: done.expired,
                                detail,
                            },
                        );
                    } else {
                        out.insert(
                            id.clone(),
                            Reconciliation::Interrupted {
                                detail: format!(
                                    "{id} is open and nothing is supervising it, with no record \
                                     of a run having finished. If you never started one, this is \
                                     expected. Otherwise the supervisor died before it could \
                                     register, and the agent died with it."
                                ),
                            },
                        );
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Everything the supervision loop needs.
///
/// A struct rather than seven positional parameters: `program` and `warrant_id` are both strings,
/// and a caller that swaps them would supervise a command named after a warrant id.
#[derive(Debug, Clone)]
pub struct SuperviseRequest {
    /// Warrant being supervised.
    pub warrant_id: String,
    /// Wall-clock deadline, epoch seconds.
    pub expires_at: u64,
    /// The agent executable.
    pub program: String,
    /// Its arguments, passed through unchanged.
    pub args: Vec<String>,
    /// Working directory -- the worktree, when the warrant has one.
    pub cwd: Option<PathBuf>,
    /// Store root, for the socket path.
    pub root: PathBuf,
    /// Current time, injected so the caller owns the clock.
    pub now: u64,
}

/// Run the supervision loop: hold the agent under an OS link until it finishes or the warrant
/// expires, then clean up.
///
/// This is the daemon's body. It is a plain function so the same logic runs whether it was reached
/// by detaching or by running in the foreground for debugging — a supervisor that behaves
/// differently when you are watching it is a supervisor you cannot debug.
///
/// # Errors
/// A string describing what failed. Registration failures are fatal *before* the agent starts, so
/// an agent never runs without a record saying who is supervising it.
pub fn supervise_run(state: &DaemonState, request: &SuperviseRequest) -> Result<i32, String> {
    let SuperviseRequest {
        warrant_id,
        expires_at,
        program,
        args,
        cwd,
        root,
        now,
    } = request;
    let (expires_at, now) = (*expires_at, *now);
    let mut supervisor = crate::supervise::Supervisor::new()?;
    let linkage = supervisor.describe();

    // Register before spawning. The reverse order would leave a window where an agent is running
    // and nothing on disk says so.
    state
        .register(&DaemonRecord {
            warrant_id: warrant_id.to_string(),
            pid: std::process::id(),
            socket: socket_path(root, warrant_id),
            started_at: now,
            expires_at,
        })
        .map_err(|e| format!("register daemon: {e}"))?;

    println!(
        "warrantor: supervising {warrant_id} as pid {}, lifetime linked by {} ({})",
        std::process::id(),
        linkage.mechanism,
        if linkage.survives_supervisor_death {
            "the agent cannot outlive this daemon"
        } else {
            "WARNING: this platform cannot guarantee the agent dies with the daemon"
        }
    );

    let pid = supervisor.spawn(program, args, cwd.as_deref())?;
    println!("warrantor: agent pid {pid}");

    // Monotonic, so the finish time survives a wall-clock adjustment during a long overnight run.
    // `now` is injected rather than read here, which is what keeps this function testable.
    let started = std::time::Instant::now();

    let remaining = expires_at.saturating_sub(now);
    let (code, expired) = match supervisor.wait_until(remaining)? {
        Some(code) => {
            println!("warrantor: agent exited with {code}");
            (code, false)
        }
        None => {
            // The deadline is the point of the warrant. Reaching it means stopping, not asking.
            println!(
                "warrantor: warrant {warrant_id} expired; terminating the agent and everything it \
                 started. Staged effects are kept -- review with `warrantor report {warrant_id}`."
            );
            supervisor.terminate()?;
            (-1, true)
        }
    };

    // Before deregistering, not after: the gap between the two is the only window in which a
    // finished run is indistinguishable from a dead supervisor, and an operator told their
    // overnight run crashed when it did not is how they stop trusting `status`.
    if let Err(e) = state.record_completion(&CompletionRecord {
        warrant_id: warrant_id.to_string(),
        pid: std::process::id(),
        exit_code: code,
        expired,
        finished_at: now.saturating_add(started.elapsed().as_secs()),
    }) {
        // Not fatal: the run really did finish, and failing here would turn a successful run into
        // an error. It costs the precision of the next `status`, which says so rather than guessing.
        eprintln!("warrantor: could not record run completion for {warrant_id}: {e}");
    }

    state
        .deregister(warrant_id)
        .map_err(|e| format!("deregister daemon: {e}"))?;
    Ok(code)
}

/// Is this process id still running?
///
/// Platform-specific because there is no portable answer, and a wrong answer in either direction
/// is bad: a false "alive" leaves a warrant permanently unreconciled, a false "dead" reports a
/// healthy run as interrupted.
#[must_use]
pub fn process_is_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let root = std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".to_string());
        let tasklist = std::path::Path::new(&root)
            .join("System32")
            .join("tasklist.exe");
        std::process::Command::new(tasklist)
            .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!("\"{pid}\"")))
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        // Signal 0 checks existence without delivering anything.
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
        false
    }
}

/// Where a daemon's control socket lives for a given warrant.
///
/// Under the store root rather than a shared temp directory: a predictable path in a
/// world-writable location invites another process to squat it and answer authorization requests
/// on the daemon's behalf.
#[must_use]
pub fn socket_path(root: &Path, warrant_id: &str) -> PathBuf {
    #[cfg(windows)]
    {
        // Named pipes are not filesystem paths, but the name is derived the same way so the two
        // platforms stay legible to each other.
        let _ = root;
        PathBuf::from(format!(r"\\.\pipe\warrantor-{warrant_id}"))
    }
    #[cfg(not(windows))]
    {
        root.join("run").join(format!("{warrant_id}.sock"))
    }
}

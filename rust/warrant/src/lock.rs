//! Cross-process locks over one warrant's record.
//!
//! # The race this closes
//!
//! Every mutating surface does the same three steps: load a warrant's JSON, decide, save it back.
//! Within one process the server serializes those steps behind a single API mutex — but two CLI
//! processes on the same store (`settle` here, `stop` there) interleave freely, and the loser's
//! save silently overwrites the winner's state transition. A warrant that reads as Open while its
//! effects are released is exactly the lost-update this exists to prevent.
//!
//! # The shape, and why it is files rather than OS handles
//!
//! An advisory byte-range lock would need a platform crate on at least one OS, and the crate's
//! dependency posture is deliberate. So the lock is a file whose *existence* is the critical
//! section: acquisition is `create_new`, which the filesystem makes atomic, and release is
//! deletion in [`Drop`] — so every early return, panic unwind and process kill between the two
//! releases it. A killed holder leaves the file behind, which is what the staleness window is
//! for: a lock older than [`LockConfig::stale_after_secs`] is stolen by any acquirer, because
//! every legitimate hold here is sub-second and the alternative is a crashed run wedging the
//! store until a human deletes a file by hand.
//!
//! The file records its holder and creation time so a stolen lock can say who held it, and so
//! staleness is judged from the recorded time rather than metadata that a copy could alter.
//!
//! Scope note, stated plainly: this serializes one warrant's record across processes. It is not a
//! general-purpose IPC facility, it says nothing about the staged-effect queue's own writes, and
//! an attacker who can write into the store directory was never stopped by anything here.

use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::store::WarrantStore;
use crate::WarrantError;

/// Wall clock as epoch seconds — the same shape every other module reads time with. Injectable
/// through [`LockConfig`] so the staleness tests can age a lock without sleeping.
fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Tunables for [`WarrantStore::lock_warrant_with`]. The defaults suit interactive commands;
/// tests shrink them so refusal paths do not dominate their runtime.
#[derive(Clone, Copy)]
pub struct LockConfig {
    /// Total acquire attempts before reporting [`WarrantError::LockBusy`].
    pub attempts: u32,
    /// Sleep between attempts.
    pub sleep_ms: u64,
    /// A lock whose recorded creation time is older than this many seconds is stolen.
    pub stale_after_secs: u64,
    /// Time source, injectable for the staleness tests.
    pub now: fn() -> u64,
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            attempts: 150,
            sleep_ms: 10,
            stale_after_secs: 60,
            now: system_now,
        }
    }
}

/// One held critical section over a warrant record. Dropping it releases.
///
/// Deliberately opaque: the guard carries no data, because its whole job is to exist in scope
/// while a load→decide→save span runs. Holding one is the only way the mutating surfaces touch a
/// record across processes.
#[derive(Debug)]
pub struct WarrantLock {
    path: PathBuf,
}

impl Drop for WarrantLock {
    fn drop(&mut self) {
        // Best effort, like every cleanup that runs during unwinding. A left-behind file is not a
        // correctness hole — the next acquirer steals it once it ages past the window — so a
        // removal failure here must not mask whatever the caller is propagating.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// First line of a lock file: format tag, so a future change cannot be mistaken for a current
/// file by an older binary reading a newer store.
const LOCK_FORMAT: &str = "warrantor-warrant-lock-v1";

fn lock_path(root: &Path, id: &str) -> PathBuf {
    root.join("locks").join(format!("{id}.lock"))
}

impl WarrantStore {
    /// Acquire the per-warrant critical section with default tuning.
    ///
    /// # Errors
    /// [`WarrantError::LockBusy`] when another holder will not yield within the retry budget, and
    /// [`WarrantError::Encode`] on I/O failure creating the lock.
    pub fn lock_warrant(&self, id: &str) -> Result<WarrantLock, WarrantError> {
        self.lock_warrant_with(id, LockConfig::default())
    }

    /// Acquire with explicit tuning — the test seam, and the escape hatch for a batch tool that
    /// would rather wait longer than fail.
    ///
    /// # Errors
    /// As [`Self::lock_warrant`].
    pub fn lock_warrant_with(
        &self,
        id: &str,
        config: LockConfig,
    ) -> Result<WarrantLock, WarrantError> {
        let path = lock_path(self.root(), id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WarrantError::Encode(format!("create {}: {e}", parent.display())))?;
        }
        let started = (config.now)();
        let mut last_busy = false;
        for _ in 0..config.attempts {
            match Self::try_acquire(&path, id, &config) {
                Ok(guard) => return Ok(guard),
                Err(LockAttempt::Held) => last_busy = true,
                Err(LockAttempt::Failed(e)) => return Err(e),
            }
            thread::sleep(Duration::from_millis(config.sleep_ms));
        }
        if last_busy {
            Err(WarrantError::LockBusy {
                id: id.to_string(),
                waited_ms: ((config.now)().saturating_sub(started)) * 1000
                    + u64::from(config.attempts) * config.sleep_ms,
            })
        } else {
            // Every attempt failed on I/O rather than contention; the last error already carried
            // the reason out through `Failed`, so reaching here means attempts was zero.
            Err(WarrantError::Encode(format!(
                "lock {id}: zero attempts configured"
            )))
        }
    }

    fn try_acquire(path: &Path, id: &str, config: &LockConfig) -> Result<WarrantLock, LockAttempt> {
        let created = (config.now)();
        let body = format!("{LOCK_FORMAT}\n{id}\n{created}\n");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(body.as_bytes())
                    .and_then(|_| file.sync_all())
                    .map_err(|e| {
                        // Half-created: remove so the next attempt starts clean instead of
                        // treating our own debris as somebody else's hold.
                        let _ = std::fs::remove_file(path);
                        LockAttempt::Failed(WarrantError::Encode(format!(
                            "write {}: {e}",
                            path.display()
                        )))
                    })?;
                Ok(WarrantLock {
                    path: path.to_path_buf(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if Self::lock_is_stale(path, config) {
                    // Two stealers may race here; the loser simply loses create_new again and
                    // keeps looping, which is the same code path as ordinary contention.
                    let _ = std::fs::remove_file(path);
                    Err(LockAttempt::Held)
                } else {
                    Err(LockAttempt::Held)
                }
            }
            Err(e) => Err(LockAttempt::Failed(WarrantError::Encode(format!(
                "create {}: {e}",
                path.display()
            )))),
        }
    }

    /// True when the file on disk names a creation time older than the staleness window. An
    /// unreadable file is treated as *fresh*, deliberately: stealing on a parse failure turns a
    /// transient read error into a double-hold, and a genuinely wedged store becomes stealable
    /// one window later anyway via the mtime fallback below.
    fn lock_is_stale(path: &Path, config: &LockConfig) -> bool {
        let now = (config.now)();
        if let Ok(body) = std::fs::read_to_string(path) {
            let mut lines = body.lines();
            if lines.next() == Some(LOCK_FORMAT) {
                // Line 2 is the holder id (unused here), line 3 the creation time.
                let _holder = lines.next();
                if let Some(created) = lines.next().and_then(|l| l.parse::<u64>().ok()) {
                    return now.saturating_sub(created) > config.stale_after_secs;
                }
            }
        }
        // Fallback for a foreign or damaged file: filesystem mtime, coarse but honest.
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| now.saturating_sub(d.as_secs()) > config.stale_after_secs)
            .unwrap_or(false)
    }
}

enum LockAttempt {
    Held,
    Failed(WarrantError),
}

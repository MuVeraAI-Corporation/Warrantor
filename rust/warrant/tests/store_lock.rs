//! The per-warrant cross-process lock: acquisition, release, contention, staleness.
//!
//! These tests run against a real store root on disk, because the property under test is
//! filesystem atomicity — `create_new` is the entire mechanism. Contention between two *threads*
//! of one process is exercised here; contention between two processes is the same code path once
//! the file exists, and the CLI/server wiring is pinned by their respective suites.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use warrantor_warrant::lock::LockConfig;
use warrantor_warrant::store::WarrantStore;

/// The injected clock is process-global, so every test that touches it takes this lock for its
/// whole body — the same discipline the notification suites use for their recording statics.
static SERIALISE: Mutex<()> = Mutex::new(());

fn begin() -> MutexGuard<'static, ()> {
    SERIALISE.lock().unwrap_or_else(|e| e.into_inner())
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-lock-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// A controllable clock anchored to the real epoch, so injected time and the filesystem's own
/// mtimes (the staleness fallback for foreign files) stay in the same timeline. `advance` moves
/// only this test binary's clock forward; it can never move backward.
static CLOCK_OFFSET: AtomicU64 = AtomicU64::new(0);

fn base_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn test_now() -> u64 {
    base_epoch().saturating_sub(120) + CLOCK_OFFSET.load(Ordering::SeqCst)
}

fn advance_clock(secs: u64) {
    CLOCK_OFFSET.fetch_add(secs, Ordering::SeqCst);
}

/// Injected clock sits this far behind the real epoch, so mtimes planted "now" on the real clock
/// are this much in its future.
const CLOCK_ANCHOR_GAP: u64 = 120;

fn fast_config() -> LockConfig {
    LockConfig {
        attempts: 3,
        sleep_ms: 1,
        stale_after_secs: 60,
        now: test_now,
    }
}

#[test]
fn an_acquired_lock_is_released_on_drop() {
    let _serial = begin();
    let dir = tempdir("release");
    let store = WarrantStore::open(&dir).expect("store");

    {
        let _guard = store
            .lock_warrant_with("wrt_1", fast_config())
            .expect("first acquire");
    }
    // The guard is gone, so this must succeed rather than report contention.
    let again = store.lock_warrant_with("wrt_1", fast_config());
    assert!(again.is_ok(), "re-acquire after drop failed: {again:?}");
}

#[test]
fn a_held_lock_refuses_a_second_holder_within_the_budget() {
    let _serial = begin();
    let dir = tempdir("contended");
    let store = WarrantStore::open(&dir).expect("store");
    let _guard = store
        .lock_warrant_with("wrt_1", fast_config())
        .expect("hold");
    let err = store.lock_warrant_with("wrt_1", fast_config()).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("locked by another process"),
        "refusal must name the situation and the remedy window: {text}"
    );
    assert!(
        !text.contains("internal"),
        "a busy lock is not an internal error; the operator can act on it: {text}"
    );
}

#[test]
fn different_warrants_do_not_contend() {
    let _serial = begin();
    let dir = tempdir("independent");
    let store = WarrantStore::open(&dir).expect("store");
    let _a = store.lock_warrant_with("wrt_a", fast_config()).expect("a");
    let _b = store.lock_warrant_with("wrt_b", fast_config()).expect("b");
}

#[test]
fn a_stale_lock_is_stolen_once_the_window_passes() {
    let _serial = begin();
    let dir = tempdir("stale");
    let store = WarrantStore::open(&dir).expect("store");
    let config = fast_config();
    let _dead_guard = store
        .lock_warrant_with("wrt_1", config)
        .expect("simulate crash");

    // A killed holder never drops. Advance the clock past the staleness window; the next
    // acquirer steals instead of wedging until a human deletes a file.
    advance_clock(61);
    let stolen = store.lock_warrant_with("wrt_1", config);
    assert!(
        stolen.is_ok(),
        "a lock older than the window must be stealable: {stolen:?}"
    );
}

#[test]
fn a_fresh_unreadable_lock_is_not_stolen() {
    let _serial = begin();
    let dir = tempdir("foreign");
    let store = WarrantStore::open(&dir).expect("store");
    let locks_dir = dir.join("locks");
    std::fs::create_dir_all(&locks_dir).expect("locks dir");
    // A foreign or damaged file at the lock path, created "now" on this clock.
    std::fs::write(locks_dir.join("wrt_1.lock"), b"not our format\n").expect("plant");
    let config = fast_config();

    let err = store.lock_warrant_with("wrt_1", config).unwrap_err();
    assert!(
        err.to_string().contains("locked by another process"),
        "an unreadable but fresh lock is treated as held, never as free to take: {err}"
    );

    // And it becomes recoverable exactly when the mtime-based fallback ages out. The foreign
    // file's mtime is on the real clock, so the advance must close the anchor gap AND the
    // staleness window before that fallback lets go of it.
    advance_clock(CLOCK_ANCHOR_GAP + 61);
    assert!(
        store.lock_warrant_with("wrt_1", config).is_ok(),
        "the same foreign file past the window is stolen via its mtime"
    );
}

//! W2 tests: daemon registration and reconciliation.
//!
//! The property under test is what happens when supervision *stops*. A daemon that dies takes its
//! agent with it — that part is OS-enforced and proven elsewhere — but the warrant it left behind
//! is in a state nobody is advancing, with staged effects nobody has decided about. Silence there
//! is the failure mode: the developer believes work is progressing when it stopped hours ago.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use warrantor_warrant::daemon::{
    process_is_alive, socket_path, CompletionRecord, DaemonRecord, DaemonState, Reconciliation,
};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-daemon-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn stored(id: &str, state: WarrantState) -> StoredWarrant {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
        exec: None,
    };
    let mut warrant = Warrant::grant(
        id,
        "goal",
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    warrant.state = state;
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

fn record(id: &str, pid: u32, root: &std::path::Path) -> DaemonRecord {
    DaemonRecord {
        warrant_id: id.to_string(),
        pid,
        socket: socket_path(root, id),
        started_at: NOW,
        expires_at: NOW + 3600,
    }
}

#[test]
fn a_daemon_record_round_trips() {
    let dir = tempdir("roundtrip");
    let state = DaemonState::open(&dir).expect("open");
    let written = record("wrt_a", 4242, &dir);
    state.register(&written).expect("register");
    assert_eq!(state.get("wrt_a"), Some(written));
}

#[test]
fn deregistering_a_missing_record_is_not_an_error() {
    let dir = tempdir("dereg");
    let state = DaemonState::open(&dir).expect("open");
    // Clean shutdown must not be noisier than a crash.
    state.deregister("never_existed").expect("deregister");
}

/// A live daemon means the run is healthy; say so rather than alarming the developer.
#[test]
fn a_live_daemon_reports_supervised() {
    let dir = tempdir("live");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_live", WarrantState::Open))
        .expect("save");
    state
        .register(&record("wrt_live", 1234, &dir))
        .expect("register");

    let found = state
        .reconcile(&store, &|pid| pid == 1234)
        .expect("reconcile");
    assert_eq!(
        found.get("wrt_live"),
        Some(&Reconciliation::Supervised { pid: 1234 })
    );
}

/// THE test. The daemon died; the warrant is still Open. Reporting nothing would leave the
/// developer believing work is in progress when it stopped.
#[test]
fn a_dead_daemon_reports_the_warrant_as_interrupted() {
    let dir = tempdir("dead");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_dead", WarrantState::Open))
        .expect("save");
    state
        .register(&record("wrt_dead", 9999, &dir))
        .expect("register");

    let found = state.reconcile(&store, &|_| false).expect("reconcile");

    match found.get("wrt_dead") {
        Some(Reconciliation::Interrupted { detail }) => {
            assert!(
                detail.contains("terminated with it"),
                "the developer must be told the agent is already dead, not still running: {detail}"
            );
            assert!(
                detail.contains("NOT resumed"),
                "resuming an agent interrupted mid-task would be guessing about half-done work"
            );
            assert!(
                detail.contains("settle or void"),
                "an interrupted warrant needs a decision, so say which one: {detail}"
            );
        }
        other => panic!("expected Interrupted, got {other:?}"),
    }
}

/// A stale record must not survive reconciliation, or every subsequent start would re-report the
/// same interruption forever.
#[test]
fn reconciling_clears_the_stale_record() {
    let dir = tempdir("clears");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_stale", WarrantState::Open))
        .expect("save");
    state
        .register(&record("wrt_stale", 9999, &dir))
        .expect("register");

    state.reconcile(&store, &|_| false).expect("reconcile");
    assert_eq!(state.get("wrt_stale"), None);
}

/// Open with no record: either never run, or the daemon died before registering. Both mean nothing
/// is supervising, and the message has to cover both without alarming someone who simply has not
/// started yet.
#[test]
fn an_open_warrant_with_no_daemon_is_reported_honestly() {
    let dir = tempdir("norecord");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_never", WarrantState::Open))
        .expect("save");

    let found = state.reconcile(&store, &|_| true).expect("reconcile");
    match found.get("wrt_never") {
        Some(Reconciliation::Interrupted { detail }) => {
            assert!(
                detail.contains("never started"),
                "the common benign case must be named so this is not read as an incident: {detail}"
            );
        }
        other => panic!("expected Interrupted, got {other:?}"),
    }
}

#[test]
fn terminal_warrants_need_no_reconciliation() {
    let dir = tempdir("terminal");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    for (id, warrant_state) in [
        ("wrt_settled", WarrantState::Settled),
        ("wrt_void", WarrantState::Void),
        ("wrt_held", WarrantState::Held),
    ] {
        store.save(&stored(id, warrant_state)).expect("save");
    }

    let found = state.reconcile(&store, &|_| false).expect("reconcile");
    for id in ["wrt_settled", "wrt_void", "wrt_held"] {
        assert_eq!(
            found.get(id),
            Some(&Reconciliation::Finished),
            "{id} is not open, so nothing should be supervising it"
        );
    }
}

/// A false "alive" leaves a warrant permanently unreconciled; a false "dead" reports a healthy run
/// as interrupted. Both are bad, so check the primitive against known-good and known-bad pids.
#[test]
fn liveness_detection_is_correct_on_this_host() {
    let me = std::process::id();
    assert!(process_is_alive(me), "this process is definitionally alive");
    // A pid this large is not in use on any normal system.
    assert!(!process_is_alive(4_294_967_294));
}

/// A predictable path in a world-writable directory invites another process to squat it and answer
/// authorization requests on the daemon's behalf.
#[test]
fn the_socket_lives_under_the_store_not_in_shared_temp() {
    let dir = tempdir("socket");
    let path = socket_path(&dir, "wrt_x");
    let text = path.to_string_lossy();
    if cfg!(windows) {
        assert!(
            text.starts_with(r"\\.\pipe\"),
            "expected a named pipe: {text}"
        );
        assert!(text.contains("wrt_x"));
    } else {
        assert!(
            text.starts_with(&*dir.to_string_lossy()),
            "the socket must live under the store root: {text}"
        );
    }
}

// ── a finished run is not a crash ─────────────────────────────────────────────────────

/// The regression this exists for: before completion records, a run that finished cleanly and a
/// supervisor that died both left no daemon record, so `status` told the operator their successful
/// overnight run had crashed. Found by the first live dogfood, where a real agent fixed a real bug
/// and was reported as an incident.
#[test]
fn a_completed_run_is_reported_as_finished_not_interrupted() {
    let dir = tempdir("completed");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_done", WarrantState::Open))
        .expect("save");
    state
        .record_completion(&CompletionRecord {
            warrant_id: "wrt_done".to_string(),
            pid: 4242,
            exit_code: 0,
            expired: false,
            finished_at: NOW + 60,
        })
        .expect("record completion");

    let found = state.reconcile(&store, &|_| true).expect("reconcile");
    match found.get("wrt_done") {
        Some(Reconciliation::Completed {
            exit_code,
            expired,
            detail,
        }) => {
            assert_eq!(*exit_code, 0);
            assert!(!*expired);
            assert!(
                detail.contains("finished on its own"),
                "a clean finish must read as a finish: {detail}"
            );
            assert!(
                !detail.contains("died"),
                "nothing died; saying so trains the operator to ignore status: {detail}"
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// A deadline stop is a completion too, and must say which it was -- the operator's next action
/// differs between "it finished" and "it ran out of time with work half done".
#[test]
fn a_deadline_stop_is_reported_as_a_deadline() {
    let dir = tempdir("expired");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_late", WarrantState::Open))
        .expect("save");
    state
        .record_completion(&CompletionRecord {
            warrant_id: "wrt_late".to_string(),
            pid: 7,
            exit_code: -1,
            expired: true,
            finished_at: NOW + 3600,
        })
        .expect("record completion");

    let found = state.reconcile(&store, &|_| true).expect("reconcile");
    match found.get("wrt_late") {
        Some(Reconciliation::Completed {
            expired, detail, ..
        }) => {
            assert!(*expired);
            assert!(
                detail.contains("deadline"),
                "the deadline case must name itself: {detail}"
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// A live daemon still wins over a stale completion record from an earlier run of the same warrant.
#[test]
fn a_live_daemon_outranks_an_old_completion_record() {
    let dir = tempdir("relive");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_again", WarrantState::Open))
        .expect("save");
    state
        .record_completion(&CompletionRecord {
            warrant_id: "wrt_again".to_string(),
            pid: 1,
            exit_code: 0,
            expired: false,
            finished_at: NOW,
        })
        .expect("record completion");
    state
        .register(&record("wrt_again", 5150, &dir))
        .expect("register");

    let found = state.reconcile(&store, &|_| true).expect("reconcile");
    assert!(
        matches!(found.get("wrt_again"), Some(Reconciliation::Supervised { pid }) if *pid == 5150),
        "a running supervisor is the truth, whatever an earlier run recorded"
    );
}

/// A second run must not inherit the first run's completion record.
///
/// Without clearing it at register time, a re-run that crashed would find the earlier record and be
/// reported as "finished on its own (agent exit 0)" -- the exact inversion the completion record
/// was introduced to prevent, one run later.
#[test]
fn a_new_run_clears_the_previous_runs_completion_record() {
    let dir = tempdir("stale");
    let store = WarrantStore::open(&dir).expect("store");
    let state = DaemonState::open(&dir).expect("state");
    store
        .save(&stored("wrt_rerun", WarrantState::Open))
        .expect("save");
    state
        .record_completion(&CompletionRecord {
            warrant_id: "wrt_rerun".to_string(),
            pid: 1,
            exit_code: 0,
            expired: false,
            finished_at: NOW,
        })
        .expect("first run finished");

    // A second run starts, then its supervisor dies without recording a completion.
    state
        .register(&record("wrt_rerun", 4242, &dir))
        .expect("register");
    assert!(
        state.completion("wrt_rerun").is_none(),
        "registering a new run must clear the old completion record"
    );

    let found = state.reconcile(&store, &|_| false).expect("reconcile");
    match found.get("wrt_rerun") {
        Some(Reconciliation::Interrupted { detail }) => {
            assert!(
                !detail.contains("finished on its own"),
                "a crashed re-run must not inherit the earlier run's success: {detail}"
            );
        }
        other => panic!("expected Interrupted for a crashed re-run, got {other:?}"),
    }
}

// -- L4-05: the EXEC gate at the supervise chokepoint ---------------------------------

use warrantor_warrant::daemon::{supervise_run, SuperviseRequest};
use warrantor_warrant::exec::{self, ExecAdmission, ExecPhase, ExecSurface, ExecVerdict};

fn agent() -> String {
    env!("CARGO_BIN_EXE_warrantor").to_string()
}

fn request(
    dir: &std::path::Path,
    id: &str,
    program: &str,
    exec: Option<BTreeSet<ExecAdmission>>,
) -> SuperviseRequest {
    SuperviseRequest {
        warrant_id: id.to_string(),
        expires_at: NOW + 3600,
        program: program.to_string(),
        args: vec!["--help".to_string()],
        cwd: None,
        root: dir.to_path_buf(),
        now: NOW,
        exec,
    }
}

/// The E-04 gate at the moment of action: a same-named modified artifact never becomes a process,
/// no daemon record is written for it, and the refusal is receipted with the digest.
#[test]
fn supervise_refuses_a_modified_artifact_before_spawning_and_receipts_it() {
    let dir = tempdir("exec-refuse");
    let state = DaemonState::open(&dir).expect("state");
    let (digest, _) = exec::sha256_file(std::path::Path::new(&agent())).expect("digest");
    let pinned: BTreeSet<ExecAdmission> = [ExecAdmission {
        surface: ExecSurface::Process,
        sha256: digest.clone(),
    }]
    .into_iter()
    .collect();

    let modified = dir.join(if cfg!(windows) {
        "warrantor.exe"
    } else {
        "warrantor"
    });
    let mut bytes = std::fs::read(agent()).expect("read");
    bytes.push(0x00);
    std::fs::write(&modified, &bytes).expect("write");

    let err = supervise_run(
        &state,
        &request(
            &dir,
            "wrt_exec_refuse",
            &modified.to_string_lossy(),
            Some(pinned.clone()),
        ),
    )
    .expect_err("a modified artifact is refused");
    assert!(err.contains("gate artifacts"), "{err}");
    assert!(
        !err.contains(&digest),
        "the admitted digest is not disclosed: {err}"
    );
    assert_eq!(
        state.get("wrt_exec_refuse"),
        None,
        "nothing was registered, because nothing ran"
    );
    assert!(state.completion("wrt_exec_refuse").is_none());
    let log = exec::read_for(&dir, "wrt_exec_refuse");
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].verdict, ExecVerdict::Refused);
    assert_eq!(log.receipts[0].phase, ExecPhase::Spawn);
    assert_ne!(log.receipts[0].sha256, digest);

    // The renamed, byte-identical copy gets the opposite verdict and actually runs.
    let renamed = dir.join(if cfg!(windows) {
        "renamed.exe"
    } else {
        "renamed"
    });
    std::fs::copy(agent(), &renamed).expect("copy");
    let code = supervise_run(
        &state,
        &request(
            &dir,
            "wrt_exec_ok",
            &renamed.to_string_lossy(),
            Some(pinned),
        ),
    )
    .expect("a byte-identical artifact runs");
    assert_eq!(code, 0);
    let log = exec::read_for(&dir, "wrt_exec_ok");
    assert_eq!(log.receipts[0].verdict, ExecVerdict::Admitted);
    assert_eq!(
        log.receipts[0].sha256, digest,
        "every EXEC receipt carries the digest"
    );
    assert_eq!(
        state.completion("wrt_exec_ok").map(|c| c.exit_code),
        Some(0)
    );
}

/// A warrant that declares no surface is not refused, and is still receipted with the digest.
#[test]
fn supervise_under_an_undeclared_surface_runs_and_records_unpinned() {
    let dir = tempdir("exec-unpinned");
    let state = DaemonState::open(&dir).expect("state");
    let code = supervise_run(&state, &request(&dir, "wrt_unpinned", &agent(), None)).expect("runs");
    assert_eq!(code, 0);
    let log = exec::read_for(&dir, "wrt_unpinned");
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].verdict, ExecVerdict::Unpinned);
    assert_eq!(log.receipts[0].sha256.len(), 64);
}

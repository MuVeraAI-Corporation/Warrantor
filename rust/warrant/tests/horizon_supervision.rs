//! The horizon governor against a REAL supervised process tree, on every kernel CI runs.
//!
//! `rust/warrant/tests/horizon.rs` tests the arithmetic. This file tests the half that earns the
//! tier word: that the wall-clock and unattended dimensions actually reach
//! [`warrantor_warrant::supervise`]'s OS process link, that the descendant dies with the root, and
//! that the record left behind names which dimension ended the run.
//!
//! Rule 2 in one sentence: a horizon that is never observed to terminate anything is arithmetic, and
//! arithmetic refuses nothing. Every halt asserted here is paired with a control that runs to
//! completion inside its ceilings, so a green run cannot be produced by a governor that kills
//! everything it is handed.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use warrantor_kill_switch_core::process_exists;
use warrantor_warrant::daemon::{self, CompletionRecord, DaemonState, SuperviseRequest};
use warrantor_warrant::horizon;
use warrantor_warrant::{Horizon, SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "warrantor-hsup-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn bounds(horizon: Option<Horizon>) -> WarrantBounds {
    WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: Default::default(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        // Deliberately a day away: every halt in this file must come from the horizon and never
        // from the deadline. A test whose deadline could also have fired proves nothing about the
        // horizon.
        expires_at: NOW + 86_400,
        budget_cents_observed: None,
        delegation_depth: 2,
        horizon,
    }
}

fn granted(id: &str, horizon: Option<Horizon>) -> Warrant {
    Warrant::grant(
        id,
        "drill",
        "spiffe://muveraai.com/agent/drill",
        bounds(horizon),
        NOW,
        &SigningKey::from_bytes(&[2; 32]).verifying_key(),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .expect("grant")
}

/// The same two-level tree `stop_kills_tree.rs` uses: a shell that starts a long `ping`/`sleep` and
/// waits on it. The root is the supervised child; the `ping`/`sleep` is the grandchild the OS link
/// has to reach and `PR_SET_PDEATHSIG` alone does not.
fn tree_command(pid_file: &Path) -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        (
            "powershell".to_string(),
            vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                format!(
                    "$p = Start-Process -FilePath ping -ArgumentList '-n','120','127.0.0.1' \
                     -WindowStyle Hidden -PassThru; Set-Content -Path '{}' -Value $p.Id; \
                     Wait-Process -Id $p.Id",
                    pid_file.display()
                ),
            ],
        )
    }
    #[cfg(unix)]
    {
        (
            "sh".to_string(),
            vec![
                "-c".to_string(),
                "sleep 120 & echo $! > \"$0\"; wait".to_string(),
                pid_file.display().to_string(),
            ],
        )
    }
}

/// A command that exits promptly and cleanly, for the controls.
fn quick_command() -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        (
            "cmd".to_string(),
            vec!["/C".to_string(), "exit".to_string(), "0".to_string()],
        )
    }
    #[cfg(unix)]
    {
        (
            "sh".to_string(),
            vec!["-c".to_string(), "exit 0".to_string()],
        )
    }
}

fn read_pid(pid_file: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(pid) = std::fs::read_to_string(pid_file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the supervised tree never wrote a descendant pid");
}

fn gone_within(pid: u32, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if !process_exists(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !process_exists(pid)
}

/// Run one supervised tree under `horizon`, returning its completion record, the store root and the
/// descendant pid the OS link had to reach.
fn run_tree_under(tag: &str, id: &str, horizon: Horizon) -> (CompletionRecord, PathBuf, u32) {
    let root = tempdir(tag);
    let state = DaemonState::open(&root).expect("daemon state");
    let pid_file = root.join("descendant.pid");
    let (program, args) = tree_command(&pid_file);
    let warrant = granted(id, Some(horizon.clone()));

    // The descendant pid appears only once the shell has started it, so it is read on another
    // thread while the supervision loop is blocked in its wait.
    let watcher = {
        let pid_file = pid_file.clone();
        std::thread::spawn(move || read_pid(&pid_file))
    };

    let code = daemon::supervise_run(
        &state,
        &SuperviseRequest {
            warrant_id: id.to_string(),
            // The effective deadline, exactly as the CLI computes it: a horizon can only move the
            // deadline in. With `expires_at` a day away, any halt here came from the horizon.
            expires_at: horizon::effective_deadline(&warrant.claims.bounds, NOW),
            program,
            args,
            cwd: None,
            root: root.clone(),
            now: NOW,
            horizon: Some(horizon),
            issued_at: NOW,
            staged_path: None,
        },
    )
    .expect("supervise_run");
    assert_eq!(
        code, -1,
        "a horizon halt reports -1, not the agent's own code"
    );

    let descendant = watcher.join().expect("pid watcher");
    let record = state
        .completion(id)
        .expect("a finished run must leave a completion record");
    (record, root, descendant)
}

// ── the wall-clock dimension reaches the OS link ────────────────────────────────────────

/// The composition claim, observed: a wall-clock horizon shortens the wait budget the supervisor
/// already enforces, and the supervisor kills the TREE. `supervise.rs` is unmodified by this task,
/// so a pass here is the horizon reaching an existing mechanism rather than a second one.
///
/// The grandchild is the load-bearing half. `PR_SET_PDEATHSIG` links the direct child only; a
/// governor that leaves descendants running has bounded nothing.
#[test]
fn horizon_wall_breach_terminates_the_process_group() {
    let (record, _root, descendant) = run_tree_under(
        "wall",
        "wrt_hz_wall",
        Horizon {
            max_wall_seconds: Some(2),
            ..Horizon::none()
        },
    );

    assert!(
        gone_within(descendant, Duration::from_secs(20)),
        "descendant {descendant} survived: the horizon killed the child, not the tree, and a \
         governor that leaves descendants running has bounded nothing"
    );

    let named = record
        .horizon_breach
        .as_deref()
        .expect("a horizon halt with no reason is a crash with better manners");
    assert!(
        named.starts_with("horizon:wall"),
        "the record must name the dimension: {named}"
    );
    assert!(
        named.contains("limit 2"),
        "the limit must be in the record: {named}"
    );
    assert!(record.expired, "a horizon halt is not a clean exit");
}

/// The control the assertion above needs: a run that finishes inside every ceiling is NOT killed,
/// records no breach, and reports the agent's own exit code. Without this, the test above would pass
/// against a supervisor that terminates every run it is given.
#[test]
fn a_run_that_finishes_inside_its_horizon_records_no_breach() {
    let root = tempdir("clean");
    let state = DaemonState::open(&root).expect("daemon state");
    let (program, args) = quick_command();
    let horizon = Horizon {
        max_wall_seconds: Some(600),
        max_effects: Some(50),
        max_unattended_seconds: Some(600),
        escalate_at_percent: Some(90),
    };
    let warrant = granted("wrt_hz_clean", Some(horizon.clone()));

    let code = daemon::supervise_run(
        &state,
        &SuperviseRequest {
            warrant_id: "wrt_hz_clean".to_string(),
            expires_at: horizon::effective_deadline(&warrant.claims.bounds, NOW),
            program,
            args,
            cwd: None,
            root: root.clone(),
            now: NOW,
            horizon: Some(horizon),
            issued_at: NOW,
            staged_path: None,
        },
    )
    .expect("supervise_run");
    assert_eq!(code, 0, "the control's agent exited cleanly");

    let record = state.completion("wrt_hz_clean").expect("completion record");
    assert!(
        record.horizon_breach.is_none(),
        "a clean run must carry no breach, or the assertion in the breach test is satisfied by a \
         field that is always populated: {:?}",
        record.horizon_breach
    );
    assert!(!record.expired);
    assert!(
        record.horizon_escalations.is_empty(),
        "nothing was near a ceiling, so nothing may have been escalated: {:?}",
        record.horizon_escalations
    );
}

// ── the unattended dimension is a clock the deadline cannot express ─────────────────────

/// The dimension a single up-front wait budget cannot express: a ceiling on time without a NAMED
/// human, re-evaluated while the run is live. Nothing acts in this store, so the clock runs from
/// issue and the run is halted for `unattended` — not for `wall`, whose ceiling is an hour away.
#[test]
fn horizon_unattended_breach_halts_a_run_the_deadline_would_have_allowed() {
    let (record, _root, descendant) = run_tree_under(
        "unattended",
        "wrt_hz_unattended",
        Horizon {
            max_wall_seconds: Some(3_600),
            max_unattended_seconds: Some(2),
            ..Horizon::none()
        },
    );
    assert!(
        gone_within(descendant, Duration::from_secs(20)),
        "descendant {descendant} survived an unattended-horizon halt"
    );
    let named = record
        .horizon_breach
        .as_deref()
        .expect("an unattended halt must name itself");
    assert!(
        named.starts_with("horizon:unattended"),
        "the wall ceiling was an hour away, so only the unattended clock can have fired: {named}"
    );
}

// ── the escalation half of L3-04 ────────────────────────────────────────────────────────

/// "Automatic escalation to a human as the horizon extends" — the half that existed nowhere.
/// Crossing the threshold writes a review request under the store root and does NOT halt the run.
///
/// What this establishes is exactly one thing: a request was made durable on this machine. It does
/// not establish that a human read it, and it adds no trust root — no approval service, no
/// directory, no new signer.
#[test]
fn crossing_the_escalation_threshold_records_a_local_review_request_without_halting() {
    let (record, root, _descendant) = run_tree_under(
        "escalate",
        "wrt_hz_escalate",
        Horizon {
            max_wall_seconds: Some(4),
            // 50% of 4s is crossed at 2s, before the ceiling arrives, so the escalation is
            // observable as a thing that happened WHILE the run was still going.
            escalate_at_percent: Some(50),
            ..Horizon::none()
        },
    );
    // The run still reached its ceiling: escalation asks, it does not stop.
    assert!(
        record
            .horizon_breach
            .as_deref()
            .is_some_and(|reason| reason.starts_with("horizon:wall")),
        "escalation must not replace the halt: {:?}",
        record.horizon_breach
    );
    assert!(
        record
            .horizon_escalations
            .iter()
            .any(|blocker| blocker.starts_with("horizon:wall:50pct")),
        "the escalation was not recorded on the run: {:?}",
        record.horizon_escalations
    );
    // Durable, not just in memory: the marker every other review request in this system uses.
    let announced = warrantor_warrant::review::last_announced(&root, "wrt_hz_escalate")
        .expect("the escalation must leave the review marker every other blocker leaves");
    assert!(
        announced.starts_with("horizon:wall:50pct"),
        "the marker must name the dimension and the threshold: {announced}"
    );
    // Announced once, not once per slice: `should_announce` compares the blocker, so a second slice
    // over the same threshold is not a second notification.
    assert_eq!(
        record
            .horizon_escalations
            .iter()
            .filter(|blocker| blocker.starts_with("horizon:wall:50pct"))
            .count(),
        1,
        "one threshold crossed once must not queue a request per slice: {:?}",
        record.horizon_escalations
    );
}

/// The control: with no `escalate_at_percent` declared, nothing is ever queued. An escalation that
/// fires without being asked for is a notification channel nobody consented to, and the first thing
/// an operator does about it is turn the governor off.
#[test]
fn a_horizon_with_no_escalation_threshold_records_nothing() {
    let (record, root, _descendant) = run_tree_under(
        "noescalate",
        "wrt_hz_noescalate",
        Horizon {
            max_wall_seconds: Some(3),
            ..Horizon::none()
        },
    );
    assert!(
        record.horizon_escalations.is_empty(),
        "an undeclared escalation threshold queued a request anyway: {:?}",
        record.horizon_escalations
    );
    assert_eq!(
        warrantor_warrant::review::last_announced(&root, "wrt_hz_noescalate"),
        None,
        "no marker may be written for a threshold nobody declared"
    );
}

// ── the poll interval is derived, not guessed ───────────────────────────────────────────

/// The slice has to be short enough that a breach is noticed near the ceiling and long enough that
/// an eight-hour run does not re-read the actor log twenty-eight thousand times. It is derived from
/// the tightest declared time ceiling rather than fixed, and this test pins both ends.
#[test]
fn the_poll_slice_is_derived_from_the_tightest_time_ceiling() {
    // A four-second ceiling has to be polled at the floor, or the ceiling arrives inside one slice
    // and the escalation between them is never observed.
    assert_eq!(
        daemon::horizon_slice_seconds(&Horizon {
            max_wall_seconds: Some(4),
            ..Horizon::none()
        }),
        1
    );
    // An eight-hour ceiling is capped, not divided: a tenth of eight hours would notice a breach
    // 48 minutes late.
    assert_eq!(
        daemon::horizon_slice_seconds(&Horizon {
            max_wall_seconds: Some(28_800),
            ..Horizon::none()
        }),
        daemon::HORIZON_SLICE_CEILING_SECONDS
    );
    // The TIGHTEST of the two time ceilings wins; a loose wall ceiling must not slow the unattended
    // clock's poll down with it.
    assert_eq!(
        daemon::horizon_slice_seconds(&Horizon {
            max_wall_seconds: Some(28_800),
            max_unattended_seconds: Some(60),
            ..Horizon::none()
        }),
        6
    );
    // An effects-only horizon declares no clock at all. The supervisor still polls, because the
    // staged count it reads is the durable half — see `horizon::EFFECT_COUNT_LIMITATION` — but
    // there is no ceiling to derive an interval from, so it uses the ceiling.
    assert_eq!(
        daemon::horizon_slice_seconds(&Horizon {
            max_effects: Some(10),
            ..Horizon::none()
        }),
        daemon::HORIZON_SLICE_CEILING_SECONDS
    );
}

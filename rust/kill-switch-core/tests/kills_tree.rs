//! The extraction is only worth doing if the extracted code still kills a real process tree.
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use warrantor_kill_switch_core::{process_exists, TreeKiller};

/// A root that spawns a descendant and writes the descendant's pid to `pid_file`, then waits.
fn spawn_tree(pid_file: &std::path::Path) -> std::process::Child {
    #[cfg(windows)]
    {
        let script = format!(
            "$p = Start-Process -FilePath ping -ArgumentList '-n','60','127.0.0.1' -WindowStyle Hidden -PassThru; \
             Set-Content -Path '{}' -Value $p.Id; Wait-Process -Id $p.Id",
            pid_file.display()
        );
        Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn tree")
    }
    #[cfg(unix)]
    {
        Command::new("sh")
            .args([
                "-c",
                "sleep 60 & echo $! > \"$0\"; wait",
                &pid_file.display().to_string(),
            ])
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn tree")
    }
}

fn read_pid(pid_file: &std::path::Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(pid_file) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                return pid;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("descendant pid never appeared in {}", pid_file.display());
}

#[test]
fn terminate_reaches_the_descendant_not_only_the_root() {
    let dir = std::env::temp_dir().join(format!("wks-core-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let pid_file = dir.join("descendant.pid");
    let mut root = spawn_tree(&pid_file);
    let descendant = read_pid(&pid_file);
    assert!(process_exists(root.id()) && process_exists(descendant));

    let terminated = TreeKiller::new().terminate(root.id()).expect("terminate");
    assert!(!terminated.already_gone);
    let _ = root.wait();
    assert!(!process_exists(root.id()), "root still alive");
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_exists(descendant) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !process_exists(descendant),
        "descendant {descendant} outlived the tree kill"
    );
}

#[test]
fn reserved_and_self_pids_are_refused_before_any_helper_runs() {
    use warrantor_kill_switch_core::TerminateError;
    assert!(matches!(
        TreeKiller::new().terminate(0),
        Err(TerminateError::Reserved { pid: 0, .. })
    ));
    assert!(matches!(
        TreeKiller::new().terminate(std::process::id()),
        Err(TerminateError::SelfTarget { .. })
    ));
}

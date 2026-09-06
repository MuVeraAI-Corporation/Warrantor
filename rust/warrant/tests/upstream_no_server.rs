//! `cmd_mcp`'s no-upstream branch, which nothing exercised until a mutation test looked.
//!
//! Commit 248764a added a check on the path where `--upstream-effects` or `--upstream-strict` is
//! typed with no `--upstream` server attached, on the principle that *a flag whose whole purpose is
//! to fail closed must never be silently inert*. The mechanism worked. Nothing tested it: deleting
//! the entire block left the full workspace gate byte-identical at 152 suites and 1546 passing, so
//! nothing distinguished the shipped tree from one where the commit was never written.
//!
//! Ten test files in this package already spawn the binary through `CARGO_BIN_EXE_warrantor`, so
//! the test was available and simply was not written. That is the gap these two cover.

use std::path::Path;
use std::process::Command;

/// Run `warrantor <args...>` against a store rooted in `home`, returning (success, stdout+stderr).
fn run(home: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor");
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), both)
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("warrantor-nous-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    dir
}

/// Grant a warrant and return its id. The upstream check sits behind warrant validation, so a
/// bogus id is refused long before `cmd_mcp` reads a single `--upstream-*` flag -- which is how
/// the first draft of these tests passed a nonexistent id and learned nothing.
fn granted(home: &Path) -> String {
    let (ok, out) = run(
        home,
        &[
            "grant", "--goal", "probe", "--tools", "git", "--write", "src/**",
        ],
    );
    assert!(ok, "grant failed: {out}");
    out.split_whitespace()
        .find(|w| w.starts_with("wrt_"))
        .map(|w| {
            w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .to_string()
        })
        .unwrap_or_else(|| panic!("no warrant id in grant output: {out}"))
}

/// A misspelled syscall is refused the day it is typed, not the day an upstream is added.
///
/// This is the half of 248764a that fails closed. Without the check the value is simply never
/// parsed, so the operator learns nothing until a server is attached — possibly weeks later, and
/// possibly in the run where it mattered.
#[test]
fn a_misspelled_syscall_is_refused_even_with_no_upstream_attached() {
    let home = tempdir("badverb");
    let id = granted(&home);
    let (ok, out) = run(
        &home,
        &[
            "mcp",
            "--agent",
            &id,
            "--upstream-strict",
            "--upstream-effects",
            "x=mutant",
        ],
    );
    assert!(!ok, "a bad syscall name must fail, not pass: {out}");
    assert!(
        out.contains("mutant") && out.contains("is not an effect syscall"),
        "the refusal must name the bad verb: {out}"
    );
    // The paired ALLOWED control: the same shape with a real syscall must not be refused for
    // being unparseable. Without this the assertion above would also pass if every value failed.
    let (_, good) = run(
        &home,
        &[
            "mcp",
            "--agent",
            &id,
            "--upstream-strict",
            "--upstream-effects",
            "x=mutate",
        ],
    );
    assert!(
        !good.contains("is not an effect syscall"),
        "a real syscall must parse; only the misspelling is refused: {good}"
    );
}

/// The other half: the session says out loud that the declarations decide nothing here.
///
/// A flag that is inert AND silent is the failure mode; being inert while saying so is the
/// designed behavior. The message must also not overclaim — see the disclosure's own unit test.
#[test]
fn the_no_upstream_session_says_the_declarations_decide_nothing() {
    let home = tempdir("disclose");
    let id = granted(&home);
    let (_, out) = run(&home, &["mcp", "--agent", &id, "--upstream-strict"]);
    assert!(
        out.contains("no --upstream server is attached"),
        "the session must disclose that nothing is attached: {out}"
    );
    assert!(
        out.contains("decide nothing in this session"),
        "it must say the declarations decide nothing: {out}"
    );
    assert!(
        out.contains("staged") && out.contains("settle"),
        "and it must NOT stop there: a staged effect is still staged and performed at settle, \
         which is the correction this sentence carries: {out}"
    );
}

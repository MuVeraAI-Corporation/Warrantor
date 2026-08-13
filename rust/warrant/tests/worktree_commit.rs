//! `--commit` stages only what the warrant permitted.
//!
//! Found by the first live dogfood. An agent fixed a real bug, ran the test suite, and left
//! `__pycache__` beside its fix. `git add -A` committed the artifacts along with the work and the
//! merge then aborted on them. The warrant already says which paths the agent could legitimately
//! write; those are the only ones that belong in the commit.

use std::collections::BTreeSet;
use std::process::Command;

use warrantor_warrant::worktree::Worktree;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-wtcommit-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

/// A repository with one commit, ready to have a worktree cut from it.
fn repo(tag: &str) -> std::path::PathBuf {
    let dir = tempdir(tag);
    git(&dir, &["init", "-q"]);
    git(&dir, &["config", "user.email", "t@local"]);
    git(&dir, &["config", "user.name", "T"]);
    std::fs::create_dir_all(dir.join("src")).expect("src");
    std::fs::write(dir.join("src/lib.txt"), "original\n").expect("write");
    std::fs::write(dir.join("README.md"), "readme\n").expect("write");
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "initial"]);
    dir
}

fn globs(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

#[test]
fn only_paths_inside_the_write_bounds_are_committed() {
    let dir = repo("bounds");
    let tree = Worktree::create(&dir, "wrt_bounds").expect("worktree");

    // The work the agent was permitted to do.
    std::fs::write(tree.path.join("src/lib.txt"), "fixed\n").expect("write");
    // Artifacts it produced outside its bounds -- a test run's leavings.
    std::fs::create_dir_all(tree.path.join("build")).expect("build dir");
    std::fs::write(tree.path.join("build/out.bin"), "junk\n").expect("write");
    std::fs::write(tree.path.join("README.md"), "agent rewrote this\n").expect("write");

    let committed = tree
        .commit_all("fix the thing", &globs(&["src/**"]))
        .expect("commit");
    assert_eq!(committed, 1, "only src/lib.txt is inside src/**");

    let out = Command::new("git")
        .arg("-C")
        .arg(tree.path)
        .args(["show", "--name-only", "--format=", "HEAD"])
        .output()
        .expect("git show");
    let names = String::from_utf8_lossy(&out.stdout);
    assert!(
        names.contains("src/lib.txt"),
        "the permitted change: {names}"
    );
    assert!(
        !names.contains("build/out.bin"),
        "an artifact outside the bounds must not be merged on the agent's behalf: {names}"
    );
    assert!(
        !names.contains("README.md"),
        "an out-of-bounds edit must not ride along: {names}"
    );
}

#[test]
fn out_of_bounds_work_is_left_in_the_worktree_not_destroyed() {
    let dir = repo("left");
    let tree = Worktree::create(&dir, "wrt_left").expect("worktree");
    std::fs::write(tree.path.join("src/lib.txt"), "fixed\n").expect("write");
    std::fs::write(tree.path.join("README.md"), "out of bounds\n").expect("write");

    tree.commit_all("fix", &globs(&["src/**"])).expect("commit");

    // Not committed -- and not reverted either. It stays where it can be inspected.
    let content = std::fs::read_to_string(tree.path.join("README.md")).expect("still there");
    assert_eq!(content, "out of bounds\n");
}

#[test]
fn nothing_inside_the_bounds_means_nothing_committed() {
    let dir = repo("empty");
    let tree = Worktree::create(&dir, "wrt_empty").expect("worktree");
    std::fs::write(tree.path.join("README.md"), "only out of bounds\n").expect("write");

    let committed = tree
        .commit_all("nothing", &globs(&["src/**"]))
        .expect("commit");
    assert_eq!(committed, 0, "no permitted path changed");
}

#[test]
fn a_warrant_permitting_no_writes_refuses_to_commit() {
    let dir = repo("nowrite");
    let tree = Worktree::create(&dir, "wrt_nowrite").expect("worktree");
    std::fs::write(tree.path.join("src/lib.txt"), "changed anyway\n").expect("write");

    let err = tree
        .commit_all("should refuse", &globs(&[]))
        .expect_err("a warrant with no write paths permits no commit");
    let text = err.to_string();
    assert!(
        text.contains("no write paths"),
        "the refusal must say why: {text}"
    );
}

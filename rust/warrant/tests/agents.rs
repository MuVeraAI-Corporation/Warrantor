//! `warrantor agents` through the real binary.
//!
//! The unit tests in `harness.rs` cover the splicers. What only a process can show is that the
//! command refuses before it writes: against a warrant that does not exist, against one that is
//! settled, and — the default that matters most — that a first invocation writes nothing at all.
//!
//! That last one is not fussiness. This command edits files an operator's *other* tools read, and
//! two of the harnesses in the registry keep those files per-user, shared across every project on
//! the machine. A command that edited one the first time it was typed is a command people run once
//! and then never trust again.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EXE: &str = env!("CARGO_BIN_EXE_warrantor");

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-agents-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(EXE)
        .args(args)
        .arg("--root")
        .arg(root)
        .output()
        .expect("run warrantor")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// A repository with one commit, which `grant` needs to cut a worktree from.
fn repo(tag: &str) -> PathBuf {
    let dir = tempdir(tag);
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("git");
    };
    git(&["init", "-q", "."]);
    git(&["config", "user.email", "t@example.invalid"]);
    git(&["config", "user.name", "t"]);
    std::fs::write(dir.join("a.txt"), "hi").expect("write");
    git(&["add", "-A"]);
    git(&["commit", "-qm", "init"]);
    dir
}

fn grant(root: &Path, repo: &Path, tools: &str) -> String {
    let output = run(
        root,
        &[
            "grant",
            "--goal",
            "wire a harness",
            "--tools",
            tools,
            "--write",
            "a.txt",
            "--repo",
            &repo.to_string_lossy(),
            "--deadline",
            "1h",
        ],
    );
    assert!(output.status.success(), "grant failed: {}", stderr(&output));
    stdout(&output)
        .lines()
        .find_map(|l| l.strip_prefix("warrant"))
        .map(|rest| rest.trim().to_string())
        .expect("grant prints the warrant id")
}

// ── the registry itself ───────────────────────────────────────────────────────────────

#[test]
fn list_states_what_is_not_mediated_rather_than_only_what_is() {
    // The whole reason this registry replaced a generator that wrote `CLAUDE.md` files saying
    // "every action is tracked". If this sentence ever disappears from the listing, the surface
    // has gone back to overstating itself.
    let root = tempdir("list");
    let output = run(&root, &["agents", "list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("do not speak MCP"), "{text}");
    assert!(text.contains("claude-code"), "{text}");
    assert!(text.contains("nothing to wire"), "{text}");
}

#[test]
fn show_names_the_specific_tools_that_escape_the_proxy() {
    let root = tempdir("show");
    let output = run(&root, &["agents", "show", "claude-code"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Not mediated"), "{text}");
    assert!(text.contains("Bash"), "{text}");
}

#[test]
fn a_harness_with_no_mcp_client_is_told_so_and_given_no_file() {
    let root = tempdir("aider");
    let work = repo("aider-repo");
    let id = grant(&root, &work, "selftest.echo");
    let output = run(
        &root,
        &[
            "agents",
            "wire",
            "aider",
            &id,
            "--repo",
            &work.to_string_lossy(),
            "--apply",
        ],
    );
    assert!(
        !output.status.success(),
        "wiring a harness with no MCP client must fail rather than write a decorative file"
    );
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(text.contains("no MCP client"), "{text}");
    // And nothing was written anywhere in the repository.
    for name in [".mcp.json", ".cursorrules", "CLAUDE.md", "AGENTS.md"] {
        assert!(
            !work.join(name).exists(),
            "{name} must not have been created"
        );
    }
}

// ── refusing before writing ───────────────────────────────────────────────────────────

#[test]
fn wiring_is_a_dry_run_until_apply_is_typed() {
    let root = tempdir("dry");
    let work = repo("dry-repo");
    let id = grant(&root, &work, "selftest.echo");
    let output = run(
        &root,
        &[
            "agents",
            "wire",
            "claude-code",
            &id,
            "--repo",
            &work.to_string_lossy(),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("DRY RUN"), "{}", stdout(&output));
    assert!(
        !work.join(".mcp.json").exists(),
        "a dry run must not create the file"
    );
}

#[test]
fn applying_writes_a_config_naming_the_warrant_and_the_store() {
    let root = tempdir("apply");
    let work = repo("apply-repo");
    let id = grant(&root, &work, "selftest.echo");
    let output = run(
        &root,
        &[
            "agents",
            "wire",
            "claude-code",
            &id,
            "--repo",
            &work.to_string_lossy(),
            "--apply",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let written = std::fs::read_to_string(work.join(".mcp.json")).expect("config written");
    let parsed: serde_json::Value = serde_json::from_str(&written).expect("valid json");
    let args = parsed["mcpServers"]["warrantor"]["args"]
        .as_array()
        .expect("args")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    assert!(args.contains(&id.as_str()), "{args:?}");
    assert!(args.contains(&"--root"), "{args:?}");
    // The store this session used, not whatever HOME the harness is later started with.
    assert!(
        args.iter().any(|a| Path::new(a) == root),
        "the generated config must address the store the warrant is actually in: {args:?}"
    );
}

#[test]
fn a_second_wiring_refuses_and_names_the_warrant_already_there() {
    let root = tempdir("twice");
    let work = repo("twice-repo");
    let first = grant(&root, &work, "selftest.echo");
    let second = grant(&root, &work, "selftest.echo");
    let wire = |id: &str, extra: &[&str]| {
        let mut args = vec!["agents", "wire", "claude-code", id, "--repo", "", "--apply"];
        let repo_path = work.to_string_lossy().to_string();
        args[5] = &repo_path;
        let mut all = args;
        all.extend_from_slice(extra);
        run(&root, &all)
    };
    assert!(wire(&first, &[]).status.success());
    let clash = wire(&second, &[]);
    assert!(!clash.status.success(), "a silent overwrite is the bug");
    let text = format!("{}{}", stdout(&clash), stderr(&clash));
    assert!(text.contains(&first), "it must name what is there: {text}");
    assert!(text.contains("--replace"), "{text}");
    assert!(wire(&second, &["--replace"]).status.success());
    let written = std::fs::read_to_string(work.join(".mcp.json")).expect("config");
    assert!(written.contains(&second));
    assert!(!written.contains(&first));
}

#[test]
fn wiring_against_a_warrant_that_does_not_exist_refuses_before_touching_anything() {
    let root = tempdir("missing");
    let work = repo("missing-repo");
    let output = run(
        &root,
        &[
            "agents",
            "wire",
            "claude-code",
            "wrt_deadbeefdeadbeef",
            "--repo",
            &work.to_string_lossy(),
            "--apply",
        ],
    );
    assert!(!output.status.success());
    assert!(
        !work.join(".mcp.json").exists(),
        "nothing may be written for a warrant that does not exist -- the agent's first tool call \
         would fail and read as Warrantor being broken"
    );
}

#[test]
fn wiring_against_a_settled_warrant_refuses() {
    let root = tempdir("settled");
    let work = repo("settled-repo");
    let id = grant(&root, &work, "selftest.echo");
    let voided = run(&root, &["void", &id]);
    assert!(voided.status.success(), "{}", stderr(&voided));

    let output = run(
        &root,
        &[
            "agents",
            "wire",
            "claude-code",
            &id,
            "--repo",
            &work.to_string_lossy(),
            "--apply",
        ],
    );
    assert!(!output.status.success());
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(text.contains("not Open"), "{text}");
    assert!(!work.join(".mcp.json").exists());
}

#[test]
fn an_unknown_harness_is_refused_with_a_pointer_to_the_list() {
    let root = tempdir("unknown");
    let output = run(&root, &["agents", "show", "not-a-harness"]);
    assert!(!output.status.success());
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(text.contains("agents list"), "{text}");
}

#[test]
fn a_manual_harness_prints_a_block_and_writes_nothing() {
    let root = tempdir("manual");
    let work = repo("manual-repo");
    let id = grant(&root, &work, "selftest.echo");
    let output = run(
        &root,
        &[
            "agents",
            "wire",
            "claude-desktop",
            &id,
            "--repo",
            &work.to_string_lossy(),
            "--apply",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("mcpServers"), "{text}");
    assert!(text.contains(&id), "{text}");
    assert!(
        text.contains("does not write it"),
        "it must say it did not write: {text}"
    );
}

#[test]
fn a_malformed_upstream_is_caught_while_writing_rather_than_at_the_agents_first_call() {
    let root = tempdir("badspec");
    let work = repo("badspec-repo");
    let id = grant(&root, &work, "selftest.echo");
    let output = run(
        &root,
        &[
            "agents",
            "wire",
            "claude-code",
            &id,
            "--repo",
            &work.to_string_lossy(),
            "--apply",
            "--upstream",
            "no-equals-sign",
        ],
    );
    assert!(!output.status.success());
    assert!(!work.join(".mcp.json").exists());
}

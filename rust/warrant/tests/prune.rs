//! The prune: the one deletion authority this build has, gated in code to the only classes it
//! can honestly delete.
//!
//! The properties that matter, each pinned here: the policy refuses to mean anything unless both
//! its halves say so; the plan ever considers only `NoIntegrityConsequence` classes, whatever the
//! config might be imagined to ask; apply deletes exactly the planned files; and the retention
//! line states the truth in all three policy states — none, in force, broken.

use std::path::{Path, PathBuf};

use warrantor_warrant::retention::{
    self, ArtifactClass, PrunePolicy, PRUNE_POLICY_FORMAT, RETENTION_STATEMENT,
};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-prune-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn policy(enabled: bool, window_seconds: u64) -> PrunePolicy {
    PrunePolicy {
        format: PRUNE_POLICY_FORMAT.to_string(),
        enabled,
        window_seconds,
    }
}

/// A file whose modification time is `age_seconds` before NOW — the only clock the prune reads.
fn file_old_by(root: &Path, class: ArtifactClass, name: &str, age_seconds: u64) -> PathBuf {
    let dir = class.path_under(root);
    std::fs::create_dir_all(&dir).expect("class dir");
    let path = dir.join(name);
    std::fs::write(&path, b"contents that nobody signed depends on").expect("write");
    let when = std::time::SystemTime::UNIX_EPOCH
        + std::time::Duration::from_secs(NOW.saturating_sub(age_seconds));
    std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("open")
        .set_modified(when)
        .expect("set mtime");
    path
}

// ── the policy ────────────────────────────────────────────────────────────────────────

/// An absent policy is `None` — no authority, and every caller says so. A policy that exists and
/// will not parse is an error naming the file; a future format is not guessed at.
#[test]
fn an_absent_policy_is_none_and_a_broken_one_is_an_error() {
    let fresh = tempdir("fresh");
    assert!(PrunePolicy::load(&fresh)
        .expect("absence is the normal state")
        .is_none());

    let root = tempdir("corrupt");
    std::fs::write(PrunePolicy::path(&root), b"{ not a policy").expect("write");
    let error = PrunePolicy::load(&root).expect_err("refused");
    assert!(error.contains("cannot be read"), "{error}");

    std::fs::write(
        PrunePolicy::path(&root),
        "{\"format\":\"warrantor.retention/2\",\"enabled\":true,\"window_seconds\":1}",
    )
    .expect("write");
    let error = PrunePolicy::load(&root).expect_err("refused");
    assert!(
        error.contains("retention/2") && error.contains("Nothing is guessed"),
        "{error}"
    );
}

/// Deleting anything requires BOTH halves — enabled, and a non-zero window. Either alone is a
/// recorded decision that enforces nothing, mirroring the archive's `retention_policy` exactly.
#[test]
fn deleting_anything_requires_both_halves() {
    assert!(policy(true, 86_400).deletes_anything());
    assert!(!policy(false, 86_400).deletes_anything());
    assert!(!policy(true, 0).deletes_anything());
    assert!(!policy(false, 0).deletes_anything());
}

// ── the gate and the plan ─────────────────────────────────────────────────────────────

/// The plan only ever considers NoIntegrityConsequence classes, whatever exists on disk: files
/// from a verdict-deciding class and an evidence class sit beside the old log and the plan
/// refuses them all, by name, with the deletion effect as the reason. The gate is in the code —
/// there is no config to ask it otherwise, on purpose.
#[test]
fn the_plan_only_ever_considers_no_consequence_classes() {
    let root = tempdir("gate");
    let old_log = file_old_by(&root, ArtifactClass::Logs, "wrt_a.log", 90 * 86_400);
    let _old_warrant = file_old_by(&root, ArtifactClass::Warrants, "wrt_b.json", 90 * 86_400);
    let _old_staged = file_old_by(&root, ArtifactClass::Staged, "wrt_c.jsonl", 90 * 86_400);

    let report = retention::plan_prune(&root, &policy(true, 86_400), NOW).expect("plan");

    let logs = report
        .classes
        .iter()
        .find(|entry| entry.class == ArtifactClass::Logs)
        .expect("logs are planned");
    assert_eq!(
        logs.files,
        vec![old_log],
        "the old log, and only the old log"
    );
    assert!(logs.refused.is_none());

    for (class, word) in [
        (ArtifactClass::Warrants, "FLIPS-VERDICT"),
        (ArtifactClass::Staged, "LOSES-EVIDENCE"),
    ] {
        let entry = report
            .classes
            .iter()
            .find(|entry| entry.class == class)
            .expect("every class appears in the report");
        assert!(
            entry.files.is_empty() && entry.refused.is_some(),
            "{word} classes are refused, never planned: {:?}",
            entry.refused
        );
    }
    assert!(
        report
            .classes
            .iter()
            .filter(|entry| entry.refused.is_some())
            .count()
            >= 10,
        "every non-prunable class carries its refusal — an operator reads what is NOT going"
    );
}

/// A file younger than the window is not planned, even in the one prunable class.
#[test]
fn a_file_younger_than_the_window_stays() {
    let root = tempdir("young");
    file_old_by(&root, ArtifactClass::Logs, "young.log", 10);
    let policy = policy(true, 86_400);

    let report = retention::plan_prune(&root, &policy, NOW).expect("plan");

    let logs = report
        .classes
        .iter()
        .find(|entry| entry.class == ArtifactClass::Logs)
        .expect("logs");
    assert!(
        logs.files.is_empty(),
        "10 seconds old against a 1-day window stays"
    );
}

// ── apply ─────────────────────────────────────────────────────────────────────────────

/// Apply deletes exactly the planned files — the old log goes, the young log stays, and a
/// verdict-deciding class is untouched even though its file is old enough that a wider gate
/// would have taken it.
#[test]
fn apply_deletes_exactly_the_planned_files() {
    let root = tempdir("apply");
    let old = file_old_by(&root, ArtifactClass::Logs, "old.log", 90 * 86_400);
    let young = file_old_by(&root, ArtifactClass::Logs, "young.log", 10);
    let warrant = file_old_by(&root, ArtifactClass::Warrants, "wrt_keep.json", 90 * 86_400);
    let policy = policy(true, 86_400);

    let report = retention::plan_prune(&root, &policy, NOW).expect("plan");
    let removed = retention::apply_prune(&report).expect("nothing refuses removal");

    assert_eq!(removed, 1);
    assert!(!old.exists(), "the planned file is gone");
    assert!(young.exists(), "the young file stays");
    assert!(
        warrant.exists(),
        "and a FLIPS-VERDICT class is untouched by a gate that refuses it"
    );
}

// ── the retention line, in all three states ───────────────────────────────────────────

/// The line an operator reads under the inventory must state the truth in every state: no policy
/// — the old sentence, still true; a policy in force — the window for prunable classes, "never"
/// for everything else; a broken policy — a BROKEN line, because a window that enforces nothing
/// while looking like one is the exact lie this exists to prevent.
#[test]
fn the_retention_line_states_the_truth_in_all_three_states() {
    // No policy: every class carries the no-authority statement.
    assert_eq!(
        retention::retention_line(ArtifactClass::Logs, None, None),
        RETENTION_STATEMENT
    );
    assert_eq!(
        retention::retention_line(ArtifactClass::Warrants, None, None),
        RETENTION_STATEMENT
    );

    // A policy in force: prunable classes state the window and the command; everything else says
    // never, with the effect.
    let in_force = policy(true, 30 * 86_400);
    let logs_line = retention::retention_line(ArtifactClass::Logs, Some(&in_force), None);
    assert!(
        logs_line.contains("warrantor prune --apply") && logs_line.contains("30d"),
        "{logs_line}"
    );
    let warrants_line = retention::retention_line(ArtifactClass::Warrants, Some(&in_force), None);
    assert!(
        warrants_line.contains("never removed by warrantor")
            && warrants_line.contains("flips-verdict"),
        "{warrants_line}"
    );

    // A policy that deletes nothing states the old sentence, for every class.
    let inert = policy(true, 0);
    assert_eq!(
        retention::retention_line(ArtifactClass::Logs, Some(&inert), None),
        RETENTION_STATEMENT
    );

    // A broken policy is said to be broken, on every class.
    let broken = retention::retention_line(ArtifactClass::Logs, None, Some("not json"));
    assert!(
        broken.contains("BROKEN") && broken.contains("not json"),
        "{broken}"
    );
}

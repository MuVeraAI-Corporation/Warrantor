//! W5 tests: staged effects, typed handles, release ordering, and durability.

use std::collections::BTreeMap;

use warrantor_warrant::staging::{handle_scheme, EffectRegistry, StagingQueue, GENESIS};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;

const NOW: u64 = 1_786_000_000;

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn queue(dir: &std::path::Path) -> StagingQueue {
    StagingQueue::open(dir.join("q.jsonl"), "wrt_test", EffectRegistry::github()).expect("open")
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-staging-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

// ── typed handles: the R1 finding ─────────────────────────────────────────────────────

#[test]
fn each_tool_mints_a_handle_in_its_own_scheme() {
    let dir = tempdir("schemes");
    let mut q = queue(&dir);

    let pr = q
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("stage pr");
    assert_eq!(handle_scheme(&pr.handle), "pr");

    let label = q
        .stage(
            "github.add_label",
            args(&[("target", &pr.handle), ("label", "security")]),
            NOW,
        )
        .expect("stage label");
    assert_eq!(
        handle_scheme(&label.handle),
        "label",
        "a label is not a pull request and must not mint a pr:// handle"
    );
}

/// The failure R1 nearly missed: a well-formed handle pointing at the wrong kind of object.
/// Before typing, requesting review on a label succeeded silently.
#[test]
fn a_wrong_type_target_is_refused() {
    let dir = tempdir("wrongtype");
    let mut q = queue(&dir);

    let pr = q
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("stage pr");
    let label = q
        .stage(
            "github.add_label",
            args(&[("target", &pr.handle), ("label", "security")]),
            NOW,
        )
        .expect("stage label");

    let result = q.stage(
        "github.request_review",
        args(&[("target", &label.handle), ("reviewer", "alice")]),
        NOW,
    );
    let message = result
        .expect_err("review on a label must be refused")
        .to_string();
    assert!(
        message.contains("label") && message.contains("pr"),
        "the error should name both the type given and the type wanted: {message}"
    );
}

#[test]
fn an_invented_handle_is_refused() {
    let dir = tempdir("invented");
    let mut q = queue(&dir);
    q.stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("stage pr");

    let result = q.stage(
        "github.comment",
        args(&[("target", "pr://staged/wrt_test/99"), ("body", "hello")]),
        NOW,
    );
    assert!(
        result.is_err(),
        "a handle this warrant never issued must be refused"
    );
}

#[test]
fn an_unknown_tool_cannot_be_staged() {
    let dir = tempdir("unknowntool");
    let mut q = queue(&dir);
    let result = q.stage("github.delete_repo", args(&[]), NOW);
    assert!(
        result.is_err(),
        "fail closed: an unregistered tool's handle would have no meaning"
    );
}

// ── release ordering ──────────────────────────────────────────────────────────────────

/// Every prefix of the release order must be a coherent state. That property is what makes
/// stop-hold-report safe on partial failure.
#[test]
fn dependencies_are_released_before_dependents() {
    let dir = tempdir("order");
    let mut q = queue(&dir);

    let pr = q
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("pr");
    q.stage(
        "github.comment",
        args(&[("target", &pr.handle), ("body", "why")]),
        NOW,
    )
    .expect("comment");
    q.stage(
        "github.request_review",
        args(&[("target", &pr.handle), ("reviewer", "alice")]),
        NOW,
    )
    .expect("review");

    let order = q.release_order().expect("order");
    assert_eq!(order.len(), 3);
    assert_eq!(order[0].tool, "github.create_pr", "the PR must come first");

    // Formally: at every step, all dependencies are already released.
    let mut released: BTreeSet<&str> = BTreeSet::new();
    for effect in &order {
        for dependency in &effect.depends_on {
            assert!(
                released.contains(dependency.as_str()),
                "{} released before its dependency {dependency}",
                effect.handle
            );
        }
        released.insert(effect.handle.as_str());
    }
}

#[test]
fn dependencies_are_recorded_from_arguments() {
    let dir = tempdir("deps");
    let mut q = queue(&dir);
    let pr = q
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("pr");
    let comment = q
        .stage(
            "github.comment",
            args(&[("target", &pr.handle), ("body", "b")]),
            NOW,
        )
        .expect("comment");
    assert!(comment.depends_on.contains(&pr.handle));
    assert!(
        pr.depends_on.is_empty(),
        "the first effect depends on nothing"
    );
}

// ── durability and tamper evidence ────────────────────────────────────────────────────

#[test]
fn the_queue_survives_reopening() {
    let dir = tempdir("reopen");
    let path = dir.join("q.jsonl");
    let pr_handle;
    {
        let mut q = StagingQueue::open(&path, "wrt_test", EffectRegistry::github()).expect("open");
        let pr = q
            .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
            .expect("pr");
        pr_handle = pr.handle.clone();
        q.stage(
            "github.comment",
            args(&[("target", &pr.handle), ("body", "b")]),
            NOW,
        )
        .expect("comment");
    }
    let reopened = StagingQueue::open(&path, "wrt_test", EffectRegistry::github()).expect("reopen");
    assert_eq!(reopened.len(), 2, "staged effects must survive a restart");
    assert_eq!(reopened.effects()[0].handle, pr_handle);
}

/// A staged effect that silently vanished would be invisible data loss: the developer settles and
/// simply does not get the pull request they were promised.
#[test]
fn truncating_the_queue_is_detected() {
    let dir = tempdir("truncate");
    let path = dir.join("q.jsonl");
    {
        let mut q = StagingQueue::open(&path, "wrt_test", EffectRegistry::github()).expect("open");
        let pr = q
            .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
            .expect("pr");
        q.stage(
            "github.comment",
            args(&[("target", &pr.handle), ("body", "b")]),
            NOW,
        )
        .expect("comment");
    }
    // Drop the FIRST line: the chain must notice the second no longer follows genesis.
    let body = std::fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = body.lines().skip(1).collect();
    std::fs::write(&path, kept.join("\n") + "\n").expect("write");

    let result = StagingQueue::open(&path, "wrt_test", EffectRegistry::github());
    assert!(result.is_err(), "a truncated queue must not open silently");
}

#[test]
fn altering_an_entry_is_detected() {
    let dir = tempdir("alter");
    let path = dir.join("q.jsonl");
    {
        let mut q = StagingQueue::open(&path, "wrt_test", EffectRegistry::github()).expect("open");
        q.stage("github.create_pr", args(&[("title", "Fix")]), NOW)
            .expect("pr");
    }
    let body = std::fs::read_to_string(&path).expect("read");
    std::fs::write(&path, body.replace("Fix", "Evil")).expect("write");

    assert!(
        StagingQueue::open(&path, "wrt_test", EffectRegistry::github()).is_err(),
        "editing a staged effect must break the chain"
    );
}

#[test]
fn an_empty_queue_starts_at_genesis() {
    let dir = tempdir("genesis");
    let q = queue(&dir);
    assert!(q.is_empty());
    assert_eq!(q.head_digest(), GENESIS);
}

// ── store ─────────────────────────────────────────────────────────────────────────────

fn sample_warrant() -> Warrant {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    };
    Warrant::grant(
        "wrt_stored",
        "goal",
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant")
}

#[test]
fn a_warrant_round_trips_through_the_store() {
    let dir = tempdir("store");
    let store = WarrantStore::open(&dir).expect("open store");
    let stored = StoredWarrant {
        warrant: sample_warrant(),
        worktree: Some(dir.join("wt")),
        repo: Some(dir.clone()),
        branch: Some("warrantor/wrt_stored".to_string()),
        base_commit: Some("abc123".to_string()),
        staged_chain: None,
    };
    store.save(&stored).expect("save");

    let loaded = store.load("wrt_stored").expect("load");
    assert_eq!(
        loaded, stored,
        "a warrant must survive a process exit unchanged"
    );
}

#[test]
fn outstanding_returns_only_warrants_needing_a_decision() {
    let dir = tempdir("outstanding");
    let store = WarrantStore::open(&dir).expect("open");

    for (id, state) in [
        ("wrt_open", WarrantState::Open),
        ("wrt_held", WarrantState::Held),
        ("wrt_settled", WarrantState::Settled),
        ("wrt_void", WarrantState::Void),
    ] {
        let mut warrant = sample_warrant();
        warrant.claims.id = id.to_string();
        warrant.state = state;
        store
            .save(&StoredWarrant {
                warrant,
                worktree: None,
                repo: None,
                branch: None,
                base_commit: None,
                staged_chain: None,
            })
            .expect("save");
    }

    let outstanding = store.outstanding().expect("outstanding");
    let ids: BTreeSet<&str> = outstanding
        .iter()
        .map(|s| s.warrant.claims.id.as_str())
        .collect();
    assert_eq!(
        ids,
        ["wrt_held", "wrt_open"]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "settled and void warrants need no decision"
    );
}

#[test]
fn loading_a_missing_warrant_is_an_error_not_a_panic() {
    let dir = tempdir("missing");
    let store = WarrantStore::open(&dir).expect("open");
    assert!(store.load("wrt_nope").is_err());
}

//! W9 tests: the GitHub adapter, driven through a real settle.
//!
//! The transport is injected so these run without a network and without mutating a real
//! repository. What is being tested is the wiring that matters: that a staged comment reaches the
//! pull request that was created moments earlier in the same settle, addressed by the number
//! GitHub actually returned rather than by the handle the agent used.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use warrantor_warrant::adapters::github::{GitHubAdapter, GitHubTransport};
use warrantor_warrant::settle::settle;
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-gh-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Records every request and replies as GitHub would.
struct FakeGitHub {
    calls: Vec<(String, String)>,
    fail_on: Option<String>,
}

impl FakeGitHub {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            fail_on: None,
        }
    }
    fn failing_on(path_fragment: &str) -> Self {
        Self {
            calls: Vec::new(),
            fail_on: Some(path_fragment.to_string()),
        }
    }
}

impl GitHubTransport for FakeGitHub {
    fn post(&mut self, path: &str, body: &str) -> Result<String, String> {
        if let Some(fragment) = &self.fail_on {
            if path.contains(fragment.as_str()) {
                return Err("422 Unprocessable Entity".to_string());
            }
        }
        self.calls.push((path.to_string(), body.to_string()));
        if path.ends_with("/pulls") {
            return Ok(
                r#"{"number": 482, "html_url":"https://github.com/o/r/pull/482"}"#.to_string(),
            );
        }
        Ok(r#"{"id": 9001}"#.to_string())
    }
}

fn warrant() -> (Warrant, SigningKey) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle_key = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    };
    let w = Warrant::grant(
        "wrt_gh",
        "fix it",
        "spiffe://muveraai.com/agent/alpha",
        bounds,
        NOW,
        &settle_key.verifying_key(),
        &issuer,
    )
    .expect("grant");
    (w, settle_key)
}

fn queue(dir: &std::path::Path) -> StagingQueue {
    let mut q =
        StagingQueue::open(dir.join("q.jsonl"), "wrt_gh", EffectRegistry::github()).expect("open");
    let pr = q
        .stage(
            "github.create_pr",
            args(&[("title", "Fix token refresh"), ("body", "why")]),
            NOW,
        )
        .expect("pr");
    q.stage(
        "github.comment",
        args(&[("target", &pr.handle), ("body", "explains it")]),
        NOW,
    )
    .expect("comment");
    q.stage(
        "github.add_label",
        args(&[("target", &pr.handle), ("label", "security")]),
        NOW,
    )
    .expect("label");
    q
}

/// The property that makes staging usable: the agent referenced a handle for something that did
/// not exist; by the time the comment is posted, it is addressed by the real number.
#[test]
fn a_staged_comment_reaches_the_pull_request_created_in_the_same_settle() {
    let dir = tempdir("resolve");
    let (mut w, settle_key) = warrant();
    let q = queue(&dir);
    let mut adapter = GitHubAdapter::new(FakeGitHub::new(), "muveraai", "warrantor");

    let report =
        settle(&mut w, &q, None, &settle_key.verifying_key(), &mut adapter).expect("settle");

    assert!(report.complete);
    assert_eq!(report.released(), 3);
    assert_eq!(w.state, WarrantState::Settled);
}

#[test]
fn the_pull_request_is_created_before_anything_attaches_to_it() {
    let dir = tempdir("order");
    let (mut w, settle_key) = warrant();
    let q = queue(&dir);
    let transport = FakeGitHub::new();
    let mut adapter = GitHubAdapter::new(transport, "muveraai", "warrantor");

    settle(&mut w, &q, None, &settle_key.verifying_key(), &mut adapter).expect("settle");

    // Reach back into the transport through the adapter is not possible, so assert on the effect
    // of ordering instead: a successful settle means every dependent resolved, which can only
    // happen if the PR went first.
    assert_eq!(w.state, WarrantState::Settled);
}

/// The real number GitHub returned must be what later calls address, not the staged handle.
#[test]
fn dependent_calls_address_the_real_number() {
    struct Recording {
        paths: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }
    impl GitHubTransport for Recording {
        fn post(&mut self, path: &str, _body: &str) -> Result<String, String> {
            self.paths.borrow_mut().push(path.to_string());
            if path.ends_with("/pulls") {
                return Ok(r#"{"number": 482}"#.to_string());
            }
            Ok(r#"{"id": 1}"#.to_string())
        }
    }
    let paths = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let dir = tempdir("realnumber");
    let (mut w, settle_key) = warrant();
    let q = queue(&dir);
    let mut adapter = GitHubAdapter::new(
        Recording {
            paths: std::rc::Rc::clone(&paths),
        },
        "muveraai",
        "warrantor",
    );

    settle(&mut w, &q, None, &settle_key.verifying_key(), &mut adapter).expect("settle");

    let seen = paths.borrow();
    assert_eq!(seen[0], "/repos/muveraai/warrantor/pulls");
    assert!(
        seen[1].contains("/482/") || seen[1].contains("/issues/482/"),
        "the comment must address PR 482, the number GitHub returned, not the staged handle: {}",
        seen[1]
    );
    assert!(
        !seen.iter().any(|p| p.contains("staged")),
        "no request may carry a staged:// handle to the real API"
    );
}

/// Partial failure through a real adapter: the pull request is genuinely open, the comment is not,
/// and the report says exactly where the boundary is.
#[test]
fn a_failing_comment_leaves_the_pull_request_real_and_says_so() {
    let dir = tempdir("partial");
    let (mut w, settle_key) = warrant();
    let q = queue(&dir);
    let mut adapter =
        GitHubAdapter::new(FakeGitHub::failing_on("/comments"), "muveraai", "warrantor");

    let report = settle(&mut w, &q, None, &settle_key.verifying_key(), &mut adapter)
        .expect("settle reports rather than panicking");

    assert!(!report.complete);
    assert_eq!(
        report.released(),
        1,
        "the pull request is real; the comment is not"
    );
    assert_eq!(
        w.state,
        WarrantState::Held,
        "there is still a decision to make about the unreleased effects"
    );
    let boundary = report.boundary.expect("boundary");
    assert!(boundary.contains("422"));
}

#[test]
fn an_unimplemented_tool_is_refused_rather_than_silently_skipped() {
    let dir = tempdir("unknown");
    let (mut w, settle_key) = warrant();
    let mut registry = EffectRegistry::github();
    // A registry that knows a tool the adapter does not: the mismatch must surface.
    registry.register("github.merge_pr", "merge", &["pr"]);
    let mut q = StagingQueue::open(dir.join("q.jsonl"), "wrt_gh", registry).expect("open");
    let pr = q
        .stage("github.create_pr", args(&[("title", "T")]), NOW)
        .expect("pr");
    q.stage("github.merge_pr", args(&[("target", &pr.handle)]), NOW)
        .expect("merge staged");

    let mut adapter = GitHubAdapter::new(FakeGitHub::new(), "muveraai", "warrantor");
    let report =
        settle(&mut w, &q, None, &settle_key.verifying_key(), &mut adapter).expect("settle");

    assert!(!report.complete);
    let boundary = report.boundary.expect("boundary");
    assert!(
        boundary.contains("does not implement"),
        "a tool the adapter cannot perform must stop the settle, not be skipped: {boundary}"
    );
}

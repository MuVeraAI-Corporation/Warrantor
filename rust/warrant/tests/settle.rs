//! W6 tests: settle, void, partial failure, and who is allowed to do any of it.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use warrantor_warrant::settle::{settle, void, void_on_breach, EffectOutcome, EffectPerformer};
use warrantor_warrant::staging::{EffectRegistry, StagedEffect, StagingQueue};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantError, WarrantState};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-settle-{tag}-{}",
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

fn warrant() -> (Warrant, SigningKey, SigningKey) {
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
        "wrt_settle",
        "fix the bug",
        "spiffe://muveraai.com/agent/alpha",
        bounds,
        NOW,
        &settle_key.verifying_key(),
        &issuer,
    )
    .expect("grant");
    (w, issuer, settle_key)
}

/// Performs effects, optionally failing at a chosen index.
struct Performer {
    fail_at: Option<usize>,
    performed: Vec<String>,
    resolutions_seen: Vec<BTreeMap<String, String>>,
}

impl Performer {
    fn new() -> Self {
        Self {
            fail_at: None,
            performed: Vec::new(),
            resolutions_seen: Vec::new(),
        }
    }
    fn failing_at(index: usize) -> Self {
        Self {
            fail_at: Some(index),
            performed: Vec::new(),
            resolutions_seen: Vec::new(),
        }
    }
}

impl EffectPerformer for Performer {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        self.resolutions_seen.push(resolved.clone());
        if self.fail_at == Some(self.performed.len()) {
            return Err("upstream returned 503".to_string());
        }
        self.performed.push(effect.handle.clone());
        Ok(format!("real-{}", effect.index))
    }
}

fn queue_with_three(dir: &std::path::Path) -> StagingQueue {
    let mut q = StagingQueue::open(dir.join("q.jsonl"), "wrt_settle", EffectRegistry::github())
        .expect("open");
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
    q
}

// ── authority ─────────────────────────────────────────────────────────────────────────

/// The whole design rests on this. If the agent could settle, staging would be decoration.
#[test]
fn the_agent_cannot_settle_and_nothing_is_released() {
    let dir = tempdir("agent-settle");
    let (mut w, _issuer, _settle_key) = warrant();
    let q = queue_with_three(&dir);
    let agent = SigningKey::from_bytes(&[9; 32]);
    let mut performer = Performer::new();

    let result = settle(&mut w, &q, None, &agent.verifying_key(), &mut performer);

    assert_eq!(result.unwrap_err(), WarrantError::NotSettleAuthority);
    assert!(
        performer.performed.is_empty(),
        "authority is checked BEFORE anything is released"
    );
    assert_eq!(
        w.state,
        WarrantState::Open,
        "a refused settle changes nothing"
    );
}

#[test]
fn the_agent_cannot_void_either() {
    let (mut w, _issuer, _settle_key) = warrant();
    let agent = SigningKey::from_bytes(&[9; 32]);
    assert_eq!(
        void(&mut w, None, &agent.verifying_key()).unwrap_err(),
        WarrantError::NotSettleAuthority
    );
    assert_eq!(w.state, WarrantState::Open);
}

// ── the happy path ────────────────────────────────────────────────────────────────────

#[test]
fn settling_releases_every_effect_in_dependency_order() {
    let dir = tempdir("happy");
    let (mut w, _issuer, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let mut performer = Performer::new();

    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    )
    .expect("settle");

    assert!(report.complete);
    assert_eq!(report.released(), 3);
    assert!(report.boundary.is_none());
    assert_eq!(w.state, WarrantState::Settled);
    assert!(
        performer.performed[0].starts_with("pr://"),
        "the pull request must be released before the things that attach to it"
    );
}

/// A comment must attach to the pull request that now genuinely exists, so the performer needs the
/// real id the earlier release produced.
#[test]
fn dependent_effects_receive_the_resolved_real_id() {
    let dir = tempdir("resolve");
    let (mut w, _issuer, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let mut performer = Performer::new();

    settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    )
    .expect("settle");

    let second = &performer.resolutions_seen[1];
    assert!(
        second.values().any(|v| v == "real-1"),
        "the second effect must see the first effect's real id, got {second:?}"
    );
}

// ── partial failure: stop, hold, report ───────────────────────────────────────────────

/// Effect 2 of 3 fails. One thing is real, two are not, and the report must say exactly that.
#[test]
fn a_partial_settle_stops_holds_and_reports_the_boundary() {
    let dir = tempdir("partial");
    let (mut w, _issuer, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let mut performer = Performer::failing_at(1);

    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    )
    .expect("settle returns a report even when it stops");

    assert!(!report.complete);
    assert_eq!(report.released(), 1, "only the first effect is real");

    assert!(matches!(report.effects[0], EffectOutcome::Released { .. }));
    assert!(matches!(report.effects[1], EffectOutcome::Failed { .. }));
    assert!(
        matches!(report.effects[2], EffectOutcome::Unreleased { .. }),
        "effects after the failure must not be attempted"
    );

    let boundary = report.boundary.expect("a boundary must be stated");
    assert!(
        boundary.contains("503"),
        "the reason must reach the developer"
    );
    assert!(boundary.contains("were not attempted"));

    assert_eq!(
        w.state,
        WarrantState::Held,
        "a partial settle is not terminal: there is still a decision to make"
    );
}

/// No compensation is attempted. Undoing is itself fallible and could leave a worse state.
#[test]
fn a_partial_settle_does_not_try_to_undo_what_succeeded() {
    let dir = tempdir("nocompensate");
    let (mut w, _issuer, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let mut performer = Performer::failing_at(1);

    settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    )
    .expect("settle");

    assert_eq!(
        performer.performed.len(),
        1,
        "exactly one effect performed; no undo calls were made"
    );
}

/// A held warrant can still be resolved: the deadline passing is not misbehaviour.
#[test]
fn a_held_warrant_can_be_settled_later() {
    let dir = tempdir("held-then-settle");
    let (mut w, _issuer, settle_key) = warrant();
    let q = queue_with_three(&dir);

    let mut failing = Performer::failing_at(1);
    settle(&mut w, &q, None, &settle_key.verifying_key(), &mut failing).expect("first");
    assert_eq!(w.state, WarrantState::Held);

    // The transient failure clears; settle again.
    let mut retry = Performer::new();
    let report = settle(&mut w, &q, None, &settle_key.verifying_key(), &mut retry).expect("second");
    assert!(report.complete);
    assert_eq!(w.state, WarrantState::Settled);
}

#[test]
fn a_settled_warrant_cannot_be_settled_again() {
    let dir = tempdir("double");
    let (mut w, _issuer, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let mut performer = Performer::new();

    settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    )
    .expect("first");
    let second = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    );
    assert!(matches!(second, Err(WarrantError::WrongState { .. })));
}

// ── void ──────────────────────────────────────────────────────────────────────────────

#[test]
fn voiding_discards_without_releasing_anything() {
    let dir = tempdir("void");
    let (mut w, _issuer, settle_key) = warrant();
    let _q = queue_with_three(&dir);

    void(&mut w, None, &settle_key.verifying_key()).expect("void");
    assert_eq!(w.state, WarrantState::Void);
}

/// A breach happens at 3am with nobody present to sign. Requiring the settle key would leave a
/// breached warrant open until morning with its staged effects intact.
#[test]
fn a_breach_voids_without_the_settle_key() {
    let (mut w, _issuer, _settle_key) = warrant();
    let note = void_on_breach(&mut w, None, "secret exposure detected: AWS Access Key")
        .expect("breach void");

    assert_eq!(w.state, WarrantState::Void);
    assert!(note.contains("secret exposure"));
    assert!(
        note.contains("receipts retained"),
        "what the agent attempted is evidence and must survive the void"
    );
}

#[test]
fn a_breach_cannot_void_an_already_settled_warrant() {
    let dir = tempdir("breach-settled");
    let (mut w, _issuer, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let mut performer = Performer::new();
    settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    )
    .expect("settle");

    assert!(matches!(
        void_on_breach(&mut w, None, "too late"),
        Err(WarrantError::WrongState { .. })
    ));
}

#[test]
fn settling_an_empty_warrant_is_legal() {
    let dir = tempdir("empty");
    let (mut w, _issuer, settle_key) = warrant();
    let q = StagingQueue::open(dir.join("q.jsonl"), "wrt_settle", EffectRegistry::github())
        .expect("open");
    let mut performer = Performer::new();

    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
    )
    .expect("an agent that staged nothing still settles");
    assert!(report.complete);
    assert_eq!(report.released(), 0);
    assert_eq!(w.state, WarrantState::Settled);
}

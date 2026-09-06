//! L4-07: every staged effect is evidenced before it is performed, and performed at most once.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use warrantor_evidence::{verify_chain, Phase, WarReceipt};
use warrantor_warrant::settle::{settle, CommitGate, EffectOutcome, EffectPerformer};
use warrantor_warrant::staging::{
    idempotency_key, EffectRegistry, FileRecorder, Recorder, RecorderAck, StagedEffect,
    StagingQueue, STAGED_RECEIPT_FORMAT,
};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-2pc-{tag}-{}",
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

fn warrant() -> (Warrant, SigningKey) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle_key = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    };
    let w = Warrant::grant(
        "wrt_2pc",
        "open the fix",
        "spiffe://muveraai.com/agent/alpha",
        bounds,
        NOW,
        &settle_key.verifying_key(),
        &issuer,
    )
    .expect("grant");
    (w, settle_key)
}

fn queue_with_three(dir: &std::path::Path) -> StagingQueue {
    let mut q =
        StagingQueue::open(dir.join("q.jsonl"), "wrt_2pc", EffectRegistry::github()).expect("open");
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
        "github.add_label",
        args(&[("target", &pr.handle), ("label", "bug")]),
        NOW,
    )
    .expect("label");
    q
}

#[test]
fn the_idempotency_key_is_stable_across_reopen_and_distinct_per_effect() {
    let dir = tempdir("key");
    let q = queue_with_three(&dir);
    let first: Vec<String> = q
        .effects()
        .iter()
        .map(|e| idempotency_key("wrt_2pc", e))
        .collect();
    let reopened = StagingQueue::open(dir.join("q.jsonl"), "wrt_2pc", EffectRegistry::github())
        .expect("reopen");
    let second: Vec<String> = reopened
        .effects()
        .iter()
        .map(|e| idempotency_key("wrt_2pc", e))
        .collect();
    assert_eq!(first, second, "the key must survive a process restart");
    assert_eq!(
        first.iter().collect::<BTreeSet<_>>().len(),
        3,
        "one key per effect"
    );
    assert_eq!(first[0].len(), 64);
    assert_ne!(
        idempotency_key("wrt_other", &q.effects()[0]),
        first[0],
        "the same effect under another warrant is another effect"
    );
}

fn receipt_for(tag: &str, phase: Phase) -> WarReceipt {
    // A real receipt is built by settle; here the recorder is tested on its own, so the
    // predicate is produced by the same builder settle uses.
    let (w, settle_key) = warrant();
    let dir = tempdir(tag);
    let q = queue_with_three(&dir);
    let effect = &q.effects()[0];
    let predicate = warrantor_warrant::settle::staged_predicate(
        &w,
        effect,
        "mutate",
        &idempotency_key("wrt_2pc", effect),
        NOW,
    )
    .expect("predicate");
    let pre = warrantor_evidence::issue_pre_commit(predicate, &settle_key, "settle");
    match phase {
        Phase::PreCommit => pre,
        _ => warrantor_evidence::issue_post_commit(
            &pre,
            warrantor_evidence::Outcome {
                status: "performed".to_string(),
                outcome_digest: "sha256:0".to_string(),
                effects: vec!["real-1".to_string()],
                error: None,
                rollback_pointer: None,
            },
            &settle_key,
            "settle",
        ),
    }
}

#[test]
fn the_file_recorder_sequences_and_survives_reopen() {
    let dir = tempdir("recorder");
    let path = dir.join("receipts.jsonl");
    let mut recorder = FileRecorder::open(&path).expect("open");
    let RecorderAck { sequence: s1 } = recorder
        .record("k1", &receipt_for("r1", Phase::PreCommit))
        .expect("pre");
    assert_eq!(s1, 1);
    assert!(
        recorder.unresolved("k1"),
        "a pre-commit with no post-commit is in flight"
    );
    assert_eq!(recorder.performed("k1"), None);

    let RecorderAck { sequence: s2 } = recorder
        .record("k1", &receipt_for("r2", Phase::PostCommit))
        .expect("post");
    assert_eq!(s2, 2, "the recorder's clock only moves forward");
    assert!(!recorder.unresolved("k1"));
    assert_eq!(recorder.performed("k1").as_deref(), Some("real-1"));

    let reopened = FileRecorder::open(&path).expect("reopen");
    assert_eq!(reopened.records().len(), 2);
    assert_eq!(reopened.records()[0].format, STAGED_RECEIPT_FORMAT);
    assert_eq!(reopened.performed("k1").as_deref(), Some("real-1"));
    let line = std::fs::read_to_string(&path).expect("read");
    assert_eq!(line.lines().count(), 2, "one line per receipt, append-only");
}

/// Records events from the recorder and the performer into one log, so ordering is testable.
struct Witnessed {
    inner: FileRecorder,
    fail_pre_commit_at: Option<usize>,
    fail_post_commits: bool,
    pre_commits: usize,
    events: Rc<RefCell<Vec<String>>>,
}

impl Recorder for Witnessed {
    fn record(&mut self, key: &str, receipt: &WarReceipt) -> Result<RecorderAck, String> {
        let phase = receipt.predicate.binding.phase;
        if phase == Phase::PreCommit {
            if self.fail_pre_commit_at == Some(self.pre_commits) {
                return Err("recorder unreachable".to_string());
            }
            self.pre_commits += 1;
        } else if self.fail_post_commits {
            return Err("recorder unreachable".to_string());
        }
        let ack = self.inner.record(key, receipt)?;
        self.events
            .borrow_mut()
            .push(format!("recorded:{phase:?}:{}", &key[..8]));
        Ok(ack)
    }
    fn performed(&self, key: &str) -> Option<String> {
        self.inner.performed(key)
    }
    fn unresolved(&self, key: &str) -> bool {
        self.inner.unresolved(key)
    }
}

struct Performer {
    prefix: &'static str,
    fail_at: Option<usize>,
    performed: Vec<String>,
    events: Rc<RefCell<Vec<String>>>,
}

impl EffectPerformer for Performer {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        _resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        if self.fail_at == Some(self.performed.len()) {
            return Err("upstream returned 503".to_string());
        }
        self.performed.push(effect.handle.clone());
        self.events.borrow_mut().push(format!(
            "performed:{}",
            &idempotency_key("wrt_2pc", effect)[..8]
        ));
        Ok(format!("{}-{}", self.prefix, effect.index))
    }
}

fn harness(dir: &std::path::Path) -> (Witnessed, Performer, Rc<RefCell<Vec<String>>>) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorder = Witnessed {
        inner: FileRecorder::open(dir.join("receipts.jsonl")).expect("open"),
        fail_pre_commit_at: None,
        fail_post_commits: false,
        pre_commits: 0,
        events: Rc::clone(&events),
    };
    let performer = Performer {
        prefix: "real",
        fail_at: None,
        performed: Vec::new(),
        events: Rc::clone(&events),
    };
    (recorder, performer, events)
}

#[test]
fn every_performed_effect_has_a_pre_commit_before_it_and_a_post_commit_after() {
    let dir = tempdir("order");
    let (mut w, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let (mut recorder, mut performer, events) = harness(&dir);

    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW,
        },
    )
    .expect("settle");

    assert!(report.complete);
    assert_eq!(w.state, WarrantState::Settled);
    let events = events.borrow();
    for effect in q.effects() {
        let key = &idempotency_key("wrt_2pc", effect)[..8];
        let pre = events
            .iter()
            .position(|e| *e == format!("recorded:PreCommit:{key}"))
            .expect("pre");
        let did = events
            .iter()
            .position(|e| *e == format!("performed:{key}"))
            .expect("performed");
        let post = events
            .iter()
            .position(|e| *e == format!("recorded:PostCommit:{key}"))
            .expect("post");
        assert!(
            pre < did && did < post,
            "{key}: pre={pre} performed={did} post={post}"
        );
    }
    // Each pair verifies as a chain under the evidence crate's own commit gate.
    let records = recorder.inner.records();
    assert_eq!(records.len(), 6);
    for pair in records.chunks(2) {
        verify_chain(&pair[0].receipt, &pair[1].receipt).expect("I-07 chain");
        assert_eq!(pair[0].idempotency_key, pair[1].idempotency_key);
        assert!(
            pair[0].sequence < pair[1].sequence,
            "receipt precedes outcome in the recorder's clock"
        );
    }
    assert_eq!(records[0].receipt.predicate.operation.class, "mutate");
    assert_eq!(records[2].receipt.predicate.operation.class, "msg");
}

#[test]
fn killing_the_recorder_mid_run_commits_nothing_after_the_kill() {
    let dir = tempdir("kill");
    let (mut w, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let (mut recorder, mut performer, _events) = harness(&dir);
    recorder.fail_pre_commit_at = Some(1);

    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW,
        },
    )
    .expect("settle returns a report even when it stops");

    assert_eq!(
        performer.performed.len(),
        1,
        "the effect whose pre-commit was refused never ran"
    );
    assert!(matches!(report.effects[1], EffectOutcome::Failed { .. }));
    assert!(matches!(
        report.effects[2],
        EffectOutcome::Unreleased { .. }
    ));
    assert!(report
        .boundary
        .expect("boundary")
        .contains("recorder did not acknowledge"));
    assert_eq!(w.state, WarrantState::Held);
}

#[test]
fn a_recorder_that_is_down_from_the_start_commits_nothing_at_all() {
    let dir = tempdir("down");
    let (mut w, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let (mut recorder, mut performer, _events) = harness(&dir);
    recorder.fail_pre_commit_at = Some(0);

    settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW,
        },
    )
    .expect("settle");

    assert!(
        performer.performed.is_empty(),
        "no acknowledgment, no effect"
    );
    assert!(recorder.inner.records().is_empty());
}

#[test]
fn replaying_a_settle_performs_each_idempotency_key_exactly_once() {
    let dir = tempdir("replay");
    let (mut w, settle_key) = warrant();
    let q = queue_with_three(&dir);

    let (mut recorder, mut first, _e) = harness(&dir);
    first.fail_at = Some(1);
    settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut first,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW,
        },
    )
    .expect("first");
    assert_eq!(w.state, WarrantState::Held);
    assert_eq!(first.performed.len(), 1);
    drop(recorder);

    // A new process: fresh recorder over the same log, a performer that would mint different ids.
    let (mut recorder, mut retry, _e) = harness(&dir);
    retry.prefix = "retry";
    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut retry,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW + 60,
        },
    )
    .expect("second");

    assert!(report.complete);
    assert_eq!(
        retry.performed.len(),
        2,
        "effects 2 and 3 only; effect 1 was already real"
    );
    assert!(
        matches!(&report.effects[0], EffectOutcome::Released { real_id, .. } if real_id == "real-1"),
        "the first effect's id comes from the record, not from a second performance: {:?}",
        report.effects[0]
    );
    assert_eq!(
        recorder.inner.records().len(),
        2 + 2 + 4,
        "pre+post for 1, pre+failed-post for 2, then pre+post for 2 and 3"
    );
}

#[test]
fn an_effect_whose_post_commit_was_never_recorded_is_not_performed_again() {
    let dir = tempdir("open-pre");
    let (mut w, settle_key) = warrant();
    let q = queue_with_three(&dir);

    let (mut recorder, mut first, _e) = harness(&dir);
    recorder.fail_post_commits = true;
    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut first,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW,
        },
    )
    .expect("first");
    assert_eq!(
        first.performed.len(),
        1,
        "the effect happened; only its record is behind"
    );
    assert!(matches!(report.effects[0], EffectOutcome::Released { .. }));
    assert!(report
        .boundary
        .expect("boundary")
        .contains("did not acknowledge the post-commit"));
    drop(recorder);

    let (mut recorder, mut retry, _e) = harness(&dir);
    let report = settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut retry,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW + 60,
        },
    )
    .expect("second");

    assert!(
        retry.performed.is_empty(),
        "ambiguity is reported, never resolved by repeating an irreversible action"
    );
    assert!(
        matches!(&report.effects[0], EffectOutcome::Failed { reason, .. } if reason.contains("may have been performed"))
    );
    assert_eq!(w.state, WarrantState::Held);
}

#[test]
fn the_receipt_log_verifies_as_pairs_and_an_edited_line_is_refused() {
    let dir = tempdir("verify");
    let (mut w, settle_key) = warrant();
    let q = queue_with_three(&dir);
    let (mut recorder, mut performer, _e) = harness(&dir);
    settle(
        &mut w,
        &q,
        None,
        &settle_key.verifying_key(),
        &mut performer,
        &mut CommitGate {
            recorder: &mut recorder,
            signer: &settle_key,
            key_id: "settle",
            now: NOW,
        },
    )
    .expect("settle");
    let path = dir.join("receipts.jsonl");
    assert_eq!(
        warrantor_warrant::staging::verify_receipt_log(&path).expect("verifies"),
        3
    );

    let body = std::fs::read_to_string(&path).expect("read");
    let edited = body.replacen("\"status\":\"performed\"", "\"status\":\"skipped\"", 1);
    std::fs::write(&path, edited).expect("write");
    let err = warrantor_warrant::staging::verify_receipt_log(&path).expect_err("edited");
    assert!(err.to_string().contains("signature"), "{err}");
}

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
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
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
    let mut q = StagingQueue::open(dir.join("q.jsonl"), "wrt_2pc", EffectRegistry::github())
        .expect("open");
    let pr = q.stage("github.create_pr", args(&[("title", "Fix")]), NOW).expect("pr");
    q.stage("github.comment", args(&[("target", &pr.handle), ("body", "why")]), NOW)
        .expect("comment");
    q.stage("github.add_label", args(&[("target", &pr.handle), ("label", "bug")]), NOW)
        .expect("label");
    q
}

#[test]
fn the_idempotency_key_is_stable_across_reopen_and_distinct_per_effect() {
    let dir = tempdir("key");
    let q = queue_with_three(&dir);
    let first: Vec<String> = q.effects().iter().map(|e| idempotency_key("wrt_2pc", e)).collect();
    let reopened = StagingQueue::open(dir.join("q.jsonl"), "wrt_2pc", EffectRegistry::github())
        .expect("reopen");
    let second: Vec<String> =
        reopened.effects().iter().map(|e| idempotency_key("wrt_2pc", e)).collect();
    assert_eq!(first, second, "the key must survive a process restart");
    assert_eq!(first.iter().collect::<BTreeSet<_>>().len(), 3, "one key per effect");
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
        &w, effect, "mutate", &idempotency_key("wrt_2pc", effect), NOW,
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
    let RecorderAck { sequence: s1 } = recorder.record("k1", &receipt_for("r1", Phase::PreCommit)).expect("pre");
    assert_eq!(s1, 1);
    assert!(recorder.unresolved("k1"), "a pre-commit with no post-commit is in flight");
    assert_eq!(recorder.performed("k1"), None);

    let RecorderAck { sequence: s2 } = recorder.record("k1", &receipt_for("r2", Phase::PostCommit)).expect("post");
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

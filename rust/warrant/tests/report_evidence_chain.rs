//! Task 1.1: every staged effect is decided by the notary, signed before it is performed and
//! signed again after, and the exported report carries the chain a stranger can verify offline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use warrantor_evidence as evidence;
use warrantor_warrant::receipts::{chains, ReceiptLog};
use warrantor_warrant::report::{build, verify_export, verify_export_signed_by, ReportError};
use warrantor_warrant::settle::{
    settle, EffectOutcome, EffectPerformer, EffectWitness, EvidencedPerformer,
};
use warrantor_warrant::staging::{EffectRegistry, StagedEffect, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;
const ID: &str = "wrt_chain";
const SUBJECT: &str = "spiffe://muveraai.com/agent/alpha";

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-chain-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn settle_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// A warrant whose tool allowlist names the effects it will stage. `tests/settle.rs` grants
/// `git` and stages `github.*`; that passes today only because nothing decides per effect.
fn warrant_with_tools(tools: &[&str]) -> Warrant {
    let bounds = WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    };
    Warrant::grant(
        ID,
        "open the fix",
        SUBJECT,
        bounds,
        NOW,
        &settle_key().verifying_key(),
        &issuer(),
    )
    .expect("grant")
}

fn queue_with_pr_and_comment(dir: &Path) -> StagingQueue {
    let mut queue =
        StagingQueue::open(dir.join("q.jsonl"), ID, EffectRegistry::github()).expect("open");
    let pr = queue
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("pr");
    queue
        .stage(
            "github.comment",
            args(&[("target", &pr.handle), ("body", "why")]),
            NOW,
        )
        .expect("comment");
    queue
}

/// Performs, and at the moment of performing counts what is already durable on disk.
struct Counting {
    log_path: PathBuf,
    fail_at: Option<usize>,
    performed: Vec<String>,
    lines_on_disk_when_performing: Vec<usize>,
}

impl EffectPerformer for Counting {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        _resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        let lines = std::fs::read_to_string(&self.log_path)
            .map(|body| body.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        self.lines_on_disk_when_performing.push(lines);
        if self.fail_at == Some(self.performed.len()) {
            return Err("upstream returned 503".to_string());
        }
        self.performed.push(effect.handle.clone());
        Ok(format!("real-{}", effect.index))
    }
}

fn witness(warrant: &Warrant) -> EffectWitness {
    EffectWitness::for_warrant(
        warrant,
        &issuer().verifying_key(),
        &issuer(),
        "issuer",
        Vec::new(),
        NOW,
    )
}

#[test]
fn the_receipt_log_is_append_only_fsynced_jsonl_that_replays() {
    let dir = tempdir("log");
    let path = dir.join("receipts.jsonl");
    let mut log = ReceiptLog::open(&path).expect("open empty");
    assert!(log.is_empty());
    let warrant = warrant_with_tools(&["github.create_pr"]);
    let mut queue =
        StagingQueue::open(dir.join("q.jsonl"), ID, EffectRegistry::github()).expect("q");
    let effect = queue
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("pr");
    let digest = warrantor_warrant::staging::effect_digest(&effect).expect("digest");
    let predicate = witness(&warrant).pre_commit_predicate(&effect, &digest, "nonce-1");
    let pre = evidence::issue_pre_commit(predicate, &issuer(), "issuer");
    log.append(&pre).expect("append");
    let reopened = ReceiptLog::open(&path).expect("reopen");
    assert_eq!(reopened.receipts(), &[pre]);
    assert_eq!(chains(reopened.receipts()).len(), 1);
    assert!(chains(reopened.receipts())[0].post_commit.is_none());
}

#[test]
fn a_pre_commit_receipt_is_on_disk_before_the_effect_is_performed() {
    let dir = tempdir("before");
    let mut warrant = warrant_with_tools(&["github.create_pr", "github.comment"]);
    let queue = queue_with_pr_and_comment(&dir);
    let log_path = dir.join("receipts.jsonl");
    let mut log = ReceiptLog::open(&log_path).expect("log");
    let mut inner = Counting {
        log_path: log_path.clone(),
        fail_at: None,
        performed: Vec::new(),
        lines_on_disk_when_performing: Vec::new(),
    };
    let witness = witness(&warrant);
    let mut performer = EvidencedPerformer::new(&mut inner, witness, &mut log);

    let report = settle(
        &mut warrant,
        &queue,
        None,
        &settle_key().verifying_key(),
        &mut performer,
    )
    .expect("settle");
    drop(performer);

    assert!(report.complete);
    // Effect 1 saw 1 line (its own pre-commit); effect 2 saw 3 (pre, post, pre).
    assert_eq!(inner.lines_on_disk_when_performing, vec![1, 3]);
    assert_eq!(warrant.state, WarrantState::Settled);
}

#[test]
fn every_released_effect_has_a_chain_that_verifies_and_names_its_real_id() {
    let dir = tempdir("chain");
    let mut warrant = warrant_with_tools(&["github.create_pr", "github.comment"]);
    let queue = queue_with_pr_and_comment(&dir);
    let mut log = ReceiptLog::open(dir.join("receipts.jsonl")).expect("log");
    let mut inner = Counting {
        log_path: dir.join("receipts.jsonl"),
        fail_at: None,
        performed: Vec::new(),
        lines_on_disk_when_performing: Vec::new(),
    };
    let witness = witness(&warrant);
    let mut performer = EvidencedPerformer::new(&mut inner, witness, &mut log);
    settle(
        &mut warrant,
        &queue,
        None,
        &settle_key().verifying_key(),
        &mut performer,
    )
    .expect("settle");
    assert!(performer.unrecorded().is_empty());
    drop(performer);

    let chains = chains(log.receipts());
    assert_eq!(log.len(), 4);
    assert_eq!(chains.len(), 2);
    for (chain, expected_real_id) in chains.iter().zip(["real-1", "real-2"]) {
        let post = chain.post_commit.as_ref().expect("post-commit");
        evidence::verify_chain(&chain.pre_commit, post).expect("chain verifies");
        let outcome = post.predicate.outcome.as_ref().expect("outcome");
        assert_eq!(outcome.status, "success");
        assert_eq!(outcome.effects, vec![expected_real_id.to_string()]);
        assert_eq!(
            chain.pre_commit.predicate.binding.enforcement_mode,
            evidence::EnforcementMode::Advisory
        );
        assert_eq!(chain.pre_commit.predicate.operation.method, "settle");
        assert!(!chain.pre_commit.predicate.operation.reversible);
    }
    assert_eq!(
        chains[0].pre_commit.predicate.operation.target,
        format!("pr://staged/{ID}/1")
    );
}

/// The refusal Rule 2 requires before any label moves: an effect for a tool the warrant does not
/// hold is refused at the authority gate, before `perform`, and no receipt is written for it.
#[test]
fn an_effect_for_a_tool_the_warrant_does_not_hold_is_refused_before_it_is_performed() {
    let dir = tempdir("deny");
    let mut warrant = warrant_with_tools(&["github.create_pr"]);
    let queue = queue_with_pr_and_comment(&dir);
    let mut log = ReceiptLog::open(dir.join("receipts.jsonl")).expect("log");
    let mut inner = Counting {
        log_path: dir.join("receipts.jsonl"),
        fail_at: None,
        performed: Vec::new(),
        lines_on_disk_when_performing: Vec::new(),
    };
    let witness = witness(&warrant);
    let mut performer = EvidencedPerformer::new(&mut inner, witness, &mut log);
    let report = settle(
        &mut warrant,
        &queue,
        None,
        &settle_key().verifying_key(),
        &mut performer,
    )
    .expect("settle");
    drop(performer);

    assert!(!report.complete);
    assert_eq!(inner.performed, vec![format!("pr://staged/{ID}/1")]);
    match &report.effects[1] {
        EffectOutcome::Failed { handle, reason } => {
            assert_eq!(handle, &format!("comment://staged/{ID}/2"));
            assert_eq!(
                reason,
                "refused by the notary at the authority gate; nothing was performed"
            );
            assert!(
                !reason.contains("github.comment"),
                "Deny carries only the gate: {reason}"
            );
        }
        other => panic!("expected the comment to be refused, got {other:?}"),
    }
    assert_eq!(
        log.len(),
        2,
        "a refused effect gets no receipt; the PR got pre and post"
    );
    assert_eq!(warrant.state, WarrantState::Held);
}

#[test]
fn a_failed_effect_gets_a_post_commit_that_says_so() {
    let dir = tempdir("failed");
    let mut warrant = warrant_with_tools(&["github.create_pr", "github.comment"]);
    let queue = queue_with_pr_and_comment(&dir);
    let mut log = ReceiptLog::open(dir.join("receipts.jsonl")).expect("log");
    let mut inner = Counting {
        log_path: dir.join("receipts.jsonl"),
        fail_at: Some(1),
        performed: Vec::new(),
        lines_on_disk_when_performing: Vec::new(),
    };
    let witness = witness(&warrant);
    let mut performer = EvidencedPerformer::new(&mut inner, witness, &mut log);
    settle(
        &mut warrant,
        &queue,
        None,
        &settle_key().verifying_key(),
        &mut performer,
    )
    .expect("settle");
    drop(performer);

    let chains = chains(log.receipts());
    assert_eq!(chains.len(), 2);
    let failed = chains[1]
        .post_commit
        .as_ref()
        .expect("post-commit for the failed effect");
    evidence::verify_chain(&chains[1].pre_commit, failed).expect("verifies");
    let outcome = failed.predicate.outcome.as_ref().expect("outcome");
    assert_eq!(outcome.status, "failed");
    assert_eq!(outcome.error.as_deref(), Some("upstream returned 503"));
    assert!(outcome.effects.is_empty());
}

fn stored_from(warrant: &Warrant) -> StoredWarrant {
    StoredWarrant {
        warrant: warrant.clone(),
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

/// Settle two effects with receipts, then build and sign the report over them.
fn settled_export(dir: &Path) -> warrantor_warrant::report::SignedReport {
    let mut warrant = warrant_with_tools(&["github.create_pr", "github.comment"]);
    let queue = queue_with_pr_and_comment(dir);
    let mut log = ReceiptLog::open(dir.join("receipts.jsonl")).expect("log");
    let mut inner = Counting {
        log_path: dir.join("receipts.jsonl"),
        fail_at: None,
        performed: Vec::new(),
        lines_on_disk_when_performing: Vec::new(),
    };
    let witness = witness(&warrant);
    let mut performer = EvidencedPerformer::new(&mut inner, witness, &mut log);
    settle(
        &mut warrant,
        &queue,
        None,
        &settle_key().verifying_key(),
        &mut performer,
    )
    .expect("settle");
    drop(performer);
    build(
        &stored_from(&warrant),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW + 60,
    )
    .with_effect_receipts(log.receipts().to_vec())
    .sign(&issuer(), "issuer")
    .expect("sign")
}

#[test]
fn the_export_embeds_the_chain_and_verifies_offline() {
    let dir = tempdir("export");
    let signed = settled_export(&dir);
    let section = signed.bundle.effect_evidence.as_ref().expect("section");
    assert_eq!(section.receipts_consulted, 4);
    assert_eq!(section.effects.len(), 2);
    assert!(section.effects.iter().all(|line| line.status == "success"));
    assert_eq!(signed.effect_receipts.len(), 4);
    verify_export(&signed).expect("verifies");
    verify_export_signed_by(&signed, &issuer().verifying_key()).expect("verifies against the pin");
    let json = serde_json::to_vec_pretty(&signed).expect("encode");
    let back: warrantor_warrant::report::SignedReport =
        serde_json::from_slice(&json).expect("decode");
    verify_export(&back).expect("round trip verifies");
}

#[test]
fn removing_one_receipt_from_the_export_is_a_commit_gate_violation() {
    let dir = tempdir("removed");
    let signed = settled_export(&dir);

    let mut without_post = signed.clone();
    without_post.effect_receipts.remove(3);
    let err = verify_export(&without_post).unwrap_err().to_string();
    assert!(err.contains("commit-gate violation (I-07)"), "{err}");

    let mut without_pre = signed.clone();
    without_pre.effect_receipts.remove(0);
    let err = verify_export(&without_pre).unwrap_err().to_string();
    assert!(err.contains("commit-gate violation (I-07)"), "{err}");
}

#[test]
fn a_chain_signed_by_another_key_cannot_ride_along() {
    let dir = tempdir("foreign");
    let mut signed = settled_export(&dir);
    let stranger = SigningKey::from_bytes(&[5; 32]);
    let pre = evidence::issue_pre_commit(
        signed.effect_receipts[0].predicate.clone(),
        &stranger,
        "stranger",
    );
    let post = evidence::issue_post_commit(
        &pre,
        signed.effect_receipts[1]
            .predicate
            .outcome
            .clone()
            .expect("outcome"),
        &stranger,
        "stranger",
    );
    signed.effect_receipts[0] = pre;
    signed.effect_receipts[1] = post;
    assert!(matches!(
        verify_export(&signed),
        Err(ReportError::Binding(_))
    ));
}

#[test]
fn a_bundle_that_lists_a_status_its_receipt_does_not_carry_is_refused() {
    let dir = tempdir("status");
    let signed = settled_export(&dir);
    let mut tampered = signed.clone();
    let post = &mut tampered.effect_receipts[1];
    post.predicate.outcome.as_mut().expect("outcome").status = "failed".to_string();
    // Changing the predicate breaks its signature first; that is the right first failure.
    assert!(matches!(
        verify_export(&tampered),
        Err(ReportError::Evidence(_))
    ));
}

#[test]
fn an_export_built_without_a_receipt_log_still_verifies_and_says_so() {
    let dir = tempdir("older");
    let warrant = warrant_with_tools(&["github.create_pr"]);
    let queue = StagingQueue::open(dir.join("q.jsonl"), ID, EffectRegistry::github()).expect("q");
    let signed = build(
        &stored_from(&warrant),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
    )
    .sign(&issuer(), "issuer")
    .expect("sign");
    assert!(signed.bundle.effect_evidence.is_none());
    assert!(signed.effect_receipts.is_empty());
    let canonical = warrantor_warrant::report::canonical_bundle(&signed.bundle).expect("canonical");
    assert!(
        !canonical.contains("effect_evidence"),
        "absent must stay absent: {canonical}"
    );
    assert!(signed
        .bundle
        .limitations
        .iter()
        .any(|l| l == warrantor_warrant::report::NO_EFFECT_RECEIPTS_LIMITATION));
    verify_export(&signed).expect("verifies");
}

#[test]
fn stray_receipts_the_bundle_does_not_list_are_refused() {
    let dir = tempdir("stray");
    let mut signed = settled_export(&dir);
    let extra = signed.effect_receipts[0].clone();
    signed.effect_receipts.push(extra);
    assert!(matches!(
        verify_export(&signed),
        Err(ReportError::Binding(_))
    ));
}

//! Genuine artifacts for the adversary to attack.
//!
//! Every fixture here is produced by the **product's own** issuance path — `settle` writes the
//! per-effect chains and `report::build(..).with_effect_receipts(..).sign(..)` produces the export —
//! so an attack that gets past `verify_export` got past the thing that actually ships. A fixture
//! hand-assembled from struct literals would let an attack succeed against a shape the product
//! never emits, which is a finding about the fixture and not about the product.
//!
//! The plan for this task named a `fixtures` module as if it existed. It did not: the settled-export
//! helpers live in `rust/warrant/tests/report_evidence_chain.rs`, which is a different test binary
//! and whose helpers are private to it. This module is that gap, filled deliberately rather than by
//! reaching for a shared crate — a `#[dev-dependencies]` shortcut would hide an edge from
//! `tools/ci/wiring_census.py`, whose lines 28-29 exclude dev-dependencies by design.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use warrantor_evidence as evidence;
use warrantor_warrant::receipts::ReceiptLog;
use warrantor_warrant::report::{build, SignedReport};
use warrantor_warrant::settle::{settle, EffectPerformer, EffectWitness, EvidencedPerformer};
use warrantor_warrant::staging::{EffectRegistry, StagedEffect, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

/// The fixed clock every fixture is issued against. Distinct from [`crate::scenario::NOW`] so a
/// mix-up between a notary scenario and a report fixture reads as a mismatch rather than as a pass.
pub const NOW: u64 = 1_786_000_000;

/// The subject every fixture warrant is granted to.
pub const SUBJECT: &str = "spiffe://muveraai.com/agent/adversary-corpus";

/// The key the report and its receipts are signed with. The adversary does **not** hold this one
/// except where a strategy says explicitly that it does — see `a9`, whose whole point is an attack
/// the audited party can mount with its own legitimate key.
pub fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// The key `settle` releases against.
fn settle_key() -> SigningKey {
    SigningKey::from_bytes(&[8; 32])
}

/// A scratch directory unique to this test run.
pub fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-adversary-{tag}-{}",
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

fn warrant(id: &str, goal: &str) -> Warrant {
    let bounds = WarrantBounds {
        tools: ["github.create_pr".to_string(), "github.comment".to_string()]
            .into_iter()
            .collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3_600,
        budget_cents_observed: None,
        delegation_depth: 2,
        horizon: None,
    };
    Warrant::grant(
        id,
        goal,
        SUBJECT,
        bounds,
        NOW,
        &settle_key().verifying_key(),
        &issuer(),
    )
    .expect("grant")
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

/// Performs every effect successfully. The adversary attacks the record, never the adapter.
struct Performing {
    performed: usize,
}

impl EffectPerformer for Performing {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        _resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        self.performed += 1;
        Ok(format!("real-{}", effect.index))
    }
}

/// A settled export: two effects performed, two verified chains attached, signed by [`issuer`].
///
/// This is the shape `warrantor report --export` writes after `warrantor settle`, and it is the
/// control for every strategy that attacks a report.
pub fn settled_export(dir: &Path, id: &str, goal: &str) -> SignedReport {
    let (export, _) = settled_export_and_receipts(dir, id, goal);
    export
}

/// [`settled_export`], and the genuine per-effect receipts alongside it.
///
/// Returned together because two strategies need the receipts on their own: one to re-issue them
/// with a field flipped, one to put the honest ones back after the bundle has been rebuilt around
/// their mutated twins.
pub fn settled_export_and_receipts(
    dir: &Path,
    id: &str,
    goal: &str,
) -> (SignedReport, Vec<evidence::WarReceipt>) {
    let mut granted = warrant(id, goal);
    let mut queue = StagingQueue::open(
        dir.join(format!("{id}-q.jsonl")),
        id,
        EffectRegistry::github(),
    )
    .expect("open queue");
    let pr = queue
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("stage pr");
    queue
        .stage(
            "github.comment",
            args(&[("target", &pr.handle), ("body", "why")]),
            NOW,
        )
        .expect("stage comment");

    let mut log = ReceiptLog::open(dir.join(format!("{id}-receipts.jsonl"))).expect("open log");
    let mut inner = Performing { performed: 0 };
    let witness = EffectWitness::for_warrant(
        &granted,
        &issuer().verifying_key(),
        &issuer(),
        "issuer",
        Vec::new(),
        NOW,
    );
    let mut performer = EvidencedPerformer::new(&mut inner, witness, &mut log);
    settle(
        &mut granted,
        &queue,
        None,
        &settle_key().verifying_key(),
        &mut performer,
    )
    .expect("settle");
    drop(performer);

    let receipts = log.receipts().to_vec();
    let export = build(
        &stored_from(&granted),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW + 60,
    )
    .with_effect_receipts(receipts.clone())
    .sign(&issuer(), "issuer")
    .expect("sign");
    (export, receipts)
}

/// Rebuild and re-sign a report around a supplied receipt set, exactly as the product would.
///
/// Used where an attack needs the bundle's derived prose to describe one thing while the export
/// carries another. Going through the real builder is what makes the result an attack on the
/// product rather than on a struct literal.
pub fn export_built_over(
    dir: &Path,
    id: &str,
    goal: &str,
    receipts: Vec<evidence::WarReceipt>,
) -> SignedReport {
    let mut granted = warrant(id, goal);
    let mut queue = StagingQueue::open(
        dir.join(format!("{id}-rebuild-q.jsonl")),
        id,
        EffectRegistry::github(),
    )
    .expect("open queue");
    let pr = queue
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("stage pr");
    queue
        .stage(
            "github.comment",
            args(&[("target", &pr.handle), ("body", "why")]),
            NOW,
        )
        .expect("stage comment");
    let mut log = ReceiptLog::open(dir.join(format!("{id}-rebuild-receipts.jsonl"))).expect("log");
    let mut inner = Performing { performed: 0 };
    let witness = EffectWitness::for_warrant(
        &granted,
        &issuer().verifying_key(),
        &issuer(),
        "issuer",
        Vec::new(),
        NOW,
    );
    let mut performer = EvidencedPerformer::new(&mut inner, witness, &mut log);
    settle(
        &mut granted,
        &queue,
        None,
        &settle_key().verifying_key(),
        &mut performer,
    )
    .expect("settle");
    drop(performer);

    build(
        &stored_from(&granted),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW + 60,
    )
    .with_effect_receipts(receipts)
    .sign(&issuer(), "issuer")
    .expect("sign")
}

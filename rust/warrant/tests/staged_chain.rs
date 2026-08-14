//! The staged-effect log can be deleted. These are the tests that make that detectable.
//!
//! The hash chain proves nobody edited the log. It cannot prove the log is still there: the file is
//! created lazily by the first append, so `staged/<id>.jsonl` being absent means either "this
//! warrant staged nothing" or "somebody removed the evidence", and [`StagingQueue::open`] reads
//! both as an empty queue at genesis. A report built from that says `0 staged effect(s)` and
//! `chain head 0000…`, and then signs it.
//!
//! So the head and the count are witnessed in the warrant record — outside the file they witness —
//! and every reader goes through `WarrantStore::open_queue`, which checks one against the other.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use warrantor_warrant::report::{self, StagedSection};
use warrantor_warrant::staging::{EffectRegistry, StagedChainMark, StagingQueue};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
const ID: &str = "wrt_witness";

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-chainmark-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn sample_warrant() -> Warrant {
    let settle = SigningKey::from_bytes(&[9u8; 32]);
    let bounds = WarrantBounds {
        tools: ["github.create_pr", "github.comment"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 3,
    };
    Warrant::grant(
        ID,
        "goal",
        "spiffe://muveraai.com/agent/local",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer(),
    )
    .expect("grant")
}

/// A store holding one warrant, witnessed from grant exactly as `warrantor grant` witnesses it.
fn seeded(tag: &str) -> (std::path::PathBuf, WarrantStore) {
    let dir = tempdir(tag);
    let store = WarrantStore::open(&dir).expect("open store");
    store
        .save(&StoredWarrant {
            warrant: sample_warrant(),
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
            staged_chain: Some(StagedChainMark::genesis(NOW)),
        })
        .expect("save");
    (dir, store)
}

/// Stage `count` effects the way the CLI does: append, then witness.
fn stage_and_witness(store: &WarrantStore, count: usize) {
    let mut queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("open queue");
    for n in 0..count {
        queue
            .stage(
                "github.create_pr",
                args(&[("title", &format!("Fix {n}"))]),
                NOW,
            )
            .expect("stage");
        store
            .witness_staged_chain(ID, &queue, NOW)
            .expect("witness");
    }
}

// ── deletion ──────────────────────────────────────────────────────────────────────────

/// The case this whole mechanism exists for. `rm staged/<id>.jsonl` used to turn "two staged
/// effects, chain head abc…" into "zero staged effects, chain head 0000…" — a success-shaped
/// answer, indistinguishable from a warrant that never staged anything, signed into a bundle.
#[test]
fn a_deleted_staged_log_is_refused_rather_than_read_as_an_empty_queue() {
    let (_dir, store) = seeded("deleted");
    stage_and_witness(&store, 2);

    std::fs::remove_file(store.staged_path(ID)).expect("remove the log");

    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("a deleted log must not open cleanly");
    let text = error.to_string();
    assert!(
        text.contains("missing records this store recorded"),
        "the refusal must say what is missing, not just that something is wrong: {text}"
    );
    assert!(
        text.contains("2 effect(s)"),
        "the refusal must name how many effects are unaccounted for: {text}"
    );
}

/// Truncation is the same failure with a subtler shape: the surviving prefix still forms a valid
/// chain, so the chain check alone passes and the queue reads as shorter than it is.
#[test]
fn a_truncated_staged_log_is_refused_even_though_the_survivors_still_chain() {
    let (_dir, store) = seeded("truncated");
    stage_and_witness(&store, 3);

    let path = store.staged_path(ID);
    let body = std::fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = body.lines().take(1).collect();
    std::fs::write(&path, format!("{}\n", kept.join("\n"))).expect("truncate");

    // The prefix on its own is a perfectly valid chain — this is the part the digests cannot catch.
    StagingQueue::open(&path, ID, EffectRegistry::github())
        .expect("the surviving prefix chains cleanly, which is exactly the problem");

    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("a truncated log must be refused");
    assert!(
        error.to_string().contains("truncated or deleted"),
        "{error}"
    );
}

/// Deleting the log and staging something new in its place produces a valid chain of the right
/// length and the wrong contents. The witness names the record it recorded, so the substitution is
/// caught at the position it happened.
#[test]
fn a_log_rewritten_under_the_witness_is_refused() {
    let (_dir, store) = seeded("rewritten");
    stage_and_witness(&store, 1);

    std::fs::remove_file(store.staged_path(ID)).expect("remove");
    let mut replacement = StagingQueue::open(store.staged_path(ID), ID, EffectRegistry::github())
        .expect("open a fresh log at the same path");
    replacement
        .stage(
            "github.create_pr",
            args(&[("title", "Something else")]),
            NOW,
        )
        .expect("stage");

    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("a substituted log must be refused");
    assert!(
        error.to_string().contains("has been rewritten"),
        "a same-length substitution is a rewrite, and must be named as one: {error}"
    );
}

// ── what must NOT be refused ──────────────────────────────────────────────────────────

/// A witness that lags the log is the ordinary case: the log is append-only, and a session stages
/// effects between witness writes. Refusing growth would make every unwitnessed stage a corruption
/// report, which would teach an operator to ignore the check.
#[test]
fn effects_staged_after_the_witness_are_growth_not_corruption() {
    let (_dir, store) = seeded("growth");
    stage_and_witness(&store, 2);

    // Staged without witnessing, as would happen if the process died before the record was saved.
    let mut queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("open queue");
    queue
        .stage("github.comment", args(&[("body", "later")]), NOW)
        .expect("stage");

    let reopened = store
        .open_queue(ID, EffectRegistry::github())
        .expect("a log that only grew must still open");
    assert_eq!(reopened.len(), 3, "every effect is still there");
}

/// A warrant that staged nothing has no log, and that absence is now provably innocent rather than
/// merely assumed to be: the witness taken at grant says the chain held nothing.
#[test]
fn a_witnessed_warrant_that_staged_nothing_opens_as_empty() {
    let (_dir, store) = seeded("never-staged");
    let queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("a never-written log is not a missing one");
    assert!(queue.is_empty());
}

/// The honest limit of the mechanism, asserted so nobody reads more into it than it says. A warrant
/// granted before the witness existed carries none, and for those the old ambiguity remains: the
/// queue opens empty and nothing here can tell whether that is the truth. Claiming otherwise would
/// mean fabricating a verdict from an absence of evidence.
#[test]
fn a_warrant_from_before_the_witness_existed_is_read_but_not_vouched_for() {
    let (_dir, store) = seeded("unwitnessed");
    stage_and_witness(&store, 1);

    let mut stored = store.load(ID).expect("load");
    stored.staged_chain = None;
    store.save(&stored).expect("save");
    std::fs::remove_file(store.staged_path(ID)).expect("remove");

    let queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("with no witness there is nothing to check against");
    assert!(
        queue.is_empty(),
        "this is the pre-witness behaviour, kept deliberately and documented as unprovable"
    );
}

// ── what the refusal reaches ──────────────────────────────────────────────────────────

/// The refusal is only worth anything if it lands in the fail-closed path the rest of the system
/// already has: an unreadable queue makes the report decline to count staged effects, which sets
/// `policy_decision` false, which makes the notary deny. End to end, from a deleted file.
#[test]
fn a_deleted_log_reaches_the_report_as_unavailable_and_denies() {
    let (_dir, store) = seeded("report");
    stage_and_witness(&store, 2);
    std::fs::remove_file(store.staged_path(ID)).expect("remove");

    let stored = store.load(ID).expect("load");
    let queue = store.open_queue(ID, EffectRegistry::github());
    let built = report::build_observed(
        &stored,
        queue.as_ref().map_err(std::string::ToString::to_string),
        &issuer().verifying_key(),
        NOW + 60,
        &[],
        None,
    );
    let bundle = built.bundle();

    assert!(
        matches!(bundle.staged, StagedSection::Unavailable { .. }),
        "a deleted log must not render as an ordered list of nothing"
    );
    assert_eq!(
        bundle.staged_count, None,
        "an unknown staged count is not zero"
    );
    assert!(
        !bundle.authority_check.allowed,
        "indeterminate is denial: nobody knows what this warrant would release"
    );

    let text = report::render_cli(bundle);
    assert!(
        !text.contains("0 staged effect(s)"),
        "the printed report must never launder a deleted log into a confident zero: {text}"
    );
}

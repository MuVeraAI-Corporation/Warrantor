//! Invariant I-05 on the product's own path: a revoked subject is refused where the product
//! actually adjudicates, not only where the corpus constructs a `VerdictContext` by hand.
//!
//! This is the test that makes the `#[ignore]` conversions in the invariant corpus mean something.
//! Both of those findings assert on a *string* — `!report.contains("revoked_svids: Vec::new()")` —
//! so deleting that string would satisfy them while changing no behavior at all. What follows is the
//! behavior.
//!
//! **Every refusal here is paired with an allowed control.** A verdict function that denied every
//! request would pass the attack half of each pair and fail the control half, and the control half is
//! written first for exactly that reason.
//!
//! # Tier
//!
//! The refusal is Tier B, a chokepoint: `warrantor_notary::verdict` returns
//! `Deny { gate: Identity }` at the moment the request is adjudicated. It is not an operating-system
//! bound. Nothing here terminates a process, closes a socket, or invalidates a credential a third
//! party holds, and an agent that never asks for a verdict is never refused.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use warrantor_warrant::report::{self, RevocationSection};
use warrantor_warrant::revoke::{RevocationSource, RevocationStore};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
const SUBJECT: &str = "spiffe://muveraai.com/agent/alpha";

/// A scratch root under the system temp dir, never inside the repository: CI runs the workspace on
/// ubuntu only, so every filesystem path this file exercises is Windows-untested there, and a
/// concurrent lane's `cargo` must not be able to race the journal.
fn scratch(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-revocation-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("scratch root");
    path
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn settle_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn stored() -> StoredWarrant {
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: Some(500),
        delegation_depth: 3,
        exec: None,
    };
    let warrant = Warrant::grant(
        "wrt_revocation",
        "prove a revoked subject is refused",
        SUBJECT,
        bounds,
        NOW,
        &settle_key().verifying_key(),
        &issuer(),
    )
    .expect("grant");
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

fn queue_at(dir: &std::path::Path) -> StagingQueue {
    StagingQueue::open(
        dir.join("q.jsonl"),
        "wrt_revocation",
        EffectRegistry::github(),
    )
    .expect("open queue")
}

fn build(queue: &StagingQueue, revocation: Option<RevocationSection>) -> report::Report {
    report::build_observed(
        &stored(),
        Ok(queue),
        &issuer().verifying_key(),
        NOW,
        &[],
        report::Observed {
            revocation,
            ..Default::default()
        },
    )
}

#[test]
fn a_revoked_subject_is_refused_at_the_identity_gate_on_the_products_own_path() {
    let dir = scratch("refused");
    let queue = queue_at(&dir);

    // CONTROL: the same warrant, the same store, nothing revoked. Must be ALLOWED -- otherwise the
    // refusal below proves only that the fixture was broken.
    let store = RevocationStore::open(&dir).expect("open a fresh store");
    assert!(
        store.revoked_svids().is_empty(),
        "the control's store must start empty"
    );
    let control = build(&queue, Some(RevocationSection::from_store(&store)));
    assert!(
        control.bundle().authority_check.allowed,
        "the CONTROL was refused, so the attack never reached the Identity gate. Fix the fixture; \
         never weaken the assertion. denied_gate = {:?}",
        control.bundle().authority_check.denied_gate,
    );

    // ATTACK: revoke the subject the warrant names, rebuild through the same function.
    let mut store = RevocationStore::open(&dir).expect("reopen");
    let record = store.revoke(SUBJECT).expect("revoke");
    assert_eq!(record.svid, SUBJECT);
    let section = RevocationSection::from_store(&store).with_latency(store.latency(&record));
    let attacked = build(&queue, Some(section));

    assert!(
        !attacked.bundle().authority_check.allowed,
        "a revoked subject was still allowed on the product's own report path"
    );
    assert_eq!(
        attacked.bundle().authority_check.denied_gate.as_deref(),
        Some("identity"),
        "a revoked subject must deny at Identity specifically. A denial at some earlier gate would \
         let this test pass for the wrong reason.",
    );
}

/// The revocation set is inside the signature, exactly as much as any other bundle field.
#[test]
fn editing_the_revoked_set_changes_the_bundle_digest() {
    let dir = scratch("digest");
    let queue = queue_at(&dir);
    let mut store = RevocationStore::open(&dir).expect("open");
    store.revoke(SUBJECT).expect("revoke");
    let built = build(&queue, Some(RevocationSection::from_store(&store)));

    let before = report::bundle_digest(built.bundle()).expect("digest");
    let mut edited = built.bundle().clone();
    edited
        .revocation
        .as_mut()
        .expect("carried")
        .revoked_svids
        .clear();
    let after = report::bundle_digest(&edited).expect("digest");
    assert_ne!(
        before, after,
        "quietly emptying the revoked set must change the digest, or recording it here bought \
         nothing"
    );
}

#[test]
fn a_report_built_without_a_revocation_source_says_so_rather_than_implying_none() {
    let dir = scratch("absent");
    let queue = queue_at(&dir);
    let built = build(&queue, None);
    assert!(
        built
            .bundle()
            .limitations
            .iter()
            .any(|line| line.contains("No revocation source was supplied to this report")),
        "an absent revocation source must be disclosed. Silence reads as \"checked and clear\", \
         which is the claim the containment limitation already refuses to make. {:?}",
        built.bundle().limitations,
    );
}

/// The middle arm. "Consulted and empty" must not collapse into "not consulted": that collapse would
/// report a bound as stronger than it is, because the second says a journal was read and the first
/// says nothing was.
#[test]
fn a_consulted_but_empty_source_is_distinguished_from_an_unconsulted_one() {
    let dir = scratch("empty");
    let queue = queue_at(&dir);
    let store = RevocationStore::open(&dir).expect("open");
    let built = build(&queue, Some(RevocationSection::from_store(&store)));

    let line = built
        .bundle()
        .limitations
        .iter()
        .find(|l| l.contains("revocation source WAS consulted"))
        .expect("the consulted-and-empty arm must be stated");
    assert!(
        line.contains("no fan-out"),
        "a consulted-and-empty source must say that a subject revoked elsewhere is unrevoked \
         here: {line}"
    );
    assert!(
        !built
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("No revocation source was supplied")),
        "the two arms are mutually exclusive; emitting both would make the report say it did and \
         did not consult a source"
    );
}

/// The strongest arm must state, in the product, everything the revocation does not reach. This is a
/// gate on the prose: the sentence is where an over-claim would live, so an assertion sits on it.
#[test]
fn the_revoked_arm_states_every_thing_the_revocation_does_not_reach() {
    let dir = scratch("says-what-it-misses");
    let queue = queue_at(&dir);
    let mut store = RevocationStore::open(&dir).expect("open");
    let record = store.revoke(SUBJECT).expect("revoke");
    let section = RevocationSection::from_store(&store).with_latency(store.latency(&record));
    let built = build(&queue, Some(section));

    // LOCATOR ADAPTED 2026-09-05, not weakened: the arm used to say "revoked in this machine's
    // journal", which overstated the scope -- the journal is per store root, and a second `--root`
    // on the same machine reads a different file. The required-clause list below is unchanged and
    // has GROWN by the store clause; nothing was removed from it.
    let line = built
        .bundle()
        .limitations
        .iter()
        .find(|l| l.contains("revoked in this STORE's journal"))
        .expect("the revoked arm must be stated");
    for required in [
        "does not recall a credential already used",
        "does not reach a copy held by a third party",
        "does not close a session already open",
        "does not propagate to any other machine",
        "does not reach another store on this same machine",
        "egress broker does not consult the revocation set",
        "not an issued SVID",
    ] {
        assert!(
            line.contains(required),
            "the revoked arm must say {required:?}; without it the sentence claims a bound this \
             build does not hold. Got: {line}"
        );
    }
}

/// The case the corpus could not see, added 2026-09-05 after review.
///
/// Every other test in this file revokes the warrant's OWN subject, so the sentence and the verdict
/// always agreed and the disagreement was untested. The Identity gate compares exactly one string —
/// `ctx.revoked_svids.contains(&req.actor.svid)`, and `req.actor.svid` is `claims.subject` — so a
/// non-empty set that does not hold this warrant's subject makes the gate ALLOW. Before this test the
/// strongest limitations arm fired on `!revoked_svids.is_empty()` and asserted the gate denied every
/// verdict, so a revocation for an unrelated subject shipped a signed bundle reading
/// `allowed: true, denied_gate: null` beside a sentence saying it denied.
///
/// The two halves move ONE thing — which subject is in the journal — and nothing else. The allowed
/// half is the control, and it is the half that would have caught the defect.
#[test]
fn a_revocation_for_another_subject_is_not_rendered_as_a_denial() {
    let dir = scratch("other-subject");
    let queue = queue_at(&dir);

    // CONTROL: a NON-EMPTY set that does not hold this warrant's subject. The gate must allow, and
    // the sentence must say the set does not make it deny.
    let mut store = RevocationStore::open(&dir).expect("open");
    store.revoke("spiffe://someone/else").expect("revoke");
    assert_eq!(
        store.revoked_svids(),
        vec!["spiffe://someone/else"],
        "the control needs a non-empty set that excludes {SUBJECT}"
    );
    let allowed = build(&queue, Some(RevocationSection::from_store(&store)));
    assert!(
        allowed.bundle().authority_check.allowed,
        "revoking an unrelated subject must not deny: the gate compares this warrant's subject \
         only. Fix the fixture; never weaken the assertion. denied_gate = {:?}",
        allowed.bundle().authority_check.denied_gate,
    );
    let line = allowed
        .bundle()
        .limitations
        .iter()
        .find(|l| l.contains("NONE"))
        .unwrap_or_else(|| {
            panic!(
                "a non-intersecting revoked set must have its own sentence. Got: {:?}",
                allowed.bundle().limitations
            )
        });
    assert!(
        line.contains("does NOT make it deny for this warrant"),
        "the sentence must agree with the verdict beside it in the same bundle: \
         authority_check says allowed={}, so the limitation may not say the gate denies. Got: \
         {line}",
        allowed.bundle().authority_check.allowed,
    );
    assert!(
        !allowed
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("the Identity gate denies every verdict")),
        "an allowed bundle must not carry the denial sentence anywhere in its limitations: {:?}",
        allowed.bundle().limitations,
    );

    // ATTACK: the same store, the same set, plus THIS warrant's subject. Now the gate denies and the
    // denial sentence is the true one.
    let mut store = RevocationStore::open(&dir).expect("reopen");
    let record = store
        .revoke(SUBJECT)
        .expect("revoke this warrant's subject");
    let section = RevocationSection::from_store(&store).with_latency(store.latency(&record));
    let denied = build(&queue, Some(section));
    assert_eq!(
        denied.bundle().authority_check.denied_gate.as_deref(),
        Some("identity"),
        "adding this warrant's own subject to the same set must deny at Identity",
    );
    assert!(
        denied
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("the Identity gate denies every verdict")),
        "the denial sentence must appear exactly when the gate denies: {:?}",
        denied.bundle().limitations,
    );
    assert!(
        !denied
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("does NOT make it deny for this warrant")),
        "the two arms are mutually exclusive; emitting both would make the bundle say the gate \
         did and did not deny: {:?}",
        denied.bundle().limitations,
    );
}

/// The constant-versus-issued clause must be READ off the subject, not asserted beside it.
///
/// `grant --subject` and `revoke --svid` both accept arbitrary strings, so "the subject revoked is
/// the constant this build presents as its principal" was false for any warrant granted with
/// `--subject`. This pins both directions: a default-subject warrant and a supplied-subject one.
#[test]
fn the_constant_versus_issued_clause_is_read_off_the_subject() {
    let dir = scratch("subject-clause");
    let queue = queue_at(&dir);
    let mut store = RevocationStore::open(&dir).expect("open");
    store.revoke(SUBJECT).expect("revoke");
    let built = build(&queue, Some(RevocationSection::from_store(&store)));
    let line = built
        .bundle()
        .limitations
        .iter()
        .find(|l| l.contains("revoked in this STORE's journal"))
        .expect("the revoked arm must be stated");
    // This fixture's subject is NOT DEFAULT_CLI_SUBJECT, so the constant sentence would be a lie.
    assert_ne!(SUBJECT, warrantor_warrant::DEFAULT_CLI_SUBJECT);
    assert!(
        line.contains("was supplied as a string, not an issued SVID"),
        "for a supplied subject the sentence must say so rather than calling it this build's \
         constant principal: {line}"
    );
    assert!(
        !line.contains("is the constant this build records"),
        "the constant clause fired for a subject that is not the constant: {line}"
    );
}

/// `adjudications_between` must be a COUNT, not a decoration.
///
/// Added 2026-09-05 after review. Deviation 5 changed a public design on the grounds that the
/// plan's counter "would have been a hard-coded zero", but the only assertion on the field expected
/// 0 in a test that computes no verdict, so a hard-coded zero satisfied the whole suite: mutating
/// `ADJUDICATIONS.fetch_add` to a no-op left every package test green. This is the test that fails
/// under that mutation.
///
/// `>= 1`, not `== 1`, because `ADJUDICATIONS` is process-global and this binary runs its tests in
/// parallel: another test's `build_observed` can land inside the window. The strict-increase
/// assertion beside it is the exact one, and both fail on a no-op counter.
#[test]
fn adjudications_between_counts_verdicts_rather_than_assuming_zero() {
    let dir = scratch("adjudication-count");
    let queue = queue_at(&dir);
    let mut store = RevocationStore::open(&dir).expect("open");
    let record = store.revoke(SUBJECT).expect("revoke");

    let before = report::adjudications_computed();
    // One verdict, computed through the product's own path, INSIDE the measurement window.
    let _ = build(&queue, Some(RevocationSection::from_store(&store)));
    let after = report::adjudications_computed();
    assert!(
        after > before,
        "build_observed computed a verdict and the counter did not move ({before} -> {after}), so \
         adjudications_between is an assumed zero rather than a count"
    );

    let latency = store.latency(&record);
    assert!(
        latency.adjudications_between >= 1,
        "a verdict was computed between durability and this read, so the count must see it. Got \
         {}, which is the hard-coded zero deviation 5 was written to avoid.",
        latency.adjudications_between,
    );
}

/// An unreadable source must not render as a clean set.
#[test]
fn an_unreadable_source_is_reported_rather_than_read_as_nothing_revoked() {
    let dir = scratch("unreadable");
    let queue = queue_at(&dir);
    let store = RevocationStore::open(&dir).expect("open a fresh (absent) journal");
    // The store validated an absent journal, then the file changed underneath it. That is the only
    // way to reach `source_readable: false`, and it is exactly the case that must not be silent.
    std::fs::write(
        dir.join(warrantor_warrant::revoke::REVOCATION_JOURNAL),
        "{ this is not json }\n",
    )
    .expect("write");

    let section = RevocationSection::from_store(&store);
    assert!(!section.source_readable);
    assert!(
        section.revoked_svids.is_empty(),
        "an unreadable journal yields no subjects; the point is that the report must not call \
         that clean"
    );

    let built = build(&queue, Some(section));
    let line = built
        .bundle()
        .limitations
        .iter()
        .find(|l| l.contains("could NOT be read"))
        .expect("an unreadable source must be stated");
    assert!(
        line.contains("having checked nothing"),
        "the line must tell a reader to treat the report as having checked nothing: {line}"
    );
}

/// The count is a count, not a decoration: two revocations produce two subjects, deduped.
#[test]
fn the_revoked_set_is_the_journal_deduped_and_in_order() {
    let dir = scratch("dedupe");
    let mut store = RevocationStore::open(&dir).expect("open");
    store.revoke("spiffe://example/a").expect("revoke a");
    store.revoke("spiffe://example/b").expect("revoke b");
    store.revoke("spiffe://example/a").expect("revoke a again");

    assert_eq!(
        store.revoked_svids(),
        vec!["spiffe://example/a", "spiffe://example/b"],
        "revocation is monotone and idempotent; a repeated revocation is one subject, not two"
    );
}

// ── the operator surface ──────────────────────────────────────────────────────────────

/// Run `warrantor revoke ...` against a store rooted in `home`.
fn run_revoke(home: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .arg("revoke")
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor revoke");
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), both)
}

#[test]
fn the_cli_lists_what_it_revoked_and_says_what_the_revocation_misses() {
    let home = scratch("cli-list");
    let store_root = home.join(".warrantor");
    std::fs::create_dir_all(&store_root).expect("store root");

    // CONTROL: nothing revoked yet, and the empty answer must not read as a fleet-wide statement.
    let (ok, empty) = run_revoke(&home, &["--list"]);
    assert!(ok, "listing an empty set must succeed: {empty}");
    assert!(
        empty.contains("no subject is revoked"),
        "an empty set must be said, not implied: {empty}"
    );
    // LOCATOR ADAPTED 2026-09-05, and STRENGTHENED: the old assertion accepted a sentence that
    // scoped the answer to the machine. The journal is per store root, so both clauses are now
    // required -- the machine clause was kept, and the store clause added.
    assert!(
        empty.contains("not a statement about any other machine"),
        "even the empty answer must scope itself off other machines: {empty}"
    );
    assert!(
        empty.contains("ONE STORE's journal"),
        "the empty answer must scope itself to the STORE, not the machine: `--root` selects the \
         journal, so a machine-wide claim is an overclaim. Got: {empty}"
    );

    // ATTACK path: record one, then list it.
    let (ok, recorded) = run_revoke(&home, &["--svid", SUBJECT]);
    assert!(ok, "a revocation inside the SLA must exit zero: {recorded}");
    assert!(recorded.contains(SUBJECT), "{recorded}");
    // The WHO clause's locator no longer pins the wrap column ("not WHO\n    revoked it"): the
    // disclosure was rewrapped on 2026-09-05 when the store clause went in, and an assertion on
    // where a sentence happens to break is an assertion about nothing. The CLAIM asserted is
    // unchanged, and the list has GROWN by the store clause -- nothing was removed.
    for required in [
        "does not recall a credential already used",
        "does not propagate to any other machine",
        "reach a SECOND STORE on this same machine",
        "broker does not consult the revocation set",
        "records WHEN a subject was",
        "not WHO revoked it",
    ] {
        assert!(
            recorded.contains(required),
            "the operator surface must state {required:?}. A revocation that does not say what it \
             fails to reach is an intention. Got:\n{recorded}"
        );
    }

    let (ok, listed) = run_revoke(&home, &["--list"]);
    assert!(ok, "{listed}");
    assert!(
        listed.contains(SUBJECT) && listed.contains("[0]"),
        "--list must reflect what --svid recorded, with its sequence: {listed}"
    );
}

/// The past-epoch pair, through the only surface a person can reach it by. Both directions, because a
/// command that answered "revoked" for every epoch would pass the positive half alone.
#[test]
fn the_cli_answers_non_revocation_at_a_past_epoch() {
    let home = scratch("cli-at");
    std::fs::create_dir_all(home.join(".warrantor")).expect("store root");
    let (ok, recorded) = run_revoke(&home, &["--svid", SUBJECT]);
    assert!(ok, "{recorded}");

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .expect("clock");

    // POSITIVE: at a later epoch the subject is revoked.
    let (ok, later) = run_revoke(
        &home,
        &["--at", &(epoch + 3600).to_string(), "--svid", SUBJECT],
    );
    assert!(ok, "{later}");
    assert!(
        later.contains("REVOKED at or before that epoch"),
        "the positive direction: {later}"
    );

    // NEGATIVE, and this is the direction an auditor asks for: an epoch before the record.
    let (ok, before) = run_revoke(
        &home,
        &["--at", &(epoch - 86_400).to_string(), "--svid", SUBJECT],
    );
    assert!(ok, "{before}");
    assert!(
        before.contains("not revoked at that epoch"),
        "a day before the record, the journal must prove NON-revocation. Without this direction \
         the answer is a constant: {before}"
    );
    assert!(
        before.contains("no service was asked"),
        "the answer must say it needed no service, which is the whole of the past-epoch claim: \
         {before}"
    );
}

/// `--at` is a read. It must never leave a record behind, or asking whether a subject was revoked
/// would revoke it.
#[test]
fn asking_about_a_past_epoch_records_nothing() {
    let home = scratch("cli-at-readonly");
    std::fs::create_dir_all(home.join(".warrantor")).expect("store root");
    let (ok, answer) = run_revoke(&home, &["--at", "1", "--svid", SUBJECT]);
    assert!(ok, "{answer}");
    assert!(answer.contains("not revoked at that epoch"), "{answer}");

    let (ok, listed) = run_revoke(&home, &["--list"]);
    assert!(ok, "{listed}");
    assert!(
        listed.contains("no subject is revoked"),
        "a read must not have written a line: {listed}"
    );
}

//! Task 10.1, the product half: the route the report signs is the release order the settle engine
//! will actually run, pinned to the staged log's own chain head.
//!
//! `rust/evidence/tests/causal_verdict.rs` proves the verdict. This proves the *record* -- that the
//! section reaching the signature comes from the real queue, in the real order, and that a signed
//! report is bound to the state of the log it was taken from.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use warrantor_evidence as evidence;
use warrantor_warrant::report::{build, verify_export};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
const ID: &str = "wrt_causal";
const SUBJECT: &str = "spiffe://muveraai.com/agent/alpha";

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-causal-{tag}-{}",
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

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

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
        &SigningKey::from_bytes(&[2; 32]).verifying_key(),
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

/// A PR, a comment on it and a review on it, staged in that order. The release order and the
/// staging order are the same here -- and, today, they are the same for every queue: `stage`
/// refuses a dependency on a handle it has not minted, so no fixture CAN stage a dependent before
/// its dependency. `a_dependency_on_a_handle_nobody_minted_is_refused_at_stage_so_the_release_order_is_the_staging_order`
/// pins that, rather than this comment promising an "interesting case" that the API does not allow.
fn queue_with_three_hops(dir: &Path) -> StagingQueue {
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
        .stage(
            "github.request_review",
            args(&[("target", &pr.handle), ("reviewer", "alice")]),
            NOW,
        )
        .expect("review");
    queue
}

/// Just the PR. A second hop count for the rendered-sentence test, so a count written into the
/// sentence by hand cannot agree with both fixtures.
fn queue_with_one_hop(dir: &Path) -> StagingQueue {
    let mut queue =
        StagingQueue::open(dir.join("q.jsonl"), ID, EffectRegistry::github()).expect("open");
    queue
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("pr");
    queue
}

/// The invariant `causal_trace`'s choice of `release_order` rests on, pinned rather than asserted
/// in a doc comment: a hop that depends on a handle no earlier hop minted is refused at `stage`,
/// so dependencies always point backward and the release order is the staging order. The
/// mutation-review lane (2026-09-06) found that rendering the staging order instead survives every
/// test; it survives because the two orders cannot differ through this API, and this is the test
/// that goes red first if `stage` ever starts accepting a forward reference.
#[test]
fn a_dependency_on_a_handle_nobody_minted_is_refused_at_stage_so_the_release_order_is_the_staging_order(
) {
    let dir = tempdir("forward");
    let mut queue =
        StagingQueue::open(dir.join("q.jsonl"), ID, EffectRegistry::github()).expect("open");
    let error = queue
        .stage(
            "github.comment",
            args(&[("target", "pr://staged/wrt_causal/1"), ("body", "early")]),
            NOW,
        )
        .expect_err("a comment on a PR that has not been staged yet must be refused at stage");
    assert!(
        error.to_string().contains("was not issued by this warrant"),
        "the refusal must say the handle was never minted, got: {error}"
    );
    assert!(
        queue.is_empty(),
        "a refused stage writes nothing to the log"
    );

    // Now the well-formed queue, on the same log: the trace, the release order and the staging
    // order are one sequence of handles.
    let queue = queue_with_three_hops(&dir);
    let staged: Vec<&str> = queue.effects().iter().map(|e| e.handle.as_str()).collect();
    let release: Vec<&str> = queue
        .release_order()
        .expect("order")
        .into_iter()
        .map(|e| e.handle.as_str())
        .collect();
    let traced: Vec<String> = queue
        .causal_trace()
        .expect("trace")
        .into_iter()
        .map(|s| s.handle)
        .collect();
    assert_eq!(
        release, staged,
        "dependencies point backward, so the orders coincide"
    );
    assert_eq!(traced, staged);
}

#[test]
fn the_trace_is_the_release_order_with_indices_that_are_their_own_positions() {
    let dir = tempdir("order");
    let queue = queue_with_three_hops(&dir);
    let steps = queue.causal_trace().expect("trace");

    let release: Vec<&str> = queue
        .release_order()
        .expect("order")
        .into_iter()
        .map(|e| e.handle.as_str())
        .collect();
    let traced: Vec<&str> = steps.iter().map(|s| s.handle.as_str()).collect();
    assert_eq!(
        traced, release,
        "the signed route must be the order settle will run, not the order the agent happened to \
         stage in"
    );

    for (position, step) in steps.iter().enumerate() {
        assert_eq!(
            step.index,
            position as u64 + 1,
            "causal_verdict gates the index against its position, so causal_trace has to number \
             hops by position in the release order"
        );
    }
    assert_eq!(steps[1].depends_on, vec![steps[0].handle.clone()]);
}

#[test]
fn the_section_carries_the_queues_own_chain_head_and_count() {
    let dir = tempdir("head");
    let queue = queue_with_three_hops(&dir);
    let section = queue.causality().expect("section");
    assert_eq!(section.queue_head, queue.head_digest());
    assert_eq!(section.step_count, 3);
    assert_eq!(section.steps.len(), 3);
    evidence::causal_verdict_pinned(&predicate_carrying(&section), queue.head_digest())
        .expect("a section read from a granted queue passes against that queue");
}

/// The tamper-evidence claim, exercised rather than asserted in prose: once one more effect is
/// staged the chain head has moved, and the section signed earlier no longer describes the log in
/// front of the reader. It is refused by name.
#[test]
fn a_section_signed_before_the_log_grew_is_refused_against_the_grown_log() {
    let dir = tempdir("grew");
    let mut queue = queue_with_three_hops(&dir);
    let earlier = queue.causality().expect("section");

    // The control first: against the log as it stood, the section passes.
    evidence::causal_verdict_pinned(&predicate_carrying(&earlier), queue.head_digest())
        .expect("the control must pass, or the refusal below proves nothing");

    let pr = queue.effects()[0].handle.clone();
    queue
        .stage(
            "github.add_label",
            args(&[("target", &pr), ("label", "urgent")]),
            NOW + 1,
        )
        .expect("label");

    match evidence::causal_verdict_pinned(&predicate_carrying(&earlier), queue.head_digest()) {
        Err(evidence::CausalRefusal::QueueHeadMismatch { recorded, observed }) => {
            assert_eq!(recorded, earlier.queue_head);
            assert_eq!(observed, queue.head_digest());
        }
        other => panic!("a moved chain head must be refused by name, got {other:?}"),
    }
}

/// End to end: the exported report's evidence receipt carries the route, declares v2, and still
/// verifies offline. This is the wiring assertion -- the types existing proves nothing about the
/// product using them.
#[test]
fn the_exported_reports_evidence_receipt_carries_the_route_and_declares_its_version() {
    let dir = tempdir("export");
    let warrant = warrant_with_tools(&[
        "github.create_pr",
        "github.comment",
        "github.request_review",
    ]);
    let queue = queue_with_three_hops(&dir);
    let signed = build(
        &stored_from(&warrant),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
    )
    .sign(&issuer(), "issuer")
    .expect("sign");

    verify_export(&signed).expect("the export verifies offline");

    let predicate = &signed.evidence_receipt.predicate;
    assert_eq!(
        predicate.predicate_version.as_deref(),
        Some(evidence::PREDICATE_TYPE),
        "a receipt carrying a route must say which rule reads it"
    );
    let section = predicate
        .causality
        .as_ref()
        .expect("the report receipt carries the route");
    assert_eq!(section.queue_head, queue.head_digest());
    assert_eq!(section.step_count, 3);

    // `Outcome.effects` was `Vec::new()` before this task. It now names the staged handles, and it
    // is derived from the same trace, so the two lists cannot disagree.
    let effects = &predicate.outcome.as_ref().expect("outcome").effects;
    let handles: Vec<String> = section.steps.iter().map(|s| s.handle.clone()).collect();
    assert_eq!(effects, &handles);

    // And the verdict over it passes, because every staged tool is inside this warrant's bounds.
    evidence::causal_verdict_pinned(predicate, queue.head_digest())
        .expect("every hop is granted, so the route is clean");
}

/// The F-02 shape reached through the product rather than a hand-built predicate: a warrant that
/// grants two of the three tools, an agent that stages all three. The notary's Authority gate
/// already denies on the union, and the causal verdict additionally names **which hop**.
#[test]
fn a_warrant_missing_one_tool_yields_a_causal_refusal_naming_that_hop() {
    let dir = tempdir("ungranted");
    let warrant = warrant_with_tools(&["github.create_pr", "github.request_review"]);
    let queue = queue_with_three_hops(&dir);
    let signed = build(
        &stored_from(&warrant),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
    )
    .sign(&issuer(), "issuer")
    .expect("sign");

    // The export still verifies: verification is about integrity, not about the verdict. A report
    // recording a denial has to keep verifying, or a denial could be made to look like tampering.
    verify_export(&signed).expect("an export recording a denial still verifies");
    assert!(
        !signed.bundle.authority_check.allowed,
        "the notary's own gate 5 already denies on the union of staged tools"
    );

    match evidence::causal_verdict(&signed.evidence_receipt.predicate) {
        Err(evidence::CausalRefusal::UnauthorizedHop {
            index,
            handle,
            tool,
        }) => {
            assert_eq!(tool, "github.comment");
            assert_eq!(index, 2, "and it names WHICH hop, which gate 5 cannot");
            assert!(handle.starts_with("comment://"));
        }
        other => panic!("the ungranted hop must be named, got {other:?}"),
    }
}

/// An unreadable queue leaves the section absent, so the causal verdict over that receipt refuses
/// as unrepresentable instead of passing -- and the bundle says so in `limitations`.
#[test]
fn an_unreadable_queue_produces_no_route_and_the_bundle_says_so() {
    let warrant = warrant_with_tools(&["github.create_pr"]);
    let signed = build(
        &stored_from(&warrant),
        Err("the staged log could not be read".to_string()),
        &issuer().verifying_key(),
        NOW,
    )
    .sign(&issuer(), "issuer")
    .expect("sign");

    verify_export(&signed).expect("verifies");
    let predicate = &signed.evidence_receipt.predicate;
    assert!(predicate.causality.is_none());
    assert!(
        predicate.predicate_version.is_none(),
        "a receipt with no route stays v1, so its canonical bytes are the shape every earlier \
         reader already knows"
    );
    assert!(matches!(
        evidence::causal_verdict(predicate),
        Err(evidence::CausalRefusal::Unrepresentable { .. })
    ));
    assert!(
        signed
            .bundle
            .limitations
            .iter()
            .any(|l| l.contains("No staged route was read")),
        "the reader of the bundle has to be told the route was not read: {:?}",
        signed.bundle.limitations
    );
}

/// The exact sentence a signed bundle carries over a route of `hops` hops pinned to `head`.
///
/// A golden, kept in this file rather than imported from the product, because the point is that a
/// change to the shipped wording has to change this file too and so show up in review. The
/// mutation-review lane (2026-09-06) showed the earlier fragment checks were not enough: a count
/// hard-coded as `3` matched the only fixture, and an Enforced-tier claim appended after the
/// honest fragments shipped inside the signed bundle with every suite green.
fn expected_causal_sentence(hops: usize, head: &str) -> String {
    format!(
        "No causal verdict was computed when this report was built, and `verify_export` \
         computes none. A reader computes it with `warrantor_evidence::causal_verdict` over \
         `evidence_receipt.predicate`, which records the staged-effect order this notary \
         read -- {hops} hop(s), pinned to staged-log chain head {head}. The signature over that \
         record makes the recorded pathway tamper-evident to a reader who verifies it: an \
         operator without the issuer key cannot rewrite the route undetected. An operator holding \
         the issuer key can re-sign a different route, and nothing in this bundle shows that it \
         happened; the verdict then judges whatever route was signed. It does **not** prove the \
         recorded route is the route the agent actually took. Effects reach that record by being \
         STAGED, and nothing intercepts the agent at each hop, so a route that never passed \
         through the staging queue is invisible here. Ordering is this machine's observation of \
         its own queue and not a distributed guarantee: two Warrantor installations produce two \
         independent orders and nothing reconciles them."
    )
}

/// The bundle's rendered caveat is derived from the section, not written beside it, and it is
/// exactly the approved sentence: the hop count and the chain head are the section's own values,
/// checked over two different hop counts, and nothing is written after the last full stop.
#[test]
fn the_bundles_causal_sentence_is_rendered_from_the_section_it_describes() {
    let warrant = warrant_with_tools(&[
        "github.create_pr",
        "github.comment",
        "github.request_review",
    ]);
    for hops in [1usize, 3] {
        let dir = tempdir(&format!("sentence-{hops}"));
        let queue = match hops {
            1 => queue_with_one_hop(&dir),
            _ => queue_with_three_hops(&dir),
        };
        assert_eq!(queue.len(), hops, "the fixture stages {hops} hop(s)");
        let signed = build(
            &stored_from(&warrant),
            Ok(&queue),
            &issuer().verifying_key(),
            NOW,
        )
        .sign(&issuer(), "issuer")
        .expect("sign");

        let sentence = signed
            .bundle
            .limitations
            .iter()
            .find(|l| l.contains("makes the recorded pathway tamper-evident"))
            .expect("the causal caveat is in the bundle");
        assert_eq!(
            sentence,
            &expected_causal_sentence(hops, queue.head_digest()),
            "over {hops} hop(s) the bundle must carry exactly the approved sentence, with this \
             queue's own count and chain head and nothing appended"
        );
    }
}

/// A predicate carrying `section`, for the pinned-verdict checks above. Built here rather than
/// through `build`+`sign` because those tests are about the section against a queue, and a
/// hand-built predicate keeps them from depending on the report path.
fn predicate_carrying(section: &evidence::Causality) -> evidence::WarPredicate {
    let chain = vec![evidence::DelegationLink {
        issuer: "spiffe://issuer".to_string(),
        subject: SUBJECT.to_string(),
        capabilities: vec![
            "github.add_label".to_string(),
            "github.comment".to_string(),
            "github.create_pr".to_string(),
            "github.request_review".to_string(),
        ],
        not_before: NOW,
        not_after: NOW + 3600,
        token_digest: "sha256:tok".to_string(),
    }];
    evidence::WarPredicate {
        predicate_version: Some(evidence::PREDICATE_TYPE.to_string()),
        binding: evidence::Binding {
            receipt_id: "rcpt-causal".to_string(),
            phase: evidence::Phase::Atomic,
            parent_receipt: None,
            nonce: "AAAAAAAAAAAAAAAAAAAAAA==".to_string(),
            issued_at: NOW,
            expires_at: NOW + 3600,
            enforcement_mode: evidence::EnforcementMode::Advisory,
        },
        actor: evidence::Actor {
            principal: SUBJECT.to_string(),
            workload_id: SUBJECT.to_string(),
            svid_digest: "sha256:svid".to_string(),
        },
        authority: evidence::Authority {
            effective_capabilities: evidence::recompute_intersection(&chain),
            intersection_proof: evidence::compute_intersection_proof(&chain),
            chain,
        },
        decision: evidence::Decision {
            verdict: evidence::Verdict::Allow,
            engine: "warrantor-notary/1.0".to_string(),
            policy_digest: "sha256:pol".to_string(),
            evaluated_at: NOW,
        },
        operation: evidence::Operation {
            class: "warrant.report".to_string(),
            target: ID.to_string(),
            method: "report".to_string(),
            parameters_digest: "sha256:para".to_string(),
            reversible: true,
            consequence_tier: evidence::ConsequenceTier::Routine,
        },
        outcome: Some(evidence::Outcome {
            status: "success".to_string(),
            outcome_digest: "sha256:out".to_string(),
            effects: section.steps.iter().map(|s| s.handle.clone()).collect(),
            error: None,
            rollback_pointer: None,
        }),
        causality: Some(section.clone()),
    }
}

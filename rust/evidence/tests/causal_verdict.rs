//! F-02: "right result, wrong route" is a violation.
//!
//! The blueprint's proof gate for L7-01 is *"produce a correct outcome by an unauthorized route and
//! assert the verdict is a violation, per effect class."* This suite is that gate.
//!
//! # What each refusal here actually proves, and what it does not
//!
//! Every check in [`warrantor_evidence::causal_verdict`] is computed from the **signed predicate
//! itself** -- the authority block's recomputed intersection, and the ordering relation among the
//! steps. Nothing is taken on the record's word: there is deliberately no `authorized: bool` on a
//! step, because a field that *declares* the answer is a field an attacker who can re-sign simply
//! sets to `true`. That is why every refusal below is re-run against a **validly re-signed**
//! forgery: a check that only survives because the attacker could not sign is a check on the
//! signature, not on the pathway.
//!
//! What none of it proves is that the recorded route is the route the agent took. See the tier
//! table in `docs/task-evidence/task-10.1.md`.

use warrantor_evidence::{
    causal_verdict, causal_verdict_pinned, generate_keypair, issue_atomic, Actor, Authority,
    Binding, CausalRefusal, CausalStep, Causality, ConsequenceTier, Decision, DelegationLink,
    EnforcementMode, EvidenceError, Operation, Outcome, Phase, Verdict, WarPredicate,
    PREDICATE_TYPE,
};

// ── the fixture: a three-hop GitHub chain, exactly the blueprint's example ────────────

const CREATE_PR: &str = "github.create_pr";
const COMMENT: &str = "github.comment";
const REQUEST_REVIEW: &str = "github.request_review";

const PR_HANDLE: &str = "pr://staged/wrt_f02/1";
const COMMENT_HANDLE: &str = "comment://staged/wrt_f02/2";
const REVIEW_HANDLE: &str = "review://staged/wrt_f02/3";

/// An authority block granting exactly `capabilities`, with a recomputable intersection proof.
fn authority_granting(capabilities: &[&str]) -> Authority {
    let chain = vec![DelegationLink {
        issuer: "spiffe://yourcorp/issuer".to_string(),
        subject: "spiffe://yourcorp/agents/bot-1".to_string(),
        capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
        not_before: 1_786_000_000,
        not_after: 1_786_003_600,
        token_digest: "sha256:c0ffee".to_string(),
    }];
    Authority {
        effective_capabilities: warrantor_evidence::recompute_intersection(&chain),
        intersection_proof: warrantor_evidence::compute_intersection_proof(&chain),
        chain,
    }
}

fn step(index: u64, handle: &str, tool: &str, depends_on: &[&str]) -> CausalStep {
    CausalStep {
        index,
        handle: handle.to_string(),
        tool: tool.to_string(),
        depends_on: depends_on.iter().map(|h| (*h).to_string()).collect(),
    }
}

/// The three-hop route: open a PR, comment on it, request review on it.
fn three_hop_steps() -> Vec<CausalStep> {
    vec![
        step(1, PR_HANDLE, CREATE_PR, &[]),
        step(2, COMMENT_HANDLE, COMMENT, &[PR_HANDLE]),
        step(3, REVIEW_HANDLE, REQUEST_REVIEW, &[PR_HANDLE]),
    ]
}

const QUEUE_HEAD: &str = "9f1c0d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";

fn causality_over(steps: Vec<CausalStep>) -> Causality {
    Causality {
        queue_head: QUEUE_HEAD.to_string(),
        step_count: steps.len() as u64,
        steps,
    }
}

/// An atomic predicate whose outcome is a **success** -- the "right result" half of F-02.
fn predicate(granted: &[&str], causality: Option<Causality>) -> WarPredicate {
    let effects = causality
        .as_ref()
        .map(|c| c.steps.iter().map(|s| s.handle.clone()).collect())
        .unwrap_or_default();
    WarPredicate {
        predicate_version: causality.as_ref().map(|_| PREDICATE_TYPE.to_string()),
        binding: Binding {
            receipt_id: "rcpt-f02".to_string(),
            phase: Phase::Atomic,
            parent_receipt: None,
            nonce: "AAAAAAAAAAAAAAAAAAAAAA==".to_string(),
            issued_at: 1_786_000_000,
            expires_at: 1_786_003_600,
            enforcement_mode: EnforcementMode::Advisory,
        },
        actor: Actor {
            principal: "spiffe://yourcorp/agents/bot-1".to_string(),
            workload_id: "spiffe://yourcorp/agents/bot-1".to_string(),
            svid_digest: "sha256:5v1d".to_string(),
        },
        authority: authority_granting(granted),
        decision: Decision {
            verdict: Verdict::Allow,
            engine: "warrantor-notary/1.0".to_string(),
            policy_digest: "sha256:po11cy".to_string(),
            evaluated_at: 1_786_000_000,
        },
        operation: Operation {
            class: "warrant.settle".to_string(),
            target: "wrt_f02".to_string(),
            method: "settle".to_string(),
            parameters_digest: "sha256:para".to_string(),
            reversible: true,
            consequence_tier: ConsequenceTier::Routine,
        },
        outcome: Some(Outcome {
            // The right result. Every refusal below happens over a predicate that says the action
            // succeeded, which is the whole point of the gate: the outcome is permitted and the
            // route is not.
            status: "success".to_string(),
            outcome_digest: "sha256:0utc0me".to_string(),
            effects,
            error: None,
            rollback_pointer: None,
        }),
        causality,
    }
}

// ── Step 4: the unauthorized hop, and its allowed control ─────────────────────────────

/// The F-02 gate itself. All three hops succeed, the outcome is `success`, and the *middle* hop
/// uses a tool the warrant never granted. The union of tools is not the question; the hop is.
#[test]
fn a_correct_outcome_reached_through_an_ungranted_middle_hop_is_a_violation() {
    let attacked = predicate(
        &[CREATE_PR, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    match causal_verdict(&attacked) {
        Err(CausalRefusal::UnauthorizedHop {
            index,
            ref handle,
            ref tool,
        }) => {
            assert_eq!(index, 2, "the refusal must name WHICH hop, by index");
            assert_eq!(handle, COMMENT_HANDLE, "and which handle");
            assert_eq!(tool, COMMENT, "and which tool");
            let rendered = causal_verdict(&attacked).unwrap_err().to_string();
            assert!(
                rendered.contains(COMMENT_HANDLE) && rendered.contains(COMMENT),
                "a refusal reading 'the chain is bad' is not auditable; it must name the handle \
                 and the tool. Got: {rendered}"
            );
            assert!(
                rendered.contains("hop 2"),
                "and the hop index in the prose, got: {rendered}"
            );
        }
        other => panic!(
            "an ungranted middle hop under a successful outcome must be a violation, got {other:?}"
        ),
    }
}

/// The allowed control, in the same file and over the same chain: grant all three tools and the
/// identical route passes. Without this, a verdict that refused everything would score green above.
#[test]
fn the_identical_chain_with_every_hop_granted_passes() {
    let control = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    causal_verdict(&control)
        .expect("a route whose every hop is inside the granted intersection must pass");
}

/// Every `SideEffectClass`, built from an exhaustive `match` rather than written down beside the
/// enum: the enum exposes no `ALL` constant or iterator, so a list would go stale silently when a
/// class is added, whereas a `match` with no wildcard arm stops compiling (E0004) at the arm the new
/// class needs. The chain is walked from the first variant, so every arm's successor is in the list.
fn every_effect_class() -> Vec<warrantor_authority_spec::SideEffectClass> {
    use warrantor_authority_spec::SideEffectClass::{
        self, Destructive, Financial, Physical, Read, Write,
    };
    fn successor(class: SideEffectClass) -> Option<SideEffectClass> {
        match class {
            Read => Some(Write),
            Write => Some(Financial),
            Financial => Some(Destructive),
            Destructive => Some(Physical),
            Physical => None,
        }
    }
    let mut classes = vec![Read];
    while let Some(next) = successor(*classes.last().expect("non-empty")) {
        classes.push(next);
    }
    classes
}

/// F-02 says *per effect class*. The refusal must fire for each class in the `SideEffectClass`
/// taxonomy rather than only for the Write-shaped GitHub example -- with the paired grant proving
/// each class can also pass. What this establishes, stated exactly: `causal_verdict` compares tool
/// names against the recomputed capability intersection and never reads a class, so the refusal is
/// class-blind by construction, and this loop shows that no class-named tool is treated differently
/// from any other. The list it walks is derived from the enum by [`every_effect_class`].
#[test]
fn the_refusal_fires_for_every_effect_class_and_the_grant_lets_each_through() {
    let classes = every_effect_class();
    assert_eq!(
        classes.len(),
        5,
        "the taxonomy this task was written against has five classes"
    );
    for class in classes {
        let middle = format!("effect.{}", class.as_str());
        let steps = vec![
            step(1, PR_HANDLE, CREATE_PR, &[]),
            step(2, COMMENT_HANDLE, &middle, &[PR_HANDLE]),
            step(3, REVIEW_HANDLE, REQUEST_REVIEW, &[PR_HANDLE]),
        ];

        let attacked = predicate(
            &[CREATE_PR, REQUEST_REVIEW],
            Some(causality_over(steps.clone())),
        );
        match causal_verdict(&attacked) {
            Err(CausalRefusal::UnauthorizedHop {
                index, ref tool, ..
            }) => {
                assert_eq!(index, 2, "class {class:?}: the middle hop is hop 2");
                assert_eq!(tool, &middle, "class {class:?}: the refusal names the tool");
            }
            other => panic!("class {class:?} must refuse an ungranted hop, got {other:?}"),
        }

        let control = predicate(
            &[CREATE_PR, &middle, REQUEST_REVIEW],
            Some(causality_over(steps)),
        );
        causal_verdict(&control)
            .unwrap_or_else(|e| panic!("class {class:?} must pass when granted, got {e:?}"));
    }
}

// ── Step 4: order broken, and its allowed control ─────────────────────────────────────

/// A hop depending on a handle no earlier hop minted. The outcome still says `success`, every tool
/// is granted, and the route is still incoherent: the comment is attached to a pull request that
/// does not exist yet at that point in the order.
#[test]
fn a_hop_depending_on_a_handle_no_earlier_hop_minted_is_a_violation() {
    let steps = vec![
        step(1, PR_HANDLE, CREATE_PR, &[]),
        step(2, COMMENT_HANDLE, COMMENT, &["pr://staged/wrt_f02/99"]),
        step(3, REVIEW_HANDLE, REQUEST_REVIEW, &[PR_HANDLE]),
    ];
    let attacked = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(steps)),
    );
    match causal_verdict(&attacked) {
        Err(CausalRefusal::OrderBroken { index, ref missing }) => {
            assert_eq!(index, 2);
            assert_eq!(missing, "pr://staged/wrt_f02/99");
            let rendered = causal_verdict(&attacked).unwrap_err().to_string();
            assert!(
                rendered.contains("pr://staged/wrt_f02/99") && rendered.contains("hop 2"),
                "the refusal must name the missing handle and the hop, got: {rendered}"
            );
        }
        other => panic!("a dangling dependency must be a violation, got {other:?}"),
    }
}

/// The allowed control for the ordering check: the same three hops with a real dependency pass.
#[test]
fn a_well_formed_order_passes() {
    let control = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    causal_verdict(&control).expect("dependencies before dependents must pass");
}

/// The order is what makes the verdict mean anything, so a *reversal* is a violation even when both
/// hops are individually granted and both handles exist somewhere in the list.
#[test]
fn swapping_two_hops_so_a_dependent_precedes_its_dependency_is_a_violation() {
    let mut steps = three_hop_steps();
    steps.swap(0, 1);
    let attacked = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(steps)),
    );
    match causal_verdict(&attacked) {
        Err(CausalRefusal::OrderBroken { index, ref missing }) => {
            assert_eq!(
                index, 2,
                "the comment now sits at list position 1 and still carries index 2; the refusal \
                 must report the step's own recorded index, not its position after the swap"
            );
            assert_eq!(missing, PR_HANDLE);
        }
        other => panic!("a dependent before its dependency must be a violation, got {other:?}"),
    }
}

// ── the declared count, checked against the list it counts ────────────────────────────

/// `step_count` is a rendered number inside a signed body, so it is gated against the list it
/// describes rather than trusted beside it.
#[test]
fn a_declared_step_count_that_disagrees_with_the_steps_is_a_violation() {
    let mut causality = causality_over(three_hop_steps());
    causality.step_count = 2;
    let attacked = predicate(&[CREATE_PR, COMMENT, REQUEST_REVIEW], Some(causality));
    match causal_verdict(&attacked) {
        Err(CausalRefusal::CountMismatch { declared, actual }) => {
            assert_eq!(declared, 2);
            assert_eq!(actual, 3);
        }
        other => panic!("a miscounted chain must be a violation, got {other:?}"),
    }
}

/// A step whose recorded index does not match its position is a violation: the index is what every
/// other refusal in this file names, so an index that means nothing makes them unauditable.
#[test]
fn a_step_whose_recorded_index_is_not_its_position_is_a_violation() {
    let mut steps = three_hop_steps();
    steps[1].index = 7;
    let attacked = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(steps)),
    );
    match causal_verdict(&attacked) {
        Err(CausalRefusal::IndexBroken { position, declared }) => {
            assert_eq!(position, 2);
            assert_eq!(declared, 7);
        }
        other => panic!("a mislabeled index must be a violation, got {other:?}"),
    }
}

// ── the two verdicts are independent ─────────────────────────────────────────────────

/// The notary's verdict and the causal verdict answer different questions, and a single field could
/// not carry both without losing which one refused. A `Deny` outcome over a clean route still
/// passes the causal check: the route was fine, the policy said no.
#[test]
fn a_denied_outcome_over_a_clean_route_still_passes_the_causal_verdict() {
    let mut clean = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    clean.decision.verdict = Verdict::Deny;
    clean.outcome.as_mut().unwrap().status = "denied".to_string();
    causal_verdict(&clean).expect(
        "the causal verdict is about the route. A denial is the notary's answer, and folding the \
         two together would lose which one refused.",
    );
    assert_eq!(
        clean.decision.verdict,
        Verdict::Deny,
        "and the notary's answer is untouched"
    );
}

/// The converse: an `Allow` outcome over a broken route is refused. Together with the test above,
/// this is what "genuinely independent" means -- each verdict can differ from the other in either
/// direction.
#[test]
fn an_allowed_outcome_over_a_broken_route_is_refused() {
    let attacked = predicate(
        &[CREATE_PR, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    assert_eq!(attacked.decision.verdict, Verdict::Allow);
    assert!(causal_verdict(&attacked).is_err());
}

// ── Step 6: the signature protects the order, and so does the verdict ─────────────────

/// First half of the ordering guarantee: an *editor* who reorders the steps in a signed predicate
/// breaks the signature, because `steps` is a `Vec` whose index order goes through
/// `canonical_predicate` into the signed bytes.
#[test]
fn reordering_the_steps_of_a_signed_predicate_breaks_the_signature() {
    let (signing, _) = generate_keypair();
    let receipt = issue_atomic(
        predicate(
            &[CREATE_PR, COMMENT, REQUEST_REVIEW],
            Some(causality_over(three_hop_steps())),
        ),
        &signing,
        "notary-1",
    );
    warrantor_evidence::verify_receipt(&receipt).expect("the control verifies before the attack");

    let mut edited = receipt.clone();
    edited
        .predicate
        .causality
        .as_mut()
        .expect("the v2 predicate carries a causality section")
        .steps
        .swap(0, 1);
    assert!(
        matches!(
            warrantor_evidence::verify_receipt(&edited),
            Err(EvidenceError::InvalidSignature)
        ),
        "the effect order is inside the signature; an editor must break it"
    );
}

/// The half that actually matters. An attacker who holds *a* valid key re-signs the reordered
/// predicate, so the forgery's own signature verifies -- and `causal_verdict` must still refuse it.
///
/// Without this test the one above would be a test of Ed25519, not of the causal verdict: an
/// unsigned forgery is refused for being unsigned and never reaches the gate under test.
#[test]
fn a_validly_re_signed_reordering_verifies_and_the_causal_verdict_still_refuses_it() {
    let (attacker, _) = generate_keypair();
    let mut forged = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    forged
        .causality
        .as_mut()
        .expect("the v2 predicate carries a causality section")
        .steps
        .swap(0, 1);
    // `issue_atomic` is the crate's ordinary signing path and the forged predicate satisfies every
    // invariant it asserts, so the attacker needs nothing this crate does not already offer any
    // holder of a key. That is the point: the forgery is signed the normal way.
    let receipt = issue_atomic(forged, &attacker, "attacker-key");

    warrantor_evidence::verify_receipt(&receipt).expect(
        "the forgery's OWN signature must verify, or this test proves nothing about the causal \
         verdict",
    );
    match causal_verdict(&receipt.predicate) {
        Err(CausalRefusal::OrderBroken { index, .. }) => assert_eq!(index, 2),
        other => panic!(
            "a validly signed reordering must still be refused by the causal verdict, got {other:?}"
        ),
    }
}

/// And the same attacker key over the *unswapped* predicate produces a receipt that both verifies
/// and passes the causal verdict, so the refusal above is about the order and not about the key.
#[test]
fn the_same_attacker_key_over_an_unswapped_predicate_verifies_and_passes() {
    let (attacker, _) = generate_keypair();
    let honest = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    let receipt = issue_atomic(honest, &attacker, "attacker-key");
    warrantor_evidence::verify_receipt(&receipt).expect("verifies under its own key");
    causal_verdict(&receipt.predicate).expect("and the route is clean");
}

// ── Step 5: the section is pinned to the queue it was read from ──────────────────────

/// `queue_head` pins the section to the hash-chained staged log rather than to a re-listing of it.
/// A predicate whose head does not match the queue the reader holds is refused.
#[test]
fn a_causality_section_whose_queue_head_does_not_match_the_observed_queue_is_refused() {
    let pinned = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    match causal_verdict_pinned(
        &pinned,
        "0000000000000000000000000000000000000000000000000000000000000000",
    ) {
        Err(CausalRefusal::QueueHeadMismatch {
            ref recorded,
            ref observed,
        }) => {
            assert_eq!(recorded, QUEUE_HEAD);
            assert_eq!(
                observed,
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
        }
        other => panic!("a head mismatch must be refused, got {other:?}"),
    }
}

/// The matching pair verifies. Same predicate, the head the section actually records.
#[test]
fn the_matching_queue_head_passes() {
    let pinned = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    causal_verdict_pinned(&pinned, QUEUE_HEAD).expect("the recorded head is the observed head");
}

// ── Step 7: v1 is a named refusal, not a pass ────────────────────────────────────────

/// Restated here as well as in `v1_predicates_still_verify.rs`, because this is the file a reader
/// opens to learn what the causal verdict does with a receipt that has no route in it.
#[test]
fn a_predicate_with_no_causality_section_is_unrepresentable_rather_than_clean() {
    let v1 = predicate(&[CREATE_PR, COMMENT, REQUEST_REVIEW], None);
    match causal_verdict(&v1) {
        Err(CausalRefusal::Unrepresentable {
            ref predicate_version,
        }) => {
            assert_eq!(predicate_version, "absent");
        }
        other => panic!("a v1 predicate must be Unrepresentable, got {other:?}"),
    }
}

/// A v2 predicate whose section is present but **empty** is a different claim from an absent one,
/// which is why the field is `Option` rather than a defaulted empty struct. An empty route is a
/// coherent record of a warrant that staged nothing, and it passes.
#[test]
fn an_empty_but_present_causality_section_is_a_pass_and_not_unrepresentable() {
    let empty = predicate(&[CREATE_PR], Some(causality_over(Vec::new())));
    causal_verdict(&empty).expect(
        "a queue that was read and was empty is a different claim from a queue that was never \
         read, and only the second is Unrepresentable",
    );
}

/// A section that is PRESENT under a version this build has no rule for is `Uninterpretable` --
/// never `Unrepresentable`, whose message says "carries no causality section", and never a pass.
/// Two records reach this refusal: a version this build does not know, and no version at all beside
/// a section. The mutation-review lane (2026-09-06) deleted the `Uninterpretable` branch and every
/// suite stayed green, because nothing exercised it; this is the test that now goes red.
#[test]
fn a_causality_section_under_a_version_this_build_cannot_read_is_uninterpretable_not_a_pass() {
    // A clean three-hop route, so a build that read it under the v2 rule anyway would PASS it --
    // which is exactly the silent outcome this refusal exists to prevent.
    let mut newer = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    newer.predicate_version = Some("https://warrantor.dev/ActionReceipt/v9".to_string());
    match causal_verdict(&newer) {
        Err(CausalRefusal::Uninterpretable {
            ref predicate_version,
        }) => {
            assert_eq!(predicate_version, "https://warrantor.dev/ActionReceipt/v9");
            let rendered = causal_verdict(&newer).unwrap_err().to_string();
            assert!(
                rendered.contains("carries a causality section")
                    && !rendered.contains("no causality section"),
                "the message must be true of a record that HAS a section, got: {rendered}"
            );
        }
        other => panic!("a route under an unknown version must be Uninterpretable, got {other:?}"),
    }
    assert!(
        matches!(
            causal_verdict_pinned(&newer, QUEUE_HEAD),
            Err(CausalRefusal::Uninterpretable { .. })
        ),
        "the pinned form reads the section before comparing heads, so it refuses the same way"
    );

    // No version beside a section: nothing says which rule reads it, so it is not read.
    let mut unversioned = predicate(
        &[CREATE_PR, COMMENT, REQUEST_REVIEW],
        Some(causality_over(three_hop_steps())),
    );
    unversioned.predicate_version = None;
    match causal_verdict(&unversioned) {
        Err(CausalRefusal::Uninterpretable {
            ref predicate_version,
        }) => assert_eq!(predicate_version, "absent"),
        other => panic!("a section with no version must be Uninterpretable, got {other:?}"),
    }
}

// ── no claim without a mechanism ─────────────────────────────────────────────────────

/// Rule 3 as a test, stated exactly: this is a **denylist of phrases**, not a semantic guard. It
/// fails when one of the listed phrases appears in any `.rs` file under `rust/`; a proof or
/// enforcement claim in other words passes it. Commit `d78c8b8`'s message said it "fails if any .rs
/// file ever claims the pathway is proven or enforced", which overstated it (claim-honesty review,
/// 2026-09-06). The sentence the signed bundle carries is held exactly, not by this list, by
/// `the_bundles_causal_sentence_is_rendered_from_the_section_it_describes` in
/// `rust/warrant/tests/causal_trace.rs`; this list is the backstop for source text elsewhere, and
/// it now includes the phrasings the review lane used to walk past the first five.
#[test]
fn no_source_file_under_rust_claims_the_pathway_is_proven_or_enforced() {
    let root = repository_root();
    let forbidden = [
        "prove the pathway",
        "pathway proven",
        "route verified",
        "causally enforced",
        "proves the pathway",
        "pathway is enforced",
        "pathway enforced",
        "pathway was enforced",
        "pathway is proven",
        "pathway was proven",
        "pathway is verified",
        "pathway verified",
        "route is proven",
        "route proven",
        "route was proven",
        "route is verified",
        "route is enforced",
        "route enforced",
        "route was enforced",
        "prove the route",
        "proves the route",
        "hop was enforced",
        "enforced at the moment of attempt",
    ];
    let mut offenders: Vec<String> = Vec::new();
    let mut stack = vec![root.join("rust")];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).expect("rust/ is readable") {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let source = std::fs::read_to_string(&path).expect("readable source");
                let lowered = source.to_lowercase();
                for phrase in forbidden {
                    // This file names the phrases in order to forbid them, so it is the one
                    // exception -- stated rather than silently skipped by a path glob.
                    if lowered.contains(phrase) && !path.ends_with("causal_verdict.rs") {
                        offenders.push(format!("{}: {phrase}", path.display()));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the causal verdict makes a recorded route tamper-evident; it does not prove a pathway. \
         These files claim otherwise: {offenders:?}"
    );
}

/// The other half: the honest sentence is actually in the product's `limitations()`, so a reader of
/// a signed bundle is told what the verdict does not establish.
#[test]
fn the_products_limitations_carry_the_tamper_evident_sentence_rather_than_a_proof_claim() {
    let report = unwrap_rust_string_continuations(
        &std::fs::read_to_string(repository_root().join("rust/warrant/src/report.rs"))
            .expect("report.rs is readable"),
    );
    for fragment in [
        "No causal verdict was computed when this report was built",
        "makes the recorded pathway tamper-evident",
        "An operator holding the issuer key can re-sign a different route",
        "does **not** prove the recorded route is the route the agent actually took",
        "not a distributed guarantee",
    ] {
        assert!(
            report.contains(fragment),
            "rust/warrant/src/report.rs must carry {fragment:?} in limitations(). A bound whose \
             caveat is only in a design document is a bound the reader of the bundle never learns \
             about."
        );
    }
    assert!(
        !report.contains("The causal verdict is computed"),
        "the product never computes the verdict, so the bundle must not say it does (the first \
         shipped wording did, in the present tense)"
    );
}

/// Collapse Rust's `\`-at-end-of-line string continuations, which eat the newline and the next
/// line's indentation.
///
/// Without this a source-text assertion is really an assertion about where `rustfmt` happened to
/// wrap the sentence, and it would go red on a reflow that changed nothing a reader sees.
fn unwrap_rust_string_continuations(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'\n') {
            chars.next();
            while chars.peek().is_some_and(|n| *n == ' ' || *n == '\r') {
                chars.next();
            }
            continue;
        }
        if c == '\\' && chars.peek() == Some(&'\r') {
            chars.next();
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            while chars.peek().is_some_and(|n| *n == ' ') {
                chars.next();
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn repository_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is rust/evidence; the repository root is two levels up.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("rust/evidence sits two levels below the repository root")
        .to_path_buf()
}

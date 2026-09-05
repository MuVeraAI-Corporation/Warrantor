//! I-04 — No consequential action without current policy.
//!
//! > Policy is re-evaluated at commit time, not just at start.
//!
//! The notary evaluates policy on every call, so a second call with a flipped decision denies.
//! What the corpus finds is that the product makes exactly one such call per action, and that the
//! post-commit receipt copies the pre-commit's `decision` block verbatim — so the evidence for a
//! commit-time evaluation would attest to an evaluation that did not happen.

use crate::{fixture, harness, scenario};
use warrantor_evidence as evidence;
use warrantor_notary as notary;

// -- static ---------------------------------------------------------------------------

#[test]
fn the_policy_gate_is_declared_as_evaluated_now() {
    assert_eq!(fixture::invariant("I-04").id, "I-04");
    harness::source_contains(
        "rust/notary/src/lib.rs",
        "// Gate 8 — Policy (I-04). Evaluated now; never cached across actions.",
        "The Policy gate's contract is that it is never cached; the comment is the only place \
         that contract is written down.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_policy_denial_refuses_the_action() {
    let mut context = scenario::allowed_context();
    context.policy_decision = false;
    let verdict = notary::verdict(&scenario::allowed_request(), &context);
    scenario::assert_denied_at(&verdict, notary::Gate::Policy, "policy returning deny");
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn a_policy_that_changes_after_the_start_check_denies_at_the_second_evaluation() {
    // The attack is time, not a payload: pass the start check, then act after the policy is
    // withdrawn. The identical request is evaluated twice; only the context moves.
    let request = scenario::allowed_request();
    let at_start = notary::verdict(&request, &scenario::allowed_context());

    let mut at_commit_context = scenario::allowed_context();
    at_commit_context.policy_decision = false;
    let at_commit = notary::verdict(&request, &at_commit_context);

    harness::refused_at_the_boundary(
        "a policy withdrawn between the start check and the commit",
        &at_start,
        &at_commit,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(&at_commit, notary::Gate::Policy, "a withdrawn policy");
}

#[test]
fn an_indeterminate_policy_is_a_denial_rather_than_a_pass() {
    // `policy_decision` is a bool, so "the engine could not be reached" and "the engine said no"
    // arrive as the same value. That is the correct collapse for a fail-closed system, and this
    // test locks it: false must never be readable as "unknown, proceed".
    let mut context = scenario::allowed_context();
    context.policy_decision = false;
    let verdict = notary::verdict(&scenario::allowed_request(), &context);
    assert!(
        !verdict.is_allow(),
        "an unavailable policy engine must deny; indeterminate is denial",
    );
}

// -- evidence field -------------------------------------------------------------------

/// FINDING (I-04, partial). `evidence::issue_post_commit` clones the pre-commit predicate and
/// changes only `phase`, `parent_receipt` and `outcome`. The `decision` block — verdict, engine,
/// policy digest and `evaluated_at` — is carried across unchanged, so a post-commit receipt
/// asserts a policy evaluation timestamped at the *start* of the action. The evidence for I-04 is
/// structurally incapable of showing that policy was re-evaluated at commit time, which is exactly
/// the clause I-04 adds over "check policy once".
///
/// Fixed by: Task 2.3 (two-phase staged effects for every syscall), which is where a commit-time
/// decision acquires a place to live. Recorded 2026-09-02.
#[test]
#[ignore = "I-04 partial: post-commit receipts copy the pre-commit decision block, so no commit-time evaluation is provable (Task 2.3, 2026-09-02)"]
fn the_post_commit_receipt_records_its_own_policy_evaluation() {
    let (key, _) = evidence::generate_keypair();
    let pre_commit = evidence::issue_pre_commit(
        scenario::predicate(evidence::Phase::PreCommit),
        &key,
        "corpus-i04",
    );
    let post_commit =
        evidence::issue_post_commit(&pre_commit, scenario::outcome(), &key, "corpus-i04");

    evidence::verify_chain(&pre_commit, &post_commit).expect("the control chain verifies");

    assert_ne!(
        post_commit.predicate.decision.evaluated_at, pre_commit.predicate.decision.evaluated_at,
        "the post-commit receipt reports the pre-commit's evaluation time, so nothing in the \
         evidence distinguishes 'policy still held at commit' from 'policy held when we started'",
    );
}

// -- finding --------------------------------------------------------------------------

/// FINDING (I-04, partial). The shipped binary reaches the notary exactly once per action, from
/// `report.rs`. One evaluation cannot be both the start check and the commit check, so the clause
/// that distinguishes I-04 from an ordinary policy check is unenforced in the product even though
/// the gate implementing it is correct.
///
/// Fixed by: Task 2.3 (two-phase staged effects), which introduces the commit point. Recorded
/// 2026-09-02.
#[test]
#[ignore = "I-04 partial: one notary call per action, so policy is never re-evaluated at commit (Task 2.3, 2026-09-02)"]
fn the_product_evaluates_policy_more_than_once_per_action() {
    let calls = harness::occurrences_in_rust_sources("rust/warrant/src", "notary::verdict(");
    assert!(
        calls > 1,
        "the warrant crate calls notary::verdict {calls} time(s). I-04 requires an evaluation at \
         commit as well as at start.",
    );
}

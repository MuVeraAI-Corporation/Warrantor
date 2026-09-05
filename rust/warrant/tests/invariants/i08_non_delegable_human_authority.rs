//! I-08 — Critical actions require non-delegable human authority.
//!
//! > A defined class of actions (financial transfer, destructive op, physical actuation) require a
//! > human approval in the chain.
//!
//! Two validators claim this invariant and they check different things. The notary's Approval gate
//! requires an approval that is both valid and non-delegable, which is the stronger reading and it
//! holds. `authority_spec::validate` requires only that `approvals` is non-empty, so a delegated
//! approval, a self-issued approval, or a list containing one empty string all satisfy it.
//!
//! Neither checks the word the invariant leans hardest on. Nothing anywhere binds an approval to a
//! human: `notary::Approval` is two booleans supplied by the caller, and an agent that can set
//! them approves its own critical action.

use crate::{fixture, harness, scenario};
use warrantor_authority_spec::SideEffectClass;
use warrantor_notary as notary;

/// A critical action carrying the approval described.
fn critical_request(approval: Option<notary::Approval>) -> notary::VerdictRequest {
    let mut request = scenario::allowed_request();
    request.operation.class = "funds.transfer".to_string();
    request.operation.consequence_tier = notary::ConsequenceTier::Critical;
    request.approval = approval;
    request
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_consequential_classes_are_the_ones_the_invariant_names() {
    assert_eq!(fixture::invariant("I-08").id, "I-08");
    // The invariant names financial transfer, destructive op and physical actuation. The code's
    // consequential set must be exactly those three: a fourth would extend the invariant silently
    // and a missing one would exempt a class the architecture says is covered.
    assert!(SideEffectClass::Financial.is_consequential());
    assert!(SideEffectClass::Destructive.is_consequential());
    assert!(SideEffectClass::Physical.is_consequential());
    assert!(!SideEffectClass::Read.is_consequential());
    assert!(!SideEffectClass::Write.is_consequential());

    harness::source_contains(
        "rust/notary/src/lib.rs",
        "/// I-08: critical action without valid, non-delegable human approval.",
        "The Approval gate must stay labeled with the invariant it serves.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_critical_action_with_no_approval_is_refused() {
    let verdict = notary::verdict(&critical_request(None), &scenario::allowed_context());
    scenario::assert_denied_at(
        &verdict,
        notary::Gate::Approval,
        "a critical action with no approval",
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn an_approval_that_was_itself_delegated_does_not_satisfy_the_gate() {
    // The attack the invariant is named for: obtain an approval, then delegate the *approving*
    // authority onward so the agent can approve its own next critical action. The control is the
    // same critical action with a non-delegable approval, which proves the request reaches gate 9
    // rather than dying at one of the eight before it.
    let control = notary::verdict(
        &critical_request(Some(notary::Approval {
            valid: true,
            non_delegable: true,
        })),
        &scenario::allowed_context(),
    );
    let attacked = notary::verdict(
        &critical_request(Some(notary::Approval {
            valid: true,
            non_delegable: false,
        })),
        &scenario::allowed_context(),
    );

    harness::refused_at_the_boundary(
        "an approval whose authority was delegated onward",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &attacked,
        notary::Gate::Approval,
        "a delegated approval on a critical action",
    );
}

#[test]
fn an_invalid_approval_does_not_satisfy_the_gate() {
    let control = notary::verdict(
        &critical_request(Some(notary::Approval {
            valid: true,
            non_delegable: true,
        })),
        &scenario::allowed_context(),
    );
    let attacked = notary::verdict(
        &critical_request(Some(notary::Approval {
            valid: false,
            non_delegable: true,
        })),
        &scenario::allowed_context(),
    );

    harness::refused_at_the_boundary(
        "an approval marked invalid",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_receipt_records_that_approval_was_the_gate_that_refused() {
    let request = critical_request(None);
    let verdict = notary::verdict(&request, &scenario::allowed_context());

    let (signing_key, _) = notary::generate_keypair();
    let receipt = notary::issue_receipt(
        &verdict,
        &request,
        notary::EnforcementMode::Observed,
        &signing_key,
        "corpus-i08",
    );
    notary::verify_receipt(&receipt).expect("the corpus receipt verifies");
    assert_eq!(
        receipt.body.verdict,
        notary::Verdict::Deny {
            gate: notary::Gate::Approval
        },
    );
    assert_eq!(receipt.body.operation_class, "funds.transfer");
}

// -- findings -------------------------------------------------------------------------

/// FINDING (I-08, partial). `authority_spec::validate` step 4 reads
/// `if class.is_consequential() && envelope.approvals.is_empty()`. Emptiness is the whole test: a
/// list containing one empty string satisfies it, as does an approval the subject issued to
/// itself, as does an approval whose authority was delegated. The notary's gate is stricter, and
/// the two validators are reached by different callers, so the weaker one is the system's real
/// floor wherever it is the only one on the path.
///
/// Fixed by: Task 4.1 (approval queue with a latency budget and default-deny timeout) and
/// Task 3.3 (operator device-key binding in settle records), which is where an approval acquires
/// something to be checked against. Recorded 2026-09-02.
#[test]
#[ignore = "I-08 partial: authority-spec accepts any non-empty approvals list (Task 3.3 / Task 4.1, 2026-09-02)"]
fn the_envelope_validator_checks_more_than_the_presence_of_an_approval() {
    let source = harness::read_repository_file("rust/authority-spec/src/lib.rs");
    assert!(
        !source.contains("if class.is_consequential() && envelope.approvals.is_empty()"),
        "the AAE validator's I-08 check is an emptiness test. It cannot distinguish a human \
         approval from a string, so the clause 'non-delegable human authority' is unenforced \
         there.",
    );
}

/// FINDING (I-08, partial). `notary::Approval` is `{ valid: bool, non_delegable: bool }` and both
/// are supplied by the caller. Nothing identifies the approver, binds the approval to a device or
/// a key, or distinguishes a person from the agent requesting the action. I-08's operative word is
/// *human*, and there is no field in which humanness could be recorded, let alone checked.
///
/// Fixed by: Task 3.3 (operator device-key binding in settle records). Recorded 2026-09-02.
#[test]
#[ignore = "I-08 partial: an approval carries no approver identity, so humanness is unrepresentable (Task 3.3, 2026-09-02)"]
fn an_approval_names_the_human_who_gave_it() {
    let approval = notary::Approval {
        valid: true,
        non_delegable: true,
    };
    let json = serde_json::to_value(approval).expect("the approval serializes");
    let fields = json.as_object().expect("the approval is an object");
    assert!(
        fields.contains_key("approver") || fields.contains_key("approver_key"),
        "an approval is two booleans the requester supplies. An agent that constructs the request \
         constructs its own approval, so nothing in the type system or the gate keeps a human in \
         the chain. Keys present: {:?}",
        fields.keys().collect::<Vec<_>>(),
    );
}

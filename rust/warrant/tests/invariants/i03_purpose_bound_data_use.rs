//! I-03 — Purpose-bound data use.
//!
//! > Data tagged with a purpose in CPE (P3) is only used for that purpose; violation fails-closed.
//!
//! # The finding, stated first
//!
//! This invariant has no implementation. Not a weak one — none. There is no purpose tag on any
//! request, no data class on any bound, no provenance label on any receipt, and no code path that
//! could fail closed on a purpose mismatch because there is nothing to compare. The architecture
//! doc names its enforcer as "(future context comps)", which is the honest form of the same
//! statement, and the marketing surface does not repeat that parenthesis.
//!
//! Three of round zero's ten hops land here — shared-cache observation, the directory-name
//! channel, and the template-injection RCE — which makes I-03 the single largest gap the corpus
//! measures. The suite below encodes each hop against a real API and demonstrates that nothing
//! refuses it.

use crate::{fixture, harness, scenario};
use std::collections::{BTreeMap, BTreeSet};
use warrantor_evidence as evidence;
use warrantor_notary as notary;
use warrantor_warrant::proxy::ToolCall;
use warrantor_warrant::{egress, SideEffectClass, WarrantBounds};

fn bounds(tools: &[&str], hosts: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        staged_classes: BTreeSet::new(),
        expires_at: scenario::NOW + 3_600,
        budget_cents_observed: None,
        delegation_depth: 0,
    }
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_absence_of_an_implementation_is_recorded_in_the_ledger() {
    // This test passes, and it is the load-bearing one. It pins two facts together: that no Rust
    // source implements I-03, and that the delivery-gaps ledger says so. Implement the invariant
    // without updating the ledger and it fails; delete the ledger entry while the invariant is
    // still absent and it fails. The finding cannot go quiet in either direction.
    assert_eq!(
        fixture::invariant("I-03").enforced_primarily_by,
        "(future context comps), all egress paths"
    );

    let references = harness::occurrences_in_rust_sources("rust", "I-03")
        - harness::occurrences_in_rust_sources("rust/warrant/tests/invariants", "I-03");
    let ledger = harness::read_repository_file("docs/W1-delivery-gaps.md");
    if references == 0 {
        assert!(
            ledger.contains("invariant-corpus:I-03"),
            "no Rust source implements I-03 and the ledger does not record that. An invariant \
             the product publishes and does not implement must be named in \
             docs/W1-delivery-gaps.md.",
        );
    } else {
        assert!(
            !ledger.contains("invariant-corpus:I-03"),
            "I-03 now has {references} implementation references; close the ledger entry and \
             convert this suite's ignored tests to real assertions.",
        );
    }
}

// -- runtime --------------------------------------------------------------------------

/// FINDING (I-03, unimplemented). The request the authorization decision is made from carries no
/// purpose and no data class, so the decision cannot be purpose-bound whatever the policy says.
/// Serializing the real request type is the check: a field that is not on the wire cannot be
/// evaluated.
///
/// Fixed by: no task in the 2026-09-02 implementation plan. Plane 5 is recorded there as "filled
/// by adopted work rather than new invention", and no adoption has happened. Recorded 2026-09-02.
#[test]
#[ignore = "I-03 unimplemented: no purpose field on the authorization request; no plan task fixes it (2026-09-02)"]
fn the_authorization_request_carries_a_purpose() {
    let request = scenario::allowed_request();
    let json = serde_json::to_value(&request).expect("the request serializes");
    let operation = json
        .get("operation")
        .and_then(|value| value.as_object())
        .expect("the request has an operation");
    assert!(
        operation.contains_key("purpose") || operation.contains_key("data_classes"),
        "the operation the notary adjudicates names no purpose and no data class, so I-03 has \
         nothing to bind against. Keys present: {:?}",
        operation.keys().collect::<Vec<_>>(),
    );
}

// -- adversarial ----------------------------------------------------------------------

/// FINDING (I-03, unimplemented). Round zero, hop 2: shared-cache observation. Two warrants
/// granting the same tools for entirely different purposes are indistinguishable to every check in
/// the system, so the delegation test that decides whether one may act under the other's authority
/// cannot see the difference.
///
/// Fixed by: no task in the 2026-09-02 plan. Recorded 2026-09-02.
#[test]
#[ignore = "I-03 unimplemented: bounds carry no purpose, so hop 2 is invisible to the boundary (2026-09-02)"]
fn hop_02_a_shared_cache_read_for_another_purpose_is_refused() {
    // The control: a narrower grant is contained by a wider one, which is the real behavior of
    // this API and proves the attack reaches the check rather than erroring earlier.
    let wide = bounds(&["read_file", "write_file"], &[]);
    let narrow = bounds(&["read_file"], &[]);
    assert!(
        wide.contains(&narrow).is_ok(),
        "control: a narrower grant must be contained by a wider one",
    );

    // The attack: an identical grant issued for a different purpose. Under I-03 the second must
    // not inherit the first's data access. Nothing in WarrantBounds records a purpose, so the two
    // are byte-identical and `contains` says yes.
    let for_reviewing_my_own_work = bounds(&["read_file"], &[]);
    let for_reading_another_tenants_cache = bounds(&["read_file"], &[]);
    assert!(
        for_reviewing_my_own_work
            .contains(&for_reading_another_tenants_cache)
            .is_err(),
        "hop 2: a grant issued for one purpose contains a grant issued for another, because \
         WarrantBounds has no purpose dimension at all",
    );
}

#[test]
fn hop_03_a_directory_name_channel_is_invisible_to_the_egress_boundary() {
    // Round zero, hop 3: the incident's agents signaled each other through directory names.
    //
    // This test PASSES, and what it asserts is the finding: the egress boundary sees hosts and
    // nothing else. The control proves the scanner works -- a call naming an http destination is
    // found and adjudicated. The attack carries the same payload in a path component, and the
    // scanner returns nothing, so no verdict is ever reached and no refusal is ever recorded.
    //
    // Encoded as a passing assertion rather than an ignored one because the absence is exact and
    // permanent until a channel census exists: Task 3.6 (improvised-channel detection and the
    // shared-surface census) is where this becomes detectable. Recorded 2026-09-02.
    let mut control_arguments = BTreeMap::new();
    control_arguments.insert(
        "url".to_string(),
        "https://exfil.example.com/beacon".to_string(),
    );
    let control = egress::destinations_of(&ToolCall {
        tool: "http.get".to_string(),
        arguments: control_arguments,
        side_effect: SideEffectClass::Read,
    });
    assert_eq!(
        control.len(),
        1,
        "control: a destination named in an argument must be found, or this test proves nothing",
    );
    assert_eq!(control[0].host, "exfil.example.com");

    let mut attacked_arguments = BTreeMap::new();
    attacked_arguments.insert(
        "path".to_string(),
        "./work/beacon-exfil-example-com-payload-7f3a/".to_string(),
    );
    let attacked = egress::destinations_of(&ToolCall {
        tool: "fs.mkdir".to_string(),
        arguments: attacked_arguments,
        side_effect: SideEffectClass::Write,
    });
    assert!(
        attacked.is_empty(),
        "hop 3: the directory-name channel is currently invisible to the egress boundary. If this \
         now finds a destination, the channel census exists -- convert this test to a refusal \
         assertion and raise the ratchet. Found: {attacked:?}",
    );
}

/// FINDING (I-03, unimplemented). Round zero, hop 10: template-injection RCE. Untrusted content
/// became a trusted instruction. The receipt records a digest of the parameters but no label for
/// where the content driving the action came from, so a reviewer reading the evidence cannot tell
/// an operator-authored instruction from an injected one.
///
/// Fixed by: Task 2.6 (provenance labels on tool outputs and peer-proposal admission).
/// Recorded 2026-09-02.
#[test]
#[ignore = "I-03 unimplemented: receipts carry no provenance label for what drove the action (Task 2.6, 2026-09-02)"]
fn hop_10_the_receipt_labels_the_provenance_of_what_drove_the_action() {
    let operation = evidence::Operation {
        class: "corpus.probe".to_string(),
        target: "local".to_string(),
        method: "render_template".to_string(),
        parameters_digest: "00".repeat(32),
        reversible: false,
        consequence_tier: evidence::ConsequenceTier::Routine,
    };
    let json = serde_json::to_value(&operation).expect("the operation serializes");
    let fields = json.as_object().expect("the operation is an object");
    assert!(
        fields.contains_key("provenance") || fields.contains_key("input_labels"),
        "the receipt's operation block records what was done but not where the instruction came \
         from, so an injected instruction and an operator's instruction are indistinguishable in \
         the evidence. Keys present: {:?}",
        fields.keys().collect::<Vec<_>>(),
    );
}

// -- evidence field -------------------------------------------------------------------

/// FINDING (I-03, unimplemented). The WAR predicate has eight sections and none of them carries a
/// purpose. I-03's evidence field does not exist, so even a purpose-bound decision taken elsewhere
/// could not be proved after the fact.
///
/// Fixed by: no task in the 2026-09-02 plan. Recorded 2026-09-02.
#[test]
#[ignore = "I-03 unimplemented: the WAR predicate has no purpose field (2026-09-02)"]
fn the_receipt_carries_the_purpose_the_data_was_tagged_with() {
    let predicate = scenario::predicate(evidence::Phase::PreCommit);
    let json = serde_json::to_value(&predicate).expect("the predicate serializes");
    let sections = json.as_object().expect("the predicate is an object");
    assert!(
        sections.contains_key("purpose") || sections.contains_key("context_rights"),
        "the WAR predicate's sections are {:?}; none of them records the purpose that I-03 binds \
         data use to, so a purpose-bound decision could not be proved after the fact",
        sections.keys().collect::<Vec<_>>(),
    );
}

// -- the gate this suite must not fake ------------------------------------------------

#[test]
fn the_notary_has_no_purpose_gate_and_does_not_pretend_to() {
    // A passing guard against the worst outcome for this invariant: somebody adding a gate named
    // for purpose that is fed a caller-supplied boolean, which would let the ledger promote I-03
    // while nothing is bound to anything. Nine gates today; a tenth must arrive with a suite.
    assert_eq!(
        notary::Gate::in_order().len(),
        9,
        "the notary grew a gate. If it is a purpose gate, this suite's ignored tests must be \
         converted and the I-03 ledger entry closed -- not merely renumbered.",
    );
}

//! I-10 — Replay is detectable.
//!
//! > Every action carries a nonce + timestamp; replays outside the window are rejected.
//!
//! The Freshness gate implements both halves: a seen nonce denies, and a timestamp outside the
//! window denies in either direction, so neither a stale replay nor a future-dated request gets
//! through. The finding is that the nonce set is a `Vec<String>` the caller supplies and the
//! product's one caller supplies an empty one, on every call, with no store behind it. Detection
//! requires memory, and there is none.

use crate::{fixture, harness, scenario};
use warrantor_evidence as evidence;
use warrantor_notary as notary;

// -- static ---------------------------------------------------------------------------

#[test]
fn the_freshness_gate_is_declared_against_this_invariant() {
    assert_eq!(fixture::invariant("I-10").id, "I-10");
    harness::source_contains(
        "rust/notary/src/lib.rs",
        "/// I-10: nonce reused, timestamp outside window, clock skew.",
        "The Freshness gate must stay labeled with the invariant it serves.",
    );
    assert_eq!(
        notary::Gate::in_order()[2],
        notary::Gate::Freshness,
        "freshness is gate 3: a replayed request must be refused before its authority is \
         recomputed, so a replay cannot be adjudicated on its merits",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_timestamp_outside_the_window_is_refused_in_both_directions() {
    let window = scenario::FRESHNESS_WINDOW_SECONDS;

    let mut stale = scenario::allowed_request();
    stale.timestamp = scenario::NOW - window - 1;
    scenario::assert_denied_at(
        &notary::verdict(&stale, &scenario::allowed_context()),
        notary::Gate::Freshness,
        "a request older than the window",
    );

    let mut future_dated = scenario::allowed_request();
    future_dated.timestamp = scenario::NOW + window + 1;
    scenario::assert_denied_at(
        &notary::verdict(&future_dated, &scenario::allowed_context()),
        notary::Gate::Freshness,
        "a request dated beyond the window",
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn a_captured_request_replayed_verbatim_is_refused() {
    // The whole attack: capture a request that was allowed, send the identical bytes again. The
    // control is the first send, which must be allowed — otherwise the second refusal is about a
    // malformed request rather than about replay.
    let request = scenario::allowed_request();
    let first = notary::verdict(&request, &scenario::allowed_context());

    // The only thing that changed is that the notary has now seen this nonce.
    let mut after_first = scenario::allowed_context();
    after_first.seen_nonces = vec![request.nonce.clone()];
    let replayed = notary::verdict(&request, &after_first);

    harness::refused_at_the_boundary(
        "a request replayed verbatim after it was allowed",
        &first,
        &replayed,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(&replayed, notary::Gate::Freshness, "a replayed nonce");
}

#[test]
fn a_replay_with_a_refreshed_timestamp_is_still_refused_on_the_nonce() {
    // The obvious evasion: the attacker updates the timestamp to land inside the window, betting
    // the check is really a clock check. The nonce is the half that survives that.
    let request = scenario::allowed_request();
    let control = notary::verdict(&request, &scenario::allowed_context());

    let mut refreshed = request.clone();
    refreshed.timestamp = scenario::NOW + 1;
    let mut after_first = scenario::allowed_context();
    after_first.seen_nonces = vec![request.nonce.clone()];
    let attacked = notary::verdict(&refreshed, &after_first);

    harness::refused_at_the_boundary(
        "a replay whose timestamp was refreshed to sit inside the window",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &attacked,
        notary::Gate::Freshness,
        "a replayed nonce with a fresh timestamp",
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_receipt_carries_the_nonce_that_makes_the_replay_visible() {
    let predicate = scenario::predicate(evidence::Phase::PreCommit);
    let (key, _) = evidence::generate_keypair();
    let receipt = evidence::issue_pre_commit(predicate, &key, "corpus-i10");
    evidence::verify_receipt(&receipt).expect("the corpus receipt verifies");

    let json = serde_json::to_value(&receipt).expect("the receipt serializes");
    let binding = json
        .get("predicate")
        .and_then(|predicate| predicate.get("binding"))
        .and_then(|binding| binding.as_object())
        .expect("the receipt carries a binding");
    assert!(
        binding
            .get("nonce")
            .and_then(|value| value.as_str())
            .is_some_and(|nonce| !nonce.is_empty()),
        "the nonce is I-10's evidence field: without it in the record, a reviewer holding two \
         receipts cannot tell a repeat from a replay",
    );
    assert!(binding.contains_key("issued_at"));
}

// -- finding --------------------------------------------------------------------------

/// FINDING (I-10, partial). `report.rs` constructs its `VerdictContext` with
/// `seen_nonces: Vec::new()`. Every call is the first call. The Freshness gate is correct and it
/// is being asked whether a nonce appears in an empty set, so the answer is always no and no
/// replay is detectable on the product's own path.
///
/// The gate's other half still bites — the timestamp window is computed against a real clock — so
/// a replay outside the window is refused. A replay *inside* the window is not, and the window is
/// the interval an attacker chooses to work in.
///
/// Fixed by: Task 1.1 (evidence and notary into the report path) for a nonce store, and Task 3.4
/// (broker-side flight recorder behind a `Recorder` trait) for one that survives a restart.
/// Recorded 2026-09-02.
#[test]
#[ignore = "I-10 partial: seen_nonces is hardcoded empty in report.rs, so no replay is detectable (Task 1.1 / Task 3.4, 2026-09-02)"]
fn the_product_remembers_the_nonces_it_has_already_seen() {
    let report = harness::read_repository_file("rust/warrant/src/report.rs");
    assert!(
        !report.contains("seen_nonces: Vec::new()"),
        "the Freshness gate is asked to find a replayed nonce in an empty set, so I-10's \
         detection clause governs nothing the product does.",
    );
}

//! A stranger recomputes an agent's standing from the serialized event record alone.
//!
//! The unit tests in `src/lib.rs` cover each function. This file exercises the crate the way a
//! consumer would — through `warrantor_reputation::*` only — which is the path that did not exist
//! while the crate sat outside the workspace: an integration target is compiled only by
//! `cargo test --all-targets`, and only for workspace members.

use warrantor_reputation::{
    aggregate, verify_event, ReputationEvent, ReputationPolicy, ReputationReport, TrustTier,
};

const ONE_DAY_MS: u64 = 86_400_000;

fn policy() -> ReputationPolicy {
    ReputationPolicy {
        half_life_ms: ONE_DAY_MS,
        floor: -100,
        ceil: 100,
        high_at: 50,
        medium_at: 20,
        low_at: 1,
    }
}

#[test]
fn a_stranger_recomputes_the_same_standing_from_the_serialized_record() {
    let issued = vec![
        ReputationEvent::new("clean_audit", 40, 0, "auditor-a"),
        ReputationEvent::new("clean_audit", 30, ONE_DAY_MS, "auditor-b"),
        ReputationEvent::new("violation", -5, 2 * ONE_DAY_MS, "auditor-a"),
    ];
    let now_ms = 2 * ONE_DAY_MS;
    let report_at_issuer = aggregate(&issued, &policy(), now_ms);

    let record = serde_json::to_string(&issued).expect("events serialize");
    let received: Vec<ReputationEvent> = serde_json::from_str(&record).expect("events deserialize");
    assert!(received.iter().all(verify_event));
    let report_at_stranger = aggregate(&received, &policy(), now_ms);

    assert_eq!(report_at_stranger, report_at_issuer);
    // 40 two half-lives old -> 10; 30 one half-life old -> 15; -5 fresh -> -5; sum 20 -> Medium.
    assert_eq!(
        report_at_stranger,
        ReputationReport {
            score: 20,
            tier: TrustTier::Medium,
            contributing: 3,
            decayed_away: 0,
            total: 3,
        }
    );
}

#[test]
fn a_tampered_record_fails_verification_before_it_is_scored() {
    let issued = vec![ReputationEvent::new("violation", -60, 0, "auditor-a")];
    let record = serde_json::to_string(&issued).expect("events serialize");
    // An agent laundering its own record: flip the sign of a violation in transit.
    let laundered = record.replace("\"weight\":-60", "\"weight\":60");
    assert_ne!(laundered, record, "the fixture must change the wire form");
    let received: Vec<ReputationEvent> =
        serde_json::from_str(&laundered).expect("a laundered record still parses");
    assert!(!verify_event(&received[0]));
    assert_eq!(
        received[0].weight, 60,
        "the digest, not the parser, is what catches it"
    );
}

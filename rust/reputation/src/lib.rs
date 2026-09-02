//! # warrantor-reputation (H-4 / catalogue Domain H)
//!
//! Agent reputation computed from signed events alone: time-decayed, clamped aggregation of weighted
//! attestations, violations, and dispute outcomes into a score and a trust tier.
//!
//! ## Why this component exists
//!
//! The identity graph (H-1) assembles an agent's dossier from signed records but explicitly *does not
//! compute reputation* — it links the events; H-4 scores them. That separation is the point: reputation is
//! not something Warrantor asserts about an agent, it is something a stranger *derives* from the receipt
//! record. A buyer evaluating whether to transact with an unknown agent can recompute its standing from the
//! same signed events, without trusting Warrantor's opinion or the agent's self-report. Decay matters
//! because a clean audit from three years ago should not outrank last week's violation; clamping matters
//! because an unbounded score is gameable by spamming small positive events.
//!
//! ## What it does
//!
//! A [`ReputationEvent`](rust/reputation/src/lib.rs) is a signed, weighted occurrence; a
//! [`ReputationPolicy`](rust/reputation/src/lib.rs) sets the decay half-life, the score clamp, and the tier
//! thresholds. [`reputation_score`](rust/reputation/src/lib.rs) sums each event's weight after exponential
//! (halving) decay and clamps to the policy band; [`aggregate`](rust/reputation/src/lib.rs) returns a
//! [`ReputationReport`](rust/reputation/src/lib.rs) with the score, its [`TrustTier`](rust/reputation/src/lib.rs),
//! and how many events still contribute versus have decayed away.
//!
//! ## What it does NOT do
//!
//! It does not verify the signatures behind the events — each event arrives already attested (the digest is
//! a content fingerprint); H-1's stranger-verification covers provenance. It does not decide what weight a
//! given `kind` deserves (that is the event producer's policy); it aggregates what it is handed. It reads no
//! wall clock — `now_ms` is caller-supplied, so scoring is deterministic and testable.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A signed, weighted reputation-relevant occurrence attached to an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationEvent {
    /// Event class (e.g. "clean_audit", "violation", "dispute_lost").
    pub kind: String,
    /// Signed weight: positive raises standing, negative lowers it.
    pub weight: i32,
    /// When the event occurred, in milliseconds.
    pub at_ms: u64,
    /// The issuer whose attestation produced the event.
    pub issuer_id: String,
    /// `sha256:` digest over the canonical JSON of the event content (excludes this field).
    pub digest: String,
}

impl ReputationEvent {
    /// Build a signed event, computing its content digest.
    #[must_use]
    pub fn new(kind: &str, weight: i32, at_ms: u64, issuer_id: &str) -> ReputationEvent {
        let digest = event_digest(kind, weight, at_ms, issuer_id);
        ReputationEvent {
            kind: kind.to_string(),
            weight,
            at_ms,
            issuer_id: issuer_id.to_string(),
            digest,
        }
    }
}

/// The decay, clamp, and tiering parameters for a reputation computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationPolicy {
    /// Age (ms) at which an event's contribution halves; `0` disables decay.
    pub half_life_ms: u64,
    /// Lower clamp on the aggregate score.
    pub floor: i64,
    /// Upper clamp on the aggregate score.
    pub ceil: i64,
    /// Score at or above which the tier is `High`.
    pub high_at: i64,
    /// Score at or above which the tier is `Medium`.
    pub medium_at: i64,
    /// Score at or above which the tier is `Low`.
    pub low_at: i64,
}

/// The trust band a score falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// At or below the low threshold — not yet trusted.
    Untrusted,
    /// Some positive standing.
    Low,
    /// Established standing.
    Medium,
    /// Strong standing.
    High,
}

/// The result of aggregating a set of events under a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationReport {
    /// The clamped aggregate score.
    pub score: i64,
    /// The tier the score maps to.
    pub tier: TrustTier,
    /// Events whose decayed contribution was non-zero.
    pub contributing: usize,
    /// Events that have decayed fully away (contribution zero).
    pub decayed_away: usize,
    /// Total events considered.
    pub total: usize,
}

/// Compute the `sha256:` content digest of a payload.
fn content_digest(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Recompute an event's digest from its content fields.
#[must_use]
pub fn event_digest(kind: &str, weight: i32, at_ms: u64, issuer_id: &str) -> String {
    let content = serde_json::json!({
        "kind": kind,
        "weight": weight,
        "at_ms": at_ms,
        "issuer_id": issuer_id,
    });
    content_digest(&serde_json::to_string(&content).unwrap_or_default())
}

/// Whether an event's stored digest matches its recomputed content.
#[must_use]
pub fn verify_event(event: &ReputationEvent) -> bool {
    event.digest == event_digest(&event.kind, event.weight, event.at_ms, &event.issuer_id)
}

/// An event's contribution after exponential (per-half-life) decay, preserving sign.
#[must_use]
pub fn decayed_weight(event: &ReputationEvent, policy: &ReputationPolicy, now_ms: u64) -> i32 {
    if policy.half_life_ms == 0 {
        return event.weight;
    }
    let age = now_ms.saturating_sub(event.at_ms);
    let halves = age / policy.half_life_ms;
    let mag = event.weight.unsigned_abs();
    let decayed = if halves >= 32 { 0 } else { mag >> halves };
    if event.weight < 0 {
        -(decayed as i32)
    } else {
        decayed as i32
    }
}

/// The clamped aggregate score of a set of events at `now_ms`.
#[must_use]
pub fn reputation_score(events: &[ReputationEvent], policy: &ReputationPolicy, now_ms: u64) -> i64 {
    let raw: i64 = events
        .iter()
        .map(|e| i64::from(decayed_weight(e, policy, now_ms)))
        .sum();
    raw.clamp(policy.floor, policy.ceil)
}

/// The tier a score maps to under the policy thresholds.
#[must_use]
pub fn tier_for(score: i64, policy: &ReputationPolicy) -> TrustTier {
    if score >= policy.high_at {
        TrustTier::High
    } else if score >= policy.medium_at {
        TrustTier::Medium
    } else if score >= policy.low_at {
        TrustTier::Low
    } else {
        TrustTier::Untrusted
    }
}

/// Aggregate a set of events into a full report (score, tier, and contribution accounting).
#[must_use]
pub fn aggregate(
    events: &[ReputationEvent],
    policy: &ReputationPolicy,
    now_ms: u64,
) -> ReputationReport {
    let mut contributing = 0usize;
    let mut decayed_away = 0usize;
    for e in events {
        if decayed_weight(e, policy, now_ms) == 0 {
            decayed_away += 1;
        } else {
            contributing += 1;
        }
    }
    let score = reputation_score(events, policy, now_ms);
    ReputationReport {
        score,
        tier: tier_for(score, policy),
        contributing,
        decayed_away,
        total: events.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ReputationPolicy {
        ReputationPolicy {
            half_life_ms: 1_000,
            floor: -100,
            ceil: 100,
            high_at: 50,
            medium_at: 20,
            low_at: 1,
        }
    }

    fn ev(kind: &str, weight: i32, at_ms: u64) -> ReputationEvent {
        ReputationEvent::new(kind, weight, at_ms, "auditor-x")
    }

    #[test]
    fn event_new_computes_and_verifies_digest() {
        let e = ev("clean_audit", 10, 5);
        assert!(e.digest.starts_with("sha256:"));
        assert!(verify_event(&e));
    }

    #[test]
    fn verify_event_detects_tampering() {
        let mut e = ev("clean_audit", 10, 5);
        e.weight = 999;
        assert!(!verify_event(&e));
    }

    #[test]
    fn positive_events_raise_score() {
        let s = reputation_score(&[ev("audit", 30, 0), ev("audit", 20, 0)], &policy(), 0);
        assert_eq!(s, 50);
    }

    #[test]
    fn negative_events_lower_score() {
        let s = reputation_score(&[ev("audit", 30, 0), ev("violation", -40, 0)], &policy(), 0);
        assert_eq!(s, -10);
    }

    #[test]
    fn old_events_decay() {
        // One half-life old → contribution halves.
        let e = ev("audit", 40, 0);
        assert_eq!(decayed_weight(&e, &policy(), 1_000), 20);
        assert_eq!(decayed_weight(&e, &policy(), 2_000), 10);
    }

    #[test]
    fn fully_decayed_event_contributes_zero() {
        let e = ev("audit", 40, 0);
        assert_eq!(decayed_weight(&e, &policy(), 100_000), 0);
    }

    #[test]
    fn score_clamps_to_ceil() {
        let events = vec![ev("audit", 90, 0), ev("audit", 90, 0)];
        assert_eq!(reputation_score(&events, &policy(), 0), 100);
    }

    #[test]
    fn score_clamps_to_floor() {
        let events = vec![ev("violation", -90, 0), ev("violation", -90, 0)];
        assert_eq!(reputation_score(&events, &policy(), 0), -100);
    }

    #[test]
    fn tier_thresholds_map_correctly() {
        let p = policy();
        assert_eq!(tier_for(60, &p), TrustTier::High);
        assert_eq!(tier_for(25, &p), TrustTier::Medium);
        assert_eq!(tier_for(5, &p), TrustTier::Low);
        assert_eq!(tier_for(0, &p), TrustTier::Untrusted);
    }

    #[test]
    fn empty_events_is_untrusted_zero() {
        let r = aggregate(&[], &policy(), 0);
        assert_eq!(r.score, 0);
        assert_eq!(r.tier, TrustTier::Untrusted);
        assert_eq!(r.total, 0);
    }

    #[test]
    fn zero_half_life_disables_decay() {
        let mut p = policy();
        p.half_life_ms = 0;
        let e = ev("audit", 40, 0);
        assert_eq!(decayed_weight(&e, &p, 999_999), 40);
    }

    #[test]
    fn aggregate_counts_contributing_vs_decayed() {
        let events = vec![ev("audit", 40, 0), ev("audit", 40, 0)];
        // At now=1000 both halve to 20 (still contributing); at now=100000 both gone.
        let r = aggregate(&events, &policy(), 1_000);
        assert_eq!((r.contributing, r.decayed_away, r.total), (2, 0, 2));
        let r2 = aggregate(&events, &policy(), 100_000);
        assert_eq!((r2.contributing, r2.decayed_away, r2.total), (0, 2, 2));
    }

    #[test]
    fn computation_is_deterministic() {
        let events = vec![ev("a", 10, 0), ev("b", -3, 500)];
        assert_eq!(
            aggregate(&events, &policy(), 1_000),
            aggregate(&events, &policy(), 1_000)
        );
    }

    #[test]
    fn event_roundtrips_through_json() {
        let e = ev("audit", 10, 5);
        let j = serde_json::to_string(&e).unwrap();
        let back: ReputationEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}

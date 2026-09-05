//! The baseline scenarios every attack mutates.
//!
//! Each builder returns something the boundary **allows**. That is deliberate: an attack is a
//! named mutation of a baseline, and the unmutated baseline is the control that proves the attack
//! reached the gate it claims to have reached. See [`crate::harness`] for why.

use warrantor_notary as notary;

/// A fixed epoch-second clock. Every input to the notary is explicit — it reads no clock — so the
/// corpus can pin time and stay deterministic.
pub const NOW: u64 = 1_700_000_000;

/// The freshness window the baseline runs under, in seconds.
pub const FRESHNESS_WINDOW_SECONDS: u64 = 300;

/// The scope the baseline operates on.
pub const SCOPE: &str = "wrt_corpus_baseline";

/// The SVID the baseline actor holds.
pub const SUBJECT: &str = "spiffe://muveraai.com/agent/invariant-corpus";

/// A request the notary allows against [`allowed_context`].
///
/// Two capabilities, one delegation link that grants both, a routine consequence tier and no
/// artifacts — so every gate is passed on its merits rather than skipped for want of an input.
pub fn allowed_request() -> notary::VerdictRequest {
    notary::VerdictRequest {
        actor: notary::Actor {
            svid: SUBJECT.to_string(),
            svid_not_after: NOW + 3_600,
            own_capabilities: vec!["fs.read".to_string(), "net.egress".to_string()],
            delegation_chain: vec![notary::DelegationLink {
                delegatee_svid: SUBJECT.to_string(),
                capabilities: vec!["fs.read".to_string(), "net.egress".to_string()],
                not_before: NOW - 60,
                not_after: NOW + 3_600,
                signature_verified: true,
            }],
        },
        operation: notary::Operation {
            class: "corpus.probe".to_string(),
            capabilities_requested: vec!["fs.read".to_string()],
            consequence_tier: notary::ConsequenceTier::Routine,
            scope: SCOPE.to_string(),
        },
        artifacts: Vec::new(),
        nonce: "nonce-baseline".to_string(),
        timestamp: NOW,
        approval: None,
    }
}

/// The context the baseline is evaluated against. Nothing contained, nothing revoked, nothing
/// replayed, policy says yes.
pub fn allowed_context() -> notary::VerdictContext {
    notary::VerdictContext {
        now: NOW,
        contained_scopes: Vec::new(),
        revoked_svids: Vec::new(),
        seen_nonces: Vec::new(),
        freshness_window_seconds: FRESHNESS_WINDOW_SECONDS,
        verified_artifacts: Vec::new(),
        budget_remaining: 100,
        policy_decision: true,
    }
}

/// Is this verdict an allow? The predicate every notary attack passes to the harness.
pub fn notary_allowed(verdict: &notary::Verdict) -> bool {
    verdict.is_allow()
}

/// The gate a denial names, or `None` for an allow. Suites assert on this so a test cannot pass
/// because the request was refused at some *earlier*, unrelated gate.
pub fn denied_gate(verdict: &notary::Verdict) -> Option<notary::Gate> {
    match verdict {
        notary::Verdict::Deny { gate } => Some(*gate),
        notary::Verdict::Allow { .. } => None,
    }
}

/// Assert the verdict denies at exactly this gate.
///
/// Naming the gate is what stops a suite from claiming credit for the wrong refusal: a malformed
/// identity fixture denies at Identity no matter what the test believed it was attacking.
#[track_caller]
pub fn assert_denied_at(verdict: &notary::Verdict, expected: notary::Gate, what: &str) {
    assert_eq!(
        denied_gate(verdict),
        Some(expected),
        "{what}: expected a denial at {expected:?}, got {verdict:?}"
    );
}

// -- the evidence plane ---------------------------------------------------------------

/// A WAR predicate that `evidence::verify_receipt` and `evidence::verify_authority` both accept.
///
/// `phase` chooses which half of the two-phase commit this describes. The outcome is left `None`
/// here; `issue_post_commit` fills it, which is the only supported way to reach a post-commit.
pub fn predicate(phase: warrantor_evidence::Phase) -> warrantor_evidence::WarPredicate {
    use warrantor_evidence as evidence;

    let chain = vec![evidence::DelegationLink {
        issuer: "operator".to_string(),
        subject: SUBJECT.to_string(),
        capabilities: vec!["fs.read".to_string(), "net.egress".to_string()],
        not_before: NOW - 60,
        not_after: NOW + 3_600,
        token_digest: "aa".repeat(32),
    }];

    evidence::WarPredicate {
        binding: evidence::Binding {
            receipt_id: "rcpt_corpus_baseline".to_string(),
            phase,
            parent_receipt: None,
            nonce: "nonce-baseline".to_string(),
            issued_at: NOW,
            expires_at: NOW + 3_600,
            enforcement_mode: evidence::EnforcementMode::Advisory,
        },
        actor: evidence::Actor {
            principal: "operator".to_string(),
            workload_id: SUBJECT.to_string(),
            svid_digest: "bb".repeat(32),
        },
        authority: evidence::Authority {
            effective_capabilities: evidence::recompute_intersection(&chain),
            intersection_proof: evidence::compute_intersection_proof(&chain),
            chain,
        },
        decision: evidence::Decision {
            verdict: evidence::Verdict::Allow,
            engine: "warrantor-notary/1.0".to_string(),
            policy_digest: "cc".repeat(32),
            evaluated_at: NOW,
        },
        operation: evidence::Operation {
            class: "corpus.probe".to_string(),
            target: "local".to_string(),
            method: "read".to_string(),
            parameters_digest: "dd".repeat(32),
            reversible: true,
            consequence_tier: evidence::ConsequenceTier::Routine,
        },
        outcome: None,
    }
}

/// The outcome a post-commit receipt carries.
pub fn outcome() -> warrantor_evidence::Outcome {
    warrantor_evidence::Outcome {
        status: "success".to_string(),
        outcome_digest: "ee".repeat(32),
        effects: vec!["read 1 file".to_string()],
        error: None,
        rollback_pointer: None,
    }
}

/// Sign an arbitrary predicate the way `evidence` signs its own, from outside the crate.
///
/// This exists so an attack can reach the check it is aiming at. `verify_chain` verifies both
/// signatures *before* it evaluates the commit gate, so a hand-edited receipt carrying a stale
/// signature is refused for being unsigned and never reaches the gate — the refusal would look
/// like a pass and prove nothing. An adversary who can author a receipt can also sign it, so the
/// corpus signs too, using the crate's own public canonicalization and PAE.
pub fn sign_as_attacker(
    predicate: &warrantor_evidence::WarPredicate,
    key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> warrantor_evidence::SignatureEnvelope {
    use ed25519_dalek::Signer;

    let pae = warrantor_evidence::dsse_pae(&warrantor_evidence::canonical_predicate(predicate));
    let signature = key.sign(&pae);
    warrantor_evidence::SignatureEnvelope {
        algorithm: "Ed25519".to_string(),
        key_id: key_id.to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        value: hex::encode(signature.to_bytes()),
    }
}

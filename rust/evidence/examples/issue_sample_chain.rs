//! Interop producer: issue a signed pre_commit→post_commit chain and write it as JSON for the
//! Python `warrantor_evidence` package to verify.
//!
//! Usage: `cargo run --example issue_sample_chain -- <output-path>`

use std::env;
use warrantor_evidence::*;

fn main() {
    let out = env::args()
        .nth(1)
        .unwrap_or_else(|| "../../.evidence_interop.json".to_string());
    let (sk, _) = generate_keypair();

    let chain = vec![
        DelegationLink {
            issuer: "spiffe://root".into(),
            subject: "spiffe://team".into(),
            capabilities: vec!["read".into(), "write".into()],
            not_before: 0,
            not_after: u64::MAX,
            token_digest: "sha256:aaa".into(),
        },
        DelegationLink {
            issuer: "spiffe://team".into(),
            subject: "spiffe://bot".into(),
            capabilities: vec!["read".into()],
            not_before: 0,
            not_after: u64::MAX,
            token_digest: "sha256:bbb".into(),
        },
    ];
    let effective = recompute_intersection(&chain);
    let proof = compute_intersection_proof(&chain);
    let authority = Authority {
        chain,
        effective_capabilities: effective,
        intersection_proof: proof,
    };

    let pre_predicate = WarPredicate {
        predicate_version: None,
        causality: None,
        binding: Binding {
            receipt_id: "rcpt-interop-001".into(),
            phase: Phase::PreCommit,
            parent_receipt: None,
            nonce: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            issued_at: 1000,
            expires_at: 99999,
            enforcement_mode: EnforcementMode::Mediated,
        },
        actor: Actor {
            principal: "interop-test".into(),
            workload_id: "spiffe://bot".into(),
            svid_digest: "sha256:svid".into(),
        },
        authority: authority.clone(),
        decision: Decision {
            verdict: Verdict::Allow,
            engine: "cedar@4".into(),
            policy_digest: "sha256:pol".into(),
            evaluated_at: 1000,
        },
        operation: Operation {
            class: "query".into(),
            target: "db".into(),
            method: "select".into(),
            parameters_digest: "sha256:params".into(),
            reversible: true,
            consequence_tier: ConsequenceTier::Routine,
        },
        outcome: None,
    };

    let pre = issue_pre_commit(pre_predicate, &sk, "interop-notary");
    let outcome = Outcome {
        status: "success".into(),
        outcome_digest: "sha256:out".into(),
        effects: vec![],
        error: None,
        rollback_pointer: None,
    };
    let post = issue_post_commit(&pre, outcome, &sk, "interop-notary");

    // Task 10.1: Python must verify a v1 **and** a v2 receipt in the same run, and must refuse a
    // version it has no rule for. Python's canonicalizer is dict-generic, so it would otherwise
    // happily verify the v2 signature while knowing nothing about the version field or the causal
    // section — which is exactly the hazard `check_predicate_version` closes on both sides.
    let mut v1_predicate = pre.predicate.clone();
    v1_predicate.binding.phase = Phase::Atomic;
    v1_predicate.binding.receipt_id = "rcpt-interop-v1".into();
    v1_predicate.outcome = Some(Outcome {
        status: "success".into(),
        outcome_digest: "sha256:out".into(),
        effects: vec![],
        error: None,
        rollback_pointer: None,
    });
    let v1_atomic = issue_atomic(v1_predicate, &sk, "interop-notary");

    let mut v2_predicate = v1_atomic.predicate.clone();
    v2_predicate.binding.receipt_id = "rcpt-interop-v2".into();
    v2_predicate.outcome = Some(Outcome {
        status: "success".into(),
        outcome_digest: "sha256:out".into(),
        effects: vec!["pr://staged/wrt_interop/1".into()],
        error: None,
        rollback_pointer: None,
    });
    v2_predicate.predicate_version = Some(PREDICATE_TYPE.to_string());
    v2_predicate.causality = Some(Causality {
        queue_head: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        step_count: 1,
        // `read` is the one capability this chain's intersection actually confers, so the route is
        // clean and Python's spot-check over the same chain agrees.
        steps: vec![CausalStep {
            index: 1,
            handle: "pr://staged/wrt_interop/1".into(),
            tool: "read".into(),
            depends_on: vec![],
        }],
    });
    let v2_atomic = issue_atomic(v2_predicate, &sk, "interop-notary");

    // A receipt whose version neither side has a rule for, signed CORRECTLY on purpose: a reader
    // that checks the signature first would call it valid, and one that never checks the version
    // would call it forged the moment the field mattered. Both are wrong, and both languages have
    // to say "unknown version" instead.
    let mut future = v2_atomic.clone();
    future.predicate.binding.receipt_id = "rcpt-interop-v9".into();
    future.predicate.predicate_version = Some("https://warrantor.dev/ActionReceipt/v9".into());
    let future = issue_atomic_unchecked_version(future.predicate, &sk, "interop-notary");

    let bundle = serde_json::json!({
        // Bumped from v1: the bundle gained keys, and a fixture that grows without saying so is the
        // silent format drift this whole task is about.
        "schema": "warrantor.evidence.interop.v2",
        "pre_commit": pre,
        "post_commit": post,
        // The v1 shape — no version field, no causal section. Every receipt signed before Task 10.1.
        "v1_atomic": v1_atomic,
        // The v2 shape — a route inside the signed bytes.
        "v2_atomic": v2_atomic,
        // A version with no rule on either side.
        "unknown_version": future,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&bundle).unwrap())
        .unwrap_or_else(|e| panic!("write {out}: {e}"));
    println!("Rust issued pre_commit→post_commit chain + v1/v2/unknown-version receipts → {out}");
}

/// Sign a predicate whose version this build does not recognize.
///
/// `issue_atomic` would be fine here too — issuance does not read the version — but going through
/// a named function makes the intent explicit: this fixture exists so both verifiers can be shown
/// refusing a *correctly signed* receipt.
fn issue_atomic_unchecked_version(
    predicate: WarPredicate,
    key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> WarReceipt {
    issue_atomic(predicate, key, key_id)
}

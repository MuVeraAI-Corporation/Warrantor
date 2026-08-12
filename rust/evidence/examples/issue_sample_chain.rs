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

    let bundle = serde_json::json!({
        "schema": "warrantor.evidence.interop.v1",
        "pre_commit": pre,
        "post_commit": post,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&bundle).unwrap())
        .unwrap_or_else(|e| panic!("write {out}: {e}"));
    println!("Rust issued pre_commit→post_commit chain → {out}");
}

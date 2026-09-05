//! Build-catalog gate A2 (L6-01): a four-deep chain where revoking the root makes every
//! descendant's staged action refuse at bind, and the deepest receipt names all four links.

use warrantor_delegation_chain::{WarrantScope, WarrantStore};
use warrantor_evidence::{
    bind_authority, generate_keypair, issue_pre_commit, verify_authority, verify_receipt, Actor,
    Authority, Binding, ConsequenceTier, Decision, EnforcementMode, EvidenceError, Operation,
    Phase, Verdict, WarPredicate,
};

fn scope(capabilities: &[&str], resource: &str, expires_at: u64, budget: u64) -> WarrantScope {
    WarrantScope {
        capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
        resource_classes: vec![resource.to_string()],
        expires_at_ms: expires_at,
        budget_micros: budget,
    }
}

/// org -> lead -> agent -> sub. Each level narrows something the level above held.
fn four_deep() -> WarrantStore {
    let mut store = WarrantStore::new();
    store.issue_root(
        "org",
        scope(
            &["github:write", "github:admin"],
            "repo:acme/*",
            1_000_000,
            500_000_000,
        ),
    );
    store
        .delegate(
            "org",
            "lead",
            &scope(
                &["github:write", "github:admin"],
                "repo:acme/api",
                900_000,
                100_000_000,
            ),
        )
        .expect("lead narrows");
    store
        .delegate(
            "lead",
            "agent",
            &scope(&["github:write"], "repo:acme/api", 500_000, 50_000_000),
        )
        .expect("agent narrows");
    store
        .delegate(
            "agent",
            "sub",
            &scope(&["github:write"], "repo:acme/api", 100_000, 5_000_000),
        )
        .expect("sub narrows");
    store
}

fn predicate_with(authority: Authority) -> WarPredicate {
    WarPredicate {
        binding: Binding {
            receipt_id: "rcpt-four-deep-001".to_string(),
            phase: Phase::PreCommit,
            parent_receipt: None,
            nonce: "AAAAAAAAAAAAAAAAAAAAAA==".to_string(),
            issued_at: 1_000,
            expires_at: 99_999,
            enforcement_mode: EnforcementMode::Mediated,
        },
        actor: Actor {
            principal: "sub".to_string(),
            workload_id: "spiffe://sub".to_string(),
            svid_digest: "sha256:svid".to_string(),
        },
        authority,
        decision: Decision {
            verdict: Verdict::Allow,
            engine: "cedar@4".to_string(),
            policy_digest: "sha256:pol".to_string(),
            evaluated_at: 1_000,
        },
        operation: Operation {
            class: "mutate".to_string(),
            target: "repo:acme/api".to_string(),
            method: "push".to_string(),
            parameters_digest: "sha256:params".to_string(),
            reversible: true,
            consequence_tier: ConsequenceTier::Routine,
        },
        outcome: None,
    }
}

#[test]
fn the_deepest_receipt_names_all_four_links() {
    let store = four_deep();
    let authority = bind_authority(&store, "sub").expect("a standing four-deep chain binds");

    assert_eq!(authority.chain.len(), 4);
    let subjects: Vec<&str> = authority.chain.iter().map(|l| l.subject.as_str()).collect();
    assert_eq!(subjects, ["org", "lead", "agent", "sub"]);
    let issuers: Vec<&str> = authority.chain.iter().map(|l| l.issuer.as_str()).collect();
    assert_eq!(
        issuers,
        ["org", "org", "lead", "agent"],
        "the root is self-issued"
    );
    let digests: Vec<String> = store
        .chain_of("sub")
        .iter()
        .map(|w| w.digest.clone())
        .collect();
    let linked: Vec<String> = authority
        .chain
        .iter()
        .map(|l| l.token_digest.clone())
        .collect();
    assert_eq!(
        linked, digests,
        "each link carries the warrant digest it stands for"
    );
    assert_eq!(
        authority.effective_capabilities,
        vec!["github:write".to_string()]
    );
    verify_authority(&authority).expect("the bound authority recomputes");

    let (signing_key, _) = generate_keypair();
    let receipt = issue_pre_commit(predicate_with(authority), &signing_key, "notary-1");
    verify_receipt(&receipt).expect("the deepest receipt verifies");
    verify_authority(&receipt.predicate.authority).expect("and its chain recomputes");
}

#[test]
fn revoking_the_root_refuses_every_descendant_at_bind() {
    let mut store = four_deep();
    let (signing_key, _) = generate_keypair();
    let before = issue_pre_commit(
        predicate_with(bind_authority(&store, "sub").expect("binds before revocation")),
        &signing_key,
        "notary-1",
    );

    store.revoke("org");

    for id in ["org", "lead", "agent", "sub"] {
        assert!(
            matches!(bind_authority(&store, id), Err(EvidenceError::Revoked(ref who)) if who.as_str() == id),
            "{id} must refuse at bind once the root is revoked"
        );
    }

    // The receipt issued BEFORE the revocation is a record of a past evaluation and keeps
    // verifying: revocation is a bind-time refusal, not a property of an archived receipt.
    verify_receipt(&before).expect("the audit path does not rot");
}

#[test]
fn revoking_the_middle_spares_the_ancestors() {
    let mut store = four_deep();
    store.revoke("agent");
    assert!(bind_authority(&store, "lead").is_ok());
    assert!(matches!(
        bind_authority(&store, "sub"),
        Err(EvidenceError::Revoked(_))
    ));
}

#[test]
fn an_unknown_warrant_cannot_bind() {
    let store = four_deep();
    assert!(matches!(
        bind_authority(&store, "ghost"),
        Err(EvidenceError::Authority(message)) if message.contains("unknown warrant ghost")
    ));
}

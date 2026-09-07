//! L5-12: a peer can propose work; it cannot grant authority, and it cannot carry a credential.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use warrantor_agent_channel::ContentClass;
use warrantor_trust_core::signing::SigningKeyWrapper;
use warrantor_warrant::provenance::{
    admit, compose, credential_handle_in, Origin, PeerProposal, ProposalVerdict, Trust,
    PROPOSAL_FORMAT,
};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
const RECEIVER: &str = "spiffe://muveraai.com/agent/receiver";
const PEER: &str = "spiffe://muveraai.com/agent/peer";

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-proposal-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn stored_open(id: &str, tools: &[&str]) -> StoredWarrant {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(id, "receive proposals", RECEIVER, bounds, NOW, &settle.verifying_key(), &issuer)
        .expect("grant");
    StoredWarrant { warrant, worktree: None, repo: None, branch: None, base_commit: None, staged_chain: None }
}

fn peer_key() -> SigningKeyWrapper {
    SigningKeyWrapper::from_bytes(&[7; 32])
}

fn proposal(tool: &str, arguments: &[(&str, Value)]) -> PeerProposal {
    PeerProposal {
        format: PROPOSAL_FORMAT.to_string(),
        proposer: PEER.to_string(),
        population: "agent".to_string(),
        task_lineage: vec!["task-root".to_string(), "task-7".to_string()],
        tool: tool.to_string(),
        arguments: arguments.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect(),
        side_effect: SideEffectClass::Read,
        expires_at: NOW + 600,
    }
}

#[test]
fn a_credential_handle_is_found_at_any_depth_and_in_token_shape() {
    assert_eq!(credential_handle_in(&json!({"text": "hi"})), None);
    assert_eq!(credential_handle_in(&json!({"args": {"Token": "abc"}})), Some("/args/Token".to_string()));
    assert_eq!(
        credential_handle_in(&json!({"h": {"warrant_id": "w", "subject": "s", "expires_at": 1, "signature": "ff"}})),
        Some("/h".to_string())
    );
    assert_eq!(credential_handle_in(&json!({"x": ["Bearer eyJ"]})), Some("/x/0".to_string()));
}

#[test]
fn a_proposal_carrying_a_credential_handle_is_refused_at_admission_regardless_of_scope() {
    // `selftest.echo` IS in the receiver's warrant. The credential is what refuses it, and the
    // receipt names the gate, not the token.
    let stored = stored_open("w-cred", &["selftest.echo"]);
    let env = compose(&proposal("selftest.echo", &[("text", json!("hi")), ("api_key", json!("sk-live-1"))]), "w-cred", 0, NOW, &peer_key())
        .expect("compose");
    let decision = admit(&env, &stored, &BTreeSet::new(), NOW);
    assert_eq!(decision.verdict, ProposalVerdict::RefusedAtAdmission { gate: "credential_handle".to_string() });
    assert!(decision.label.is_none());
}

#[test]
fn a_credential_share_class_is_refused_before_the_payload_is_read() {
    let stored = stored_open("w-class", &["selftest.echo"]);
    let mut env = compose(&proposal("selftest.echo", &[("text", json!("hi"))]), "w-class", 0, NOW, &peer_key()).expect("compose");
    // Re-sign with the declared class changed; the signature covers `class`, so this is a fresh message.
    env.message = warrantor_agent_channel::Message::sign("w-class", warrantor_agent_channel::AgentId(PEER.to_string()), 0, ContentClass::CredentialShare, env.payload.as_bytes(), NOW, &peer_key())
        .expect("sign");
    let decision = admit(&env, &stored, &BTreeSet::new(), NOW);
    assert_eq!(decision.verdict, ProposalVerdict::RefusedAtAdmission { gate: "class".to_string() });
}

#[test]
fn a_proposal_outside_the_receivers_warrant_is_refused_at_bind_naming_the_bound() {
    let stored = stored_open("w-bind", &["selftest.echo"]);
    let env = compose(&proposal("github.create_pr", &[("title", json!("x"))]), "w-bind", 0, NOW, &peer_key()).expect("compose");
    let decision = admit(&env, &stored, &BTreeSet::new(), NOW);
    assert_eq!(decision.verdict, ProposalVerdict::RefusedAtBind { bound: "tools".to_string() });
    assert!(decision.reason.contains("github.create_pr"), "{}", decision.reason);
}

#[test]
fn admitting_a_proposal_leaves_effective_authority_unchanged() {
    let stored = stored_open("w-admit", &["selftest.echo"]);
    let before = stored.warrant.claims.bounds.clone();
    let env = compose(&proposal("selftest.echo", &[("text", json!("do this"))]), "w-admit", 0, NOW, &peer_key()).expect("compose");
    let decision = admit(&env, &stored, &BTreeSet::new(), NOW);
    assert_eq!(decision.verdict, ProposalVerdict::Admitted);
    let label = decision.label.expect("an admitted proposal is labeled");
    assert_eq!(label.origin, Origin::Peer { agent: PEER.to_string() });
    assert_eq!(label.trust, Trust::None);
    assert!(label.non_transitive);
    assert_eq!(label.expires_at, NOW + 600, "the shorter of proposal and warrant expiry");
    // The blueprint gate C-03: effective authority is unchanged. The bounds are signed claims,
    // and the proxy built from them still refuses what it refused before the proposal.
    assert_eq!(stored.warrant.claims.bounds, before);
    let mut proxy = Proxy::new(before, ProxyMode::Enforce, EffectRegistry::github());
    let call = ToolCall { tool: "github.create_pr".to_string(), arguments: BTreeMap::new(), side_effect: SideEffectClass::Write };
    assert!(matches!(proxy.decide(&call), Decision::Deny { bound: "tools", .. }));
}

#[test]
fn a_proposal_from_another_population_is_refused() {
    let stored = stored_open("w-pop", &["selftest.echo"]);
    let mut p = proposal("selftest.echo", &[("text", json!("hi"))]);
    p.proposer = "spiffe://muveraai.com/other/peer".to_string();
    p.population = "other".to_string();
    let env = compose(&p, "w-pop", 0, NOW, &peer_key()).expect("compose");
    let decision = admit(&env, &stored, &BTreeSet::new(), NOW);
    assert_eq!(decision.verdict, ProposalVerdict::RefusedAtAdmission { gate: "population".to_string() });
}

#[test]
fn a_replayed_envelope_is_refused() {
    let stored = stored_open("w-replay", &["selftest.echo"]);
    let env = compose(&proposal("selftest.echo", &[("text", json!("hi"))]), "w-replay", 0, NOW, &peer_key()).expect("compose");
    let first = admit(&env, &stored, &BTreeSet::new(), NOW);
    assert_eq!(first.verdict, ProposalVerdict::Admitted);
    let seen: BTreeSet<String> = [first.message_digest.clone()].into_iter().collect();
    let second = admit(&env, &stored, &seen, NOW);
    assert_eq!(second.verdict, ProposalVerdict::RefusedAtAdmission { gate: "replay".to_string() });
}

#[test]
fn a_tampered_signature_is_refused_at_the_signature_gate() {
    let stored = stored_open("w-sig", &["selftest.echo"]);
    let mut env = compose(&proposal("selftest.echo", &[("text", json!("hi"))]), "w-sig", 0, NOW, &peer_key()).expect("compose");
    env.message.signature[0] ^= 0xff;
    let decision = admit(&env, &stored, &BTreeSet::new(), NOW);
    assert_eq!(decision.verdict, ProposalVerdict::RefusedAtAdmission { gate: "signature".to_string() });
}

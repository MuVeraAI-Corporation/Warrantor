//! Interop example (reverse direction): generate a keypair in Rust, sign the minimal manifest,
//! and write the signed manifest JSON to argv[1]. Python then verifies it.
//!
//! Usage: `cargo run --example interop_sign -- <output-path>`

use warrantor_agent_manifest::{generate_keypair, sign, AgentManifest};

fn main() {
    use std::env;
    let args: Vec<String> = env::args().collect();
    let out = args.get(1).expect("usage: interop_sign <output-path>");

    let manifest = AgentManifest {
        api_version: "agent.warrantor.io/v1".to_string(),
        kind: "AgentManifest".to_string(),
        name: "research-bot-1".to_string(),
        identity: "spiffe://yourcorp/agents/research-bot-1".to_string(),
        capabilities: vec!["read".to_string()],
        policy_refs: vec!["pol_default".to_string()],
        dependencies: None,
        attestation: None,
        enforcement_mode: "observed".to_string(),
        description: None,
        version: None,
    };

    let (sk, _) = generate_keypair();
    let signed = sign(&manifest, &sk, "interop-rs-key");
    let json = serde_json::to_string(&signed).expect("serialize SignedManifest");
    std::fs::write(out, json).unwrap_or_else(|e| panic!("write {}: {}", out, e));
    println!("Rust signed minimal manifest → {}", out);
}

// Re-export so the example can find the type without a separate use when built as an example.
use warrantor_agent_manifest as _;

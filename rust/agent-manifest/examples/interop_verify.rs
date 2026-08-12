//! Interop example: read a signed manifest JSON (produced by the Python implementation),
//! deserialize it, and verify the Ed25519 signature using the Rust implementation.
//!
//! Usage: `cargo run --example interop_verify -- <path-to-signed.json>`
//!
//! This proves canonical-JSON + Ed25519 interop across languages: a signature produced by
//! Python's `warrantor_agent_manifest.sign()` verifies under Rust's `verify()`, because both
//! compute byte-identical canonical bytes over the same manifest.

use std::env;

use warrantor_agent_manifest::{verify, SignedManifest};

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args
        .get(1)
        .expect("usage: interop_verify <path-to-signed.json>");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let signed: SignedManifest = serde_json::from_str(&raw).expect("deserialize SignedManifest");

    match verify(&signed) {
        Ok(()) => {
            println!("INTEROP OK: Rust verified a Python-signed manifest.");
            println!("  identity  : {}", signed.manifest.identity);
            println!("  key_id    : {}", signed.signature.key_id);
            println!("  algorithm : {}", signed.signature.algorithm);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("INTEROP FAIL: {:?}", e);
            std::process::exit(1);
        }
    }
}

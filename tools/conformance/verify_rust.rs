//! A6 conformance — Rust verifier entry point.
//!
//! Reads a golden vector from stdin (JSON) and verifies the signature against the recorded
//! verifying key. Exits 0 on success, 1 on verification failure.
//!
//! This mirrors the Python and Go verifiers in this directory; running all three against the
//! same vector is the cross-language conformance test for T1 trust-core.

use std::io::Read;

#[derive(serde::Deserialize)]
struct Vector {
    payload_hex: String,
    verifying_key_hex: String,
    signature_hex: String,
    expected: String,
}

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("read stdin");
    let v: Vector = serde_json::from_str(&s).expect("parse vector JSON");

    let payload = hex::decode(&v.payload_hex).expect("payload hex");
    let vk_bytes: [u8; 32] = hex::decode(&v.verifying_key_hex)
        .expect("vk hex")
        .as_slice()
        .try_into()
        .expect("vk len");
    let sig_bytes: [u8; 64] = hex::decode(&v.signature_hex)
        .expect("sig hex")
        .as_slice()
        .try_into()
        .expect("sig len");

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).expect("vk");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    let valid = vk.verify(&payload, &sig).is_ok();

    if valid == (v.expected == "valid") {
        println!("rust: ok (valid={valid}, expected={})", v.expected);
        std::process::exit(0);
    } else {
        eprintln!("rust: MISMATCH (valid={valid}, expected={})", v.expected);
        std::process::exit(1);
    }
}

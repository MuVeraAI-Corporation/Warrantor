//! The frozen v1 notary receipt body: what every receipt signed before the causal verdict looked
//! like on the wire, and what it must still look like afterward.
//!
//! # Why the strings are literals
//!
//! Task 10.1 changes a signed structure. A regression test that *recomputes* the canonical form
//! from a struct proves nothing about a format change, because it recomputes it under the new
//! rule and agrees with itself. So the canonical bytes and their digest are frozen here as `const`
//! strings, and both were derived a second time in Python -- `_canonicalize` in
//! `python/warrantor_notary`, sorted keys, `separators=(",", ":")` -- before either was pasted in.
//! Two implementations produced the same 243 bytes and the same digest.
//!
//! # What this file establishes, and what it does not
//!
//! It establishes that a v1 body still canonicalizes to the same bytes and still hashes to the same
//! digest, so an Ed25519 signature taken over those bytes at any point in the past still verifies.
//! It does **not** establish anything about the nine sibling `issue_receipt` implementations in
//! other crates; each carries its own body type and its own canonicalizer, and Task 10.1
//! deliberately added no field here for exactly that reason.

use warrantor_notary::{
    receipt_digest_hex, verify_receipt, EnforcementMode, ReceiptBody, SignatureEnvelope, Verdict,
    WarReceipt,
};

/// The canonical form of a minimal v1 body: six keys, sorted, no whitespace.
const CANONICAL_V1: &str = r#"{"actor_svid":"spiffe://yourcorp/agents/bot-1","enforcement_mode":"observed","notary_version":"warrantor-notary/1.0","operation_class":"report","timestamp":1786000000,"verdict":{"effective_capabilities":["github.create_pr"],"outcome":"allow"}}"#;

/// SHA-256 of exactly those bytes. Independently computed in Python.
const DIGEST_V1: &str = "6835a03a44df0556406780dd2fb1cc7b73ed58fde2f03da8073c74f3a22da466";

fn v1_body() -> ReceiptBody {
    ReceiptBody {
        verdict: Verdict::Allow {
            effective_capabilities: vec!["github.create_pr".to_string()],
        },
        actor_svid: "spiffe://yourcorp/agents/bot-1".to_string(),
        operation_class: "report".to_string(),
        timestamp: 1_786_000_000,
        enforcement_mode: EnforcementMode::Observed,
        notary_version: "warrantor-notary/1.0".to_string(),
    }
}

/// The digest is the whole of the chaining primitive `receipt_digest` exists to provide, so it is
/// pinned directly. A body whose canonical bytes moved by one character hashes to something else.
#[test]
fn a_v1_body_still_hashes_to_the_digest_it_hashed_to_before_the_causal_verdict() {
    assert_eq!(
        receipt_digest_hex(&v1_body()),
        DIGEST_V1,
        "the v1 receipt body's canonical digest moved. Every receipt chained to by digest is now \
         unreachable, and every archived signature over those bytes now reads as a forgery."
    );
}

/// `canonical_receipt_body` is private, so the byte-for-byte claim is proved the way a third party
/// would prove it: sign the frozen bytes with a key the test holds, hand `verify_receipt` the
/// *rebuilt struct* plus that signature, and require it to verify. It can only verify if the bytes
/// this build canonicalizes the struct to are the frozen bytes, character for character.
#[test]
fn the_canonical_bytes_of_a_v1_body_are_the_frozen_bytes_character_for_character() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let signature = signing.sign(CANONICAL_V1.as_bytes());
    let receipt = WarReceipt {
        body: v1_body(),
        signature: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            key_id: "frozen-v1".to_string(),
            public_key: hex_encode(&signing.verifying_key().to_bytes()),
            value: hex_encode(&signature.to_bytes()),
        },
    };

    verify_receipt(&receipt).expect(
        "a signature taken over the frozen v1 canonical bytes must still verify against the \
         canonical form this build computes. If it does not, the canonicalization changed and \
         every receipt ever signed is now unverifiable.",
    );
}

/// The paired control: the same construction over bytes that are *not* the frozen form must fail,
/// so the test above cannot pass by verifying everything.
#[test]
fn a_signature_over_anything_but_the_frozen_bytes_is_refused() {
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let mut tampered = CANONICAL_V1.to_string();
    tampered.push(' ');
    let signature = signing.sign(tampered.as_bytes());
    let receipt = WarReceipt {
        body: v1_body(),
        signature: SignatureEnvelope {
            algorithm: "Ed25519".to_string(),
            key_id: "frozen-v1".to_string(),
            public_key: hex_encode(&signing.verifying_key().to_bytes()),
            value: hex_encode(&signature.to_bytes()),
        },
    };

    assert!(
        verify_receipt(&receipt).is_err(),
        "one trailing space must break the signature, or the test above proves nothing"
    );
}

/// The silent-drop hole. Serde's default behavior is to ignore unknown keys, so a body carrying a
/// field this build has never heard of deserializes, loses it, re-canonicalizes without it, and
/// fails as `InvalidSignature` -- a version mismatch reported to a third-party auditor as a
/// forgery. `#[serde(deny_unknown_fields)]` turns that into a parse refusal that names the field.
#[test]
fn a_body_carrying_an_unknown_field_is_refused_at_parse_rather_than_silently_stripped() {
    let with_extra = CANONICAL_V1.replace(
        r#"{"actor_svid""#,
        r#"{"causality":{"steps":[]},"actor_svid""#,
    );
    let parsed: Result<ReceiptBody, _> = serde_json::from_str(&with_extra);
    let error = parsed.expect_err(
        "an unknown field must be refused. Accepting it strips the field and then reports the \
         resulting canonical mismatch as a bad signature, which tells an auditor 'forgery' when \
         the truth is 'newer format'.",
    );
    assert!(
        error.to_string().contains("causality"),
        "the refusal must name the field it did not recognize, got: {error}"
    );
}

/// Paired control for the refusal above: the frozen v1 bytes, with no unknown field, still parse.
#[test]
fn the_frozen_v1_bytes_still_parse() {
    let parsed: ReceiptBody =
        serde_json::from_str(CANONICAL_V1).expect("the frozen v1 form must still deserialize");
    assert_eq!(parsed, v1_body());
    assert_eq!(receipt_digest_hex(&parsed), DIGEST_V1);
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

//! Integration test against a REAL Rekor instance.
//!
//! Ignored by default. Run with a local Sigstore stack up:
//!
//! ```text
//! docker compose -f deploy/local-sigstore/docker-compose.yml up -d
//! REKOR_URL=http://127.0.0.1:3000 \
//!   cargo test -p warrantor-trust-core --test rekor_live -- --ignored
//! ```
//!
//! This exists because five separate bugs in the Rekor client were invisible to the unit
//! tests -- and two were actively asserted BY those tests. Every one made notarization
//! fail 100% of the time against any real Rekor, public or local, and nothing caught it
//! because nothing had ever posted to one.
//!
//! 1. entry kind `hashedrekor`, missing the trailing `d`
//! 2. `data.hash.value` sent base64; Rekor wants hex
//! 3. `publicKey.content` sent raw key bytes; Rekor wants base64 of a PEM document
//! 4. hash algorithm `sha256`; Ed25519 entries require `sha512`
//! 5. plain Ed25519 over the digest; Rekor uses Ed25519ph, a *different* algorithm
//!
//! A mock transport cannot catch any of them: every one produces a perfectly well-formed
//! request that only a server rejects. That is the whole argument for this file.

use ed25519_dalek::{Digest, Sha512};
use ed25519_dalek::{Signature, SigningKey};
use warrantor_trust_core::rekor::RekorClient;

#[test]
#[ignore = "requires a running Rekor; see module docs"]
fn notarize_is_accepted_by_a_real_rekor() {
    let Ok(url) = std::env::var("REKOR_URL") else {
        eprintln!("REKOR_URL unset; skipping");
        return;
    };

    let mut seed = [0u8; 32];
    fill_test_seed(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let payload = format!("warrantor live rekor test {}", unique_suffix());

    // Ed25519ph over SHA-512 -- bug 5 above. Plain Ed25519 over the same digest is a
    // different signature and Rekor rejects it with "ed25519: invalid signature", which
    // reads like a key problem and is not.
    let mut prehash = Sha512::new();
    prehash.update(payload.as_bytes());
    let signature: Signature = signing_key
        .sign_prehashed(prehash, None)
        .expect("ed25519ph sign");

    let client = RekorClient::with_base_url(&url);
    let entry = client
        .notarize(
            payload.as_bytes(),
            signature.to_bytes().as_ref(),
            verifying_key.to_bytes().as_ref(),
        )
        .expect("rekor accepted the entry");

    // Assert the log assigned its own values. A stub could return the request; only a log
    // can assign an index and an integration time.
    assert!(!entry.log_id.is_empty(), "log_id must be populated");
    assert!(entry.log_index >= 0, "log_index must be assigned");
    assert!(
        entry.integrated_time > 0,
        "integrated_time must be set by the log, got {}",
        entry.integrated_time
    );
    assert!(entry.uuid.is_some(), "uuid must be returned");
}

/// Distinct payload per run so entries never collide with an existing one.
fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Seed a throwaway key without adding a dependency.
///
/// Deliberately NOT a CSPRNG, and that is safe here only because this key exists for the
/// duration of one call, signs one public test string, and is never persisted or trusted.
/// Do not copy this into anything that keeps a key.
fn fill_test_seed(buf: &mut [u8; 32]) {
    let nanos = unique_suffix().to_le_bytes();
    let addr = (buf.as_ptr() as usize).to_le_bytes();
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = nanos[i % nanos.len()] ^ addr[i % addr.len()] ^ (i as u8);
    }
}

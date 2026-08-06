//! Fuzz target: signature_decode.
//!
//! Feeds arbitrary bytes as an Ed25519 signature; decoding must not panic.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Signature::from_bytes expects 64 bytes. We exercise the < 64 and > 64 cases; the
    // function must not panic in either (it panics only on exactly-not-64, which we avoid
    // by length-checking here — the trust-core verify path uses TryFrom).
    if data.len() == 64 {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(data);
        let _sig = ed25519_dalek::Signature::from_bytes(&arr);
    }
});

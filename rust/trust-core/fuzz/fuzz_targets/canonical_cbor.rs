//! Fuzz target: canonical_cbor.
//!
//! Feeds arbitrary bytes as a CBOR value into canonical_cbor; the function must not panic
//! on any input (it may return an error, which is fine). This locks invariant: "canonical
//! encoding never panics on untrusted input" — important because canonical_cbor is on every
//! signed-receipt path.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_cbor::from_slice::<serde_cbor::Value>(data) {
        // canonical_cbor returns Result<Vec<u8>, CanonicalError>. We only care that it doesn't panic.
        let _ = warrantor_trust_core::canonical::canonical_cbor(&value);
    }
});

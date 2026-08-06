//! Fuzz target: rekor_response.
//!
//! Feeds arbitrary bytes as a Rekor transparency-log entry JSON; parsing must not panic.
//! (Rekor integration is task 03 — this target lands the harness so the nightly fuzz job
//! has something to exercise the moment rekor.rs is wired.)

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // We don't yet have a RekorClient in trust-core (task 03), but JSON parsing of
    // untrusted bytes is the risky surface. Exercise serde_json's parser on it; it must not panic.
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<serde_json::Value, _> = serde_json::from_str(s);
    }
});

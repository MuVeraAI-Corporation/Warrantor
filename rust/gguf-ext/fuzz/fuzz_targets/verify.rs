#![no_main]

use warrantor_gguf_ext::{verify, GgufLimits, VerifyPolicy};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let policy = VerifyPolicy {
        limits: GgufLimits {
            max_file_bytes: 8 * 1024 * 1024,
            max_metadata_entries: 10_000,
            max_tensors: 10_000,
            max_array_elements: 100_000,
            max_total_array_elements: 100_000,
            max_allocation_bytes: 16 * 1024 * 1024,
            ..GgufLimits::default()
        },
        now: 1_800_000_000,
        clock_skew_seconds: 0,
        maximum_age_seconds: Some(31_536_000),
        require_expiry: true,
    };
    let _ = verify(&mut Cursor::new(data), &policy);
});

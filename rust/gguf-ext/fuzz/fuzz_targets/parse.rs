#![no_main]

use warrantor_gguf_ext::{inspect, payload_digest, GgufLimits};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let limits = GgufLimits {
        max_file_bytes: 8 * 1024 * 1024,
        max_metadata_entries: 10_000,
        max_tensors: 10_000,
        max_array_elements: 100_000,
        max_total_array_elements: 100_000,
        max_allocation_bytes: 16 * 1024 * 1024,
        ..GgufLimits::default()
    };
    let _ = inspect(Cursor::new(data), &limits);
    let _ = payload_digest(Cursor::new(data), &limits);
});

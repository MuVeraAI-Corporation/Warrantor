# S3 GGUF-Ext adversarial vectors

`cases.json` is the portable seed corpus for the bounded GGUF v3 parser. Each `hex` value is a
complete input file and each expected error is a stable semantic class rather than a Rust error
message. The Rust suite consumes every case directly. Future language bindings and fuzz harnesses
must reuse the same inputs.

The signed, tampered-tensor, tampered-manifest, bad-signature, unknown-safety-key, expired,
wrong-type, overlap, invalid-alignment, invalid-boolean, nested-array, and round-trip cases are
constructed deterministically in `rust/gguf-ext` tests because their offsets depend on encoded
metadata lengths. The fixed corpus here covers format admission before allocation.

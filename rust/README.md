# rust/ — Warrantor trusted core workspace

The Rust workspace owns every security invariant in Warrantor (per the polyglot stack pressure test:
*"no security invariant may have two authoritative implementations"*). Wave-1 members:

| Crate | Canonical ID | Purpose |
|---|---|---|
| `trust-core` | T1 | Sign / verify / canonicalize — the foundation |
| `defstack-cli` | X1 | Unified installer/orchestrator CLI |
| `nvtrust-bridge` | C1-1 | NVIDIA NVTrust FFI bindings + Mock backend for CI |
| `eval-guard` | R2 | Sandbox boundary attestation (eBPF) |
| `kill-switch` | R3 | AI Kill Switch Act compliance (<5s end-to-end) |
| `credential-vault` | R4 | Agent-scoped credential brokering (<1s revocation) |

## Build

```bash
cd rust
cargo build         # build every member
cargo test          # test every member
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

## Conventions

- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` at the top of every lib.
- `thiserror`-typed errors; no `unwrap()`/`expect()` in production paths.
- `zeroize` on any struct holding key material.
- Constant-time crypto (the `ed25519-dalek` default).

See [`docs/cross-cutting/18-developer-experience.md`](../docs/cross-cutting/18-developer-experience.md)
for the full contribution workflow.

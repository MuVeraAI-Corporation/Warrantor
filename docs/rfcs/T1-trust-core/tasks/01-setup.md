# Task 01-setup — T1 trust-core

> **Sprint:** MVP week 1–2. **Acceptance:** cargo build green, CI running.

## Objective
Stand up the `rust/trust-core/` crate skeleton with CI, lint, formatting, and a smoke test.

## Steps
1. Create `rust/trust-core/Cargo.toml` — crate name `warrantor-trust-core`, edition 2021, `[lib]` +
   `[[bin]]` for the CLI.
2. Add dependencies: `ed25519-dalek = "2"`, `serde_cbor = "0.12"`, `thiserror`, `zeroize`,
   `sigstore = "0.10"`, `clap = { version = "4", features = ["derive"] }`.
3. Add dev-dependencies: `proptest`, `quickcheck`.
4. `rust/trust-core/src/lib.rs` — empty `pub fn version() -> &'static str { "0.1.0" }`.
5. `rust/trust-core/src/cli.rs` — clap-derived `Trust` enum with `sign`, `verify`, `key-gen`,
   `notarize` variants (stubs returning `unimplemented!()`).
6. `rust/trust-core/tests/smoke.rs` — assert `version()` returns `"0.1.0"`.
7. `.github/workflows/trust-core-ci.yml` — checkout, install Rust, `cargo fmt --check`,
   `cargo clippy -- -D warnings`, `cargo test`. Add CycloneDX SBOM generation step.
8. Add `rust/trust-core/CHANGELOG.md` (Keep a Changelog; entry under `[Unreleased]`).

## Acceptance criteria
- [ ] `cargo build` succeeds with zero warnings.
- [ ] `cargo test` runs the smoke test green.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] CI workflow runs on push and PR.
- [ ] SBOM generation step present (even if empty CycloneDX for now).

## Out of scope
- Actual signing logic (task 02).
- Bindings (task 05–07).
- Fuzz targets (task 06).

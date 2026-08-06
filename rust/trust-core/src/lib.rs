//! # aumos-trust-core
//!
//! The single authoritative implementation of every security invariant in AumOS.
//! No security invariant may have two authoritative implementations (polyglot stack
//! pressure test kill criterion).
//!
//! See `docs/rfcs/T1-trust-core.md` for the full RFC.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod canonical;
pub mod merkle;
pub mod signing;
pub mod verification;

/// Crate version (matches Cargo.toml via the workspace).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the crate version. Smoke-test entrypoint.
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}

//! L4-05: anything Warrantor executes is identified by the digest of its bytes, never by name,
//! and the surface it runs on is declared in the warrant.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use warrantor_warrant::exec::{
    self, ExecAdmission, ExecPhase, ExecSurface, ExecVerdict, EXEC_RECEIPT_FORMAT,
};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-exec-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// The artifact every test executes: this crate's own binary. Present on every platform, exits
/// at once with `--help`, and its bytes are real.
fn artifact() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_warrantor"))
}

#[test]
fn an_admission_is_a_surface_and_a_lowercase_hex_digest_and_nothing_else() {
    let digest = "a".repeat(64);
    let parsed = ExecAdmission::parse(&format!("process={digest}")).expect("parse");
    assert_eq!(parsed.surface, ExecSurface::Process);
    assert_eq!(parsed.sha256, digest);
    assert_eq!(ExecSurface::parse("upstream").expect("upstream"), ExecSurface::Upstream);
    for bad in [
        "process",                         // no digest
        "shell=aaaa",                      // a surface this build has no chokepoint for
        &format!("process={}", "A".repeat(64)), // uppercase would make two spellings of one digest
        &format!("process={}", "a".repeat(63)),
        "process=/usr/bin/python3",        // a NAME is exactly what this refuses to accept
    ] {
        let err = ExecAdmission::parse(bad).expect_err(bad);
        assert!(err.contains("process") || err.contains("64"), "{bad}: {err}");
    }
}

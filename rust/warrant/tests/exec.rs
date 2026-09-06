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

#[test]
fn a_renamed_copy_has_the_same_digest_and_a_one_byte_change_does_not() {
    let dir = tempdir("digest");
    let renamed = dir.join(if cfg!(windows) { "agent-renamed.exe" } else { "agent-renamed" });
    std::fs::copy(artifact(), &renamed).expect("copy");
    let modified = dir.join(if cfg!(windows) { "agent-modified.exe" } else { "agent-modified" });
    let mut bytes = std::fs::read(artifact()).expect("read");
    bytes.push(0x00);
    std::fs::write(&modified, &bytes).expect("write");

    let (original, size) = exec::sha256_file(&artifact()).expect("digest");
    assert_eq!(original.len(), 64);
    assert_eq!(size, std::fs::metadata(artifact()).expect("meta").len());
    assert_eq!(exec::sha256_file(&renamed).expect("digest").0, original);
    assert_ne!(exec::sha256_file(&modified).expect("digest").0, original);
}

#[test]
fn a_bare_name_is_resolved_on_path_and_never_in_the_worktree() {
    // A file the agent wrote into its own worktree must not shadow a tool of the same name: that
    // is the supply-chain shape, and CreateProcess's cwd-first search order is exactly the trap.
    let worktree = tempdir("shadow");
    let shadow_name = if cfg!(windows) { "warrantor-shadow.exe" } else { "warrantor-shadow" };
    std::fs::copy(artifact(), worktree.join(shadow_name)).expect("copy");
    let err = exec::resolve_program("warrantor-shadow", Some(&worktree))
        .expect_err("a bare name is looked up on PATH only");
    assert!(err.contains("PATH"), "{err}");
    // An explicit relative path is joined to the worktree, and an absolute one is taken as is.
    let relative = format!("./{shadow_name}");
    let resolved = exec::resolve_program(&relative, Some(&worktree)).expect("relative");
    assert!(resolved.starts_with(&worktree), "{}", resolved.display());
    assert_eq!(resolved.file_name().and_then(|n| n.to_str()), Some(shadow_name));
    assert_eq!(
        exec::resolve_program(&artifact().to_string_lossy(), None).expect("absolute"),
        artifact()
    );
}

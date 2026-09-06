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

fn pinned(digest: &str) -> BTreeSet<ExecAdmission> {
    [ExecAdmission { surface: ExecSurface::Process, sha256: digest.to_string() }]
        .into_iter()
        .collect()
}

#[test]
fn a_renamed_artifact_gets_the_same_verdict_and_a_modified_one_is_refused() {
    let dir = tempdir("admit");
    let renamed = dir.join(if cfg!(windows) { "renamed.exe" } else { "renamed" });
    std::fs::copy(artifact(), &renamed).expect("copy");
    let modified = dir.join(if cfg!(windows) { "warrantor.exe" } else { "warrantor" });
    let mut bytes = std::fs::read(artifact()).expect("read");
    bytes.push(0x00);
    std::fs::write(&modified, &bytes).expect("write");
    let (digest, _) = exec::sha256_file(&artifact()).expect("digest");
    let declared = pinned(&digest);

    let same = exec::admit(Some(&declared), ExecSurface::Process,
        &renamed.to_string_lossy(), None, "wrt_x", ExecPhase::Spawn, NOW).expect("admit");
    assert_eq!(same.verdict, ExecVerdict::Admitted);
    assert_eq!(same.sha256, digest, "the receipt carries the digest, not the name");
    assert_eq!(same.gate, None);

    // Same NAME as the real binary, different bytes.
    let changed = exec::admit(Some(&declared), ExecSurface::Process,
        &modified.to_string_lossy(), None, "wrt_x", ExecPhase::Spawn, NOW).expect("admit");
    assert_eq!(changed.verdict, ExecVerdict::Refused);
    assert_eq!(changed.gate, Some(warrantor_notary::Gate::Artifacts));
    let sentence = exec::refusal_sentence(&changed);
    assert!(sentence.contains("artifacts"), "{sentence}");
    assert!(
        !sentence.contains(&digest),
        "a refusal must not disclose which digests ARE admitted (Deny carries only the gate)"
    );
}

#[test]
fn an_undeclared_surface_is_unpinned_and_a_declared_empty_surface_refuses_everything() {
    let unpinned = exec::admit(None, ExecSurface::Process, &artifact().to_string_lossy(),
        None, "wrt_x", ExecPhase::Preflight, NOW).expect("admit");
    assert_eq!(unpinned.verdict, ExecVerdict::Unpinned);
    assert_eq!(unpinned.sha256.len(), 64, "unpinned still carries the digest");

    let strict_empty: BTreeSet<ExecAdmission> = BTreeSet::new();
    let refused = exec::admit(Some(&strict_empty), ExecSurface::Process,
        &artifact().to_string_lossy(), None, "wrt_x", ExecPhase::Preflight, NOW).expect("admit");
    assert_eq!(refused.verdict, ExecVerdict::Refused, "E-04: undeclared is refused under strict");

    // Admitted on one surface is not admitted on another.
    let (digest, _) = exec::sha256_file(&artifact()).expect("digest");
    let upstream_only: BTreeSet<ExecAdmission> =
        [ExecAdmission { surface: ExecSurface::Upstream, sha256: digest }].into_iter().collect();
    let wrong_surface = exec::admit(Some(&upstream_only), ExecSurface::Process,
        &artifact().to_string_lossy(), None, "wrt_x", ExecPhase::Preflight, NOW).expect("admit");
    assert_eq!(wrong_surface.verdict, ExecVerdict::Refused);
}

#[test]
fn a_program_that_cannot_be_hashed_cannot_be_admitted() {
    let err = exec::admit(None, ExecSurface::Process, "no-such-program-2f9c",
        None, "wrt_x", ExecPhase::Spawn, NOW).expect_err("unresolvable");
    assert!(err.contains("PATH"), "{err}");
}

#[test]
fn receipts_append_as_versioned_jsonl_and_read_back() {
    let root = tempdir("receipts");
    let receipt = exec::admit(None, ExecSurface::Process, &artifact().to_string_lossy(),
        None, "wrt_r", ExecPhase::Spawn, NOW).expect("admit");
    exec::record(&root, &receipt).expect("record");
    exec::record(&root, &receipt).expect("record again");
    let raw = std::fs::read_to_string(exec::log_path(&root, "wrt_r")).expect("read");
    assert_eq!(raw.lines().count(), 2);
    assert!(raw.contains(&format!("\"format\":\"{EXEC_RECEIPT_FORMAT}\"")), "{raw}");
    let log = exec::read_for(&root, "wrt_r");
    assert_eq!(log.receipts.len(), 2);
    assert_eq!(log.unreadable_lines, 0);
    assert_eq!(log.receipts[0].sha256, receipt.sha256);
}

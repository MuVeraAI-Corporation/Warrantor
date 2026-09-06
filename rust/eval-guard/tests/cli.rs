//! The shipped `eval-guard` binary, driven as a process.
//!
//! # Why a binary test and not only the unit tests
//!
//! `.github/workflows/release.yml` ships this binary by name, and until 2026-09-05 it signed an
//! all-pass attestation for `--agent x` on a laptop in no sandbox at all. The fix added two required
//! flags, and the crate's unit tests pin the library half -- that `Provenance` is in the signed bytes.
//! Nothing pinned the CLI half: the `--assume-all-pass` refusal could be deleted and
//! `cargo test -p warrantor-eval-guard --all-targets` stayed green, because no test ran the binary. A
//! reviewer showed it by deleting the refusal and signing an all-pass attestation with
//! `--provenance asserted:operator:vj` alone -- the old defect, now with a named party inside it.
//!
//! The plan's exit gate for Task 13.7 also asks for `eval-guard --agent x` to exit non-zero with no
//! attestation on stdout; that clause was a manual run in the evidence file and is a test here.

use warrantor_eval_guard::{verify_attestation, SandboxAttestation};

const EXE: &str = env!("CARGO_BIN_EXE_eval-guard");

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = std::process::Command::new(EXE)
        .args(args)
        .output()
        .expect("run eval-guard");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn a_caller_who_names_no_provenance_is_handed_no_signature() {
    // The exit gate's second clause, verbatim: `--agent x` must exit non-zero with no attestation on
    // stdout, because a caller who names no provenance can no longer be handed a signature. Exit 2
    // is clap's usage-error code: the binary refuses at argument parsing.
    let (code, stdout, stderr) = run(&["--agent", "x"]);
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.is_empty(), "nothing may reach stdout: {stdout}");
    assert!(stderr.contains("--provenance"), "{stderr}");
}

#[test]
fn naming_a_source_alone_does_not_restore_the_fabricated_pass() {
    // The refusal the module doc calls load-bearing: naming who is speaking is not the same act as
    // declaring four unmeasured booleans true, and collapsing the two would let
    // `--provenance asserted:me` quietly restore the old behavior. This is the invocation the
    // reviewer used to sign an all-pass attestation once the refusal was deleted.
    let (code, stdout, stderr) = run(&["--agent", "x", "--provenance", "asserted:operator:vj"]);
    assert_eq!(code, Some(2), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.is_empty(), "nothing may reach stdout: {stdout}");
    assert!(stderr.contains("refusing to sign anything"), "{stderr}");
    assert!(stderr.contains("--assume-all-pass"), "{stderr}");

    // CONTROL: with the declaration made on the record, the binary signs -- so the refusal above is
    // a gate on the flag and not a binary that refuses everything. The attestation it prints is a
    // real one: it parses, it verifies, and it carries the party that asserted it inside the signed
    // bytes.
    let (code, stdout, stderr) = run(&[
        "--agent",
        "x",
        "--provenance",
        "asserted:operator:vj",
        "--assume-all-pass",
    ]);
    assert_eq!(code, Some(0), "stdout: {stdout}\nstderr: {stderr}");
    let attestation: SandboxAttestation =
        serde_json::from_str(&stdout).expect("stdout is one attestation");
    verify_attestation(&attestation).expect("the printed attestation verifies");
    assert_eq!(attestation.results, [true, true, true, true]);
    assert_eq!(attestation.provenance.word(), "asserted");
    assert_eq!(attestation.provenance.source(), "operator:vj");
    // And the caveat goes to stderr, where a caller piping stdout to a file cannot lose it.
    assert!(
        stderr.contains("nothing measured this boundary"),
        "{stderr}"
    );
}

#[test]
fn a_failed_boundary_is_refused_whatever_the_provenance_says() {
    // Invariant I-09 through the binary: a boundary the caller reports as failed produces no
    // attestation, even under a `measured:` source and the all-pass declaration.
    let (code, stdout, stderr) = run(&[
        "--agent",
        "x",
        "--provenance",
        "measured:netns-probe/1",
        "--assume-all-pass",
        "--skip",
        "network",
    ]);
    assert_eq!(code, Some(1), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.is_empty(), "nothing may reach stdout: {stdout}");
    assert!(
        stderr.contains("boundary check failed: NetworkIsolation"),
        "{stderr}"
    );
    assert!(stderr.contains("REFUSING to start the agent"), "{stderr}");
}

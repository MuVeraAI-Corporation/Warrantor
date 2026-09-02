//! Shared machinery for the invariant attack corpus.
//!
//! # The rule this module exists to enforce
//!
//! An adversarial test that fails trivially is worse than no test. It produces a green result and
//! a false guarantee, which is the incident's own phantom-scorer dynamic reproduced inside our
//! test suite: hundreds of agents organized for four days against a check that did not exist.
//!
//! So every attack in this corpus is run twice. Once with the attack **backed out** — the control,
//! which must be allowed — and once with the attack applied, which must be refused. If the control
//! is refused, the attack never reached the boundary and its refusal proves nothing: a typo in the
//! attack payload, a malformed request, a fixture denied three gates earlier. That is a false
//! pass, and [`refused_at_the_boundary`] fails on it with a message saying so.
//!
//! The remedy for a failing control is always to fix the attack. It is never to weaken the
//! assertion.

use std::path::{Path, PathBuf};

/// The repository root, derived from this crate's manifest directory (`<root>/rust/warrant`).
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the warrant crate lives two directories below the repository root")
        .to_path_buf()
}

/// Read a repository-relative file as text. Used by the static checks, which assert properties of
/// source this test binary does not link — the invariants reach further than warrant's dependency
/// graph, and a static check is how a suite says so honestly.
pub fn read_repository_file(relative: &str) -> String {
    let path = repository_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// Assert that an attack reached the boundary and was refused there.
///
/// * `control` is the same scenario with the attack backed out. It MUST be allowed.
/// * `attacked` is the scenario with the attack applied. It MUST be refused.
///
/// `allowed` decides which is which for the outcome type in question, so this serves the notary's
/// `Verdict`, the broker's `EgressVerdict`, a `Result`, or a bare `bool`.
///
/// # Panics
/// Panics naming the control failure when the attack never reached the boundary, and naming the
/// missing refusal when the boundary let the attack through.
#[track_caller]
pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)
where
    T: std::fmt::Debug,
    F: Fn(&T) -> bool,
{
    assert!(
        allowed(control),
        "{what}: the CONTROL was refused, so the attack never reached the boundary and its \
         refusal proves nothing. This is a false pass. Fix the attack so the control is allowed; \
         never weaken the assertion. Control outcome: {control:?}"
    );
    assert!(
        !allowed(attacked),
        "{what}: the attack REACHED the boundary and was NOT refused. Control outcome: \
         {control:?}; attacked outcome: {attacked:?}"
    );
}

/// Assert that an attack reached the boundary and was **not** refused.
///
/// The inverse of [`refused_at_the_boundary`], for a violation the corpus has demonstrated and is
/// recording rather than fixing. It makes the finding executable: once the invariant is enforced
/// this call starts failing, and whoever fixed it must convert the test to
/// [`refused_at_the_boundary`] and raise the ratchet. A finding that silently goes stale is a
/// finding nobody will ever close.
#[track_caller]
pub fn reached_the_boundary_unrefused<T, F>(what: &str, control: &T, attacked: &T, allowed: F)
where
    T: std::fmt::Debug,
    F: Fn(&T) -> bool,
{
    assert!(
        allowed(control),
        "{what}: the CONTROL was refused, so this demonstrates nothing about the attack. \
         Control outcome: {control:?}"
    );
    assert!(
        allowed(attacked),
        "{what}: this invariant is now enforced — the attack was refused. Good. Convert this test \
         to harness::refused_at_the_boundary, close the finding in docs/W1-delivery-gaps.md, and \
         raise the ratchet in tools/ci/invariant-ratchet.json. Attacked outcome: {attacked:?}"
    );
}

/// Assert a source file contains a fragment, with a message naming the invariant at stake.
#[track_caller]
pub fn source_contains(relative: &str, fragment: &str, why: &str) {
    let source = read_repository_file(relative);
    assert!(
        source.contains(fragment),
        "{relative} no longer contains {fragment:?}. {why}"
    );
}

/// Count occurrences of a fragment across a repository-relative directory's `.rs` files.
///
/// The static checks use this to ask whether a symbol is ever *constructed* rather than merely
/// declared — the distinction between an enforced boundary and a rendered one.
pub fn occurrences_in_rust_sources(relative_directory: &str, fragment: &str) -> usize {
    let root = repository_root().join(relative_directory);
    let mut total = 0;
    let mut stack = vec![root];
    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));
        for entry in entries {
            let entry = entry.expect("readable directory entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
                total += source.matches(fragment).count();
            }
        }
    }
    total
}

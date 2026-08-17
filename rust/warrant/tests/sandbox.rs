//! `warrantor sandbox` end to end: the profile a real warrant produces.
//!
//! The unit tests in `src/sandbox.rs` pin the derivation. What this adds is the path a warrant
//! actually takes through the store, and the one refusal that only shows up with a real
//! `StoredWarrant`: a worktree path from the wrong operating system.
//!
//! Nothing here executes `bwrap`. That boundary is deliberate and is stated in the emitted profile:
//! whether bubblewrap confines what it says it confines is bubblewrap's claim, and this repository
//! has never run it.

use std::collections::BTreeSet;

use warrantor_warrant::sandbox::{self, Confinement, Divergence};
use warrantor_warrant::{SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn bounds(write: &[&str], egress: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: ["github.create_pr"].into_iter().map(String::from).collect(),
        write_paths: write.iter().map(|s| (*s).to_string()).collect(),
        egress_hosts: egress.iter().map(|s| (*s).to_string()).collect(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: Some(500),
        delegation_depth: 1,
    }
}

#[test]
fn a_no_egress_warrant_produces_a_command_that_unshares_the_network() {
    let profile = sandbox::profile(
        &bounds(&["src/**"], &[]),
        "/home/u/wt",
        Confinement::Bubblewrap,
    );
    let line = profile.shell_line();
    assert!(line.starts_with("bwrap "), "{line}");
    assert!(line.contains("--ro-bind / /"), "{line}");
    assert!(line.contains("--bind /home/u/wt /home/u/wt"), "{line}");
    assert!(line.contains("--unshare-net"), "{line}");
    assert!(line.contains("--die-with-parent"), "{line}");
    assert!(
        profile.overreaches().is_empty(),
        "{:?}",
        profile.overreaches()
    );
}

#[test]
fn a_warrant_that_permits_egress_gets_no_netns_and_is_told_why() {
    // The finding the module exists for: a netns is all-or-nothing, so emitting one here would deny
    // what the warrant grants and the agent would fail at its first fetch — a failure that does not
    // look like a bound refusing anything.
    let profile = sandbox::profile(
        &bounds(&["src/**"], &["api.github.com"]),
        "/home/u/wt",
        Confinement::Bubblewrap,
    );
    assert!(!profile.shell_line().contains("--unshare-net"));
    let over = profile.overreaches();
    assert_eq!(over.len(), 1);
    let Divergence::Overreach { bound, why } = over[0] else {
        unreachable!()
    };
    assert_eq!(bound, "egress_hosts");
    assert!(why.contains("api.github.com"), "{why}");
}

#[test]
fn a_windows_worktree_is_refused_before_any_command_is_written() {
    // Found by running `warrantor sandbox` on Windows, which emitted a syntactically perfect
    // `bwrap --bind 'M:\wt-depth\...'`. It reads as runnable. Pasted into a Linux shell it fails
    // with bwrap's error about a missing directory, naming the symptom and not the cause.
    let error = sandbox::check_worktree(r"M:\wt-depth\.warrantor\wrt_1")
        .expect_err("a Windows path cannot appear in a Linux confinement");
    assert!(error.contains("Linux-only"), "{error}");
    assert!(error.contains("LOOKS runnable"), "{error}");
    sandbox::check_worktree("/home/u/wt").expect("a POSIX path is fine");
}

#[test]
fn the_profile_never_claims_a_bound_became_enforced() {
    // The rule the whole module rests on. `bound_strengths` is the product's honest report and this
    // module must not move a single entry in it: a profile that is never launched confines nothing,
    // and this process cannot tell whether the operator launched it.
    let before: BTreeSet<String> = warrantor_warrant::bound_strengths()
        .into_iter()
        .map(|(name, strength)| format!("{name}={strength:?}"))
        .collect();
    let profile = sandbox::profile(
        &bounds(&["src/**"], &[]),
        "/home/u/wt",
        Confinement::Bubblewrap,
    );
    assert!(!profile.argv.is_empty());
    let after: BTreeSet<String> = warrantor_warrant::bound_strengths()
        .into_iter()
        .map(|(name, strength)| format!("{name}={strength:?}"))
        .collect();
    assert_eq!(
        before, after,
        "writing a profile must not restate any bound"
    );
    assert!(profile.caveat.contains("COMMAND, not an enforcement"));
}

//! Task 7.6, exit gate: the unmediated statement is carried into every surface that renders
//! coverage. `warrantor agents list` is that surface. This drives the shipped binary, so the
//! sentence and the remainder are proven to reach an operator, not only to exist in a module.

use std::path::Path;
use std::process::Command;

use warrantor_warrant::computer_use::{ungoverned_remainder, UNMEDIATED_SENTENCE};

fn agents_list(home: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .args(["agents", "list"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor agents list");
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), both)
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "warrantor-agents-list-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("tempdir");
    dir
}

#[test]
fn the_coverage_surface_says_computer_use_is_unmediated_and_lists_every_ungoverned_action() {
    let home = tempdir();
    let (ok, out) = agents_list(&home);
    assert!(ok, "agents list must succeed: {out}");

    // The control: the surface still renders the harness registry it always did. Without this,
    // the assertions below would also pass on a binary that printed only the computer-use block.
    assert!(
        out.contains("CODING AGENT") && out.contains("MCP calls mediated, built-ins are not"),
        "the harness rows must still render: {out}"
    );

    assert!(
        out.contains("COMPUTER USE:"),
        "the surface must have a computer-use section: {out}"
    );
    // The sentence is rendered whole, so an operator reads all three reasons, not a summary.
    assert!(
        out.contains(UNMEDIATED_SENTENCE),
        "the unmediated sentence must appear verbatim: {out}"
    );
    for entry in ungoverned_remainder() {
        assert!(
            out.contains(entry.action) && out.contains(entry.why),
            "every ungoverned action and its reason must be rendered: {:?}",
            entry.action
        );
    }
    // The worst outcome the exit gate names is partial mediation rendered as coverage.
    for forbidden in [
        "partially mediated",
        "fully governed",
        "computer use: mediated",
    ] {
        assert!(
            !out.to_lowercase().contains(forbidden),
            "the surface must not render computer use as covered: found {forbidden:?}"
        );
    }
}

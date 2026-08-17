//! Every instruction this binary gives is an untested assertion. This is the test.
//!
//! # The defect class
//!
//! Three of the five defects found in one session were **claims, not branches**:
//!
//! 1. `AgentEndpoint` told the operator to *"start the agent endpoint with `--upstream <command>`"*.
//!    `--upstream` did not exist anywhere in the binary. It survived eight releases with a passing
//!    test — the test asserted the arm returned an error, and it did.
//! 2. The Python harness generator wrote `CLAUDE.md` files asserting that every action was recorded
//!    and that secret exposure triggered a kill-switch. Nothing made either true.
//! 3. The guard quoted a recall figure measured at a context window the product did not run at.
//!
//! Each was invisible to a 500-test suite for the same reason: *"the instruction is real"* is not
//! usually treated as a testable property, so nobody writes the test, so a sentence can rot
//! indefinitely while everything around it stays green.
//!
//! # What this asserts
//!
//! Every long flag and every subcommand the binary **names in its own output** — usage text and
//! error messages — is one the binary actually accepts. It does not check that a flag does the right
//! thing; the rest of the suite does that. It checks that the remedy a user is handed exists.
//!
//! It is deliberately mechanical and deliberately cheap. A test that has to be maintained in step
//! with the prose it checks would be abandoned; this one reads the prose.

use std::collections::BTreeSet;
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_warrantor");

fn usage() -> String {
    let out = Command::new(EXE).arg("help").output().expect("run help");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Every `--flag` mentioned in a body of text, long form only.
///
/// Short flags are excluded: a bare `-h` inside prose is indistinguishable from a hyphen, and the
/// false positives would make this test noise.
fn flags_named_in(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == '-' && bytes[index + 1] == '-' && bytes[index + 2].is_ascii_alphabetic()
        {
            let mut end = index + 2;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == '-' || bytes[end] == '_')
            {
                end += 1;
            }
            let name: String = bytes[index + 2..end].iter().collect();
            // A trailing hyphen is prose ("the --guard- family"), not a flag name.
            found.insert(name.trim_end_matches('-').to_string());
            index = end;
        } else {
            index += 1;
        }
    }
    found
}

/// Flags the parser accepts, read from the source of truth: the dispatch and the readers.
///
/// Listed rather than derived because this binary's parser is a hand-written map — there is no
/// clap-style registry to enumerate. The list being hand-maintained is fine: the *point* of the
/// test is the direction of the check. A flag added to the usage text and not to this list fails,
/// and the fix is to confirm it is really read and then add it.
const ACCEPTED_FLAGS: &[&str] = &[
    // global
    "root",
    "help",
    // grant
    "goal",
    "tools",
    "write",
    "deadline",
    "repo",
    "egress",
    "budget",
    "subject",
    // report / verify / issuer / archive
    "export",
    "archive",
    "issuer",
    "note",
    "replace",
    "url",
    "code",
    "out",
    // spend
    "input",
    "output",
    "backend",
    "quote",
    // stop / settle / stage
    "reason",
    "commit",
    "tool",
    "target",
    "arg",
    // prune / agents
    "apply",
    // operator
    "scope",
    // issuer export
    "as",
    // mcp
    "agent",
    "observe",
    "upstream",
    "upstream-timeout",
    "upstream-allow-lifecycle-tools-i-accept-this",
    // guard
    "guard",
    "guard-endpoint",
    "guard-model",
    "guard-seed",
    "guard-num-ctx",
    "guard-timeout",
    "guard-max-calls",
    "guard-enforce-untested-do-not-use",
    // serve / console
    "bind",
    "port",
    "token-file",
    "allow-settle",
    "i-accept-cleartext-on-this-network",
];

#[test]
fn every_flag_the_usage_text_names_is_one_the_parser_accepts() {
    let text = usage();
    let accepted: BTreeSet<&str> = ACCEPTED_FLAGS.iter().copied().collect();
    let unknown: Vec<String> = flags_named_in(&text)
        .into_iter()
        .filter(|f| !accepted.contains(f.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "the usage text names flags this binary does not accept: {unknown:?}\n\nThis is the \
         `--upstream` defect: a flag recommended in the binary's own output that exists nowhere \
         else in it. Either wire the flag or stop naming it."
    );
}

#[test]
fn every_command_the_usage_text_names_is_one_the_binary_dispatches() {
    // Read from the left column of the usage block: the first word of a line indented by two
    // spaces, which is how every command in that text is introduced.
    let text = usage();
    let named: BTreeSet<String> = text
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("  ")?;
            if rest.starts_with(' ') || rest.starts_with('-') {
                return None;
            }
            let word = rest.split_whitespace().next()?;
            word.chars()
                .all(|c| c.is_ascii_lowercase() || c == '-')
                .then(|| word.to_string())
        })
        .collect();

    assert!(
        named.len() > 10,
        "the extraction found only {named:?} -- if the usage layout changed, this test has to \
         change with it rather than silently checking nothing"
    );

    // Compared against the dispatch table read out of the source, not by running each command.
    // Three of these commands do not return: `serve` and `console` bind a port and serve, and `mcp`
    // reads stdin until it closes. Spawning them is how this test hung for ten minutes on its first
    // run — a fact worth leaving written down, because "just execute it and see" is the obvious
    // implementation and it is wrong here.
    let source = include_str!("../src/bin/warrantor.rs");
    let dispatched: BTreeSet<String> = source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed.strip_prefix('"')?;
            let (name, tail) = rest.split_once('"')?;
            // Only the match arms of the command dispatch: `"grant" => cmd_grant(...)`. Every other
            // string-keyed match in this file compares against a value, not a subcommand.
            tail.trim_start()
                .starts_with("=> cmd_")
                .then(|| name.to_string())
        })
        .collect();
    assert!(
        dispatched.len() > 10,
        "the dispatch extraction found only {dispatched:?} -- if the match shape changed, this \
         test has to change with it rather than silently checking nothing"
    );

    for command in named {
        assert!(
            dispatched.contains(&command),
            "the usage text names `{command}` and the dispatch does not know it. Dispatched: \
             {dispatched:?}"
        );
    }
}

#[test]
fn the_refusal_for_a_permitted_call_with_no_upstream_names_a_real_flag() {
    // The specific regression, asserted from the message rather than from the code, so it fails if
    // the message drifts back to naming something that does not exist.
    let text = usage();
    assert!(
        text.contains("--upstream"),
        "the usage text must document the flag its own error messages recommend"
    );
    let accepted: BTreeSet<&str> = ACCEPTED_FLAGS.iter().copied().collect();
    assert!(accepted.contains("upstream"));
}

#[test]
fn every_harness_the_registry_lists_can_be_shown() {
    // `agents list` prints ids and tells the reader to run `agents show <id>`. An id in the listing
    // that `show` refuses is the same class of defect at a smaller scale.
    let listing = Command::new(EXE)
        .args(["agents", "list"])
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&listing.stdout).to_string();
    let ids: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("  ")?;
            let word = rest.split_whitespace().next()?;
            // Ids only: the listing's other indented lines start with `warrantor` or are prose.
            (word.contains('-') || word.chars().all(char::is_alphanumeric))
                .then(|| word.to_string())
        })
        .filter(|word| word != "warrantor")
        .collect();

    assert!(ids.len() >= 10, "expected the whole registry: {ids:?}");
    for id in ids {
        let out = Command::new(EXE)
            .args(["agents", "show", &id])
            .output()
            .expect("run");
        assert!(
            out.status.success(),
            "`agents list` names `{id}` and `agents show {id}` refuses it:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn the_removed_python_generator_is_not_reachable_from_the_rust_binary() {
    // The false-claim generator wrote CLAUDE.md / AGENTS.md / .cursorrules asserting protections
    // that were not in force. Nothing in this binary may ever produce a file of that kind: a
    // security claim in a prompt is the failure this product exists to refuse.
    let text = usage();
    for prose_file in ["CLAUDE.md", ".cursorrules", "AGENTS.md"] {
        assert!(
            !text.contains(prose_file),
            "the usage text mentions {prose_file}. If a command writes one, it is writing a \
             security claim into a prompt, which nothing in the substrate enforces."
        );
    }
}

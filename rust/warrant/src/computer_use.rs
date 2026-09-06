//! L4-18 — what a computer-use session's effects decompose to, and the list of what they do not.
//!
//! # The finding this module exists to state
//!
//! A computer-use surface defeats the effect model by construction. Every other effect in this
//! system arrives as a structured call — a tool name and named arguments — and Task 2.1 decomposes
//! it into the nine syscalls by looking at what the operator DECLARED about that tool. A screen
//! action arrives as a coordinate. `click(842, 517)` carries no argument that says whether the
//! button under the cursor submits a search or wires money, and no amount of reading the click
//! tells you: the consequence lives in the page, not in the call.
//!
//! So this module does not claim a decomposition for computer use. It splits the surface in two and
//! makes both halves legible:
//!
//! - [`decompose`] returns a syscall set for the actions whose effect-relevant argument IS
//!   structured data the caller declares: a navigation URL, text typed into a field whose role the
//!   caller states, a path chosen in a file dialog. Declaration only, never inference — the same
//!   rule as [`crate::effects`], for the same reason.
//! - [`UNGOVERNED`] is the remainder, as data rather than prose, so a surface can render it and a
//!   test can assert it is never empty. Every entry names the action and why it cannot be
//!   decomposed.
//!
//! # What this does NOT establish, in the words the exit gate asks for
//!
//! **Computer use is unmediated in this build.** Not partially mediated: unmediated. Three separate
//! reasons, each sufficient on its own:
//!
//! 1. Nothing calls this module, and nothing calls the `warrantor-computer-use` crate either — it
//!    is one of the 28 orphans in `evidence/wiring-coverage.json`. A decomposition no code consults
//!    decides nothing.
//! 2. Even a decomposition that WAS consulted would cover only the declared subset below. The
//!    remainder is most of what a computer-use agent does.
//! 3. `rust/sandbox-runtime` cannot confine a computer-use session. It is a WASI runtime that
//!    executes WASM modules with declared imports; a browser is not a WASM module and cannot be
//!    hosted in it. The obvious hope — run the session in the sandbox and get Tier A for "no
//!    network" and "no credential access" — is not available in this repository.
//!
//! # Mediation of the call is not governance of the effect
//!
//! [`crate::harness::Coverage`] answers a different question than this module, and reading one as
//! the other is the mistake this file is written to prevent. `Coverage` answers *is the call
//! refusable* — if a screen action arrives through an MCP server, the proxy sees a tool name and
//! can refuse it. This module answers *is the effect decomposable* — what the call will DO once
//! permitted. A computer-use tool can be perfectly mediated in the first sense and completely
//! ungoverned in the second, which is exactly the state of this surface today. An operator shown
//! only the first answer has been told the boundary holds when it does not.

use std::collections::BTreeSet;

use crate::effects::Syscall;

/// The format tag for any rendered computer-use coverage document.
pub const COMPUTER_USE_COVERAGE_FORMAT: &str = "warrantor.computer-use-coverage/1";

/// What the caller states a text field is for. **Declared, never inferred.**
///
/// Nothing here reads the page to decide whether a field holds a password. A heuristic that guessed
/// would under-govern exactly where it matters, which is the defect [`crate::effects`] refuses by
/// the same rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldRole {
    /// The caller states this field takes a secret: a password, token or one-time code.
    Credential,
    /// The caller states this field takes ordinary text with no authority in it.
    FreeText,
}

/// Which way bytes move through a file dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileDirection {
    /// A file is read from disk into the page.
    Read,
    /// A file is written to disk from the page.
    Write,
}

/// A single thing a computer-use harness can be asked to do.
///
/// The first three variants carry the argument their effect turns on. The rest carry a coordinate
/// or a selector, and their consequence is a property of the page rather than of the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenAction {
    /// Go to a URL. The URL is the effect-relevant argument.
    Navigate {
        /// Where to.
        url: String,
    },
    /// Type into a field whose role the caller declares.
    TypeIntoDeclaredField {
        /// What the caller says the field is for.
        role: FieldRole,
        /// The element, for the record. Not what the decomposition turns on.
        selector: String,
    },
    /// Choose a path in a file dialog, in a stated direction.
    ChooseFileInDialog {
        /// The path.
        path: String,
        /// Read or write.
        direction: FileDirection,
    },
    /// Click at a pixel coordinate.
    ClickAtCoordinates {
        /// Horizontal pixels.
        x: i32,
        /// Vertical pixels.
        y: i32,
    },
    /// Click the element a selector names.
    ClickSelector {
        /// The element.
        selector: String,
    },
    /// Capture the screen.
    Screenshot,
    /// Read visible text back out of the page.
    ScrapeVisibleText {
        /// Optionally scoped to an element.
        selector: Option<String>,
    },
}

/// One action the effect model cannot decompose, and the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ungoverned {
    /// The action, named as an operator would recognize it.
    pub action: &'static str,
    /// Why no syscall set can be derived from it. Written to be quoted at a reader.
    pub why: &'static str,
}

/// The remainder: every computer-use action whose effect this model cannot see.
///
/// This is a list in code and not a paragraph so that a surface can render it, a test can assert it
/// is non-empty, and adding a governed action requires deleting an entry here rather than editing
/// prose somewhere else.
pub const UNGOVERNED: &[Ungoverned] = &[
    Ungoverned {
        action: "click at a coordinate",
        why: "A pixel carries no semantics. The same coordinate submits a search on one page and \
              transfers money on the next, and the call contains nothing that distinguishes them.",
    },
    Ungoverned {
        action: "click the element a selector names",
        why: "A selector names WHERE the click lands, never what it does. `#submit` is a name the \
              page chose; the effect behind it is the page's code, which this process never sees.",
    },
    Ungoverned {
        action: "type into a field whose role was not declared",
        why: "Typed text is a credential or a comment depending on the field, and nothing here \
              reads the page to tell them apart. Guessing would under-govern precisely the case \
              that matters, so an undeclared field is refused a decomposition rather than given a \
              wrong one.",
    },
    Ungoverned {
        action: "capture the screen",
        why:
            "A screenshot removes whatever is on screen from the session's confinement, including \
              a secret the agent was never handed. It is a read whose scope is the display, and no \
              argument of the call bounds it.",
    },
    Ungoverned {
        action: "read visible text back out of the page",
        why:
            "Same reach as a screenshot, in a form easier to forward. The selector narrows what is \
              returned; it does not bound what was readable.",
    },
    Ungoverned {
        action: "any consequence a page produces on its own after an action",
        why:
            "A navigation can run scripts, post a form, or open a dialog with no further call from \
              the agent. Those effects have no call to decompose at all.",
    },
];

// The remainder is never empty. A coverage query that could return an empty list would let a
// surface render computer use as fully governed, which is the outcome the exit gate calls the worst
// available. Emptying this list must be a build failure, not a rendering choice.
const _: () = assert!(!UNGOVERNED.is_empty());

/// What [`decompose`] can say about one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decomposed {
    /// The caller declared enough for a syscall set to follow from the call itself.
    Declared(BTreeSet<Syscall>),
    /// The effect is not visible to this model. Carries the reason, for rendering.
    Ungoverned(&'static Ungoverned),
}

fn ungoverned(action: &str) -> &'static Ungoverned {
    UNGOVERNED
        .iter()
        .find(|u| u.action == action)
        .expect("every ungoverned branch names an entry in UNGOVERNED")
}

/// Decompose one screen action, or say why it cannot be decomposed.
///
/// The declared subset and its justification:
///
/// - [`ScreenAction::Navigate`] is `NET`. A URL is a destination, and a destination is the one thing
///   about a screen action that is structured data in the call.
/// - [`ScreenAction::TypeIntoDeclaredField`] with [`FieldRole::Credential`] is `CRED` plus `NET`:
///   typing a secret into a page hands it to whatever the page posts to, so the credential use and
///   its transmission are one act. With [`FieldRole::FreeText`] it is `MSG` — text entering a
///   system where someone else may read it.
/// - [`ScreenAction::ChooseFileInDialog`] is `MUTATE` for a write, since a file leaves this
///   machine's control, and `NET` for a read, since choosing a file for upload sends it. A read is
///   deliberately not bare: the point of a file dialog in a browser is that the bytes go somewhere.
#[must_use]
pub fn decompose(action: &ScreenAction) -> Decomposed {
    let set = |verbs: &[Syscall]| Decomposed::Declared(verbs.iter().copied().collect());
    match action {
        ScreenAction::Navigate { .. } => set(&[Syscall::Net]),
        ScreenAction::TypeIntoDeclaredField { role, .. } => match role {
            FieldRole::Credential => set(&[Syscall::Cred, Syscall::Net]),
            FieldRole::FreeText => set(&[Syscall::Msg]),
        },
        ScreenAction::ChooseFileInDialog { direction, .. } => match direction {
            FileDirection::Write => set(&[Syscall::Mutate]),
            FileDirection::Read => set(&[Syscall::Net]),
        },
        ScreenAction::ClickAtCoordinates { .. } => {
            Decomposed::Ungoverned(ungoverned("click at a coordinate"))
        }
        ScreenAction::ClickSelector { .. } => {
            Decomposed::Ungoverned(ungoverned("click the element a selector names"))
        }
        ScreenAction::Screenshot => Decomposed::Ungoverned(ungoverned("capture the screen")),
        ScreenAction::ScrapeVisibleText { .. } => {
            Decomposed::Ungoverned(ungoverned("read visible text back out of the page"))
        }
    }
}

/// The ungoverned remainder. Never empty; see the assertion beside [`UNGOVERNED`].
#[must_use]
pub fn ungoverned_remainder() -> &'static [Ungoverned] {
    UNGOVERNED
}

/// The sentence a surface renders beside any computer-use coverage figure.
///
/// It states the three independent reasons the surface is unmediated, because a reader who fixes
/// only the wiring would otherwise believe the other two were addressed.
pub const UNMEDIATED_SENTENCE: &str =
    "Computer use is UNMEDIATED in this build. The decomposition below is a declaration \
     vocabulary that nothing consults: no code path calls it, and the warrantor-computer-use crate \
     is an orphan that nothing depends on. Even if it were wired, it would cover only the declared \
     subset -- a navigation URL, text typed into a field whose role the caller states, and a file \
     dialog path -- and not the remainder, which is most of what a computer-use agent does. And it \
     cannot be confined here instead: rust/sandbox-runtime executes WASM modules with declared \
     imports, so it cannot host a browser, and the no-network, no-credential confinement that \
     would earn an OS-level bound for those two properties is not available in this repository.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declared_subset_decomposes_and_the_remainder_does_not() {
        // The paired control in one test: the same surface answers both ways, so neither answer can
        // come from a function that always says the same thing.
        let declared = [
            (
                ScreenAction::Navigate {
                    url: "https://example.test/app".to_string(),
                },
                vec![Syscall::Net],
            ),
            (
                ScreenAction::TypeIntoDeclaredField {
                    role: FieldRole::Credential,
                    selector: "input[type=password]".to_string(),
                },
                vec![Syscall::Cred, Syscall::Net],
            ),
            (
                ScreenAction::TypeIntoDeclaredField {
                    role: FieldRole::FreeText,
                    selector: "#comment".to_string(),
                },
                vec![Syscall::Msg],
            ),
            (
                ScreenAction::ChooseFileInDialog {
                    path: "/tmp/report.csv".to_string(),
                    direction: FileDirection::Write,
                },
                vec![Syscall::Mutate],
            ),
            (
                ScreenAction::ChooseFileInDialog {
                    path: "/tmp/report.csv".to_string(),
                    direction: FileDirection::Read,
                },
                vec![Syscall::Net],
            ),
        ];
        for (action, expected) in declared {
            let want: BTreeSet<Syscall> = expected.into_iter().collect();
            assert_eq!(
                decompose(&action),
                Decomposed::Declared(want),
                "declared action must decompose: {action:?}"
            );
        }

        let remainder = [
            ScreenAction::ClickAtCoordinates { x: 842, y: 517 },
            ScreenAction::ClickSelector {
                selector: "#submit".to_string(),
            },
            ScreenAction::Screenshot,
            ScreenAction::ScrapeVisibleText { selector: None },
        ];
        for action in remainder {
            match decompose(&action) {
                Decomposed::Ungoverned(reason) => assert!(
                    UNGOVERNED.iter().any(|u| u.action == reason.action),
                    "the reason must be an entry in the rendered list: {reason:?}"
                ),
                other => panic!("{action:?} must not decompose, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_pixel_click_that_opens_a_credential_dialog_is_invisible_to_the_effect_model() {
        // THE FINDING, as a test rather than a paragraph. A click that opens a login dialog and a
        // click that opens a help page are the same value to this model. If a future change makes
        // them distinguishable, this test fails and the ungoverned list shrinks -- which is the
        // only honest way for that claim to change.
        let opens_credential_dialog = ScreenAction::ClickAtCoordinates { x: 842, y: 517 };
        let opens_help = ScreenAction::ClickAtCoordinates { x: 842, y: 517 };
        assert_eq!(
            opens_credential_dialog, opens_help,
            "the model holds no field that could distinguish these two clicks"
        );
        assert!(
            matches!(
                decompose(&opens_credential_dialog),
                Decomposed::Ungoverned(_)
            ),
            "and so it must refuse to decompose either, rather than guess"
        );
        // CRED is reachable in this module -- see the declared-field case -- so its absence here is
        // a property of the coordinate click and not of a vocabulary that cannot express it.
        let typed = ScreenAction::TypeIntoDeclaredField {
            role: FieldRole::Credential,
            selector: "input[type=password]".to_string(),
        };
        assert_eq!(
            decompose(&typed),
            Decomposed::Declared([Syscall::Cred, Syscall::Net].into_iter().collect())
        );
    }

    #[test]
    fn a_coverage_query_never_returns_an_empty_remainder() {
        let remainder = ungoverned_remainder();
        assert!(
            !remainder.is_empty(),
            "an empty remainder would let a surface render computer use as fully governed"
        );
        for entry in remainder {
            assert!(!entry.action.is_empty(), "every entry names its action");
            assert!(
                entry.why.len() > 40,
                "every entry gives a reason a reader can act on: {entry:?}"
            );
        }
        // Every ungoverned branch of `decompose` resolves to a listed entry, so the list cannot
        // fall behind the code: `ungoverned()` panics if it does.
        let _ = decompose(&ScreenAction::Screenshot);
        let _ = decompose(&ScreenAction::ScrapeVisibleText {
            selector: Some("main".to_string()),
        });
    }

    #[test]
    fn the_unmediated_sentence_states_all_three_reasons() {
        // A reader who fixes only the wiring must not be able to read this sentence as satisfied.
        for fragment in [
            "UNMEDIATED",
            "orphan",
            "declared subset",
            "remainder",
            "WASM modules with declared imports",
        ] {
            assert!(
                UNMEDIATED_SENTENCE.contains(fragment),
                "the disclosure must carry {fragment:?}"
            );
        }
        assert!(
            !UNMEDIATED_SENTENCE.contains("partially mediated"),
            "partial mediation reported as coverage is the worst outcome available here"
        );
    }
}

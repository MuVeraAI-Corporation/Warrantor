# Task 7.6 — Adapter: browser and computer use (L4-18)

Branch `feat/computer-use-adapter`, worktree `M:/wt-7.6`, cut from `main` at `2463504` on
2026-09-06. The plan calls this the hardest adapter in the catalog and says its honest outcome may
be *"unmediated, and here is the sentence that says so."* That is the outcome. The sentence is in
the product, the remainder it cannot govern is a list in code, and the three reasons are each
proven rather than asserted.

| commit | what |
|---|---|
| (this branch, one commit) | `rust/warrant/src/computer_use.rs` (new), `rust/warrant/src/lib.rs` (one `pub mod` line), `rust/warrant/src/bin/warrantor.rs` (the `agents list` surface renders the disclosure), `rust/warrant/tests/agents_list_computer_use.rs` (new), `rust/computer-use/src/lib.rs` (header corrected), `docs/W1-delivery-gaps.md` (section 3.1d), this file |

## The exit gate, quoted verbatim from the plan

> **Exit gate.** Either a decomposition test for a named subset of computer-use effects with the
> remainder explicitly listed as ungoverned, **or** a documented statement that computer use is
> unmediated, carried into `docs/W1-delivery-gaps.md` and every surface that renders coverage. A
> partial mediation reported as full is the worst outcome available here.

## Status of that gate: RUN, both branches of the "either / or"

**The decomposition test for a named subset, with the remainder listed as ungoverned.**
`computer_use::tests::the_declared_subset_decomposes_and_the_remainder_does_not` decomposes five
declared actions to their syscall sets and refuses four undeclared ones, in one test so that
neither answer can come from a function that always says the same thing. The remainder is
`computer_use::UNGOVERNED`, six entries, each with the reason a reader can act on, guarded by
`const _: () = assert!(!UNGOVERNED.is_empty())` so that emptying it is a build failure.

**The documented statement, carried into the gaps document and the coverage surface.**
`computer_use::UNMEDIATED_SENTENCE` is rendered verbatim by `warrantor agents list`, which is the
surface that renders coverage for every harness this build knows. The same sentence opens section
3.1d of `docs/W1-delivery-gaps.md`. The binary test
`the_coverage_surface_says_computer_use_is_unmediated_and_lists_every_ungoverned_action` drives the
shipped executable and asserts the sentence appears whole, every remainder entry appears with its
reason, the harness rows the surface always rendered are still there (the control), and none of
"partially mediated", "fully governed" or "computer use: mediated" appears.

The transcript, from the built binary:

```
$ warrantor agents list
[... the harness registry, unchanged ...]
COMPUTER USE:
  Computer use is UNMEDIATED in this build. The decomposition below is a declaration vocabulary that nothing consults: no code path calls it, and the warrantor-computer-use crate is an orphan that nothing depends on. Even if it were wired, it would cover only the declared subset -- a navigation URL, text typed into a field whose role the caller states, and a file dialog path -- and not the remainder, which is most of what a computer-use agent does. And it cannot be confined here instead: rust/sandbox-runtime executes WASM modules with declared imports, so it cannot host a browser, and the no-network, no-credential confinement that would earn an OS-level bound for those two properties is not available in this repository.

  Effects this model cannot see, so no warrant bounds them:
    - click at a coordinate: A pixel carries no semantics. The same coordinate submits a search on one page and transfers money on the next, and the call contains nothing that distinguishes them.
    - click the element a selector names: A selector names WHERE the click lands, never what it does. `#submit` is a name the page chose; the effect behind it is the page's code, which this process never sees.
    - type into a field whose role was not declared: Typed text is a credential or a comment depending on the field, and nothing here reads the page to tell them apart. Guessing would under-govern precisely the case that matters, so an undeclared field is refused a decomposition rather than given a wrong one.
    - capture the screen: A screenshot removes whatever is on screen from the session's confinement, including a secret the agent was never handed. It is a read whose scope is the display, and no argument of the call bounds it.
    - read visible text back out of the page: Same reach as a screenshot, in a form easier to forward. The selector narrows what is returned; it does not bound what was readable.
    - any consequence a page produces on its own after an action: A navigation can run scripts, post a form, or open a dialog with no further call from the agent. Those effects have no call to decompose at all.
```

## Step 2 — what existed, measured

| Fact | Value |
|---|---|
| `rust/computer-use/src/lib.rs` | 626 lines before this task; one crate, one file |
| On the orphan list | yes: `warrantor-computer-use` is one of the 28 `orphaned` entries in `evidence/wiring-coverage.json` (13 of 41 reachable, 23 edges). Nothing in any manifest outside the crate names it |
| Its own tests | 12 unit tests, `cargo test -p warrantor-computer-use --all-targets` → `12 passed; 0 failed`. The only callers of its code in the repository |
| What `status=partial` referred to | the crate's header, which claimed "Every screen action (click, type, navigate, scrape) goes through an authority-scoped broker" and "'No internet' is enforced in the browser, not in the prompt" |
| `rust/sandbox-runtime/src/lib.rs` | 1,314 lines. A WASI runtime: executes WASM modules whose imports are declared in a signed `SandboxPolicy`; network access is by policy-indexed origin through a host backend. It hosts WASM modules. It cannot host a browser |

## Step 3 — the failing test that is the finding

`a_pixel_click_that_opens_a_credential_dialog_is_invisible_to_the_effect_model`. A click that opens
a login dialog and a click that opens a help page are the same value, `ClickAtCoordinates { x: 842,
y: 517 }`, and the test asserts they are equal and that `decompose` refuses both. The paired control
in the same test shows `CRED` is reachable from this module — typing into a field the caller
declares a credential field decomposes to `{cred, net}` — so the coordinate click's invisibility is
a property of the click and not of a vocabulary that cannot express credentials. The plan said to
expect this test to fail; it is written so that it *passes by asserting the failure*, and a future
change that made the two clicks distinguishable would turn it red, which is the only honest way for
the claim to change.

## Steps 4 and 5 — the declared subset and the remainder

| action | decomposition | why that set |
|---|---|---|
| navigate to a URL | `net` | the URL is a destination, and a destination is the one thing about a screen action that is structured data in the call |
| type into a field the caller declares a credential field | `cred + net` | typing a secret into a page hands it to whatever the page posts to; use and transmission are one act |
| type into a field the caller declares free text | `msg` | text entering a system where someone else may read it |
| choose a file in a dialog, write | `mutate` | a file leaves this machine's control |
| choose a file in a dialog, read | `net` | the point of a file dialog in a browser is that the bytes go somewhere; a read is deliberately not bare |

Declaration only. Nothing reads the page to infer a field's role, for the reason Task 2.1 refuses
schema inference: a guess under-governs exactly the case that matters. The six ungoverned entries
are in the transcript above, verbatim from the code.

## Step 6 — a coverage query never returns an empty remainder

`a_coverage_query_never_returns_an_empty_remainder` asserts the list is non-empty, that every entry
names its action, and that every reason is long enough to act on; the compile-time assertion makes
the empty case a build failure rather than a test failure. `ungoverned()` inside `decompose` panics
if a refusing branch names an action absent from the list, so the list cannot fall behind the code.

**Why the existing `harness::Coverage` enum was not used for this.** The plan points at it as the
honest-disclosure mechanism that already exists, and it is — for a different question. `Coverage`
answers *is the call refusable*: a screen action arriving through an MCP server is refusable by tool
name. This module answers *is the effect decomposable*: what the call will do once permitted. A
computer-use tool can be fully mediated in the first sense and fully ungoverned in the second,
which is the state of the surface today. Bending `Coverage::McpAndBuiltins` to carry the remainder
would have rendered the second answer under the first's label, and the module header says why that
is the mistake this file exists to prevent. The surface renders both.

## Step 7 — sandbox confinement, and which two properties it actually earns

**None, here.** The plan anticipated that a session run inside a sandbox with no network and no
credential access would be Tier A *for those two properties only* and Tier C for everything inside.
`rust/sandbox-runtime` is a WASI runtime for WASM modules with declared imports. A browser is not a
WASM module. The confinement that would earn the word does not exist in this repository, and the
disclosure says so as its third reason, because a reader who fixed the wiring and the declared
subset must not be able to believe the confinement half was ever available.

## The honest tier of every bound this task introduces

| what | tier | why not a stronger word, and what escapes |
|---|---|---|
| the declared subset's decomposition (`decompose`) | **no tier — a vocabulary** | no shipping code calls `decompose`; verified by grep, its only callers are its own tests. A decomposition no code consults decides nothing. When something does, the bound it yields is a proxy decision, Mediated, with the remainder as what escapes it |
| the ungoverned remainder | **ungoverned** | not Observed: nothing at settle sees a pixel click either. Receipts name the tool, never the effect |
| the `warrantor-computer-use` broker | **no tier — an orphan** | `decide` is a real chokepoint refusal against a URL pattern and a DOM selector and would be Mediated if wired. Nothing wires it |
| the disclosure on the `agents list` surface | **not a bound** | it is the sentence that stops an operator from believing there is one. It has a shipping caller — the only part of this task that does |
| a sandbox-confined session | **not available** | see Step 7 |

Nothing in this task is Enforced, Mediated, or Observed. That is the finding.

## What this task does NOT establish

1. **No computer-use effect is governed.** Not the declared subset either: `decompose` has no
   shipping caller. This task makes the gap legible; it does not close it.
2. **The orphan crate is still an orphan.** Its header is now true. Wiring it is a design decision
   this task does not take, because wiring makes the call refusable and leaves the effect exactly
   as ungoverned as the remainder says.
3. **L4-18 stays `status=partial`.** What is partial is the declared subset. What is not partial is
   the remainder, and the product text no longer lets the first be read as the second.

## Corrections made along the way, including one of mine

- **The orphan crate's header claimed the present tense.** "Every screen action goes through an
  authority-scoped broker" and "'No internet' is enforced in the browser" described a design as
  shipped code. Nothing depends on the crate and there is no browser in the repository. Corrected to
  what the crate is: a decision function that works, exercised by its own 12 tests and nothing else.
- **My first correction of that header was itself wrong.** I wrote that the crate had no tests,
  because `cargo test -p warrantor-computer-use` showed `running 0 tests` — and that was the doctest
  summary, the last block in the output, which I read instead of the count. `--all-targets` runs
  12. The header states the measured number. Reading the tail instead of the count is the exact
  defect this repository keeps a memory entry about, and it happened here to the person auditing
  for it.

## Gate on the branch tip, exit codes captured before any pipe

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo test -p warrantor-warrant --lib computer_use` | 0; `4 passed; 0 failed` |
| `cargo test -p warrantor-warrant --test agents_list_computer_use` | 0; `1 passed; 0 failed` (drives the shipped binary) |
| `cargo test -p warrantor-computer-use --all-targets` | 0; `12 passed; 0 failed` |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo doc -p warrantor-warrant --no-deps` | 0, under `#![deny(missing_docs)]` |
| `check_docs.py` | PASS |
| `check_us_english.py --files` on all five touched files | ok |

The full workspace test run is the merge's, on the merged tree, and is recorded below it lands.

## Mutations run against the tests, with their outcomes

Each applied to the tree, run, then restored and verified by sha256 against the pre-mutation copy.

| mutation | expected | observed | restored |
|---|---|---|---|
| the `COMPUTER USE:` block removed from `cmd_agents_list` in `warrantor.rs` | the binary test goes RED | `test result: FAILED. 0 passed; 1 failed`, exit 101, on "the surface must have a computer-use section" | `ed5062bd042d1db9` before and after |
| `UNGOVERNED` emptied to `&[]` in `computer_use.rs` | the BUILD fails, not a test | `error[E0080]: evaluation panicked: assertion failed: !UNGOVERNED.is_empty()` at line 142, exit 101 | `ab48b50edde480af` before and after |

The first proves the disclosure test constrains the surface rather than decorating it. The second
proves that rendering computer use as fully governed cannot be reached by editing a list: it is a
compile error.

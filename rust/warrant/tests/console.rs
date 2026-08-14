//! The console assets, and the boundary they are allowed to cross.
//!
//! `serve.rs` answers `/v1` with a 401 *before* it resolves a route, so an unauthenticated caller
//! cannot tell a real warrant id from an invented one. Serving a browser console punches one hole
//! in that: a browser cannot put an `Authorization` header on the navigation that loads a page, so
//! three paths have to answer without a token or the console can never be opened.
//!
//! These tests exist to hold that hole to exactly three paths and exactly three fixed byte
//! strings. The load-bearing one is
//! [`serving_the_console_does_not_make_the_api_reachable_without_a_token`] — everything else here
//! is detail, but that one is the property the whole surface rests on, and it is the one a future
//! change to `console_asset` would break first.
//!
//! # What these tests can and cannot reach
//!
//! The assets are static bytes, so Rust can only assert *over* them. That is the right level for
//! two things and the wrong level for a third.
//!
//! Right for the prose: the first-run panel's claims about what a warrant is, why granting is
//! terminal-only, and what `--write` actually buys are the product's own explanation of its
//! boundary, and a wrong sentence there is a defect whether or not any code changed.
//!
//! Right for the policy invariants: `script-src 'self'` carries no `unsafe-inline`, so an
//! `onclick=`, a `style=` attribute or a webfont from a CDN fails *silently in the browser* while
//! every other test here still passes. Byte assertions are the only guard that exists.
//!
//! Wrong for behaviour: `emptyKind`'s branch selection in `console.js` — which decides whether a
//! reader is told "no warrants yet", "no warrants in this state", or that the list could not be
//! read — cannot be exercised from here. This module used to go further and say it could not be
//! exercised at all, because "there is no JavaScript runner, and RFC W1 §Dependencies forbids
//! adding one". That was one word too strong, and the gap it excused was real: three of the four
//! rungs were wrong or unreachable while every test in this file passed. §Dependencies forbids a
//! build step, a framework, a bundler and a package manager. `node --test` is none of those, it
//! installs nothing, and it already runs `desktop/test/policy.test.js` in this repository. The
//! behaviour now lives in `src/console/console.test.js`, and what is still uncovered is stated
//! there rather than implied here.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

use ed25519_dalek::SigningKey;

use warrantor_warrant::serve::{
    handle, no_adapter, serve_conn, status, HttpRequest, SessionToken, StoreApi,
};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
fn now() -> u64 {
    NOW
}

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn token() -> SessionToken {
    SessionToken::from_value(TOKEN)
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-console-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn api(dir: &Path, release_authority: bool) -> StoreApi {
    let store = WarrantStore::open(dir).expect("store");
    StoreApi::new(
        store,
        dir.to_path_buf(),
        SigningKey::from_bytes(&[1; 32]),
        release_authority.then(|| SigningKey::from_bytes(&[2; 32])),
        no_adapter,
        now,
    )
}

fn seed(dir: &Path, id: &str, task: &str) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(
        id,
        task,
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    WarrantStore::open(dir)
        .expect("store")
        .save(&StoredWarrant {
            warrant,
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
        })
        .expect("save");
}

/// A request with no `Authorization` header at all — what a browser sends on navigation.
fn anonymous(method: &str, path: &[&str]) -> HttpRequest {
    HttpRequest::new(method, path, BTreeMap::new())
}

fn wire(api: &mut StoreApi, raw: &str) -> String {
    let mut input = Cursor::new(raw.as_bytes().to_vec());
    let mut output: Vec<u8> = Vec::new();
    serve_conn(api, &token(), &mut input, &mut output).expect("write");
    String::from_utf8(output).expect("utf8")
}

fn headers_of(raw: &str) -> String {
    raw.split_once("\r\n\r\n")
        .map(|(head, _)| head.to_ascii_lowercase())
        .expect("header/body split")
}

fn body_of(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").expect("header/body split").1
}

/// Fetch one asset's body from a server on an empty store.
///
/// An empty store deliberately, because that is the machine the first-run panel is written for —
/// and because the assets are the same bytes either way, which
/// [`the_console_is_byte_identical_across_stores_because_it_carries_no_store_data`] pins.
fn asset(path: &str) -> String {
    let dir = tempdir("asset");
    let mut api = api(&dir, false);
    let raw = wire(
        &mut api,
        &format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n"),
    );
    assert!(raw.starts_with("HTTP/1.1 200 OK"), "{path}: {raw:.60}");
    body_of(&raw).to_string()
}

/// Collapse runs of whitespace before asserting on a sentence.
///
/// The prose is the contract; where the markup happens to wrap is not. Without this, adding one
/// level of indentation to a paragraph would fail a test about what the product claims, which
/// teaches people to weaken the assertion rather than to read it.
fn flatten(document: &str) -> String {
    document.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every offset in `document` where an attribute name could begin.
///
/// An attribute name starts after ASCII whitespace — a space, but equally a newline or a tab. The
/// two guards below matched the literal `" on"` and `" style="`, so an attribute written on its own
/// line was invisible to both, and this document already wraps tags that way (`<input>`, the
/// `<script>` element). The doc comment claimed "whitespace-delimited" while the code read one
/// character; the comment was right about what the guard must do, so the code moved to meet it.
fn attribute_starts(document: &str) -> impl Iterator<Item = usize> + '_ {
    document
        .char_indices()
        .filter(|(_, c)| c.is_ascii_whitespace())
        .map(|(at, c)| at + c.len_utf8())
}

/// Does this document carry an inline event-handler attribute?
///
/// Written by hand rather than with a regex crate, because adding a dependency to catch a thing
/// that is currently absent is the wrong trade. It looks for a whitespace-delimited attribute
/// name beginning `on` and immediately followed by `=`, which is the only shape an inline handler
/// can take; prose containing the word "on" has a space or a letter after it, never `=`.
fn has_inline_event_handler(document: &str) -> bool {
    attribute_starts(document).any(|at| {
        let Some(rest) = document[at..].strip_prefix("on") else {
            return false;
        };
        let name = rest.chars().take_while(|c| c.is_ascii_alphabetic()).count();
        name > 0 && rest[name..].starts_with('=')
    })
}

/// Does this document carry a `style=` attribute?
///
/// Same whitespace rule, and the same reason: `style-src 'self'` carries no `unsafe-inline`, so a
/// style attribute written after a newline would be as dead in the browser as one after a space.
fn has_inline_style_attribute(document: &str) -> bool {
    attribute_starts(document).any(|at| document[at..].starts_with("style="))
}

// ── THE property ──────────────────────────────────────────────────────────────────────

/// The load-bearing test.
///
/// Three console paths answer without a token. Nothing else may. If a future refactor makes
/// `console_asset` match too eagerly — a wildcard, a prefix test, a fallthrough to `index.html`
/// for unknown paths — this fails, and it fails on the exact request an attacker would send.
#[test]
fn serving_the_console_does_not_make_the_api_reachable_without_a_token() {
    let dir = tempdir("boundary");
    let mut api = api(&dir, true);
    seed(&dir, "wrt_real", "fix the auth bug");

    for path in [
        vec!["v1", "health"],
        vec!["v1", "warrants"],
        vec!["v1", "warrants", "wrt_real"],
        vec!["v1", "warrants", "wrt_real", "report"],
        vec!["v1", "warrants", "wrt_real", "settle"],
        vec!["v1", "summary", "daily"],
    ] {
        let response = handle(&mut api, &token(), &anonymous("GET", &path));
        assert_eq!(
            response.status,
            status::UNAUTHORIZED,
            "/{} must still refuse an anonymous caller",
            path.join("/")
        );
    }
}

/// The console must not become a way to read a warrant id out of an unauthenticated response.
#[test]
fn an_unknown_path_is_not_quietly_answered_with_the_console() {
    let dir = tempdir("unknown");
    let mut api = api(&dir, false);

    // A single-segment path that is not one of the three assets. If this returned the document,
    // `console_asset` would be a catch-all and the 401 boundary would be a fiction.
    let response = handle(&mut api, &token(), &anonymous("GET", &["dashboard"]));
    assert_eq!(response.status, status::UNAUTHORIZED);
}

// ── the assets themselves ─────────────────────────────────────────────────────────────

#[test]
fn the_console_document_is_served_to_a_caller_with_no_token() {
    let dir = tempdir("document");
    let mut api = api(&dir, false);

    let raw = wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    let headers = headers_of(&raw);

    assert!(raw.starts_with("HTTP/1.1 200 OK"), "got: {raw:.60}");
    assert!(
        headers.contains("content-type: text/html; charset=utf-8"),
        "the document must be served as html, not as json: {headers}"
    );
    assert!(body_of(&raw).contains("<title>Warrantor</title>"));
}

#[test]
fn each_asset_is_served_as_its_own_type() {
    let dir = tempdir("types");
    let mut api = api(&dir, false);

    for (path, expected) in [
        ("/console.css", "content-type: text/css; charset=utf-8"),
        (
            "/console.js",
            "content-type: text/javascript; charset=utf-8",
        ),
    ] {
        let raw = wire(
            &mut api,
            &format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n"),
        );
        assert!(raw.starts_with("HTTP/1.1 200 OK"), "{path}: {raw:.60}");
        assert!(
            headers_of(&raw).contains(expected),
            "{path} should be {expected}"
        );
    }
}

/// The policy is the reason serving an unauthenticated document is safe.
///
/// `connect-src 'self'` is the one that matters: the console holds a token to an API that can hold
/// settle authority, so what must be impossible is not script execution but *exfiltration*. A
/// script with nowhere to send the token cannot leak it.
#[test]
fn console_assets_carry_the_policy_that_keeps_a_token_from_leaving() {
    let dir = tempdir("policy");
    let mut api = api(&dir, true);

    let headers = headers_of(&wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n"));

    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ] {
        assert!(
            headers.contains(directive),
            "the console policy must carry {directive}: {headers}"
        );
    }
    assert!(headers.contains("x-frame-options: deny"));
    assert!(headers.contains("referrer-policy: no-referrer"));
    // Inherited from the shared writer, and worth pinning here too: a sniffed content type would
    // undo the type declarations above.
    assert!(headers.contains("x-content-type-options: nosniff"));
    // No CORS header, ever. One would let any page in the user's browser reach this API.
    assert!(
        !headers.contains("access-control-allow-origin"),
        "the console must not be granted a CORS header: {headers}"
    );
}

/// The claim in `console_asset`'s doc comment, tested rather than asserted.
///
/// The assets are fixed byte strings compiled into the binary, so they cannot carry a store path,
/// a warrant id or a token. Two servers on different roots — one holding a warrant, one empty —
/// must answer byte-identically. If someone later templates the store path or a warrant count into
/// the document, this fails, and serving it unauthenticated stops being safe.
#[test]
fn the_console_is_byte_identical_across_stores_because_it_carries_no_store_data() {
    let populated_dir = tempdir("populated");
    let empty_dir = tempdir("empty");
    seed(
        &populated_dir,
        "wrt_secret",
        "a task name that must never reach an anonymous response",
    );

    let mut populated = api(&populated_dir, true);
    let mut empty = api(&empty_dir, false);

    for path in ["/", "/console.css", "/console.js"] {
        let request = format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        let from_populated = wire(&mut populated, &request);
        let from_empty = wire(&mut empty, &request);
        assert_eq!(
            from_populated, from_empty,
            "{path} differed between two stores, so it is carrying store data"
        );
        assert!(!from_populated.contains("wrt_secret"));
        assert!(!from_populated.contains(&populated_dir.display().to_string()));
        assert!(!from_populated.contains(TOKEN));
    }

    // Named here rather than in its own test because this is where the property lives. The
    // first-run panel is the most tempting place in the whole console to template something
    // store-derived — a warrant count, the store root, the printed console URL — and the moment
    // anyone does, serving this document before the token check stops being safe. The equality
    // above is the real assertion; this makes the panel's presence explicit so the next reader
    // sees which addition they would be breaking.
    let root = wire(&mut populated, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    assert!(root.contains("id=\"first-run\""));
    assert!(
        wire(&mut empty, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n").contains("id=\"first-run\"")
    );
}

// ── the first-run explanation ─────────────────────────────────────────────────────────

/// A console that answers "no warrants" to someone who has never had one is indistinguishable
/// from a broken app. The fix is not a friendlier empty string; it is an explanation of the
/// primitive, in words that do not assume the reader has read the CLI's help.
#[test]
fn the_console_explains_what_a_warrant_is_before_there_is_one_to_look_at() {
    let flat = flatten(&asset("/"));

    assert!(
        flat.contains(
            "A warrant is written, signed permission for an AI agent to do one stated job"
        ),
        "the first-run panel must define the primitive, not just name it"
    );
    // What the second sentence may say is exactly what `cmd_grant` does: with `--repo`, a git
    // worktree on its own branch, merged at settle. Not "isolated", and not "nothing it does is
    // visible outside" — see the test below.
    assert!(flat.contains("separate worktree on a branch of its own"));
    assert!(flat.contains("stay off your working copy until a person settles the warrant"));
}

/// The lede is the first thing a non-developer reads, and therefore where a wrong mental model
/// gets formed. It made two blanket promises this system does not keep.
///
/// "nothing it does is visible outside that copy" is containment, and there is none: `lib.rs`
/// records that there is "no network namespace, no seccomp filter and no firewall anywhere in this
/// crate", `bound_strengths()` marks `write_paths` **Observed**, and the panel two paragraphs later
/// was already scrupulous about that for `--write` while the lede overrode it.
///
/// "external effects are staged rather than performed" is worse, because it is checkable and
/// false: `proxy.rs::decide()` returns `Decision::Forward` unless the call's class is in
/// `staged_classes` **and** the tool is in the registry. `cmd_grant` seeds `staged_classes` with
/// `Write` alone, and `EffectRegistry::github()` holds four GitHub tools — so a `Financial`,
/// `Destructive` or `Physical` effect, and any `Write` to a non-GitHub tool, is performed the
/// moment the agent calls it, under the exact grant line this panel prints.
///
/// This asserts the honest replacement, and asserts the overclaims stay gone in the words they
/// would come back in.
#[test]
fn the_lede_claims_only_the_strengths_the_code_actually_holds() {
    let flat = flatten(&asset("/"));

    // The three tiers, named as `bound_strengths()` names them, and attached to the right bounds.
    assert!(flat.contains("Those bounds are not all held the same way"));
    assert!(flat.contains("The deadline and the delegation limit are <strong>enforced</strong>"));
    assert!(flat.contains("refused by the broker the agent's tool calls pass through"));
    assert!(
        flat.contains("is not a cage: what does not go through the broker is not decided by it"),
        "the mediated tier must say what it does not hold, or it reads as the enforced tier"
    );
    assert!(
        flat.contains("measured and reported, never refused as they happen"),
        "written paths and spend are Observed and the panel has to say so"
    );
    assert!(
        flat.contains("It composes with a sandbox; it is not one."),
        "the panel must not be readable as a containment product"
    );

    // Staging, described as the list it is rather than the universal promise it was.
    assert!(flat.contains("waits for review only when the warrant names its class"));
    assert!(flat.contains("today, the GitHub effects"));
    assert!(flat.contains("Everything else the agent is allowed to call happens when it calls it"));

    for overclaim in [
        "nothing it does is visible outside",
        "isolated copy of your repository",
        "staged rather than performed",
        "cannot reach the network",
        "sandboxed",
        "fully contained",
    ] {
        assert!(
            !flat.contains(overclaim),
            "the lede must not promise what the code does not enforce: {overclaim}"
        );
    }
}

/// The absence of a grant button is the single most likely thing to be read as an unfinished
/// product. It is the opposite, and the panel has to say so in plain words: an unexplained
/// omission and a stated boundary look identical to a reader, and only one of them is true here.
#[test]
fn the_console_says_why_granting_is_terminal_only_rather_than_hiding_it() {
    let flat = flatten(&asset("/"));

    assert!(flat.contains("deliberately absent rather than missing"));
    assert!(
        flat.contains("Granting mints authority"),
        "the reason has to be the minting of authority, not a UI limitation"
    );
    assert!(flat.contains("issuer key held on this machine"));
    assert!(flat.contains("publishes no grant route at all"));
    assert!(flat.contains("authority being minted by a human at a terminal"));
    assert!(flat.contains("It cannot create authority."));
}

/// The command has to be the one that works, character for character. A reader who cannot grant
/// after reading this panel is in exactly the state the panel exists to end.
#[test]
fn the_first_run_panel_carries_the_grant_command_verbatim() {
    let flat = flatten(&asset("/"));

    // `--repo .` is not decoration. `cmd_grant` creates a worktree only when `--repo` is given, so
    // the line without it granted a warrant with no worktree at all — while the panel above it
    // described the agent working in a copy of the repository. The prose was corrected; so was the
    // command, because the command was the half that could be made true.
    assert!(
        flat.contains(r#"warrantor grant --goal "..." --tools git --write src --repo ."#),
        "the grant line must appear exactly as it is typed, and must be the one that makes the \
         worktree the lede describes"
    );
    assert!(
        flat.contains("id=\"copy-command\""),
        "and it must be copyable without retyping"
    );
    assert!(
        flat.contains("<code id=\"first-run-command\">warrantor grant"),
        "no whitespace may separate the tag from the command: copyGrantCommand copies textContent \
         verbatim, so a wrapped tag puts a newline on the clipboard"
    );
}

/// Prose near `--write` is the easiest place in the product to re-commit an error the codebase
/// documents at length.
///
/// `bound_strengths()` marks `write_paths` **Observed**, and `lib.rs` records why: it was once
/// labelled `Enforced`, and that was caught empirically when an agent granted `--write 'src/**'`
/// wrote `tests/__pycache__/` and nothing refused it. "Worse than an absent guarantee is one
/// someone relies on." So this asserts the honest shape — containment at settle — and asserts the
/// absent-limit invariant beside it, because omitting `--write` yields an empty set of in-bounds
/// paths, which means none and never every.
#[test]
fn the_panel_describes_an_out_of_bounds_write_as_contained_not_refused() {
    let flat = flatten(&asset("/"));

    assert!(flat.contains("containment rather than refusal"));
    assert!(flat.contains("not blocked as it happens"));
    assert!(flat.contains("never staged, so it never reaches your branch"));
    assert!(
        flat.contains("means no path is in bounds, not every path"),
        "an absent limit means none, never unlimited"
    );
    // The claim the panel must never make, in any of the words it would be made with.
    for overclaim in [
        "prevented from writing",
        "cannot write outside",
        "blocks writes",
    ] {
        assert!(
            !flat.contains(overclaim),
            "the panel must not promise enforcement the system does not perform: {overclaim}"
        );
    }
}

/// An empty store and an empty filter are different facts, and the console used to render both as
/// "No warrants in this view." — which makes clicking a chip look like data loss and makes a
/// machine with history look like a fresh one. Four causes, four sentences.
#[test]
fn an_empty_store_and_an_empty_filter_are_different_sentences() {
    let flat = flatten(&asset("/"));

    let first_run = "No warrants on this machine yet.";
    let filtered = "No warrants in this state.";

    assert!(flat.contains(first_run));
    assert!(flat.contains(filtered));
    assert_ne!(first_run, filtered);
    assert!(
        !first_run.contains(filtered) && !filtered.contains(first_run),
        "one wording must not be a substring of the other, or a reader cannot tell them apart"
    );

    // The other two causes an empty list can have, each of which outranks "first run".
    assert!(flat.contains("id=\"list-empty-unreadable\""));
    assert!(flat.contains("id=\"list-empty-error\""));
    // Worded for all three failures it now actually fires on. It said only "The server did not
    // answer." while `emptyKind` branched on the HTTP status alone — so the one failure the
    // sentence described was the one failure that could never reach it, and a 200 carrying an
    // unparseable body rendered as "No warrants on this machine yet." instead.
    assert!(
        flat.contains(
            "This list could not be read: the server did not answer, refused, or \
                       replied with something this console could not parse."
        ),
        "an unanswered question must not be rendered as the answer 'none'"
    );
    assert!(flat.contains("That is not the same as there being nothing here."));
    // And the way out of a filtered view, so an empty filter is never a dead end.
    assert!(flat.contains("id=\"show-all\""));

    assert!(
        !flat.contains("No warrants in this view."),
        "the collapsed single-string empty state must be gone, not merely supplemented"
    );
}

// ── the policy, asserted over the bytes it governs ────────────────────────────────────

/// The CSP is enforced by the browser and by nothing in this repository.
///
/// `script-src 'self'` carries no `unsafe-inline`, so an `onclick=` on the copy button, a `style=`
/// attribute or a `<style>` block would break *in the browser*, silently, while every other test
/// here passed. This is the only place that failure is visible before a user finds it.
#[test]
fn the_console_carries_no_inline_script_handler_or_style_because_the_policy_forbids_them() {
    let document = asset("/");

    assert_eq!(
        document.matches("<script").count(),
        1,
        "exactly one script tag, and it is the module"
    );
    assert!(
        document.contains(r#"<script type="module" src="/console.js">"#),
        "the one script must be loaded from this origin, not written inline"
    );
    assert!(
        !has_inline_event_handler(&document),
        "an inline event handler is dead under script-src 'self' with no unsafe-inline"
    );
    assert!(
        !has_inline_style_attribute(&document),
        "style-src 'self' carries no unsafe-inline, so a style attribute would not apply"
    );
    assert!(!document.contains("<style"));
}

/// The guard's own reach, tested — because a guard that is narrower than its doc comment says is
/// worse than no guard: this module's docs call these byte assertions "the only guard that exists"
/// for a failure that is otherwise silent in the browser, so the next reader trusts them instead
/// of re-checking. Both guards read a single literal space until this test was written.
#[test]
fn the_inline_attribute_guards_see_an_attribute_however_its_tag_is_wrapped() {
    for hostile in [
        "<button onclick=\"act()\">",
        "<button\nonclick=\"act()\">",
        "<button\tonclick=\"act()\">",
        "<button\r\n      onmouseover=\"act()\">",
        "<button\n  class=\"copy\"\n  onfocus=\"act()\"\n>",
    ] {
        assert!(
            has_inline_event_handler(hostile),
            "an inline handler must be seen however the tag is wrapped: {hostile:?}"
        );
    }
    for hostile in ["<div style=\"color:red\">", "<div\n  style=\"color:red\">"] {
        assert!(
            has_inline_style_attribute(hostile),
            "a style attribute must be seen however the tag is wrapped: {hostile:?}"
        );
    }

    // And prose is not an attribute, or the guard would be unusable on a document that explains
    // itself in English — which this one does at length.
    for benign in [
        "<p>Turn it on and leave it on.</p>",
        "<p>the list on the left re-reads itself</p>",
        "<p>one on=two is not a handler</p>",
        "<p>\n  once granted, only a person settles it\n</p>",
    ] {
        assert!(!has_inline_event_handler(benign), "{benign:?}");
    }
    assert!(!has_inline_style_attribute("<p>Turn it on.</p>"));
}

/// `default-src 'none'` means every off-origin fetch is denied, so a webfont, an icon from a CDN
/// or an `@import` is not a slow load — it is a thing that never arrives. `deploy/airgap` says the
/// same in a second way: there is no network on the target at all.
#[test]
fn the_console_loads_nothing_from_off_this_origin() {
    let document = asset("/");
    let stylesheet = asset("/console.css");

    for off_origin in ["src=\"http", "href=\"http", "src=\"//", "href=\"//"] {
        assert!(
            !document.contains(off_origin),
            "the document must fetch nothing off this origin: {off_origin}"
        );
    }
    for off_origin in ["url(http", "url(//", "@import"] {
        assert!(
            !stylesheet.contains(off_origin),
            "the stylesheet must fetch nothing off this origin: {off_origin}"
        );
    }
}

#[test]
fn a_non_get_on_a_console_path_is_refused_with_the_method_it_wanted() {
    let dir = tempdir("method");
    let mut api = api(&dir, true);

    let response = handle(&mut api, &token(), &anonymous("POST", &[]));
    assert_eq!(response.status, status::METHOD_NOT_ALLOWED);

    let raw = wire(
        &mut api,
        "POST /console.js HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
    );
    assert!(headers_of(&raw).contains("allow: get"));
}

/// `/index.html` is the same document as `/`, because a browser that was handed the one will
/// sometimes ask for the other.
#[test]
fn index_html_and_the_root_are_the_same_document() {
    let dir = tempdir("alias");
    let mut api = api(&dir, false);

    let root = wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    let named = wire(
        &mut api,
        "GET /index.html HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(root, named);
}

/// A token that *is* presented on an asset request changes nothing: the assets are public, and a
/// caller holding a token still gets the same bytes rather than a privileged variant.
#[test]
fn presenting_a_token_does_not_produce_a_different_console() {
    let dir = tempdir("same");
    let mut api = api(&dir, true);

    let anonymous_body = wire(&mut api, "GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    let authenticated = wire(
        &mut api,
        &format!("GET / HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: Bearer {TOKEN}\r\n\r\n"),
    );
    assert_eq!(anonymous_body, authenticated);
}

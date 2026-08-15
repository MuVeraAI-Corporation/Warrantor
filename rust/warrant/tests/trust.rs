//! The pinned-issuer directory: what pinning means, what refuses, and what a name can never be.
//!
//! The security of `verify --issuer <name>` is exactly the security of this file and the
//! operations that change it, so the refusals matter more than the successes: a pin that could
//! change silently is an attacker's shortest path, and the tests below pin each refusal in place.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;

use warrantor_warrant::trust::{self, Directory, PinOutcome};

const NOW: u64 = 1_786_000_000;

fn key(bytes: u8) -> SigningKey {
    SigningKey::from_bytes(&[bytes; 32])
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-trust-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

// ── the file ──────────────────────────────────────────────────────────────────────────

/// An absent directory is an empty one — the normal state of a machine that has pinned nothing.
#[test]
fn an_absent_directory_is_empty_and_a_corrupt_one_is_an_error() {
    let fresh = tempdir("fresh");
    assert!(Directory::load(&fresh)
        .expect("absence is the normal state")
        .issuers
        .is_empty());

    let root = tempdir("corrupt");
    std::fs::create_dir_all(root.join("trusted")).expect("dir");
    std::fs::write(trust::directory_path(&root), b"{ not a directory").expect("write");

    let error = Directory::load(&root).expect_err("corruption is not emptiness");
    assert!(
        error.contains("cannot be read"),
        "the error names the file: {error}"
    );
}

/// A directory from a future format is refused, not field-picked.
#[test]
fn a_future_format_is_refused() {
    let root = tempdir("future");
    std::fs::create_dir_all(root.join("trusted")).expect("dir");
    std::fs::write(
        trust::directory_path(&root),
        "{\"format\":\"warrantor.trusted-issuers/2\",\"issuers\":{}}",
    )
    .expect("write");

    let error = Directory::load(&root).expect_err("refused");
    assert!(
        error.contains("trusted-issuers/2") && error.contains("Nothing is guessed"),
        "{error}"
    );
}

/// A directory pinning something that is not a key is refused in full, rather than read around
/// the broken entry — a partially-trusted trust file is the worst shape this can take.
#[test]
fn a_directory_with_a_non_key_pin_is_refused_rather_than_partly_read() {
    let root = tempdir("bad-key");
    let mut directory = Directory::empty();
    directory.issuers.insert(
        "ana".to_string(),
        warrantor_warrant::trust::PinnedIssuer {
            key: "not a key".to_string(),
            pinned_at: NOW,
            note: String::new(),
        },
    );
    directory.save(&root).expect("save");

    let error = Directory::load(&root).expect_err("refused");
    assert!(
        error.contains("ana") && error.contains("not an Ed25519 verifying key"),
        "{error}"
    );
}

// ── pinning ───────────────────────────────────────────────────────────────────────────

/// A pin round-trips and resolves back to the key that was pinned.
#[test]
fn a_pin_round_trips_and_resolves() {
    let root = tempdir("pin");
    let mut directory = Directory::empty();

    let outcome = directory
        .pin(
            "ana",
            &key(7).verifying_key(),
            NOW,
            "checked over a video call",
        )
        .expect("pin");
    assert_eq!(outcome, PinOutcome::Pinned);
    directory.save(&root).expect("save");

    let back = Directory::load(&root).expect("load");
    assert_eq!(back.resolve("ana"), Some(key(7).verifying_key()));
    assert_eq!(back.resolve("bo"), None, "and only that name");
    let pin = &back.issuers["ana"];
    assert_eq!(pin.pinned_at, NOW);
    assert_eq!(pin.note, "checked over a video call");
}

/// Pinning the same name to the same key again is a no-op, not a change and not an error —
/// re-running a setup script must not be a failure, and must not bump the pin's date either,
/// because WHEN a pin was made is part of what it claims.
#[test]
fn pinning_the_same_key_again_is_a_no_op_that_keeps_the_original_moment() {
    let mut directory = Directory::empty();
    directory
        .pin("ana", &key(7).verifying_key(), NOW, "")
        .expect("pin");

    let outcome = directory
        .pin("ana", &key(7).verifying_key(), NOW + 86_400, "")
        .expect("not an error");

    assert_eq!(outcome, PinOutcome::AlreadyPinned);
    assert_eq!(directory.issuers["ana"].pinned_at, NOW);
}

/// Pinning a name that is already pinned to a DIFFERENT key refuses, and the refusal is the
/// feature: changing what a name means is the one operation an attacker who cannot forge
/// signatures wants most, so it never happens without an explicit replace that knows what it
/// is replacing.
#[test]
fn pinning_a_different_key_over_a_name_refuses_and_names_both_keys() {
    let mut directory = Directory::empty();
    directory
        .pin("ana", &key(7).verifying_key(), NOW, "")
        .expect("pin");

    let outcome = directory
        .pin("ana", &key(9).verifying_key(), NOW + 60, "")
        .expect("a refusal is an answer, not an error");

    assert_eq!(
        outcome,
        PinOutcome::RefusedDifferentKey {
            existing: hex::encode(key(7).verifying_key().to_bytes()),
            pinned_at: NOW,
        }
    );
    assert_eq!(directory.resolve("ana"), Some(key(7).verifying_key()));
}

/// An explicit replace changes the pin and records the new moment, so the file always says when
/// this name last changed meaning.
#[test]
fn an_explicit_replace_changes_the_pin_and_records_the_new_moment() {
    let mut directory = Directory::empty();
    directory
        .pin("ana", &key(7).verifying_key(), NOW, "")
        .expect("pin");

    directory
        .replace("ana", &key(9).verifying_key(), NOW + 86_400, "rotated")
        .expect("replace");

    assert_eq!(directory.resolve("ana"), Some(key(9).verifying_key()));
    assert_eq!(directory.issuers["ana"].pinned_at, NOW + 86_400);

    let error = directory
        .replace("nobody", &key(1).verifying_key(), NOW, "")
        .expect_err("replacing nothing is a mistake about which verb to use");
    assert!(
        error.contains("warrantor issuer add nobody"),
        "the error says which command was meant: {error}"
    );
}

/// Unpinning removes the name and hands back the pin that was there, so the caller can say what
/// stopping trusting it costs.
#[test]
fn unpinning_removes_the_name_and_returns_what_was_there() {
    let mut directory = Directory::empty();
    directory
        .pin("ana", &key(7).verifying_key(), NOW, "out of band")
        .expect("pin");

    let removed = directory.unpin("ana").expect("remove");

    assert_eq!(removed.key, hex::encode(key(7).verifying_key().to_bytes()));
    assert!(directory.resolve("ana").is_none());
    assert!(directory.unpin("ana").is_err(), "and only once");
}

// ── names ─────────────────────────────────────────────────────────────────────────────

/// A name that could be mistaken for a key is refused by the length cap alone — a key is 64
/// characters, a name can be at most 32, so `--issuer <text>` never has to guess which kind it
/// was given and the two forms cannot overlap.
#[test]
fn a_name_that_looks_like_a_key_is_refused() {
    let hexish = "ab".repeat(32);
    let error = trust::check_name(&hexish).expect_err("refused");
    assert!(
        error.contains("never 64") && error.contains("mistaken for the key"),
        "the refusal says why the cap is what it is: {error}"
    );
}

/// Names are restricted to what a shell will not reinterpret — an operator will type these in
/// scripts, and a name containing a space or a semicolon is a command waiting to be misparsed.
#[test]
fn names_are_restricted_to_shell_safe_characters() {
    for bad in ["", "ana lovelace", "rm -rf", "a;echo", &"x".repeat(33)] {
        assert!(
            trust::check_name(bad).is_err(),
            "{bad:?} must not be a pin name"
        );
    }
    for good in ["ana", "issuer-2026", "acme.corp", "key_1"] {
        assert!(trust::check_name(good).is_ok(), "{good:?} should be fine");
    }
}

/// The raw-key form is recognised by shape alone, so the CLI can send 64 hex characters down
/// today's path and everything else to the directory, with no overlap between them.
#[test]
fn the_key_form_is_recognised_by_shape_alone() {
    assert!(trust::looks_like_a_key(&"ab".repeat(32)));
    assert!(!trust::looks_like_a_key("ana"));
    assert!(!trust::looks_like_a_key(&"ab".repeat(31)));
    assert!(!trust::looks_like_a_key(&"zz".repeat(32))); // hex digits only
}

/// A key round-trips through the parser that reads it back out of the file.
#[test]
fn parse_key_round_trips() {
    let text = hex::encode(key(7).verifying_key().to_bytes());
    assert_eq!(
        trust::parse_key(&text).expect("parse").to_bytes(),
        key(7).verifying_key().to_bytes()
    );
    assert!(trust::parse_key("nothex").is_err());
    assert!(trust::parse_key(&"ab".repeat(31)).is_err());
}

// ── the CLI: pinning, and verifying against a name ────────────────────────────────────

/// Run `warrantor <args...>` against a store rooted in `home`.
fn run(home: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor");
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), both)
}

/// A warrant and an exported report, made through the real binary, plus the hex of the issuer
/// key that signed it — read off the key file grant created, which is exactly the out-of-band
/// channel pinning is meant to replace.
fn exported_report(home: &std::path::Path) -> (String, String) {
    let (ok, output) = run(
        home,
        &["grant", "--goal", "pin the issuer", "--tools", "git"],
    );
    assert!(ok, "{output}");
    let id = output
        .lines()
        .find_map(|line| line.strip_prefix("warrant  "))
        .expect("grant prints the id")
        .trim()
        .to_string();
    let export = home.join("report.json");
    let (ok, output) = run(
        home,
        &["report", &id, "--export", export.to_str().expect("path")],
    );
    assert!(ok, "{output}");
    // The key file holds the private half; `--issuer` takes the public one. Deriving it here is
    // the out-of-band channel this fixture stands in for.
    let private = SigningKey::from_bytes(
        &std::fs::read(home.join(".warrantor/keys/issuer.key"))
            .expect("issuer key")
            .try_into()
            .expect("32 bytes"),
    );
    (
        export.to_string_lossy().to_string(),
        hex::encode(private.verifying_key().to_bytes()),
    )
}

/// The whole loop: pin a name, verify against the name, and read back which anchor the verdict
/// used — a pinned name and a pasted key must never print the same sentence.
#[test]
fn verify_by_name_prints_the_pin_and_its_moment() {
    let home = tempdir("verify-by-name");
    let (export, issuer) = exported_report(&home);

    let (ok, output) = run(&home, &["issuer", "add", "ana", &issuer]);
    assert!(ok, "{output}");
    assert!(
        output.contains("TRUST ON FIRST USE"),
        "pinning says what kind of decision it is: {output}"
    );

    let (ok, output) = run(&home, &["verify", &export, "--issuer", "ana"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("pinned as `ana`") && output.contains("trust on first"),
        "the verdict names the pin and its nature: {output}"
    );
    assert!(
        !output.contains("self-consistency only"),
        "an anchored verify never prints the no-anchor limitation: {output}"
    );

    // The same bytes, the raw key form: a true verdict with a different, honest origin line.
    let (ok, hex_output) = run(&home, &["verify", &export, "--issuer", &issuer]);
    assert!(ok, "{hex_output}");
    assert!(
        hex_output.contains("given on this command line"),
        "the raw-key form says where it came from: {hex_output}"
    );
}

/// An unpinned name refuses, naming the command that would pin it — never a guess, and never a
/// quiet fallthrough to treating the name as something else.
#[test]
fn verify_with_an_unpinned_name_refuses_and_says_how_to_pin() {
    let home = tempdir("unpinned");
    let (export, _issuer) = exported_report(&home);

    let (ok, output) = run(&home, &["verify", &export, "--issuer", "ghost"]);

    assert!(!ok, "{output}");
    assert!(
        output.contains("not pinned on this machine")
            && output.contains("warrantor issuer add ghost <"),
        "the refusal teaches the fix, in the same breath: {output}"
    );
}

/// Re-pinning a name to a different key refuses without --replace, and the refusal says why in
/// the attacker's terms — the sentence an operator in a hurry needs to slow down for.
#[test]
fn a_second_key_under_a_name_refuses_until_replaced_on_purpose() {
    let home = tempdir("repin");
    let (_, issuer) = exported_report(&home);
    let other = hex::encode(SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes());
    run(&home, &["issuer", "add", "ana", &issuer]);

    let (ok, output) = run(&home, &["issuer", "add", "ana", &other]);

    assert!(!ok, "{output}");
    assert!(
        output.contains("--replace") && output.contains("old key"),
        "the refusal names the escape hatch and what it costs: {output}"
    );

    // `--replace` comes last: the flag parser gives a flag the next token as its value, so
    // `--replace ana` would eat the name.
    let (ok, output) = run(&home, &["issuer", "add", "ana", &other, "--replace"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("was")
            && output.contains("now")
            && output.contains("verified against the old key"),
        "a replace prints both keys and the verdict caveat: {output}"
    );
}

/// An empty directory is a sentence, not a bare table header — and it is a different sentence
/// from the one a corrupt directory produces, which is an error.
#[test]
fn an_empty_directory_lists_as_a_sentence() {
    let home = tempdir("empty-list");
    let (ok, output) = run(&home, &["issuer", "list"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("nothing is pinned on this machine")
            && output.contains("issuer add <name>"),
        "{output}"
    );
}

/// Unpinning says what it costs, and a later verify by that name refuses — the cost was real.
#[test]
fn verifying_by_a_removed_name_refuses() {
    let home = tempdir("unpinned-verify");
    let (export, issuer) = exported_report(&home);
    run(&home, &["issuer", "add", "ana", &issuer]);

    let (ok, output) = run(&home, &["issuer", "remove", "ana"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("will now refuse until the name is pinned again"),
        "{output}"
    );

    let (ok, output) = run(&home, &["verify", &export, "--issuer", "ana"]);
    assert!(!ok, "the removed pin no longer anchors anything: {output}");
}

// ── show-hex: the issuer's public key, without fishing it out of verify's output ──────

/// After a grant, `show-hex` prints exactly the hex `verify` prints as its "signed by" line —
/// the same 32 bytes, from the one command whose job is to produce them.
#[test]
fn show_hex_names_the_key_verify_reports_as_the_signer() {
    let home = tempdir("show-hex");
    let (export, _issuer) = exported_report(&home);

    let (ok, shown) = run(&home, &["issuer", "show-hex"]);
    assert!(ok, "{shown}");

    let (ok, verified) = run(&home, &["verify", &export]);
    assert!(ok, "{verified}");
    let signed_by = verified
        .lines()
        .find_map(|line| line.trim().strip_prefix("signed by"))
        .expect("verify prints the signer's public key")
        .trim()
        .to_string();
    let first_line = shown.lines().next().map(str::trim).unwrap_or_default();
    assert_eq!(
        first_line,
        format!("issuer public key  {signed_by}"),
        "show-hex and verify's signer line are the same 32 bytes"
    );
}

/// On a machine with no issuer key, `show-hex` refuses and names the command that creates one —
/// and it must not mint a key as a side effect of being asked to show one.
#[test]
fn show_hex_without_an_issuer_key_refuses_and_mints_nothing() {
    let home = tempdir("show-hex-fresh");

    let (ok, output) = run(&home, &["issuer", "show-hex"]);

    assert!(!ok, "{output}");
    assert!(
        output.contains("will not mint one") && output.contains("warrantor grant"),
        "the refusal names the reason and the command that creates the key: {output}"
    );
    assert!(
        !home.join(".warrantor/keys/issuer.key").exists(),
        "asking to SEE a key must not create one: {output}"
    );
}

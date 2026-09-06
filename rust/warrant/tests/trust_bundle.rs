//! The trust directory as a carried bundle, driven through the binary on separate stores.
//!
//! Three `HOME`s stand in for three machines: A issues evidence, B has checked A's key out of band
//! and exports its pins, C is a stranger who has checked only B's key. The gates: a bundle from an
//! unpinned key is refused and writes nothing; C verifies A's report with a name it inherited from
//! B and the verdict says it was inherited; every anchored verdict says revocation is not
//! established.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-bundle-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

/// Run `warrantor <args...>` against the store under `home`.
fn run(home: &Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The hex of a store's issuer public key, read off the key file — the out-of-band channel.
fn issuer_hex(home: &Path) -> String {
    let private = SigningKey::from_bytes(
        &std::fs::read(home.join(".warrantor/keys/issuer.key"))
            .expect("issuer key")
            .try_into()
            .expect("32 bytes"),
    );
    hex::encode(private.verifying_key().to_bytes())
}

/// Grant on `home`, so it has an issuer key; return the id.
fn grant(home: &Path) -> String {
    let (ok, output) = run(
        home,
        &["grant", "--goal", "carry the directory", "--tools", "git"],
    );
    assert!(ok, "{output}");
    output
        .lines()
        .find_map(|line| line.strip_prefix("warrant  "))
        .expect("grant prints the id")
        .trim()
        .to_string()
}

/// A report exported by the real binary on `home`; returns its path.
fn exported_report(home: &Path) -> String {
    let id = grant(home);
    let export = home.join("report.json");
    let (ok, output) = run(
        home,
        &["report", &id, "--export", export.to_str().expect("path")],
    );
    assert!(ok, "{output}");
    export.to_string_lossy().to_string()
}

/// The value of verify's `anchor` line, without the `  anchor        ` label — the label's own
/// column padding is not the whitespace run these tests are looking for.
fn anchor_line_of(output: &str) -> &str {
    output
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("anchor "))
        .expect("verify prints an anchor line")
        .trim_start()
}

/// A stranger on a clean machine verifies A's report with only B's key checked out of band, and
/// the verdict says exactly how much that establishes.
#[test]
fn a_stranger_verifies_a_report_with_a_pin_inherited_from_a_bundle() {
    let a = tempdir("issuer-a");
    let report = exported_report(&a);
    let a_hex = issuer_hex(&a);

    let b = tempdir("exporter-b");
    grant(&b);
    let (ok, output) = run(
        &b,
        &["issuer", "add", "ana", &a_hex, "--note", "video call"],
    );
    assert!(ok, "{output}");
    let bundle = b.join("team-b.json");
    let bundle_path = bundle.to_str().expect("path");
    let (ok, output) = run(
        &b,
        &["issuer", "export", "--out", bundle_path, "--as", "team-b"],
    );
    assert!(ok, "{output}");
    assert!(output.contains("Revocation is NOT established"), "{output}");
    let b_hex = issuer_hex(&b);

    let c = tempdir("stranger-c");
    // Before the bundle: the name means nothing here.
    let (ok, output) = run(&c, &["verify", &report, "--issuer", "ana"]);
    assert!(
        !ok && output.contains("not pinned on this machine"),
        "{output}"
    );

    // A dry run computes the import and writes nothing.
    let (ok, output) = run(&c, &["issuer", "import", bundle_path]);
    assert!(!ok, "the signer is not pinned yet: {output}");
    assert!(!c.join(".warrantor/trusted/issuers.json").exists());

    // One out-of-band check: B's key, under a name C chose.
    let (ok, output) = run(&c, &["issuer", "add", "team-b", &b_hex]);
    assert!(ok, "{output}");
    let (ok, output) = run(&c, &["issuer", "import", bundle_path]);
    assert!(
        ok && output.contains("DRY RUN") && output.contains("1 name(s) would be pinned"),
        "{output}"
    );
    let (ok, output) = run(&c, &["issuer", "import", bundle_path, "--apply"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("ana") && output.contains("pinned from this bundle"),
        "{output}"
    );
    assert!(output.contains("no revocation channel"), "{output}");

    // The gate: the stranger verifies, offline, by a name they never checked themselves.
    let (ok, output) = run(&c, &["verify", &report, "--issuer", "ana"]);
    assert!(ok, "{output}");
    let anchor = anchor_line_of(&output);
    assert!(anchor.contains("pinned as `ana`"), "{anchor}");
    assert!(
        anchor.contains("INHERITED from a bundle signed by `team-b`"),
        "the verdict must say the pin was inherited: {anchor}"
    );
    assert!(
        !anchor.contains("trust on first use"),
        "an inherited pin was not checked here and must not read as if it was: {anchor}"
    );
    assert!(
        !anchor.contains("   "),
        "no whitespace runs mid-sentence: {anchor}"
    );
    assert!(
        output.contains("Revocation is NOT established"),
        "every anchored verdict says what a pin cannot know: {output}"
    );

    // The anchor binds: the same report against B's key is a refusal, not a weaker pass.
    let (ok, output) = run(&c, &["verify", &report, "--issuer", "team-b"]);
    assert!(!ok && output.contains("does NOT verify"), "{output}");
}

/// A locally-made pin still reads as trust on first use, with no whitespace runs.
#[test]
fn a_local_pin_reads_as_checked_here() {
    let a = tempdir("local-pin");
    let report = exported_report(&a);
    let a_hex = issuer_hex(&a);
    run(&a, &["issuer", "add", "me", &a_hex]);
    let (ok, output) = run(&a, &["verify", &report, "--issuer", "me"]);
    assert!(ok, "{output}");
    let anchor = anchor_line_of(&output);
    assert!(
        anchor.contains("trust on first use") && !anchor.contains("INHERITED"),
        "{anchor}"
    );
    assert!(!anchor.contains("   "), "{anchor}");
    assert!(output.contains("Revocation is NOT established"), "{output}");
}

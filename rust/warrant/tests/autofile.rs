//! Automatic filing at settle: the policy, the queue that catches failures, and the contract
//! that a failed filing never fails the settle.
//!
//! Two halves, deliberately in one file. The library half drives [`warrantor_warrant::autofile`]
//! against a scripted transport — the only place its three outcomes (filed, queued, dropped) can
//! be produced on demand. The CLI half drives the real binary, because the property that matters
//! most is an exit code: a settle whose filing failed must exit exactly as the same settle with
//! no policy would, and only the binary can prove that.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde_json::json;

use warrantor_warrant::archive_client::{
    self, ArchiveAnswer, ArchiveConfig, ArchiveTransport, ARCHIVE_CONFIG_FORMAT,
    ARCHIVE_RESPONSE_FORMAT,
};
use warrantor_warrant::autofile;
use warrantor_warrant::report::sha256_hex;

const NOW: u64 = 1_786_000_000;
const DEVICE: &str = "dev_00112233445566778899aabbccddeeff";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-autofile-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn config() -> ArchiveConfig {
    ArchiveConfig {
        format: ARCHIVE_CONFIG_FORMAT.to_string(),
        url: "http://127.0.0.1:8788".to_string(),
        device_id: DEVICE.to_string(),
        device_public_key: hex::encode(key().verifying_key().to_bytes()),
        label: "Ana's laptop".to_string(),
        enrolled_at: NOW,
        auto_file: archive_client::AutoFile::Settle,
    }
}

/// Whatever the test says the archive said, one answer per request.
struct Canned {
    answers: Vec<Result<ArchiveAnswer, String>>,
}

impl Canned {
    /// A 200 that accepts exactly these bytes — the digest names them, which is the check `push`
    /// performs at runtime, so a fixture that got it wrong fails as a disagreement.
    fn accepting(bytes: &[u8]) -> Self {
        Self::saying(vec![Ok(ArchiveAnswer {
            status: 200,
            body: serde_json::to_vec(&json!({
                "format": ARCHIVE_RESPONSE_FORMAT,
                "data": {
                    "digest": sha256_hex(bytes),
                    "kind": "report",
                    "warrant_id": "wrt_auto",
                    "already_held": false,
                    "submitted_by_device": DEVICE,
                    "submitted_at": NOW,
                },
                "not_a_verdict": {
                    "ingest_check": "ok",
                    "reason": "",
                    "verify_locally": "verify locally with `warrantor verify <file> --issuer <hex>`",
                },
            }))
            .expect("encode"),
        })])
    }

    fn refusing(status: u16, code: &str, message: &str) -> Self {
        Self::saying(vec![Ok(ArchiveAnswer {
            status,
            body: serde_json::to_vec(&json!({
                "format": ARCHIVE_RESPONSE_FORMAT,
                "error": { "code": code, "message": message },
                "not_a_verdict": {
                    "ingest_check": "unknown",
                    "reason": "nothing was checked",
                    "verify_locally": "verify locally",
                },
            }))
            .expect("encode"),
        })])
    }

    fn saying(answers: Vec<Result<ArchiveAnswer, String>>) -> Self {
        Self { answers }
    }
}

impl ArchiveTransport for Canned {
    fn send(
        &mut self,
        _method: &str,
        _path: &str,
        _authorization: Option<&str>,
        _body: &[u8],
    ) -> Result<ArchiveAnswer, String> {
        self.answers
            .pop()
            .expect("this test scripted one answer per request")
    }
}

/// An export file on disk, as the settle hook would have written it. The bytes are arbitrary —
/// the queue's promise is about whatever is at the path, and these tests are about the queue.
fn export(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("wrt_auto.settle-report.json");
    std::fs::write(&path, bytes).expect("write the export");
    path
}

// ── the ledger ────────────────────────────────────────────────────────────────────────

/// A queued filing round-trips through the ledger with its digest, its reason and its path.
#[test]
fn a_queued_filing_round_trips_through_the_ledger() {
    let root = tempdir("roundtrip");
    let path = export(&root, b"the final report");
    let digest = sha256_hex(b"the final report");

    autofile::queue_filing(&root, "wrt_auto", &path, &digest, "connection refused", NOW)
        .expect("queue");

    let pending = autofile::load_pending(&root).expect("load");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].warrant_id, "wrt_auto");
    assert_eq!(pending[0].path, path.display().to_string());
    assert_eq!(pending[0].digest, digest);
    assert_eq!(pending[0].attempts, 1);
    assert_eq!(pending[0].last_reason, "connection refused");
    assert_eq!(pending[0].format, autofile::PENDING_FORMAT);
}

/// An absent ledger is an empty queue — its normal state, written lazily by the first failure.
/// A ledger that exists and will not parse is an error naming the line, because reading it as
/// "nothing pending" would silently abandon filings this machine promised to retry.
#[test]
fn an_absent_ledger_is_empty_and_a_corrupt_one_is_an_error() {
    let empty = tempdir("absent");
    assert!(autofile::load_pending(&empty)
        .expect("absence is the queue's normal state")
        .is_empty());

    let root = tempdir("corrupt");
    std::fs::create_dir_all(root.join("archive")).expect("dir");
    let ledger = autofile::pending_path(&root);
    std::fs::write(&ledger, b"{ not a pending filing\n").expect("write");

    let error = autofile::load_pending(&root).expect_err("refused rather than read around");
    assert!(
        error.contains("line 1") && error.contains("fix or remove"),
        "the error names the line and the choice: {error}"
    );

    // Complete in every field but the format line, so the refusal is about the format and not
    // about a missing field two lines of error away from the point. Built with serde_json so a
    // Windows path's backslashes are escaped rather than becoming invalid JSON escapes.
    let future_entry = json!({
        "format": "warrantor.pending-filing/2",
        "warrant_id": "wrt_auto",
        "path": ledger.display().to_string(),
        "digest": "0".repeat(64),
        "queued_at": NOW,
        "attempts": 1,
        "last_reason": "connection refused",
    });
    std::fs::write(
        &ledger,
        format!(
            "{}\n",
            serde_json::to_string(&future_entry).expect("encode")
        ),
    )
    .expect("write");
    let future = autofile::load_pending(&root).expect_err("a future format is not guessed at");
    assert!(
        future.contains("pending-filing/2") && future.contains("Nothing is guessed"),
        "{future}"
    );
}

// ── filing under the policy ───────────────────────────────────────────────────────────

/// A filing that reaches the archive is a filing; nothing is queued.
#[test]
fn a_filing_that_reaches_the_archive_is_not_queued() {
    let root = tempdir("filed");
    let bytes = b"the final report";
    let path = export(&root, bytes);
    let mut archive = Canned::accepting(bytes);

    let filing = autofile::file_or_queue(
        &mut archive,
        &config(),
        &key(),
        &root,
        "wrt_auto",
        &path,
        NOW,
    )
    .expect("the queue write is the only Err, and there was no failure to queue");

    assert!(
        matches!(filing, autofile::Filing::Filed(ref filed) if !filed.already_held),
        "{filing:?}"
    );
    assert!(
        autofile::load_pending(&root).expect("load").is_empty(),
        "a success leaves no residue in the ledger"
    );
}

/// A filing that fails is queued with the digest of the bytes on disk and the refusal verbatim.
#[test]
fn a_filing_that_fails_is_queued_with_its_digest_and_the_refusal_verbatim() {
    let root = tempdir("queued");
    let bytes = b"the final report";
    let path = export(&root, bytes);
    let mut archive = Canned::refusing(
        503,
        "store_unavailable",
        "the archive could not write to its store, so nothing was filed. Retry.",
    );

    let filing = autofile::file_or_queue(
        &mut archive,
        &config(),
        &key(),
        &root,
        "wrt_auto",
        &path,
        NOW,
    )
    .expect("a failed filing is an outcome, not an error");

    let autofile::Filing::Queued { entry, reason } = filing else {
        panic!("a refused push is queued, not filed: {filing:?}");
    };
    assert_eq!(entry.digest, sha256_hex(bytes));
    assert_eq!(entry.path, path.display().to_string());
    assert!(
        reason.contains("store_unavailable") && reason.contains("nothing was filed"),
        "the archive's own sentence is carried, not paraphrased: {reason}"
    );
    assert_eq!(
        autofile::load_pending(&root).expect("load").len(),
        1,
        "and it is on the ledger, not just in the return value"
    );
}

// ── the drain ─────────────────────────────────────────────────────────────────────────

/// A drain files what was queued and empties the ledger — removed, not left at zero entries,
/// so an absent ledger keeps meaning "nothing pending".
#[test]
fn a_drain_files_what_was_queued_and_removes_the_ledger() {
    let root = tempdir("drain-ok");
    let bytes = b"the final report";
    let path = export(&root, bytes);
    autofile::queue_filing(
        &root,
        "wrt_auto",
        &path,
        &sha256_hex(bytes),
        "connection refused",
        NOW,
    )
    .expect("queue");
    let mut archive = Canned::accepting(bytes);

    let outcome =
        autofile::drain_pending(&mut archive, &config(), &key(), &root, NOW).expect("drain");

    assert_eq!(outcome.filed.len(), 1);
    assert_eq!(outcome.filed[0].digest, sha256_hex(bytes));
    assert!(outcome.still_pending.is_empty());
    assert!(outcome.dropped.is_empty());
    assert!(
        !autofile::pending_path(&root).exists(),
        "an emptied ledger is removed, not left behind at zero"
    );
}

/// A drain that fails again keeps the entry, counts the attempt, and carries the newest reason —
/// so a queue that never succeeds still tells the truth about how hard it has tried.
#[test]
fn a_drain_keeps_what_fails_again_and_counts_the_attempts() {
    let root = tempdir("drain-fail");
    let bytes = b"the final report";
    let path = export(&root, bytes);
    autofile::queue_filing(
        &root,
        "wrt_auto",
        &path,
        &sha256_hex(bytes),
        "connection refused",
        NOW,
    )
    .expect("queue");
    let mut archive = Canned::refusing(
        503,
        "store_unavailable",
        "the archive could not write to its store, so nothing was filed. Retry.",
    );

    let outcome =
        autofile::drain_pending(&mut archive, &config(), &key(), &root, NOW).expect("drain");

    assert_eq!(outcome.filed.len(), 0);
    assert_eq!(
        outcome.still_pending.len(),
        1,
        "{:?}",
        outcome.still_pending
    );
    assert!(
        outcome.still_pending[0].contains("attempt 2"),
        "the sentence names the attempt count: {:?}",
        outcome.still_pending
    );
    let pending = autofile::load_pending(&root).expect("load");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].attempts, 2);
    assert!(
        pending[0].last_reason.contains("store_unavailable"),
        "the newest reason replaces the oldest: {}",
        pending[0].last_reason
    );
}

/// An entry whose file is gone is dropped, with a sentence an operator can act on — there are no
/// bytes to file, and a queue that held it forever would be promising a retry that cannot happen.
#[test]
fn a_drain_drops_an_entry_whose_file_is_gone() {
    let root = tempdir("drain-gone");
    let bytes = b"the final report";
    let path = export(&root, bytes);
    autofile::queue_filing(
        &root,
        "wrt_auto",
        &path,
        &sha256_hex(bytes),
        "connection refused",
        NOW,
    )
    .expect("queue");
    std::fs::remove_file(&path).expect("the export is gone");
    let mut archive = Canned::saying(Vec::new());

    let outcome =
        autofile::drain_pending(&mut archive, &config(), &key(), &root, NOW).expect("drain");

    assert_eq!(outcome.dropped.len(), 1);
    assert!(
        outcome.dropped[0].contains("no longer be read"),
        "{:?}",
        outcome.dropped
    );
    assert!(
        !autofile::pending_path(&root).exists(),
        "the dropped entry is gone from the ledger"
    );
}

/// An entry whose bytes changed since queueing is dropped, not filed. A filing is a promise about
/// specific bytes, and whether the *new* bytes should be filed is an operator decision — quietly
/// filing them under the old promise is the one automatic move this module refuses to make.
#[test]
fn a_drain_drops_an_entry_whose_bytes_changed() {
    let root = tempdir("drain-changed");
    let bytes = b"the final report";
    let path = export(&root, bytes);
    autofile::queue_filing(
        &root,
        "wrt_auto",
        &path,
        &sha256_hex(bytes),
        "connection refused",
        NOW,
    )
    .expect("queue");
    std::fs::write(&path, b"different bytes entirely").expect("the export changed");
    let mut archive = Canned::saying(Vec::new());

    let outcome =
        autofile::drain_pending(&mut archive, &config(), &key(), &root, NOW).expect("drain");

    assert_eq!(outcome.dropped.len(), 1);
    let dropped = &outcome.dropped[0];
    assert!(
        dropped.contains("changed since the filing was queued")
            && dropped.contains(&sha256_hex(b"the final report"))
            && dropped.contains(&sha256_hex(b"different bytes entirely")),
        "both digests are named, so the operator can tell which bytes are which: {dropped}"
    );
}

// ── the policy field ──────────────────────────────────────────────────────────────────

/// A pairing record from before this field existed still loads, and still means `off` — a
/// machine that never asked for automatic filing never gets it.
#[test]
fn an_old_pairing_record_without_the_policy_field_reads_as_off() {
    let root = tempdir("old-record");
    let body = format!(
        "{{\"format\":\"{ARCHIVE_CONFIG_FORMAT}\",\"url\":\"http://127.0.0.1:8788\",\
         \"device_id\":\"{DEVICE}\",\"device_public_key\":\"{}\",\"label\":\"Ana's laptop\",\
         \"enrolled_at\":{NOW}}}",
        hex::encode(key().verifying_key().to_bytes())
    );
    std::fs::write(ArchiveConfig::path(&root), body).expect("write an old record");

    let config = ArchiveConfig::load(&root).expect("an old record still loads");
    assert_eq!(config.auto_file, archive_client::AutoFile::Off);
}

/// A policy word this build does not know is refused, not guessed at.
#[test]
fn an_unknown_policy_word_is_refused() {
    let root = tempdir("bad-word");
    let mut config = config();
    config.auto_file = archive_client::AutoFile::Off;
    config.save(&root).expect("save");
    let record = ArchiveConfig::path(&root);
    let body = std::fs::read_to_string(&record)
        .expect("read")
        .replace("\"off\"", "\"sometimes\"");
    std::fs::write(&record, body).expect("write");

    let error = ArchiveConfig::load(&root).expect_err("refused");
    assert!(
        error.to_string().contains("sometimes"),
        "the refusal names the word it refused: {error}"
    );
}

// ── the CLI: policy, and the settle that must not change its exit code ────────────────

/// Run `warrantor <args...>` against a store rooted in `home`.
fn run(home: &Path, args: &[&str]) -> (bool, String) {
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

/// A paired store: a pairing record whose device key is on disk beside it, aimed at a port
/// nothing is listening on. If a test here ever reaches a live archive it will fail loudly
/// rather than pass by accident.
fn paired(home: &Path, url: &str) {
    let root = home.join(".warrantor");
    std::fs::create_dir_all(root.join("keys")).expect("keys dir");
    let mut config = config();
    config.url = url.to_string();
    config.save(&root).expect("save the pairing record");
    std::fs::write(root.join("keys/device.key"), key().to_bytes()).expect("write the device key");
}

/// Grant a warrant through the real binary and return its id, parsed from the grant's own output
/// rather than guessed — the id is `wrt_` plus what the printer said.
fn grant(home: &Path) -> String {
    let (ok, output) = run(
        home,
        &[
            "grant",
            "--goal",
            "exercise automatic filing",
            "--tools",
            "git",
        ],
    );
    assert!(ok, "{output}");
    let id = output
        .lines()
        .find_map(|line| line.strip_prefix("warrant  "))
        .expect("grant prints the warrant id");
    id.trim().to_string()
}

/// `auto` before pairing is a pairing refusal, not a policy question.
#[test]
fn auto_on_an_unpaired_machine_names_pairing() {
    let home = tempdir("auto-unpaired");

    let (ok, output) = run(&home, &["archive", "auto", "settle"]);

    assert!(!ok, "{output}");
    assert!(
        output.contains("warrantor archive enrol"),
        "the refusal says how to pair: {output}"
    );
}

/// The policy turns on, reads back, and turns off — and `auto` with no argument reports both the
/// policy and the queue.
#[test]
fn the_policy_turns_on_reads_back_and_turns_off() {
    let home = tempdir("auto-on-off");
    paired(&home, "http://127.0.0.1:9");

    let (ok, output) = run(&home, &["archive", "auto", "settle"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("retried at the next settle"),
        "turning it on states the failure contract: {output}"
    );
    let root = home.join(".warrantor");
    assert_eq!(
        ArchiveConfig::load(&root).expect("load").auto_file,
        archive_client::AutoFile::Settle
    );

    let (ok, output) = run(&home, &["archive", "auto"]);
    assert!(ok, "{output}");
    assert!(
        output.contains("automatic filing: at settle, to http://127.0.0.1:9")
            && output.contains("pending filings: 0"),
        "the read-back names the archive and the empty queue: {output}"
    );

    let (ok, output) = run(&home, &["archive", "auto", "off"]);
    assert!(ok, "{output}");
    assert_eq!(
        ArchiveConfig::load(&root).expect("load").auto_file,
        archive_client::AutoFile::Off
    );
}

/// An unknown policy word is refused, with the two real ones named.
#[test]
fn an_unknown_policy_word_is_refused_by_the_cli() {
    let home = tempdir("auto-bad");
    paired(&home, "http://127.0.0.1:9");

    let (ok, output) = run(&home, &["archive", "auto", "sometimes"]);

    assert!(!ok, "{output}");
    assert!(
        output.contains("settle") && output.contains("off"),
        "the refusal names both policies: {output}"
    );
}

/// The contract the whole feature hangs on: a settle whose filing failed exits exactly as the
/// same settle with no policy would. The failure is printed in its own block, the export is on
/// disk, and the filing is queued — but the exit code belongs to the settle.
#[test]
fn a_settle_whose_filing_failed_exits_as_a_settle() {
    let quiet = tempdir("settle-off");
    let quiet_id = grant(&quiet);
    let (quiet_ok, quiet_output) = run(&quiet, &["settle", &quiet_id]);
    assert!(
        quiet_ok,
        "a nothing-staged warrant settles cleanly: {quiet_output}"
    );
    assert!(
        !quiet_output.contains("AUTOMATIC"),
        "with the policy off, settle's output is byte-for-byte today's: {quiet_output}"
    );
    assert!(
        !quiet.join(".warrantor/exports").exists() && !quiet.join(".warrantor/archive").exists(),
        "and it writes no filing state: {quiet_output}"
    );

    let loud = tempdir("settle-auto");
    grant(&loud); // a first warrant, to keep ids distinct from the quiet run
    paired(&loud, "http://127.0.0.1:9");
    run(&loud, &["archive", "auto", "settle"]);
    let loud_id = grant(&loud);
    let (loud_ok, loud_output) = run(&loud, &["settle", &loud_id]);

    assert_eq!(
        quiet_ok, loud_ok,
        "the filing's failure does not change settle's exit code"
    );
    assert!(
        loud_output.contains("AUTOMATIC FILING FAILED")
            && loud_output.contains("IS settled")
            && loud_output.contains("NOT filed"),
        "the failure block states both facts in separate words: {loud_output}"
    );
    let root = loud.join(".warrantor");
    let export = root
        .join("exports")
        .join(format!("{loud_id}.settle-report.json"));
    assert!(
        export.exists(),
        "the evidence is on disk even though filing failed"
    );
    let pending = autofile::load_pending(&root).expect("the queue is readable");
    assert_eq!(pending.len(), 1, "and exactly one filing is queued");
    assert_eq!(pending[0].warrant_id, loud_id);
    assert!(
        export.display().to_string().contains(&pending[0].path)
            || pending[0].path == export.display().to_string(),
        "the queued entry points at the export that exists: {} vs {}",
        pending[0].path,
        export.display()
    );
}

/// The next settle is the retry point: an entry queued by one settle is retried by the next one,
/// and when the archive is still down it stays queued with one more attempt behind it.
#[test]
fn a_later_settle_retries_what_an_earlier_one_queued() {
    let home = tempdir("settle-retry");
    paired(&home, "http://127.0.0.1:9");
    run(&home, &["archive", "auto", "settle"]);
    let first = grant(&home);
    let (ok, output) = run(&home, &["settle", &first]);
    assert!(ok, "{output}");
    let root = home.join(".warrantor");

    let second = grant(&home);
    let (ok, output) = run(&home, &["settle", &second]);
    assert!(ok, "{output}");
    assert!(
        output.contains("PENDING FILINGS, RETRIED AT THIS SETTLE"),
        "the drain is announced, not done quietly: {output}"
    );
    assert!(
        output.contains("still queued"),
        "the still-pending entry is listed with its newest reason: {output}"
    );
    let pending = autofile::load_pending(&root).expect("load");
    assert_eq!(pending.len(), 2, "the retried failure plus the new failure");
    assert_eq!(
        pending
            .iter()
            .find(|e| e.warrant_id == first)
            .map(|e| e.attempts),
        Some(2),
        "the first warrant's filing has failed twice now"
    );
}

/// A machine that never paired sees none of this: settle's output is unchanged, no export is
/// written, no queue is created. The policy has no meaning without a pairing, and silence is
/// the honest rendering of that.
#[test]
fn a_settle_on_an_unpaired_machine_writes_no_filing_state() {
    let home = tempdir("settle-unpaired");
    let id = grant(&home);

    let (ok, output) = run(&home, &["settle", &id]);

    assert!(ok, "{output}");
    assert!(
        !output.contains("AUTOMATIC") && !output.contains("archive"),
        "an unpaired machine's settle does not mention filing at all: {output}"
    );
    assert!(
        !home.join(".warrantor/exports").exists() && !home.join(".warrantor/archive").exists(),
        "and it writes nothing toward one"
    );
}

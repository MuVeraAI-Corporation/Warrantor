//! The staged-effect log can be deleted. These are the tests that make that detectable.
//!
//! The hash chain proves nobody edited the log. It cannot prove the log is still there: the file is
//! created lazily by the first append, so `staged/<id>.jsonl` being absent means either "this
//! warrant staged nothing" or "somebody removed the evidence", and [`StagingQueue::open`] reads
//! both as an empty queue at genesis. A report built from that says `0 staged effect(s)` and
//! `chain head 0000…`, and then signs it.
//!
//! So the head and the count are witnessed outside the file they witness: the mark taken at grant
//! in the warrant record, every mark after it appended to `witness/<id>.jsonl` — never by rewriting
//! the record, which on the agent's hot path would clobber the lifecycle state `settle` and `stop`
//! are slowly writing to the same file. `WarrantStore::load` merges the two, and every reader goes
//! through it.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use warrantor_warrant::mcp::Endpoint;
use warrantor_warrant::mcp_endpoints::{agent_endpoint_for, ControlEndpoint};
use warrantor_warrant::proxy::ProxyMode;
use warrantor_warrant::report::{self, StagedSection};
use warrantor_warrant::serve::{no_adapter, route, status, HttpRequest, StoreApi};
use warrantor_warrant::staging::{EffectRegistry, StagedChainMark, StagingQueue};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

const NOW: u64 = 1_786_000_000;
const ID: &str = "wrt_witness";

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-chainmark-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn sample_warrant() -> Warrant {
    let settle = SigningKey::from_bytes(&[9u8; 32]);
    let bounds = WarrantBounds {
        tools: ["github.create_pr", "github.comment"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 3,
    };
    Warrant::grant(
        ID,
        "goal",
        "spiffe://muveraai.com/agent/local",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer(),
    )
    .expect("grant")
}

/// A store holding one warrant, witnessed from grant exactly as `warrantor grant` witnesses it.
fn seeded(tag: &str) -> (std::path::PathBuf, WarrantStore) {
    let dir = tempdir(tag);
    let store = WarrantStore::open(&dir).expect("open store");
    store
        .save(&StoredWarrant {
            warrant: sample_warrant(),
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
            staged_chain: Some(StagedChainMark::genesis(NOW)),
        })
        .expect("save");
    (dir, store)
}

/// Stage `count` effects the way the CLI does: append, then witness.
fn stage_and_witness(store: &WarrantStore, count: usize) {
    let mut queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("open queue");
    for n in 0..count {
        queue
            .stage(
                "github.create_pr",
                args(&[("title", &format!("Fix {n}"))]),
                NOW,
            )
            .expect("stage");
        store
            .witness_staged_chain(ID, &queue, NOW)
            .expect("witness");
    }
}

// ── deletion ──────────────────────────────────────────────────────────────────────────

/// The case this whole mechanism exists for. `rm staged/<id>.jsonl` used to turn "two staged
/// effects, chain head abc…" into "zero staged effects, chain head 0000…" — a success-shaped
/// answer, indistinguishable from a warrant that never staged anything, signed into a bundle.
#[test]
fn a_deleted_staged_log_is_refused_rather_than_read_as_an_empty_queue() {
    let (_dir, store) = seeded("deleted");
    stage_and_witness(&store, 2);

    std::fs::remove_file(store.staged_path(ID)).expect("remove the log");

    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("a deleted log must not open cleanly");
    let text = error.to_string();
    assert!(
        text.contains("missing records this store recorded"),
        "the refusal must say what is missing, not just that something is wrong: {text}"
    );
    assert!(
        text.contains("2 effect(s)"),
        "the refusal must name how many effects are unaccounted for: {text}"
    );
}

/// Truncation is the same failure with a subtler shape: the surviving prefix still forms a valid
/// chain, so the chain check alone passes and the queue reads as shorter than it is.
#[test]
fn a_truncated_staged_log_is_refused_even_though_the_survivors_still_chain() {
    let (_dir, store) = seeded("truncated");
    stage_and_witness(&store, 3);

    let path = store.staged_path(ID);
    let body = std::fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = body.lines().take(1).collect();
    std::fs::write(&path, format!("{}\n", kept.join("\n"))).expect("truncate");

    // The prefix on its own is a perfectly valid chain — this is the part the digests cannot catch.
    StagingQueue::open(&path, ID, EffectRegistry::github())
        .expect("the surviving prefix chains cleanly, which is exactly the problem");

    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("a truncated log must be refused");
    assert!(
        error.to_string().contains("truncated or deleted"),
        "{error}"
    );
}

/// Deleting the log and staging something new in its place produces a valid chain of the right
/// length and the wrong contents. The witness names the record it recorded, so the substitution is
/// caught at the position it happened.
#[test]
fn a_log_rewritten_under_the_witness_is_refused() {
    let (_dir, store) = seeded("rewritten");
    stage_and_witness(&store, 1);

    std::fs::remove_file(store.staged_path(ID)).expect("remove");
    let mut replacement = StagingQueue::open(store.staged_path(ID), ID, EffectRegistry::github())
        .expect("open a fresh log at the same path");
    replacement
        .stage(
            "github.create_pr",
            args(&[("title", "Something else")]),
            NOW,
        )
        .expect("stage");

    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("a substituted log must be refused");
    assert!(
        error.to_string().contains("has been rewritten"),
        "a same-length substitution is a rewrite, and must be named as one: {error}"
    );
}

// ── what must NOT be refused ──────────────────────────────────────────────────────────

/// A witness that lags the log is the ordinary case: the log is append-only, and a session stages
/// effects between witness writes. Refusing growth would make every unwitnessed stage a corruption
/// report, which would teach an operator to ignore the check.
#[test]
fn effects_staged_after_the_witness_are_growth_not_corruption() {
    let (_dir, store) = seeded("growth");
    stage_and_witness(&store, 2);

    // Staged without witnessing, as would happen if the process died before the record was saved.
    let mut queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("open queue");
    queue
        .stage("github.comment", args(&[("body", "later")]), NOW)
        .expect("stage");

    let reopened = store
        .open_queue(ID, EffectRegistry::github())
        .expect("a log that only grew must still open");
    assert_eq!(reopened.len(), 3, "every effect is still there");
}

/// A warrant that staged nothing has no log, and that absence is now provably innocent rather than
/// merely assumed to be: the witness taken at grant says the chain held nothing.
#[test]
fn a_witnessed_warrant_that_staged_nothing_opens_as_empty() {
    let (_dir, store) = seeded("never-staged");
    let queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("a never-written log is not a missing one");
    assert!(queue.is_empty());
}

/// The honest limit of the mechanism, asserted so nobody reads more into it than it says. A warrant
/// granted before the witness existed carries none, and for those the old ambiguity remains: the
/// queue opens empty and nothing here can tell whether that is the truth. Claiming otherwise would
/// mean fabricating a verdict from an absence of evidence.
#[test]
fn a_warrant_from_before_the_witness_existed_is_read_but_not_vouched_for() {
    let (_dir, store) = seeded("unwitnessed");
    stage_and_witness(&store, 1);

    // A warrant from before the mechanism existed has neither half of it: no mark in the record and
    // no witness log. Removing only the field would leave the log, which is a different situation
    // entirely -- see the next test.
    let mut stored = store.load(ID).expect("load");
    stored.staged_chain = None;
    store.save(&stored).expect("save");
    std::fs::remove_file(store.witness_path(ID)).expect("remove the witness log");
    std::fs::remove_file(store.staged_path(ID)).expect("remove");

    let queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("with no witness there is nothing to check against");
    assert!(
        queue.is_empty(),
        "this is the pre-witness behaviour, kept deliberately and documented as unprovable"
    );
}

/// Nulling the field in `warrants/<id>.json` used to be enough to restore the silence, because the
/// record was the only place the witness lived. It is not the only place any more, and the witness
/// log is what an editor who only knows about the record leaves behind.
#[test]
fn editing_the_record_to_unwitnessed_does_not_silence_a_deleted_log() {
    let (_dir, store) = seeded("record-edited");
    stage_and_witness(&store, 2);

    let mut stored = store.load(ID).expect("load");
    stored.staged_chain = None;
    store.save(&stored).expect("save");
    std::fs::remove_file(store.staged_path(ID)).expect("remove");

    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("the witness log outlives an edit to the record");
    assert!(
        error.to_string().contains("2 effect(s)"),
        "the surviving witness still names what is missing: {error}"
    );
}

/// A witness log nobody can parse is not a warrant nobody witnessed. Downgrading one to the other
/// would hand an attacker the whole mechanism for the price of one junk byte.
#[test]
fn a_corrupt_witness_log_is_refused_rather_than_read_as_unwitnessed() {
    let (_dir, store) = seeded("corrupt-witness");
    stage_and_witness(&store, 1);

    let path = store.witness_path(ID);
    let body = std::fs::read_to_string(&path).expect("read");
    std::fs::write(&path, format!("{body}not json\n")).expect("corrupt");

    let error = store
        .load(ID)
        .expect_err("an unreadable witness must not load as an absent one");
    assert!(
        error.to_string().contains("corrupt at line 2"),
        "the refusal has to name where it stopped believing the file: {error}"
    );
}

// ── the record is not rewritten to advance the witness ────────────────────────────────

/// The regression this file's mechanism nearly introduced. `witness_staged_chain` ran on the
/// agent's hot path — after every `warrantor stage` and every MCP `tools/call` that stages — while
/// `settle` and `stop` hold a copy of the same record across seconds of real outward work. When the
/// witness was a load → mutate → save on `warrants/<id>.json`, a stage that loaded before their save
/// and stored after it put `Open` back on disk: a settled warrant that can be settled again, and a
/// stop whose signed record claims containment over a warrant the store says is still running.
///
/// The interleaving is written out here in the order that broke it.
#[test]
fn witnessing_a_stage_cannot_revert_a_lifecycle_state_written_while_it_ran() {
    let (_dir, store) = seeded("lost-update");

    // The slow writer: `stop` (or `settle`) loads the record and then spends seconds terminating a
    // process group and waiting for quiescence before it saves.
    let mut slow = store.load(ID).expect("load");

    // The fast writer, interleaved: a staged effect, witnessed, entirely inside that window.
    stage_and_witness(&store, 1);

    // The slow writer finally saves the copy it loaded before any of that happened.
    slow.warrant.state = WarrantState::Held;
    store.save(&slow).expect("save");

    let after = store.load(ID).expect("reload");
    assert_eq!(
        after.warrant.state,
        WarrantState::Held,
        "a stage must never put a stopped warrant back to Open: that is a duplicate settle and a \
         signed stop record that no longer matches the store"
    );
    assert_eq!(
        after.staged_chain.map(|mark| mark.count),
        Some(1),
        "and the stale save must not lose the witness either: the mark advanced in a file the \
         record's writer never touches"
    );

    // Both halves, checked where they matter: the effect is still accounted for.
    std::fs::remove_file(store.staged_path(ID)).expect("remove");
    let error = store
        .open_queue(ID, EffectRegistry::github())
        .expect_err("the witness survived the concurrent save");
    assert!(error.to_string().contains("1 effect(s)"), "{error}");
}

/// The other order, which is the same bug: the state save lands first and the witness after it.
#[test]
fn a_witness_written_after_a_settle_does_not_reopen_the_warrant() {
    let (_dir, store) = seeded("late-witness");

    let mut queue = store
        .open_queue(ID, EffectRegistry::github())
        .expect("open queue");
    queue
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("stage");

    let mut settled = store.load(ID).expect("load");
    settled.warrant.state = WarrantState::Settled;
    store.save(&settled).expect("save");

    // The witness for the effect above, recorded after the settle -- the shape of a `tools/call`
    // whose witness write lost the race to the settle that followed it.
    store
        .witness_staged_chain(ID, &queue, NOW)
        .expect("witness");

    assert_eq!(
        store.load(ID).expect("reload").warrant.state,
        WarrantState::Settled,
        "recording a witness must not be able to re-open a settled warrant"
    );
}

// ── what the refusal reaches ──────────────────────────────────────────────────────────

/// The refusal is only worth anything if it lands in the fail-closed path the rest of the system
/// already has: an unreadable queue makes the report decline to count staged effects, which sets
/// `policy_decision` false, which makes the notary deny. End to end, from a deleted file.
#[test]
fn a_deleted_log_reaches_the_report_as_unavailable_and_denies() {
    let (_dir, store) = seeded("report");
    stage_and_witness(&store, 2);
    std::fs::remove_file(store.staged_path(ID)).expect("remove");

    let stored = store.load(ID).expect("load");
    let queue = store.open_queue(ID, EffectRegistry::github());
    let built = report::build_observed(
        &stored,
        queue.as_ref().map_err(std::string::ToString::to_string),
        &issuer().verifying_key(),
        NOW + 60,
        &[],
        None,
    );
    let bundle = built.bundle();

    assert!(
        matches!(bundle.staged, StagedSection::Unavailable { .. }),
        "a deleted log must not render as an ordered list of nothing"
    );
    assert_eq!(
        bundle.staged_count, None,
        "an unknown staged count is not zero"
    );
    assert!(
        !bundle.authority_check.allowed,
        "indeterminate is denial: nobody knows what this warrant would release"
    );

    let text = report::render_cli(bundle);
    assert!(
        !text.contains("0 staged effect(s)"),
        "the printed report must never launder a deleted log into a confident zero: {text}"
    );
}

// ── every rewired reader, exercised rather than compile-checked ───────────────────────
//
// `open_witnessed(path, id, registry, None)` is exactly `open`, so a suite whose fixtures all carry
// `staged_chain: None` type-checks the new argument and executes none of the refusal. These four
// tests are the four readers the change rewired, each driven from a real store with a real witness
// and a real deletion.

fn live() -> u64 {
    NOW + 60
}

fn settle_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// A store with two staged effects witnessed and the log removed underneath them.
fn robbed(tag: &str) -> (std::path::PathBuf, WarrantStore) {
    let (dir, store) = seeded(tag);
    stage_and_witness(&store, 2);
    std::fs::remove_file(store.staged_path(ID)).expect("remove the log");
    (dir, store)
}

fn api(dir: &std::path::Path) -> StoreApi {
    StoreApi::new(
        WarrantStore::open(dir).expect("store"),
        dir.to_path_buf(),
        issuer(),
        Some(settle_key()),
        no_adapter,
        live,
    )
}

/// `StoreApi::signed_report` — the HTTP report. It signs what it prints, so a deleted log reaching
/// it as an empty queue would put "0 staged effect(s)" inside a signed bundle served to a reader
/// with no access to this machine.
#[test]
fn the_http_report_marks_a_deleted_log_unavailable_and_denies() {
    let (dir, _store) = robbed("serve-report");
    let mut api = api(&dir);

    let response = route(
        &mut api,
        &HttpRequest::new("GET", &["v1", "warrants", ID, "report"], BTreeMap::new()),
    );

    assert_eq!(response.status, status::OK, "{}", response.body);
    let bundle = &response.body["data"]["bundle"];
    assert_eq!(
        bundle["staged"]["status"], "unavailable",
        "the HTTP report must not serve a deleted log as an ordered list of nothing: {bundle}"
    );
    assert_eq!(
        bundle["staged_count"],
        Value::Null,
        "an unknown staged count is not zero"
    );
    assert_eq!(
        bundle["authority_check"]["allowed"],
        Value::Bool(false),
        "indeterminate is denial on this surface too: {bundle}"
    );
}

/// `StoreApi::settle` — the one that performs real outward effects. Settling against a log that has
/// lost records would release whatever survived and call it the whole queue.
#[test]
fn the_http_settle_refuses_a_log_that_lost_records() {
    let (dir, store) = robbed("serve-settle");
    let mut api = api(&dir);

    let response = route(
        &mut api,
        &HttpRequest::new("POST", &["v1", "warrants", ID, "settle"], BTreeMap::new())
            .with_body(&json!({})),
    );

    assert_ne!(
        response.status,
        status::OK,
        "settle must not succeed against a log it cannot read: {}",
        response.body
    );
    assert!(
        response.body.to_string().contains("nothing was settled"),
        "the refusal has to say that nothing was released: {}",
        response.body
    );
    assert_eq!(
        store.load(ID).expect("load").warrant.state,
        WarrantState::Open,
        "a refused settle leaves the warrant where it was"
    );
}

/// `ControlEndpoint::open_queue` — the MCP path that both reports and settles.
#[test]
fn the_mcp_report_refuses_to_count_a_deleted_log() {
    let (dir, _store) = robbed("mcp-report");
    let mut control = ControlEndpoint::new(
        WarrantStore::open(&dir).expect("store"),
        dir.clone(),
        issuer(),
        settle_key(),
        live,
    );

    let result = control.call(
        "warrant_report",
        &[("warrant_id".to_string(), json!(ID))]
            .into_iter()
            .collect(),
    );

    assert!(
        !result.text.contains("staged effects: none"),
        "the MCP report laundered a deleted log into 'none': {}",
        result.text
    );
    assert!(
        result.text.contains("missing records this store recorded"),
        "it has to say what is missing: {}",
        result.text
    );
    assert!(
        result.text.contains("authority: deny"),
        "an unreadable queue must deny here as it does everywhere else: {}",
        result.text
    );
}

/// `agent_endpoint_for` — the session boundary. Without the check a new agent session opens on the
/// gap and appends fresh effects on top of it, so the log ends up internally consistent and short.
#[test]
fn no_agent_session_starts_on_a_log_that_lost_records() {
    let (_dir, store) = robbed("agent-endpoint");
    let stored = store.load(ID).expect("load");

    let refused = agent_endpoint_for(&stored, store.staged_path(ID), ProxyMode::Enforce, live);

    let error = refused
        .err()
        .expect("a session must not start on a truncated chain");
    assert!(
        error
            .to_string()
            .contains("missing records this store recorded"),
        "{error}"
    );
}

// ── the CLI's own exit code ──────────────────────────────────────────────────────────

/// `warrantor report` prints, signs and exports before it decides its exit code, so the six lines
/// that turn an unreadable queue into a failure are the entire guard — and a library test that
/// calls `report::build_observed` cannot see them. This drives the real binary.
#[test]
fn the_report_command_exits_non_zero_when_the_staged_log_is_gone() {
    let home = tempdir("cli-report");
    let root = home.join(".warrantor");
    let store = WarrantStore::open(&root).expect("open store");
    store
        .save(&StoredWarrant {
            warrant: sample_warrant(),
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
            staged_chain: Some(StagedChainMark::genesis(NOW)),
        })
        .expect("save");
    stage_and_witness(&store, 2);
    // The store's issuer key is the one the sample warrant was signed with, so the only thing that
    // can fail this command is the queue.
    std::fs::create_dir_all(root.join("keys")).expect("keys dir");
    std::fs::write(root.join("keys/issuer.key"), issuer().to_bytes()).expect("write issuer key");

    let intact = run_report(&home);
    assert!(
        intact.0,
        "the control case has to pass, or the assertion below proves nothing: {}",
        intact.1
    );

    std::fs::remove_file(store.staged_path(ID)).expect("remove the log");
    let (success, output) = run_report(&home);

    assert!(
        !success,
        "`warrantor report` exited 0 on a warrant whose staged log is gone: {output}"
    );
    assert!(
        !output.contains("0 staged effect(s)"),
        "and it must not print a confident zero on the way out: {output}"
    );
    assert!(
        output.contains("does NOT describe what this warrant staged"),
        "the operator has to be told what the non-zero exit means: {output}"
    );
    assert!(
        output.contains("evidence bundle"),
        "the report is still built and signed -- only its verdict changed: {output}"
    );
}

/// Run `warrantor report <id>` against a store rooted in `home`, returning success and all output.
fn run_report(home: &std::path::Path) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .args(["report", ID])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()
        .expect("run warrantor report");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

//! `warrantor` — grant a warrant, run an agent under it, then settle or void.
//!
//! # Key handling
//!
//! Two keys live under `~/.warrantor/keys/`:
//!
//! * `issuer.key` signs warrants and capability tokens.
//! * `settle.key` authorises settling, voiding and renewal.
//!
//! They are separate because the agent must not be able to settle its own warrant. In this CLI
//! both are on the developer's machine, which is correct — the developer *is* the settle
//! authority. What matters is that the settle key is never loaded into the process the agent runs
//! in. When the daemon lands it will hold the issuer key and supervise agents; the settle key
//! stays here, in the command the human types.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ed25519_dalek::{SigningKey, VerifyingKey};
use warrantor_warrant::daemon::{
    process_is_alive, supervise_run, DaemonState, Reconciliation, SuperviseRequest,
};
use warrantor_warrant::egress::{
    render_decision, EgressBroker, EgressVerdict, BROKER_VERSION, ENFORCEMENT_NOTE,
};
use warrantor_warrant::mcp::serve;
use warrantor_warrant::mcp_endpoints::{agent_endpoint_for, ControlEndpoint};
use warrantor_warrant::proxy::{host_of, ProxyMode};
use warrantor_warrant::report;
use warrantor_warrant::serve as http;
use warrantor_warrant::settle::{settle, void, EffectOutcome, EffectPerformer, SettleReport};
use warrantor_warrant::spend::{self, SpendStore, SpendVerdict};
use warrantor_warrant::staging::{EffectRegistry, StagedEffect, StagingQueue};
use warrantor_warrant::stop::{self, OsProcessControl, StopStore};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::supervise::{describe_linkage, spawn_detached};
use warrantor_warrant::worktree::Worktree;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fail(message: &str) -> ExitCode {
    eprintln!("warrantor: {message}");
    ExitCode::FAILURE
}

// ── keys ──────────────────────────────────────────────────────────────────────────────

/// Load a key, creating it on first use.
///
/// Generating on demand keeps the first run to one command. The tradeoff is stated in the message
/// rather than hidden: a key that appears without ceremony is easy to forget you must protect.
fn load_or_create_key(path: &Path, label: &str) -> Result<SigningKey, String> {
    if let Ok(body) = std::fs::read(path) {
        let bytes: [u8; 32] = body
            .as_slice()
            .try_into()
            .map_err(|_| format!("{label} key at {} is not 32 bytes", path.display()))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create key dir: {e}"))?;
    }
    let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let key = SigningKey::generate(&mut csprng);
    std::fs::write(path, key.to_bytes()).map_err(|e| format!("write {label} key: {e}"))?;
    eprintln!(
        "warrantor: created a new {label} key at {}. Protect it: anyone holding the settle key \
         can release staged effects.",
        path.display()
    );
    Ok(key)
}

// ── argument parsing ──────────────────────────────────────────────────────────────────

struct Args {
    command: String,
    positional: Vec<String>,
    flags: BTreeMap<String, String>,
    /// Everything after a bare `--`, passed through untouched.
    ///
    /// Kept separate because it is the agent's own command line: rewriting or re-parsing it would
    /// change what the developer asked to run.
    trailing: Vec<String>,
}

fn parse_args() -> Option<Args> {
    parse_tokens(std::env::args().skip(1))
}

/// The parser proper, over any sequence of tokens.
///
/// Split from [`parse_args`] so the flag grammar can be tested without a process: `parse_args`
/// reads `std::env::args`, and a rule that can only be exercised by launching a binary is a rule
/// that gets tested once, by hand, on the day it is written.
fn parse_tokens<I: IntoIterator<Item = String>>(tokens: I) -> Option<Args> {
    let mut raw = tokens.into_iter();
    let command = raw.next()?;
    let mut positional = Vec::new();
    let mut flags = BTreeMap::new();
    let mut trailing = Vec::new();
    let mut pending: Option<String> = None;
    let mut after_separator = false;
    for token in raw {
        if after_separator {
            trailing.push(token);
        } else if token == "--" {
            if let Some(previous) = pending.take() {
                flags.insert(previous, "true".to_string());
            }
            after_separator = true;
        } else if let Some(name) = token.strip_prefix("--") {
            if let Some(previous) = pending.take() {
                flags.insert(previous, "true".to_string());
            }
            if let Some((name, value)) = name.split_once('=') {
                flags.insert(name.to_string(), value.to_string());
            } else {
                pending = Some(name.to_string());
            }
        } else if let Some(name) = pending.take() {
            flags.insert(name, token);
        } else {
            positional.push(token);
        }
    }
    if let Some(remaining) = pending {
        flags.insert(remaining, "true".to_string());
    }
    Some(Args {
        command,
        positional,
        flags,
        trailing,
    })
}

fn csv(value: Option<&String>) -> BTreeSet<String> {
    value
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a duration like `8h`, `30m`, `90s`.
fn duration_seconds(value: &str) -> Option<u64> {
    let (number, unit) = value.split_at(value.len().checked_sub(1)?);
    let n: u64 = number.parse().ok()?;
    match unit {
        "h" => Some(n * 3600),
        "m" => Some(n * 60),
        "s" => Some(n),
        _ => None,
    }
}

// ── commands ──────────────────────────────────────────────────────────────────────────

const USAGE: &str = "\
warrantor — bounded authority for coding agents

  grant   --goal G --tools T,T --write P,P [--deadline 8h] [--repo .] [--egress H,H]
  list
  report  <warrant-id> [--export <path>]
  verify  <exported-report.json | exported-stop.json | exported-spend.json>
  egress  <warrant-id> <destination> [<destination> ...]
  spend   <warrant-id> [--input N --output N [--backend ID] [--quote]] [--export <path>]
  stop    <warrant-id> [--reason \"...\"] [--export <path>]
  settle  <warrant-id> [--commit \"<message>\"]
  void    <warrant-id>
  stage   <warrant-id> --tool T [--target H] [--arg k=v ...]
  run     <warrant-id> -- <command> [args...]
  status
  mcp     [--agent <warrant-id>] [--observe]
  serve   [--bind <addr>] [--port <n>] [--token-file <path>] [--allow-settle]

Report --export writes a signed, self-contained evidence bundle. Verify checks one
offline, on any machine, with no access to this one: it proves nothing changed since
signing, and says plainly what it does not prove. It reads stop records and spend
ledgers too, dispatching on the format the file declares.

Stop ends a run now: it terminates the supervisor, lets the OS lifetime link take the
agent tree with it, holds the warrant so its staged work survives for a decision, and
writes a signed stop record scored against the four mandated containment capabilities.
It reports what it actually contained -- including when the answer is \"not enough\" --
and exits non-zero rather than claiming a stop it could not make.

Spend keeps the budget bound's ledger. It is OBSERVED and stays observed: model API
calls never pass through Warrantor, so every figure is one the agent reported about
itself, and an agent that does not report spends unwatched. What it buys is that the
number is finally read -- a durable per-warrant total, a refusal when a reported use
would break the ceiling, and cost-aware routing advice from your own price table in
~/.warrantor/backends.json. A warrant granted without --budget has a ceiling of zero.

Egress asks the broker, ahead of a run, exactly what the proxy will ask during one:
for each destination, allow or deny and why. It answers for tool calls that go
through the Warrantor MCP proxy, which is the only place egress is decided. For a
warrant no live session could reach -- expired, not Open, or already stopped -- it
refuses outright rather than answering about the bound.

Mcp serves the warrant lifecycle to your own coding agent over MCP. With --agent it
instead serves a SUPERVISED agent: only that warrant's tools, policed, with no
lifecycle tool published -- so the agent has no route to settling its own work.

Serve puts the store behind a read API so a second person, a desktop app or a
browser client can watch a run -- the thing a directory of JSON files on one
machine could never do. It binds 127.0.0.1 unless you say otherwise, mints a
per-session bearer token and checks it before it resolves a route, and computes
every verification verdict itself: a client renders `verified`, it never derives
it. Three routes change anything -- settle, void and stop -- and there is no
grant over HTTP. /v1/summary/refusals is the one to read weekly: it aggregates
every wall your agents hit, across warrants, and says whether the bound was
wrong or the agent was.

The token is printed and written to ~/.warrantor/serve/token, owner-only where
the platform has such a thing; --token-file puts it somewhere else and will not
create the directory for you. It lasts one run: Ctrl-C lets the requests in
flight finish, then deletes the file, and the next start mints a new one. A
--bind that is not loopback prints a warning naming what just became reachable,
because there is no TLS here -- the token controls access, not confidentiality.

Run starts the agent under a supervisor detached from this terminal: closing the
terminal ends your view of the run, not the run. Status says what is still going
and what stopped and needs a decision.

Grant creates an isolated git worktree. The agent works there; nothing it does is
visible outside until you settle. External effects are staged, not performed.";

fn cmd_grant(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    let Some(goal) = args.flags.get("goal") else {
        return fail("--goal is required: a warrant without a stated purpose cannot be reviewed");
    };
    let tools = csv(args.flags.get("tools"));
    if tools.is_empty() {
        return fail("--tools is required: a warrant with no tools can do nothing");
    }
    let deadline = args
        .flags
        .get("deadline")
        .map_or(Some(8 * 3600), |d| duration_seconds(d));
    let Some(deadline) = deadline else {
        return fail("--deadline must look like 8h, 30m or 90s");
    };
    // `--budget 5x` used to parse to None, and None means NO CEILING. So a developer who believed
    // they had set a cap had set nothing, at the exact moment they were thinking about the cap.
    // An unparseable limit is now a refusal, because the alternative reading is the unsafe one.
    let budget_cents = match args.flags.get("budget") {
        None => None,
        Some(raw) => match raw.parse::<u64>() {
            Ok(cents) => Some(cents),
            Err(_) => {
                return fail(&format!(
                    "--budget must be whole cents, e.g. --budget 500 for $5.00. {raw:?} does not \
                     parse, and a budget that does not parse would silently mean NO ceiling."
                ))
            }
        },
    };

    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), "issuer") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), "settle") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };

    let id = format!("wrt_{:016x}", now().wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let bounds = WarrantBounds {
        tools,
        write_paths: csv(args.flags.get("write")),
        egress_hosts: csv(args.flags.get("egress")),
        // Writes are staged by default: the safe reading of an unspecified flag.
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: now() + deadline,
        budget_cents_observed: budget_cents,
        delegation_depth: 3,
    };

    let warrant = match Warrant::grant(
        &id,
        goal,
        args.flags
            .get("subject")
            .map_or("spiffe://muveraai.com/agent/local", String::as_str),
        bounds,
        now(),
        &settle_key.verifying_key(),
        &issuer,
    ) {
        Ok(w) => w,
        Err(e) => return fail(&e.to_string()),
    };

    // A worktree is only possible inside a git repository; a warrant without one is still useful
    // for staging-only work, so this is a warning rather than a failure.
    let repo = args.flags.get("repo").map(PathBuf::from);
    let worktree = match &repo {
        Some(path) => match Worktree::create(path, &id) {
            Ok(tree) => Some(tree),
            Err(e) => {
                eprintln!("warrantor: no worktree ({e}); the warrant still bounds staged effects");
                None
            }
        },
        None => None,
    };

    let stored = StoredWarrant {
        warrant,
        worktree: worktree.as_ref().map(|t| t.path.clone()),
        repo: worktree.as_ref().map(|t| t.repo.clone()),
        branch: worktree.as_ref().map(|t| t.branch.clone()),
        base_commit: worktree.as_ref().map(|t| t.base_commit.clone()),
    };
    if let Err(e) = store.save(&stored) {
        return fail(&e.to_string());
    }

    println!("warrant  {id}");
    println!("goal     {goal}");
    println!(
        "expires  {} ({}s from now)",
        stored.warrant.claims.bounds.expires_at, deadline
    );
    if let Some(tree) = &worktree {
        println!("worktree {}", tree.path.display());
        println!("branch   {}", tree.branch);
    }
    println!("\nRun your agent with its working directory set to the worktree.");
    println!("Then: warrantor report {id}");
    ExitCode::SUCCESS
}

fn cmd_list(store: &WarrantStore) -> ExitCode {
    let warrants = match store.list() {
        Ok(w) => w,
        Err(e) => return fail(&e.to_string()),
    };
    if warrants.is_empty() {
        println!("no warrants yet — try: warrantor grant --goal \"...\" --tools git");
        return ExitCode::SUCCESS;
    }
    println!("{:<22}{:<10}GOAL", "WARRANT", "STATE");
    for stored in warrants {
        println!(
            "{:<22}{:<10}{}",
            stored.warrant.claims.id,
            format!("{:?}", stored.warrant.state).to_lowercase(),
            stored.warrant.claims.goal
        );
    }
    ExitCode::SUCCESS
}

fn open_queue(store: &WarrantStore, id: &str) -> Result<StagingQueue, String> {
    StagingQueue::open(store.staged_path(id), id, EffectRegistry::github())
        .map_err(|e| e.to_string())
}

/// `warrantor report <id> [--export <path>]` — the morning read, and the evidence behind it.
///
/// The prose is unchanged from before there was a bundle: the same five sections, byte for byte,
/// rendered from [`report::render_cli`]. What is new is additive and sits below it — a signed
/// evidence bundle covering exactly the numbers the prose just printed, and `--export` writing it
/// somewhere a third party can check it without access to this machine.
///
/// It takes `root` now because signing needs the issuer key. Not the settle key: reporting is a
/// read, and loading settle authority to describe work would put it in a process that has no
/// business holding it.
fn cmd_report(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor report <warrant-id> [--export <path>]");
    };
    let stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let queue = match open_queue(store, id) {
        Ok(q) => q,
        Err(e) => return fail(&e),
    };
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), "issuer") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };

    // Containment is read before the verdict is taken, and read fail-closed: if the stop-record
    // directory cannot be opened we do not know whether this warrant was stopped, and a report
    // that quietly assumed "not stopped" would pass the containment gate on an unknown.
    let stops = match StopStore::open(root) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "cannot read stop records, so containment is unknown: {e}"
            ))
        }
    };
    let contained = stops.contained_scopes(id);

    // The budget bound's ledger, read the same fail-closed way: an unreadable or wrongly-signed
    // ledger is an error, not a zero. A report that silently showed no spend because the ledger
    // would not parse would be worse than one that showed nothing at all, because it would look
    // like an answer.
    let ledgers = match SpendStore::open(root) {
        Ok(s) => s,
        Err(e) => return fail(&format!("cannot read the spend ledger: {e}")),
    };
    let ledger = match ledgers.load(
        &stored.warrant.claims.bounds,
        id,
        &stored.warrant.claims.subject,
        &issuer.verifying_key(),
    ) {
        Ok(l) => l,
        Err(e) => return fail(&format!("cannot read the spend ledger: {e}")),
    };

    // The verifying key from disk is the trust anchor, not the one the warrant carries about
    // itself: a warrant re-signed by some other key must not vouch for itself.
    let built = report::build_observed(
        &stored,
        Ok(&queue),
        &issuer.verifying_key(),
        now(),
        &contained,
        Some(spend::section(&ledger)),
    );
    print!("{}", report::render_cli(built.bundle()));

    let signed = match built.sign(&issuer, "issuer") {
        Ok(s) => s,
        Err(e) => {
            // The report above is still true and still printed. Only the proof is missing, and
            // saying so is better than exiting successfully with silence where evidence goes.
            eprintln!("warrantor: the report above could not be signed: {e}");
            return ExitCode::FAILURE;
        }
    };
    print!("{}", report::render_signature_section(&signed));

    if let Some(path) = args.flags.get("export") {
        if path == "true" {
            return fail("--export needs a file path: warrantor report <id> --export report.json");
        }
        if let Err(e) = write_export(&signed, Path::new(path)) {
            return fail(&e);
        }
        println!("exported  {path}");
        println!("Check it anywhere, with no access to this machine:  warrantor verify {path}");
    }
    ExitCode::SUCCESS
}

/// Write a signed artifact where a third party can read it. Generic because a report bundle and a
/// stop record are exported the same way, and two copies of this would drift.
fn write_export<T: serde::Serialize>(signed: &T, path: &Path) -> Result<(), String> {
    let body = serde_json::to_vec_pretty(signed).map_err(|e| format!("encode export: {e}"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, &body).map_err(|e| format!("write {}: {e}", path.display()))
}

/// `warrantor verify <path>` — check an exported artifact offline.
///
/// The command that makes signing worth doing. It needs no store, no key, no network and no prior
/// relationship with the machine that produced the file: everything it checks is in the file. It
/// ends by stating what a pass does *not* establish, because a verifier that only ever says
/// "verified" teaches the reader to hear more than was said.
///
/// Two artifacts share the verb, dispatched on the file's declared `format` rather than on whether
/// a struct happens to deserialise: a report bundle and a stop record are different claims, and
/// guessing between them by shape is how one gets checked with the other's rules.
fn cmd_verify(args: &Args) -> ExitCode {
    let Some(path) = args.positional.first() else {
        return fail("usage: warrantor verify <exported-report.json | exported-stop.json>");
    };
    let body = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return fail(&format!("read {path}: {e}")),
    };
    let declared: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return fail(&format!("{path} is not a warrantor evidence file: {e}")),
    };
    match declared.get("format").and_then(serde_json::Value::as_str) {
        Some(f) if f == report::REPORT_EXPORT_FORMAT => verify_report_export(path, &body),
        Some(f) if f == stop::STOP_EXPORT_FORMAT => verify_stop_export(path, &body),
        Some(f) if f == spend::LEDGER_EXPORT_FORMAT => verify_spend_export(path, &body),
        Some(other) => fail(&format!(
            "{path} declares format {other:?}. warrantor verify reads {}, {} and {}.",
            report::REPORT_EXPORT_FORMAT,
            stop::STOP_EXPORT_FORMAT,
            spend::LEDGER_EXPORT_FORMAT
        )),
        None => fail(&format!(
            "{path} has no format field, so it is not a warrantor evidence file."
        )),
    }
}

fn verify_report_export(path: &str, body: &[u8]) -> ExitCode {
    let signed: report::SignedReport = match serde_json::from_slice(body) {
        Ok(s) => s,
        Err(e) => return fail(&format!("{path} is not an exported warrantor report: {e}")),
    };
    // Integrity is checked with the time-free verifier on purpose. An exported report is a record
    // of a past evaluation; it must not become unverifiable because a deadline went by, or an
    // archive would rot into a pile of files that all say "does NOT verify".
    if let Err(e) = report::verify_export(&signed) {
        return fail(&format!("{path} does NOT verify: {e}"));
    }
    // Liveness is a different question with a different answer, so it is reported rather than
    // conflated with tampering. Printing it is also what stops the receipt's `expires_at` from
    // being a field nothing ever reads.
    let checked_at = now();
    let liveness = match report::verify_export_at(&signed, checked_at) {
        Ok(()) => format!(
            "live at {checked_at}; the warrant's deadline is {}",
            signed.bundle.expires_at
        ),
        Err(report::ReportError::Expired { expires_at, .. }) => format!(
            "EXPIRED — the deadline passed at {expires_at}, checked at {checked_at}. The \
             signatures are intact: this is a true record of a past decision, not a statement \
             about authority the subject still holds."
        ),
        // `verify_export` already passed, so the only thing left for `verify_export_at` to add is
        // the expiry check. Anything else means the two disagreed, which is worth saying out loud
        // rather than swallowing into a cheerful "live".
        Err(e) => format!("could not be determined: {e}"),
    };

    let check = &signed.bundle.authority_check;
    println!("verified  {}", signed.bundle_digest);
    println!("  warrant       {}", signed.bundle.warrant_id);
    println!("  goal          {}", signed.bundle.goal);
    println!("  subject       {}", signed.bundle.subject);
    println!("  state         {:?}", signed.bundle.state);
    println!("  generated at  {}", signed.bundle.generated_at);
    println!(
        "  authority     {} ({}), decided by {}",
        if check.allowed { "allow" } else { "deny" },
        check
            .denied_gate
            .clone()
            .unwrap_or_else(|| "all nine gates passed".to_string()),
        check.engine
    );
    println!(
        "  signed by     {}",
        signed.evidence_receipt.signature.public_key
    );
    println!("  still live    {liveness}");

    println!("\n── WHAT THIS DOES NOT ESTABLISH ──");
    for limitation in &signed.bundle.limitations {
        println!("  - {limitation}");
    }
    ExitCode::SUCCESS
}

/// Check an exported spend ledger.
///
/// A pass means the ledger has not changed since it was signed and its arithmetic is internally
/// consistent. It does not mean the figures are true — they are the agent's own — so the caveats
/// are printed on every pass, not only on failure.
fn verify_spend_export(path: &str, body: &[u8]) -> ExitCode {
    let signed: spend::SignedSpend = match serde_json::from_slice(body) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "{path} is not an exported warrantor spend ledger: {e}"
            ))
        }
    };
    if let Err(e) = spend::verify_spend(&signed) {
        return fail(&format!("{path} does NOT verify: {e}"));
    }
    let ledger = &signed.ledger;
    println!("verified  {}", signed.ledger_digest);
    println!("  warrant       {}", ledger.warrant_id);
    println!("  subject       {}", ledger.subject);
    println!(
        "  ceiling       {}",
        if ledger.cap_declared {
            spend::usd(ledger.cap_micros)
        } else {
            "none declared, so none granted".to_string()
        }
    );
    println!("  observed      {}", spend::usd(ledger.spent_micros));
    println!("  remaining     {}", spend::usd(ledger.remaining_micros()));
    println!("  records       {}", ledger.entries.len());
    println!("  signed by     {}", signed.receipt.signature_public_key);

    println!("\n── WHAT THIS DOES NOT ESTABLISH ──");
    for limitation in &signed.limitations {
        println!("  - {limitation}");
    }
    ExitCode::SUCCESS
}

/// Check an exported stop record.
///
/// Exits non-zero when the record verifies but records a containment FAIL: a stop that could not
/// contain the run is a true record of a bad outcome, and reporting it as a clean pass would be the
/// exact failure the record exists to prevent.
fn verify_stop_export(path: &str, body: &[u8]) -> ExitCode {
    let signed: stop::SignedStop = match serde_json::from_slice(body) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "{path} is not an exported warrantor stop record: {e}"
            ))
        }
    };
    if let Err(e) = stop::verify_stop(&signed) {
        return fail(&format!("{path} does NOT verify: {e}"));
    }

    let outcome = &signed.record.outcome;
    println!("verified  {}", signed.record_digest);
    println!("  warrant       {}", signed.record.warrant_id);
    println!("  goal          {}", signed.record.goal);
    println!("  stopped at    {}", signed.record.stopped_at);
    if let Some(reason) = &signed.record.reason {
        println!("  reason        {reason}");
    }
    println!(
        "  state         {:?} -> {:?}",
        outcome.state_before, outcome.state_after
    );
    println!(
        "  signed by     {}",
        signed.record.conformance.signature_public_key
    );
    for capability in &signed.record.conformance.report.capabilities {
        println!(
            "  {:<18}{}",
            capability.capability.label(),
            stop::verdict_word(capability.verdict)
        );
    }
    print!("{}", stop::render_limitations(&signed));
    if stop::contained(&signed) {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "warrantor: this record verifies, and what it records is a containment FAILURE. The \
             run was not contained."
        );
        ExitCode::FAILURE
    }
}

/// `warrantor stop <id>` — end a run now, and say exactly what ending it achieved.
///
/// The single most reassuring control an operator has, so it is written to be loud rather than
/// tidy. Four things happen, in this order, and each is reported:
///
/// 1. The supervisor's process group is terminated, and stop waits for it to actually be gone.
/// 2. The warrant transitions `Open -> Held`, so staged work survives for a settle decision. Stop
///    never discards work: `warrantor void <id>` is still the separate, deliberate act.
/// 3. A signed stop record is written to `<root>/stops/<id>.json`, scored against the four mandated
///    containment capabilities and downgraded by the suite's anti-sandbagging rule.
/// 4. The warrant's scope becomes contained, so its next `warrantor report` denies at gate 1.
///
/// It exits non-zero when the record contains a FAIL — a supervisor that would not die, a platform
/// with no parent-death link, or a warrant whose access is still open. A stop that could not
/// contain must not exit like one that did.
fn cmd_stop(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor stop <warrant-id> [--reason \"...\"] [--export <path>]");
    };
    let mut stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let daemons = match DaemonState::open(root) {
        Ok(d) => d,
        Err(e) => return fail(&e.to_string()),
    };
    let stops = match StopStore::open(root) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    // The issuer key, not the settle key. Stop releases nothing and performs nothing, so loading
    // settle authority to record it would put that key in a process with no business holding it.
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), "issuer") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };

    let daemon = daemons.get(id);
    let mut outcome = stop::execute(
        &mut stored,
        daemon.as_ref(),
        &OsProcessControl,
        &store.staged_path(id),
    );
    if daemon.is_some() {
        match daemons.deregister(id) {
            Ok(()) => outcome.deregistered = true,
            Err(e) => eprintln!(
                "warrantor: the run was stopped, but its daemon record could not be removed: {e}. \
                 `warrantor status` may keep reporting it."
            ),
        }
    }
    // Persist the held state before writing the record, so a crash between the two leaves a warrant
    // that is held with no record rather than a record of a hold that did not happen.
    if let Err(e) = store.save(&stored) {
        return fail(&format!(
            "the run was stopped but the warrant state could not be persisted: {e}"
        ));
    }

    let reason = args
        .flags
        .get("reason")
        .filter(|value| value.as_str() != "true")
        .map(String::as_str);
    let signed = match stop::sign(&stored, &outcome, reason, &issuer, now()) {
        Ok(s) => s,
        Err(e) => {
            // The run really is stopped; only the evidence is missing. Saying so beats exiting
            // successfully with silence where the record goes.
            eprintln!("warrantor: the run was stopped, but the record could not be signed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let written = match stops.save(&signed) {
        Ok(path) => path,
        Err(e) => {
            return fail(&format!(
                "the run was stopped but the record was not kept: {e}"
            ))
        }
    };

    print!("{}", stop::render_cli(&signed));
    println!("  kept at         {}", written.display());
    print!("{}", stop::render_limitations(&signed));

    if let Some(path) = args.flags.get("export") {
        if path == "true" {
            return fail("--export needs a file path: warrantor stop <id> --export stop.json");
        }
        if let Err(e) = write_export(&signed, Path::new(path)) {
            return fail(&e);
        }
        println!("\nexported  {path}");
        println!("Check it anywhere, with no access to this machine:  warrantor verify {path}");
    }

    if stop::contained(&signed) {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "warrantor: this stop did NOT contain the run -- see the FAIL above. Treat the agent \
             as still running until you have confirmed otherwise yourself."
        );
        ExitCode::FAILURE
    }
}

/// Parse a flag that must be a whole number, refusing rather than defaulting.
///
/// The `--budget 5x -> None -> uncapped` bug in one helper: everywhere a number bounds something,
/// an unparseable value is a refusal, never a zero and never an absence.
fn whole_number(args: &Args, flag: &str) -> Result<Option<u64>, String> {
    match args.flags.get(flag) {
        None => Ok(None),
        Some(raw) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("--{flag} must be a whole number; {raw:?} does not parse")),
    }
}

/// `warrantor spend <id>` — what the budget bound has actually observed.
///
/// The budget was the one bound the system talked about and never looked at: declared at grant,
/// checked once against a parent at issue, and then read by nothing. `bound_strengths()` called it
/// `observed`, which was a promise nobody was keeping. This verb is what keeps it.
///
/// Three modes, one code path:
///
/// * bare — print the ledger.
/// * `--quote` with `--input/--output` — price the work against every approved backend and say
///   which the remaining allowance still covers. Records nothing.
/// * `--input/--output` — record the agent's claim, or refuse it and exit non-zero.
///
/// It stays `Observed` and it will not be relabelled. Recording is not permission: the provider
/// call this describes already happened somewhere Warrantor cannot see, so a refusal here means
/// "the ledger will not carry this and you should act", not "the money was not spent".
fn cmd_spend(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    const USAGE_LINE: &str = "usage: warrantor spend <warrant-id> [--input N --output N \
                              [--backend ID] [--quote]] [--export <path>]";
    let Some(id) = args.positional.first() else {
        return fail(USAGE_LINE);
    };
    let stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    // The issuer key, not the settle key: recording what an agent says it spent releases nothing.
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), "issuer") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let ledgers = match SpendStore::open(root) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let bounds = &stored.warrant.claims.bounds;
    let subject = &stored.warrant.claims.subject;
    let mut ledger = match ledgers.load(bounds, id, subject, &issuer.verifying_key()) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };

    let input = match whole_number(args, "input") {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let output = match whole_number(args, "output") {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };

    // Bare view: the ledger, and nothing invented around it.
    if input.is_none() && output.is_none() {
        print!("{}", render_ledger(&ledger));
        println!("\n{}", spend::OBSERVATION_NOTE);
        println!(
            "\nRecord what an agent used:  warrantor spend {id} --input <tokens> --output <tokens>"
        );
        return ExitCode::SUCCESS;
    }

    let claim = spend::UsageClaim {
        backend: args
            .flags
            .get("backend")
            .filter(|value| value.as_str() != "true")
            .cloned(),
        input_tokens: input.unwrap_or(0),
        output_tokens: output.unwrap_or(0),
    };
    let backends = match spend::load_backends(root) {
        Ok(b) => b,
        Err(e) => return fail(&e.to_string()),
    };

    // Cost-aware routing metadata: every approved backend priced for this exact work, and whether
    // what remains of the cap covers it. Advice, computed from the operator's own price table --
    // Warrantor is not in the inference path and routes nothing.
    println!("warrant {id} — {} token(s) of work", claim.tokens());
    println!("{:<28}{:>14}  AFFORDABLE NOW", "BACKEND", "COST");
    for quote in spend::quotes(&ledger, &claim, &backends) {
        println!(
            "{:<28}{:>14}  {}",
            quote.backend,
            spend::usd(quote.cost_micros),
            match (quote.safe, quote.affordable) {
                (false, _) => "no (not approved safe)",
                (true, true) => "yes",
                (true, false) => "no (over the remaining ceiling)",
            }
        );
    }
    println!();

    if args.flags.contains_key("quote") {
        print!("{}", render_ledger(&ledger));
        println!("\nQuoted only; nothing was recorded.");
        println!("{}", spend::OBSERVATION_NOTE);
        return ExitCode::SUCCESS;
    }

    let decision = spend::record(bounds, &mut ledger, &claim, &backends, now());
    match &decision.verdict {
        SpendVerdict::Allow {
            cost_micros,
            remaining_usd_micros,
            chosen_backend,
            ..
        } => {
            println!(
                "recorded  {} on {chosen_backend}; {} left of the declared ceiling",
                spend::usd(*cost_micros),
                spend::usd(*remaining_usd_micros)
            );
        }
        SpendVerdict::Deny { reason } => {
            // Nothing was recorded and the ledger is untouched, so there is nothing to sign or
            // save. Saying what would fix it matters more than the reason code.
            eprintln!(
                "warrantor: REFUSED to record this usage — {}.",
                spend::reason_word(reason)
            );
            print!("{}", render_ledger(&ledger));
            if !ledger.cap_declared {
                eprintln!(
                    "warrantor: this warrant declares no budget, so its ceiling is zero. An \
                     absent limit means none, never unlimited -- grant with --budget <cents>."
                );
            }
            eprintln!(
                "warrantor: the model call this describes has already happened; Warrantor was \
                 never in its path. Refusing the RECORD does not undo the SPEND. Consider \
                 `warrantor stop {id}`."
            );
            return ExitCode::FAILURE;
        }
    }

    let signed = match spend::sign(&ledger, &decision, &issuer, "issuer", now()) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "the usage could not be signed, so it was not kept: {e}"
            ))
        }
    };
    let written = match ledgers.save(&signed) {
        Ok(path) => path,
        Err(e) => return fail(&format!("the usage was not kept: {e}")),
    };
    print!("{}", render_ledger(&ledger));
    println!("  kept at                 {}", written.display());
    println!("\n{}", spend::OBSERVATION_NOTE);

    if let Some(path) = args.flags.get("export") {
        if path == "true" {
            return fail("--export needs a file path: warrantor spend <id> --export spend.json");
        }
        if let Err(e) = write_export(&signed, Path::new(path)) {
            return fail(&e);
        }
        println!("\nexported  {path}");
        println!("Check it anywhere, with no access to this machine:  warrantor verify {path}");
    }
    ExitCode::SUCCESS
}

/// The ledger as a human reads it. One renderer so the record, quote and refusal paths agree.
fn render_ledger(ledger: &warrantor_warrant::spend::SpendLedger) -> String {
    let mut out = String::new();
    out.push_str("\n── BUDGET (OBSERVED, SELF-REPORTED) ──\n");
    for line in spend::section_lines(&spend::section(ledger)) {
        out.push_str(&line);
        out.push('\n');
    }
    for entry in ledger.entries.iter().rev().take(5) {
        out.push_str(&format!(
            "  {:<10} {:<18}{:>10} in {:>10} out  {}\n",
            entry.at,
            entry.backend,
            entry.input_tokens,
            entry.output_tokens,
            spend::usd(entry.cost_micros)
        ));
    }
    out
}

/// `warrantor egress <id> <destination>...` — what the proxy will decide, before the agent asks.
///
/// The same broker, the same catalogue derived from the same signed bounds, the same per-
/// destination decision. Nothing here is a simulation of the run-time path; it *is* the run-time
/// path, called with a destination you typed instead of one an agent named.
///
/// That claim only holds if the *session* preconditions hold too, so they are checked first, and
/// a warrant that fails one is refused before any destination is decided. The broker alone would
/// happily print `allow` for a host named by an expired, Held, Voided or stopped warrant — true
/// about the bound, and a lie about the run, because no live session under that warrant reaches
/// anything. A pre-flight check that disagrees with the run is worse than no pre-flight check.
///
/// Containment is read fail-closed, as `warrantor report` reads it: a stop directory that will not
/// open means containment is unknown, and an unknown is refused rather than assumed clear.
///
/// It exits non-zero if any destination is refused, so it can be used as a check in a script. It
/// needs no key: asking what a warrant permits is a read.
fn cmd_egress(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    const USAGE_LINE: &str =
        "usage: warrantor egress <warrant-id> <destination> [<destination> ...]";
    let Some(id) = args.positional.first() else {
        return fail(USAGE_LINE);
    };
    let destinations: Vec<&String> = args.positional.iter().skip(1).collect();
    if destinations.is_empty() {
        return fail(USAGE_LINE);
    }
    let stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let stops = match StopStore::open(root) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "cannot read stop records, so it is unknown whether {id} is contained: {e}"
            ))
        }
    };
    if let Err(unreachable) = warrantor_warrant::egress::session_reachability(
        stored.warrant.state,
        stored.warrant.claims.bounds.expires_at,
        stops.is_stopped(id),
        now(),
    ) {
        eprintln!(
            "warrantor: REFUSING to decide egress for {id} — {}",
            unreachable.sentence()
        );
        eprintln!(
            "warrantor: the bound is still readable with `warrantor report {id}`. It is not \
             printed as an allow here, because an allow would describe a call that cannot happen."
        );
        return ExitCode::FAILURE;
    }

    let broker = EgressBroker::for_bounds(&stored.warrant.claims.bounds);
    println!(
        "warrant {id} — {} catalogued destination(s)",
        broker.catalogued()
    );
    if let Some(digest) = broker.catalog_digest() {
        println!("catalogue {digest} (derived from the signed bounds; not separately signed)");
    }
    println!();

    let mut denied = 0;
    for raw in destinations {
        // The same normalisation the proxy applies, so what you type here is decided the way an
        // agent's argument would be: scheme, path, credentials and port stripped.
        let host = host_of(raw);
        let verdict = broker.decide(host);
        if matches!(verdict, EgressVerdict::Deny { .. }) {
            denied += 1;
        }
        println!("{}", render_decision(host, &verdict));
    }

    println!("\nDecided by {BROKER_VERSION}.");
    println!("{ENFORCEMENT_NOTE}");
    if denied > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Refuses every effect, naming what is missing.
///
/// Used when no adapter can be constructed. Refusing rather than pretending is the whole point:
/// a settle that silently reported success would be the worst possible failure for a tool whose
/// claim is that you can trust what it tells you.
struct NoAdapter {
    reason: String,
}

impl EffectPerformer for NoAdapter {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        _resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        Err(format!(
            "{} was not performed: {}. The effect remains staged.",
            effect.tool, self.reason
        ))
    }
}

/// A real HTTPS transport for the GitHub API.
///
/// The token is read here, in the settling process. The agent never runs in this process, so it
/// cannot read the token out of memory, and by construction it never had it.
struct HttpsGitHub {
    token: String,
    agent: ureq::Agent,
}

impl warrantor_warrant::adapters::github::GitHubTransport for HttpsGitHub {
    fn post(&mut self, path: &str, body: &str) -> Result<String, String> {
        let response = self
            .agent
            .post(&format!("https://api.github.com{path}"))
            .set("authorization", &format!("Bearer {}", self.token))
            .set("accept", "application/vnd.github+json")
            .set("user-agent", "warrantor")
            .send_string(body);
        match response {
            Ok(ok) => ok.into_string().map_err(|e| format!("read response: {e}")),
            // Report the status, never the body: a GitHub error body can echo the request, and
            // the request may contain the developer's content.
            Err(ureq::Error::Status(code, _)) => Err(format!("GitHub returned HTTP {code}")),
            Err(other) => Err(format!("GitHub request failed: {other}")),
        }
    }
}

/// Build the performer for a settle: the real adapter when configured, an honest refusal otherwise.
fn build_performer() -> Box<dyn EffectPerformer> {
    let Ok(slug) = std::env::var("WARRANTOR_GITHUB_REPO") else {
        return Box::new(NoAdapter {
            reason: "set WARRANTOR_GITHUB_REPO=owner/repo to enable the GitHub adapter".to_string(),
        });
    };
    let Ok(token) = std::env::var("WARRANTOR_GITHUB_TOKEN") else {
        return Box::new(NoAdapter {
            reason: "set WARRANTOR_GITHUB_TOKEN to enable the GitHub adapter".to_string(),
        });
    };
    let Some((owner, repo)) = slug.split_once('/') else {
        return Box::new(NoAdapter {
            reason: format!("WARRANTOR_GITHUB_REPO={slug:?} must look like owner/repo"),
        });
    };
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        // A settle must not follow a redirect: the token would go to the redirect target.
        .redirects(0)
        .build();
    Box::new(warrantor_warrant::adapters::github::GitHubAdapter::new(
        HttpsGitHub { token, agent },
        owner,
        repo,
    ))
}

fn print_settle_report(report: &SettleReport) {
    for outcome in &report.effects {
        match outcome {
            EffectOutcome::Released { handle, real_id } => {
                println!("  released    {handle} -> {real_id}");
            }
            EffectOutcome::Failed { handle, reason } => {
                println!("  FAILED      {handle}: {reason}");
            }
            EffectOutcome::Unreleased { handle } => {
                println!("  unreleased  {handle}");
            }
        }
    }
    if let Some(boundary) = &report.boundary {
        println!("\n{boundary}");
    }
}

fn cmd_settle(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor settle <warrant-id> [--commit \"<message>\"]");
    };
    let mut stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let queue = match open_queue(store, id) {
        Ok(q) => q,
        Err(e) => return fail(&e),
    };
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), "settle") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };

    let tree = worktree_of(&stored, id);

    // `--commit` is opt-in and named in the refusal, because most agents edit without committing
    // and the merge would otherwise drop the work. Doing it silently would merge under a message
    // nobody chose; refusing without offering a way through leaves the documented path unfinishable.
    if let Some(message) = args.flags.get("commit") {
        let Some(tree) = tree.as_ref() else {
            return fail("--commit needs a worktree, and this warrant has none");
        };
        let message = if message.trim().is_empty() {
            format!("warrant {id}: {}", stored.warrant.claims.goal)
        } else {
            message.clone()
        };
        match tree.commit_all(&message, &stored.warrant.claims.bounds.write_paths) {
            Ok(0) => println!(
                "warrantor: nothing to commit inside the warrant's write paths. Anything the \
                 agent left elsewhere is still in the worktree, uncommitted, on purpose."
            ),
            Ok(n) => println!(
                "warrantor: committed {n} path(s), staged only from the write paths this warrant \
                 permitted. Artifacts the agent produced outside them are left in the worktree."
            ),
            Err(e) => return fail(&e.to_string()),
        }
    }
    let mut performer = build_performer();
    match settle(
        &mut stored.warrant,
        &queue,
        tree.as_ref(),
        &settle_key.verifying_key(),
        performer.as_mut(),
    ) {
        Ok(report) => {
            print_settle_report(&report);
            if let Err(e) = store.save(&stored) {
                return fail(&e.to_string());
            }
            println!("\nwarrant is now {:?}", stored.warrant.state);
            if report.complete {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// Reconstruct this warrant's worktree handle.
///
/// Delegates to [`warrantor_warrant::worktree::of_stored`], which is this function promoted into the
/// library so the HTTP API is not a fourth independent copy of the same nine lines. The `id`
/// argument is kept because the call sites read better with it, and it is now redundant: the stored
/// warrant carries its own id.
fn worktree_of(stored: &StoredWarrant, _id: &str) -> Option<Worktree> {
    warrantor_warrant::worktree::of_stored(stored)
}

fn cmd_void(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor void <warrant-id>");
    };
    let mut stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), "settle") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let tree = worktree_of(&stored, id);
    match void(
        &mut stored.warrant,
        tree.as_ref(),
        &settle_key.verifying_key(),
    ) {
        Ok(()) => {
            if let Err(e) = store.save(&stored) {
                return fail(&e.to_string());
            }
            println!("warrant {id} voided. Staged effects discarded; receipts retained.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_stage(args: &Args, store: &WarrantStore) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor stage <warrant-id> --tool T [--arg k=v ...]");
    };
    let Some(tool) = args.flags.get("tool") else {
        return fail("--tool is required");
    };
    let mut queue = match open_queue(store, id) {
        Ok(q) => q,
        Err(e) => return fail(&e),
    };
    let mut arguments = BTreeMap::new();
    if let Some(target) = args.flags.get("target") {
        arguments.insert("target".to_string(), target.clone());
    }
    for pair in args.positional.iter().skip(1) {
        if let Some((k, v)) = pair.split_once('=') {
            arguments.insert(k.to_string(), v.to_string());
        }
    }
    match queue.stage(tool, arguments, now()) {
        Ok(effect) => {
            println!("staged  {}", effect.handle);
            println!("(queued; performed only when the warrant settles)");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

// ── run / status / supervise ──────────────────────────────────────────────────────────

/// `warrantor run <id> -- <command...>` — start the agent under a detached supervisor.
///
/// The command you type exits immediately; the daemon it started keeps supervising. That is the
/// whole point of the split, and it is why this prints where the log went: a detached process has
/// nowhere else to say anything.
fn cmd_run(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor run <warrant-id> -- <command> [args...]");
    };
    if args.trailing.is_empty() {
        return fail("nothing to run: put the agent command after `--`");
    }
    let stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    if !matches!(stored.warrant.state, WarrantState::Open) {
        return fail(&format!(
            "{id} is {:?}, not Open. A warrant that has been settled or voided cannot be run \
             again -- grant a new one.",
            stored.warrant.state
        ));
    }
    if stored.warrant.claims.bounds.expires_at <= now() {
        return fail(&format!(
            "{id} expired at {}. Grant a new warrant rather than extending a dead one.",
            stored.warrant.claims.bounds.expires_at
        ));
    }

    // A third precondition of the same kind as the two above, and the one place the observed budget
    // has real teeth: an agent that reported spending its whole ceiling does not get started again
    // under the same warrant. This does not make the budget enforced -- an agent that never
    // reported is unaffected, which is exactly why the bound stays `Observed`. It makes an honest
    // report cost something, which it previously did not.
    //
    // Only when a ceiling was declared. A warrant that never had a budget was never
    // budget-exhausted, and refusing to start it here would be a different bound wearing this
    // one's name.
    //
    // A ledger store that will not open is the same unknown as a ledger that will not load, and it
    // is refused in the same breath -- skipping the check because the directory is unavailable
    // would start a run whose budget state nobody knows, which is the one outcome this precondition
    // exists to prevent.
    let ledgers = match SpendStore::open(root) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "cannot open the spend ledger store, so {id}'s budget state is unknown: {e}"
            ))
        }
    };
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), "issuer") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    match ledgers.load(
        &stored.warrant.claims.bounds,
        id,
        &stored.warrant.claims.subject,
        &issuer.verifying_key(),
    ) {
        Ok(ledger) if ledger.exhausted() => {
            return fail(&format!(
                "{id} has reported spending {} of its {} ceiling. Grant a new warrant with a new \
                 budget rather than restarting a spent one. (Self-reported: an agent that does not \
                 report is not caught by this.)",
                spend::usd(ledger.spent_micros),
                spend::usd(ledger.cap_micros)
            ));
        }
        Ok(_) => {}
        // An unreadable or wrongly-signed ledger is not a reason to start a run whose budget
        // state is unknown.
        Err(e) => {
            return fail(&format!(
                "cannot read {id}'s spend ledger, so its budget state is unknown: {e}"
            ))
        }
    }

    let state = match DaemonState::open(root) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    if let Some(existing) = state.get(id) {
        if process_is_alive(existing.pid) {
            return fail(&format!(
                "{id} is already supervised by pid {}. Two supervisors on one warrant would each \
                 enforce the deadline independently.",
                existing.pid
            ));
        }
    }

    let Ok(exe) = std::env::current_exe() else {
        return fail("cannot locate the warrantor executable to re-launch as a daemon");
    };
    let mut daemon_args = vec!["supervise".to_string(), id.clone(), "--".to_string()];
    daemon_args.extend(args.trailing.iter().cloned());

    let log = root.join("logs").join(format!("{id}.log"));
    match spawn_detached(&exe.to_string_lossy(), &daemon_args, &log) {
        Ok(pid) => {
            let linkage = describe_linkage();
            println!("warrantor: supervisor started as pid {pid}, detached from this terminal.");
            println!(
                "  lifetime link : {} — {}",
                linkage.mechanism, linkage.detail
            );
            println!("  log           : {}", log.display());
            println!("  check on it   : warrantor status");
            if !linkage.survives_supervisor_death {
                eprintln!(
                    "warrantor: WARNING -- on this platform the agent can outlive the supervisor. \
                     Do not leave this run unattended."
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// The daemon body. Not advertised in the usage text: `run` re-enters the binary here.
fn cmd_supervise(args: &Args, store: &WarrantStore, root: &Path) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor supervise <warrant-id> -- <command> [args...]");
    };
    let Some((program, rest)) = args.trailing.split_first() else {
        return fail("nothing to supervise: put the agent command after `--`");
    };
    let stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let state = match DaemonState::open(root) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };

    // The agent runs in its worktree when it has one, so an escape from the warrant's write paths
    // would have to be an absolute path rather than a relative slip.
    let cwd = stored.worktree.as_deref();

    match supervise_run(
        &state,
        &SuperviseRequest {
            warrant_id: id.clone(),
            expires_at: stored.warrant.claims.bounds.expires_at,
            program: program.clone(),
            args: rest.to_vec(),
            cwd: cwd.map(Path::to_path_buf),
            root: root.to_path_buf(),
            now: now(),
        },
    ) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => fail(&e),
    }
}

/// `warrantor status` — what is running, what stopped, and what needs a decision.
///
/// The command you run first thing in the morning. It reconciles as a side effect, which is
/// deliberate: the answer to "what happened overnight" and the cleanup of dead supervisors are the
/// same operation.
fn cmd_status(store: &WarrantStore, root: &Path) -> ExitCode {
    let state = match DaemonState::open(root) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let found = match state.reconcile(store, &process_is_alive) {
        Ok(f) => f,
        Err(e) => return fail(&e.to_string()),
    };

    let mut live = 0;
    // Two buckets, because a run that finished and a supervisor that died need different words.
    // Both want a decision; only one of them is bad news, and the morning review is unusable if
    // every completed overnight run is announced as a failure.
    let mut finished = Vec::new();
    let mut needs_decision = Vec::new();
    for (id, status) in &found {
        match status {
            Reconciliation::Supervised { pid } => {
                live += 1;
                println!("  running    {id}  (supervisor pid {pid})");
            }
            Reconciliation::Completed {
                detail, expired, ..
            } => {
                finished.push((id, detail, *expired));
            }
            Reconciliation::Interrupted { detail } => {
                needs_decision.push((id, detail));
            }
            Reconciliation::Finished => {}
        }
    }
    if live == 0 && finished.is_empty() && needs_decision.is_empty() {
        println!("warrantor: nothing open. `warrantor list` shows finished warrants.");
        return ExitCode::SUCCESS;
    }
    for (id, detail, expired) in &finished {
        println!(
            "  {}  {id}",
            if *expired { "deadline " } else { "finished " }
        );
        println!("             {detail}");
    }
    for (id, detail) in &needs_decision {
        println!("  attention  {id}");
        println!("             {detail}");
    }
    ExitCode::SUCCESS
}

// ── mcp ───────────────────────────────────────────────────────────────────────────────

/// `warrantor mcp [--agent <id>] [--observe]` — serve MCP over stdio.
///
/// Two endpoints, and which one you get is decided here rather than by a runtime permission check.
/// Without `--agent` you get the control endpoint, which holds the settle key and belongs in the
/// agent *you* drive. With `--agent <id>` you get the supervised endpoint, which publishes only the
/// warrant's own tools and has no lifecycle tool to call.
///
/// Registering the control endpoint inside a supervised agent would hand it settle authority. The
/// flag split makes that a deliberate act rather than a default.
fn cmd_mcp(args: &Args, store: WarrantStore, root: &Path) -> ExitCode {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    if let Some(id) = args.flags.get("agent") {
        let stored = match store.load(id) {
            Ok(s) => s,
            Err(e) => return fail(&e.to_string()),
        };
        let mode = if args.flags.contains_key("observe") {
            ProxyMode::Observe
        } else {
            ProxyMode::Enforce
        };
        let mut endpoint = match agent_endpoint_for(&stored, store.staged_path(id), mode, now) {
            Ok(e) => e,
            Err(e) => return fail(&e.to_string()),
        };
        // stderr, not stdout: stdout is the JSON-RPC channel and a stray line there desynchronises
        // every client reading it line by line.
        eprintln!(
            "warrantor: MCP agent endpoint for {id} ({}). Lifecycle tools are not published on \
             this endpoint.",
            if mode == ProxyMode::Observe {
                "observe -- recording, not enforcing"
            } else {
                "enforce"
            }
        );
        return match serve(&mut endpoint, stdin.lock(), &mut stdout) {
            Ok(_) => {
                // Write the session's refusals down before printing them. Until this line they
                // existed only in this process's memory for the lifetime of one session, which is
                // why `warrantor serve` could not answer "what was refused" by calling an existing
                // function: the types were there and the data was not.
                match http::record_refusals(
                    root,
                    id,
                    &endpoint.authority_requests(),
                    &endpoint.egress_refusals(),
                    now(),
                ) {
                    Ok(0) => {}
                    Ok(count) => eprintln!(
                        "warrantor: recorded {count} refusal group(s) for {id}. Review them across \
                         runs with `warrantor serve` at /v1/summary/refusals."
                    ),
                    // The run is over and its refusals are still printed below. Losing the durable
                    // copy costs a tuning signal, not a guarantee, so it is reported rather than
                    // turned into a failing exit code.
                    Err(e) => eprintln!(
                        "warrantor: the session's refusals could not be written down ({e}). They \
                         are printed below and nowhere else."
                    ),
                }
                for request in endpoint.authority_requests() {
                    eprintln!(
                        "warrantor: denied {} x{} ({})",
                        request.tool, request.count, request.bound
                    );
                }
                // The destination is the part a developer acts on, and the line above cannot carry
                // it: `egress_hosts x12` does not say whether one wall was hit twelve times or
                // twelve were hit once.
                for refusal in endpoint.egress_refusals() {
                    eprintln!(
                        "warrantor: egress denied {} x{} ({}, named in {:?} by {})",
                        refusal.destination,
                        refusal.count,
                        warrantor_warrant::egress::reason_word(refusal.reason.clone()),
                        refusal.argument,
                        refusal.tool
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(&format!("mcp: {e}")),
        };
    }

    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), "issuer") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), "settle") {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let mut endpoint = ControlEndpoint::new(store, root.to_path_buf(), issuer, settle_key, now);
    eprintln!(
        "warrantor: MCP control endpoint. This holds the settle key -- register it only in an \
         agent you are driving, never in one running under a warrant."
    );
    match serve(&mut endpoint, stdin.lock(), &mut stdout) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("mcp: {e}")),
    }
}

// ── serve ─────────────────────────────────────────────────────────────────────────────

/// `warrantor serve [--bind ADDR] [--port N] [--token-file PATH] [--allow-settle]` — the store over
/// HTTP.
///
/// Loopback by default. A non-loopback bind is an explicit `--bind`, and it prints a warning naming
/// exactly what became reachable — including that there is no TLS, so the bearer token controls
/// access and not confidentiality.
///
/// Keys are **loaded, never created**: the CLI's `load_or_create_key` mints one on first use with
/// default permissions, which would give a fresh box an issuer identity nobody chose and start
/// signing evidence with it.
///
/// The token file is removed on the way out. A file left behind naming a token that no longer opens
/// anything is not harmless: the next reader has no way to tell it apart from a live one, and the
/// obvious conclusion — that the token in the file is the token the server wants — is wrong.
fn cmd_serve(args: &Args, store: WarrantStore, root: &Path) -> ExitCode {
    let addr = match resolve_bind(args) {
        Ok(addr) => addr,
        Err(e) => return fail(&e),
    };
    let token_file = match resolve_token_file(args) {
        Ok(path) => path,
        Err(e) => return fail(&e),
    };

    let issuer = match http::load_key(&root.join("keys/issuer.key"), "issuer") {
        Ok(k) => k,
        Err(e) => return fail(&e.to_string()),
    };
    // Release authority is OPT-IN. This was the other way round, and the other way round is
    // unsafe on this product's own terms.
    //
    // The token lives on a filesystem the supervised agent can read, and there are no read bounds
    // in this system at all — `read_paths` does not exist; bounds cover tools, egress and
    // write_paths, and write_paths is Observed. Owner-only permissions exclude other *users*; the
    // agent runs as the same user. So an agent can read the token and call settle on its own
    // warrant, and the one load-bearing property of the whole product — that an agent cannot
    // settle its own warrant, which has a test by that name — would be false whenever a server
    // was running.
    //
    // Under a same-UID model this is not fully fixable: an agent that can read a file can usually
    // also ptrace the process holding the secret. What IS fixable is the consequence. Default to a
    // server that has no settle key to steal, so the same file read yields a viewer rather than a
    // release button, and make arming it a thing the operator typed.
    //
    // Which is also just the rule this product already applies everywhere else: an absent limit
    // means none, never unlimited.
    let settle_key = if args.flags.contains_key("allow-settle") {
        match http::load_key(&root.join("keys/settle.key"), "settle") {
            Ok(k) => Some(k),
            Err(e) => return fail(&e.to_string()),
        }
    } else {
        None
    };
    let release_authority = settle_key.is_some();

    let token = match http::SessionToken::mint() {
        Ok(t) => t,
        Err(e) => return fail(&e.to_string()),
    };
    // Written before the socket is bound. If the secret cannot be put somewhere the operator can
    // read it, there is no point opening a port that only refuses.
    let token_path = match &token_file {
        None => match token.write_to(root) {
            Ok(path) => path,
            Err(e) => return fail(&e.to_string()),
        },
        Some(path) => match token.write_to_file(path) {
            Ok(()) => path.clone(),
            Err(e) => return fail(&e.to_string()),
        },
    };

    // Ctrl-C is installed before the listener, so the window in which an impatient operator gets a
    // hard kill instead of a drain is as small as it can be.
    let shutdown = http::Shutdown::new();
    let interruptible = http::install_interrupt_handler();

    println!("warrantor: serving {} on http://{addr}", root.display());
    println!("  token         {}", token.as_str());
    println!("  token file    {}", token_path.display());
    if cfg!(unix) {
        println!(
            "                (mode 0600{})",
            if token_file.is_some() {
                ", in a directory you named -- its permissions are yours"
            } else {
                ", in a 0700 directory"
            }
        );
    } else {
        println!(
            "                (this platform has no owner-only file mode in std: the file is \
             protected by inherited directory ACLs only)"
        );
    }
    println!(
        "  authority     {}",
        if release_authority {
            "settle, void and stop are reachable. A token holder can release staged effects."
        } else {
            "read and stop only -- settle and void refuse. Pass --allow-settle to arm them."
        }
    );
    println!(
        "  try           curl -H \"authorization: Bearer {}\" http://{addr}/v1/health",
        token.as_str()
    );
    if interruptible {
        println!(
            "  stop          Ctrl-C. In-flight requests finish, then the token file is removed."
        );
    } else {
        // The honest version of "press Ctrl-C to stop". On a platform with no handler this module
        // knows, Ctrl-C kills the process where it stands -- possibly mid-settle -- and leaves the
        // token file behind.
        println!(
            "  stop          Ctrl-C, but this platform has no interrupt handler here: it ends the \
             process where it stands, and {} is left behind.",
            token_path.display()
        );
    }
    if let Some(warning) = http::bind_warning(addr, root, release_authority) {
        eprintln!("{warning}");
    }

    let api = http::StoreApi::new(
        store,
        root.to_path_buf(),
        issuer,
        settle_key,
        build_performer,
        now,
    );
    let outcome = http::listen(api, token, addr, &shutdown);
    // Removed whether the drain completed or not, and whether or not the loop ended in an error:
    // the token is a per-session secret and this session is over either way.
    let removed = std::fs::remove_file(&token_path);
    match outcome {
        Ok(drain) => {
            println!();
            match drain {
                http::Drain::Complete => println!("warrantor: stopped. Nothing was cut off."),
                http::Drain::Incomplete(outstanding) => println!(
                    "warrantor: stopped with {outstanding} request(s) still running after the \
                     drain window. Anything they were part-way through -- a settle, a stop -- may \
                     be half done. Read the store before you trust it."
                ),
            }
            if let Err(e) = removed {
                eprintln!(
                    "warrantor: WARNING -- could not remove {}: {e}. The token in it is dead; \
                     delete it so nobody reads it as live.",
                    token_path.display()
                );
            } else {
                println!("           {} removed.", token_path.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// Work out where the session token is written, honouring `--token-file`.
///
/// `None` means the default under the store root. A `--token-file` with no value is a refusal
/// rather than a fallback to the default: an operator who typed the flag was moving a secret, and
/// quietly writing it to the place they were moving it away from is the wrong recovery.
fn resolve_token_file(args: &Args) -> Result<Option<PathBuf>, String> {
    match args.flags.get("token-file") {
        None => Ok(None),
        Some(raw) if raw == "true" => Err(
            "--token-file needs a path, e.g. --token-file /run/user/1000/warrantor-token"
                .to_string(),
        ),
        Some(raw) if raw.trim().is_empty() => {
            Err("--token-file was given an empty path".to_string())
        }
        Some(raw) => Ok(Some(PathBuf::from(raw))),
    }
}

/// Work out what to bind, defaulting to loopback and refusing anything unparseable.
///
/// An address that does not parse is a refusal rather than a fallback to the default: silently
/// binding loopback when the operator asked for something else would be the friendlier failure and
/// the wrong one, and silently binding something else when they meant loopback would be worse.
fn resolve_bind(args: &Args) -> Result<std::net::SocketAddr, String> {
    let port = match args.flags.get("port") {
        None => http::DEFAULT_PORT,
        Some(raw) => raw
            .parse::<u16>()
            .map_err(|_| format!("--port must be a whole number; {raw:?} does not parse"))?,
    };
    let Some(raw) = args.flags.get("bind") else {
        return Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    };
    if raw == "true" {
        return Err("--bind needs an address, e.g. --bind 127.0.0.1:8787".to_string());
    }
    if let Ok(addr) = raw.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    match raw.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(std::net::SocketAddr::new(ip, port)),
        Err(_) => Err(format!(
            "--bind must be an address like 127.0.0.1 or 0.0.0.0:8787; {raw:?} is neither. No \
             hostname is resolved here: binding whatever a name happens to point at today is not a \
             decision this should make for you."
        )),
    }
}

fn main() -> ExitCode {
    let Some(args) = parse_args() else {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    };
    let root = match WarrantStore::default_root() {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    let store = match WarrantStore::open(&root) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };

    match args.command.as_str() {
        "grant" => cmd_grant(&args, &store, &root),
        "list" => cmd_list(&store),
        "report" => cmd_report(&args, &store, &root),
        "verify" => cmd_verify(&args),
        "egress" => cmd_egress(&args, &store, &root),
        "spend" => cmd_spend(&args, &store, &root),
        "stop" => cmd_stop(&args, &store, &root),
        "settle" => cmd_settle(&args, &store, &root),
        "void" => cmd_void(&args, &store, &root),
        "stage" => cmd_stage(&args, &store),
        "run" => cmd_run(&args, &store, &root),
        "supervise" => cmd_supervise(&args, &store, &root),
        "status" => cmd_status(&store, &root),
        "mcp" => cmd_mcp(&args, store, &root),
        "serve" => cmd_serve(&args, store, &root),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => fail(&format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

/// Unused import guard: `WarrantState` is referenced in report output formatting.
#[allow(dead_code)]
fn _state_is_used(state: WarrantState) -> String {
    format!("{state:?}")
}

/// Same, for the key type used only through `load_or_create_key`.
#[allow(dead_code)]
fn _key_is_used(key: &VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

/// The `serve` verb's own argument grammar.
///
/// These are here rather than in `tests/serve.rs` because they are about the *command line*, and a
/// binary's command line is not reachable from an integration test without spawning a process. The
/// rules under test are the ones where a friendly fallback would be the dangerous answer: an
/// address that does not parse must not become loopback, and a flag that was typed but left empty
/// must not become its default.
#[cfg(test)]
mod serve_cli {
    use super::{parse_tokens, resolve_bind, resolve_token_file};

    fn args(tokens: &[&str]) -> super::Args {
        parse_tokens(
            std::iter::once("serve".to_string())
                .chain(tokens.iter().map(|t| (*t).to_string()))
                .collect::<Vec<_>>(),
        )
        .expect("a command")
    }

    #[test]
    fn serve_binds_loopback_on_a_named_default_port_when_told_nothing() {
        let addr = resolve_bind(&args(&[])).expect("default");
        assert!(addr.ip().is_loopback(), "the default must never be public");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), warrantor_warrant::serve::DEFAULT_PORT);
        // And nothing was written anywhere the operator did not ask for.
        assert_eq!(resolve_token_file(&args(&[])).expect("default"), None);
    }

    #[test]
    fn a_port_moves_the_default_and_an_address_may_carry_its_own() {
        let addr = resolve_bind(&args(&["--port", "9191"])).expect("port");
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 9191);

        // A bare address takes the port from --port, in either order.
        let addr = resolve_bind(&args(&["--bind", "0.0.0.0", "--port", "9191"])).expect("bind");
        assert_eq!(addr.to_string(), "0.0.0.0:9191");
        // An address that carries its own port keeps it.
        let addr = resolve_bind(&args(&["--bind", "192.168.1.9:7000"])).expect("bind");
        assert_eq!(addr.to_string(), "192.168.1.9:7000");
        // v6 too, since the bracket form is the one people get wrong.
        let addr = resolve_bind(&args(&["--bind", "[::1]:7000"])).expect("bind");
        assert!(addr.ip().is_loopback());
    }

    /// The dangerous fallbacks, refused one at a time.
    #[test]
    fn an_address_that_does_not_parse_is_refused_rather_than_quietly_looped_back() {
        for tokens in [
            vec!["--bind", "localhost"], // a name: this resolves nothing on purpose
            vec!["--bind", "not-an-address"],
            vec!["--bind", "999.999.999.999"],
            vec!["--bind"], // typed, with nothing after it
        ] {
            let refusal = resolve_bind(&args(&tokens)).expect_err(&format!("{tokens:?}"));
            assert!(
                refusal.contains("--bind"),
                "the refusal must name the flag: {refusal}"
            );
        }
        // A hostname is refused with a reason, not just a shrug: binding whatever a name points at
        // today is a decision about exposure.
        let refusal = resolve_bind(&args(&["--bind", "localhost"])).expect_err("refusal");
        assert!(refusal.contains("No \nhostname") || refusal.contains("hostname"));
    }

    #[test]
    fn a_port_that_is_not_a_port_is_refused() {
        for value in ["eight-thousand", "-1", "70000", "8787.0"] {
            let refusal = resolve_bind(&args(&["--port", value])).expect_err(value);
            assert!(refusal.contains("--port"), "{refusal}");
        }
    }

    #[test]
    fn a_token_file_is_taken_verbatim_and_an_empty_one_is_refused() {
        let path = resolve_token_file(&args(&["--token-file", "/run/user/1000/wt"]))
            .expect("path")
            .expect("some");
        assert_eq!(path, std::path::PathBuf::from("/run/user/1000/wt"));

        // `--token-file=` and a bare `--token-file` are both a typed flag with no path. Falling
        // back to the default would write the secret to the place the operator was moving it from.
        for tokens in [vec!["--token-file"], vec!["--token-file="]] {
            let refusal = resolve_token_file(&args(&tokens)).expect_err(&format!("{tokens:?}"));
            assert!(refusal.contains("--token-file"), "{refusal}");
        }
    }

    /// `--allow-settle` is a bare flag, and the parser has to see it as present-with-no-value rather
    /// than swallowing whatever came next.
    #[test]
    fn allow_settle_is_a_bare_flag_and_does_not_eat_the_next_one() {
        let parsed = args(&["--allow-settle", "--port", "9000"]);
        assert_eq!(
            parsed.flags.get("allow-settle").map(String::as_str),
            Some("true")
        );
        assert_eq!(resolve_bind(&parsed).expect("bind").port(), 9000);
    }

    /// The usage text is the only place most people will read the grammar, so it has to carry every
    /// flag this verb answers to.
    #[test]
    fn the_usage_text_names_every_serve_flag() {
        for flag in ["--bind", "--port", "--token-file", "--allow-settle"] {
            assert!(super::USAGE.contains(flag), "usage does not mention {flag}");
        }
        assert!(
            super::USAGE.contains("127.0.0.1"),
            "usage must say what it binds by default"
        );
        assert!(
            super::USAGE.contains("Ctrl-C"),
            "usage must say how it stops"
        );
    }
}

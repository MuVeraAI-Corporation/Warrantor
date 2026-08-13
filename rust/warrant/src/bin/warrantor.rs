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
    let mut raw = std::env::args().skip(1);
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
through the Warrantor MCP proxy, which is the only place egress is decided.

Mcp serves the warrant lifecycle to your own coding agent over MCP. With --agent it
instead serves a SUPERVISED agent: only that warrant's tools, policed, with no
lifecycle tool published -- so the agent has no route to settling its own work.

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
    if let Err(e) = report::verify_export(&signed) {
        return fail(&format!("{path} does NOT verify: {e}"));
    }

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
/// It exits non-zero if any destination is refused, so it can be used as a check in a script. It
/// needs no key: asking what a warrant permits is a read.
fn cmd_egress(args: &Args, store: &WarrantStore) -> ExitCode {
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

fn worktree_of(stored: &StoredWarrant, id: &str) -> Option<Worktree> {
    match (&stored.repo, &stored.worktree) {
        (Some(repo), Some(path)) => Some(Worktree::existing(
            repo.clone(),
            path.clone(),
            stored
                .branch
                .clone()
                .unwrap_or_else(|| format!("{}{}", warrantor_warrant::worktree::BRANCH_PREFIX, id)),
            stored.base_commit.clone().unwrap_or_default(),
        )),
        _ => None,
    }
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
    if let Ok(ledgers) = SpendStore::open(root) {
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
                    "{id} has reported spending {} of its {} ceiling. Grant a new warrant with a \
                     new budget rather than restarting a spent one. (Self-reported: an agent that \
                     does not report is not caught by this.)",
                    spend::usd(ledger.spent_micros),
                    spend::usd(ledger.cap_micros)
                ));
            }
            Ok(_) => {}
            // An unreadable or wrongly-signed ledger is not a reason to start a run whose budget
            // state is unknown.
            Err(e) => {
                return fail(&format!(
                    "cannot read {id}'s spend ledger, so its budget state \
                                            is unknown: {e}"
                ))
            }
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
        "egress" => cmd_egress(&args, &store),
        "spend" => cmd_spend(&args, &store, &root),
        "stop" => cmd_stop(&args, &store, &root),
        "settle" => cmd_settle(&args, &store, &root),
        "void" => cmd_void(&args, &store, &root),
        "stage" => cmd_stage(&args, &store),
        "run" => cmd_run(&args, &store, &root),
        "supervise" => cmd_supervise(&args, &store, &root),
        "status" => cmd_status(&store, &root),
        "mcp" => cmd_mcp(&args, store, &root),
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

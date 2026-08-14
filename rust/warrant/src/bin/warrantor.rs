//! `warrantor` — grant a warrant, run an agent under it, then settle or void.
//!
//! # Key handling
//!
//! Three keys live under `~/.warrantor/keys/`:
//!
//! * `issuer.key` signs warrants and capability tokens.
//! * `settle.key` authorises settling, voiding and renewal.
//! * `device.key` signs requests to an evidence archive this machine is paired with.
//!
//! The first two are separate because the agent must not be able to settle its own warrant. In this
//! CLI both are on the developer's machine, which is correct — the developer *is* the settle
//! authority. What matters is that the settle key is never loaded into the process the agent runs
//! in. When the daemon lands it will hold the issuer key and supervise agents; the settle key
//! stays here, in the command the human types.
//!
//! `device.key` is different in kind: it is a credential rather than an authority, minted only by
//! `warrantor archive enrol` and meaningless until an archive has enrolled its public half. It is
//! never created on demand, it is minted fresh on every enrolment, and the pairing record beside it
//! (`~/.warrantor/archive.json`) records which public key it must be — because one device key must
//! name exactly one device id for revocation at the archive to mean anything.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ed25519_dalek::{SigningKey, VerifyingKey};
use warrantor_warrant::archive_client::{self, ArchiveAnswer, ArchiveConfig, ArchiveTransport};
use warrantor_warrant::daemon::{
    process_is_alive, supervise_run, DaemonState, Reconciliation, SuperviseRequest,
};
use warrantor_warrant::egress::{
    render_decision, EgressBroker, EgressVerdict, BROKER_VERSION, ENFORCEMENT_NOTE,
};
use warrantor_warrant::guard;
use warrantor_warrant::mcp::serve;
use warrantor_warrant::mcp_endpoints::{agent_endpoint_for, ControlEndpoint};
use warrantor_warrant::proxy::{host_of, ProxyMode};
use warrantor_warrant::report;
use warrantor_warrant::serve as http;
use warrantor_warrant::settle::{settle, void, EffectOutcome, EffectPerformer, SettleReport};
use warrantor_warrant::spend::{self, SpendStore, SpendVerdict};
use warrantor_warrant::staging::{EffectRegistry, StagedChainMark, StagedEffect, StagingQueue};
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

/// The keys this machine holds, and what each one actually authorises.
///
/// An enum rather than a `&str` label, because the sentence printed when a key is created must name
/// the authority *that* key carries. It used to be one hardcoded line about the settle key printed
/// for every kind, so creating an issuer key warned the operator about releasing staged effects —
/// an authority the issuer key does not have — and a device key would have warned about the same
/// thing again. A warning about the wrong power is worse than none: it teaches the reader that the
/// warnings are boilerplate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    /// Signs warrants and capability tokens.
    Issuer,
    /// Authorises settling, voiding and renewal.
    Settle,
    /// Signs requests to an evidence archive this machine is paired with.
    Device,
}

impl KeyKind {
    fn label(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Settle => "settle",
            Self::Device => "archive device",
        }
    }

    /// What somebody who steals this file can do with it. One sentence per key, and each one names
    /// only what that key can actually do.
    fn protect(self) -> &'static str {
        match self {
            Self::Issuer => {
                "anyone holding the issuer key can mint warrants and sign evidence that this \
                 machine's own verification will accept as its own"
            }
            Self::Settle => "anyone holding the settle key can release staged effects",
            Self::Device => {
                "anyone holding the device key can file evidence to your archive under this \
                 device's name, and read anything it holds"
            }
        }
    }
}

/// Load a key, creating it on first use.
///
/// Generating on demand keeps the first run to one command. The tradeoff is stated in the message
/// rather than hidden: a key that appears without ceremony is easy to forget you must protect.
fn load_or_create_key(path: &Path, kind: KeyKind) -> Result<SigningKey, String> {
    if let Some(key) = load_key(path, kind)? {
        return Ok(key);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create key dir: {e}"))?;
    }
    let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let key = SigningKey::generate(&mut csprng);
    std::fs::write(path, key.to_bytes()).map_err(|e| format!("write {} key: {e}", kind.label()))?;
    eprintln!(
        "warrantor: created a new {} key at {}. Protect it: {}.",
        kind.label(),
        path.display(),
        kind.protect()
    );
    Ok(key)
}

/// Write a freshly minted device key, replacing whatever was there.
///
/// Separate from [`load_or_create_key`] because a device key is not created on first *use* — it is
/// created on enrolment, and enrolment is the only caller. The write goes through a temporary file
/// and a rename so a key file is never half a key: a truncated device key is 32 bytes of nothing
/// that would be read back as a valid signing key and refused by the archive as a stranger.
fn write_device_key(path: &Path, key: &SigningKey) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create key dir: {e}"))?;
    }
    let temporary = path.with_extension("key.tmp");
    std::fs::write(&temporary, key.to_bytes())
        .map_err(|e| format!("write {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("write {}: {e}", path.display()))?;
    eprintln!(
        "warrantor: wrote a new {} key at {}. Protect it: {}.",
        KeyKind::Device.label(),
        path.display(),
        KeyKind::Device.protect()
    );
    Ok(())
}

/// Load a key that must already exist, reporting its absence as absence.
///
/// Separate from [`load_or_create_key`] because creation is not always the right answer. A device
/// key is only a credential once an archive has enrolled its public half; minting one on demand
/// would produce a file that looks like a key, signs perfectly well, and is refused by every
/// archive on earth — and the operator would be reading a message about signatures when their
/// problem is that they never paired.
fn load_key(path: &Path, kind: KeyKind) -> Result<Option<SigningKey>, String> {
    match std::fs::read(path) {
        Ok(body) => {
            let bytes: [u8; 32] = body.as_slice().try_into().map_err(|_| {
                format!("{} key at {} is not 32 bytes", kind.label(), path.display())
            })?;
            Ok(Some(SigningKey::from_bytes(&bytes)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "read the {} key at {}: {e}",
            kind.label(),
            path.display()
        )),
    }
}

/// Parse a 64-character hex Ed25519 verifying key — the anchor a reader pins with `--issuer`.
///
/// Refuses rather than truncating or padding. A key the caller half-typed is not a key that should
/// produce a verdict about somebody's evidence, and a lenient parser here would turn a typo into a
/// confident "does NOT verify" against the wrong anchor.
fn parse_verifying_key(text: &str) -> Result<VerifyingKey, String> {
    let raw = hex::decode(text.trim()).map_err(|_| {
        format!("{text:?} is not hex. An issuer key is 64 hex characters (32 bytes).")
    })?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        format!(
            "that key is {} bytes; an Ed25519 verifying key is 32 (64 hex characters).",
            raw.len()
        )
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| format!("that is not a valid Ed25519 verifying key: {e}"))
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
  report  <warrant-id> [--export <path> [--archive [<url>]]]
  verify  <exported-report.json | exported-stop.json | exported-spend.json>
  archive enrol --url <url> --code <code> [--replace] | push <file>
                | fetch <sha256> --out <path>
  egress  <warrant-id> <destination> [<destination> ...]
  spend   <warrant-id> [--input N --output N [--backend ID] [--quote]] [--export <path>]
  stop    <warrant-id> [--reason \"...\"] [--export <path>]
  settle  <warrant-id> [--commit \"<message>\"]
  void    <warrant-id>
  stage   <warrant-id> --tool T [--target H] [--arg k=v ...]
  run     <warrant-id> -- <command> [args...]
  status
  mcp     [--agent <warrant-id>] [--observe] [--guard [--guard-model M] ...]
  serve   [--bind <addr>] [--port <n>] [--token-file <path>] [--allow-settle]
  console [--bind <addr>] [--port <n>] [--token-file <path>] [--allow-settle]

Report --export writes a signed, self-contained evidence bundle. Verify checks one
offline, on any machine, with no access to this one: it proves nothing changed since
signing, and says plainly what it does not prove. It reads stop records and spend
ledgers too, dispatching on the format the file declares.

Archive files evidence with a self-hosted evidence archive, and reads it back. Enrol
pairs this machine against a one-time code an operator mints on the archive host and
writes ~/.warrantor/keys/device.key plus a pairing record; every later request is
signed with that key, so the archive records WHO filed an artifact rather than that
someone with a token did. Enrol mints a FRESH keypair and REFUSES to run over an
existing pairing without --replace: one key must name one device id, because revoking
the id you can name withdraws nothing if a second id shares its key. Push sends a
file's bytes VERBATIM -- the digest the archive returns must equal the SHA-256 of the
bytes sent, or the push is refused rather than reported. --archive on report/stop/spend
files the file --export just wrote, through the same path, and exits non-zero if it
fails.

A filing is CUSTODY, NOT A VERDICT. The archive holds bytes it did not produce and
cannot forge; it stores artifacts whose signatures do not check out and marks them,
because refusing to hold a tampered file would destroy the evidence that it arrived.
Nothing here prints \"verified\": check evidence where evidence is always checked, with
warrantor verify <file> --issuer <hex>, against a key you got out of band.

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

--guard attaches a local guard model to a supervised MCP session. It is OBSERVE-ONLY
unless you also pass --guard-enforce-untested-do-not-use: it records what a classifier
thought about each call the warrant permitted and blocks nothing, because measured
adversarial recall is 0.8152 and the adversarial false-positive rate is 0.0923. A call
a bound refused is never classified -- it did not happen, so no signal claims it did.
The endpoint must be loopback -- the guard is sent the agent's tool arguments -- and a
model whose digest the backend cannot report does not attach at all, because a signal
with no provenance is not evidence. Knobs: --guard-endpoint, --guard-model, --guard-seed,
--guard-num-ctx, --guard-timeout, --guard-max-calls. Signals land in <root>/guard/ and
read back beside the refusals at /v1/warrants/<id>/refusals. An absent or failed guard
writes nothing, and that is reported as no coverage rather than as a clean run.

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

Console is serve, plus it opens the browser for you. It is the same server with
the same flags and the same refusals; what it removes is the two steps nobody
outside engineering will perform, which are starting a daemon and pasting a hex
token. The token reaches the browser through a redirect page in the same
owner-only directory as the token file, never through a command line, because an
argv is readable by other users on a default Linux and the browser would hold it
for as long as it ran. Read-only by default, like serve: pass --allow-settle to
arm the release buttons.

Run starts the agent under a supervisor detached from this terminal: closing the
terminal ends your view of the run, not the run. Status says what is still going
and what stopped and needs a decision.

Grant creates a git worktree and points the agent at it. External effects are
staged, not performed, and settle stages only in-bounds paths, so out-of-bounds
edits are never merged into your working copy.

That is containment AT SETTLE, not at write. Nothing stops the agent writing
outside the worktree while it runs: write_paths is Observed, and the one place a
bound is refused at the moment of action is the MCP proxy, which sees only what
the agent routes through it. In the first live dogfood an agent granted
--write 'src/**' wrote tests/__pycache__/ and nothing refused it. Every warrant
reports which of its bounds are Enforced, Mediated and Observed -- read that, and
compose with a sandbox if you need writes stopped as they happen.";

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

    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), KeyKind::Issuer) {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), KeyKind::Settle) {
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
        // Witnessed from the moment the warrant exists rather than from its first staged effect,
        // so there is no window in which a deleted staged log still reads back as an empty queue.
        staged_chain: Some(StagedChainMark::genesis(now())),
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

/// Open a warrant's queue through the store, so it is checked against the chain the store
/// witnessed rather than replayed from whatever is on disk.
fn open_queue(store: &WarrantStore, id: &str) -> Result<StagingQueue, String> {
    store
        .open_queue(id, EffectRegistry::github())
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
    // An unreadable queue is reported, not hidden behind an early exit. This used to `return
    // fail(...)`, which printed one line and stopped -- so the fail-closed machinery the rest of
    // this file relies on (`Unavailable` -> `queue_available: false` -> `policy_decision: false`
    // -> the notary denies) was reachable from `serve` and MCP but never from the CLI, and the
    // operator most likely to notice a missing staged log got the least evidence of it. Now the
    // report is built, printed, signed and exported with the queue marked unreadable, and the
    // command still exits non-zero at the end.
    let queue = open_queue(store, id);
    let queue_input: Result<&StagingQueue, String> = queue.as_ref().map_err(Clone::clone);
    // `KeyKind::Issuer` rather than the "issuer" string this branch was written against: #archive
    // replaced the stringly-typed argument while this was in flight, so that a device key and an
    // issuer key cannot be requested by two spellings of the same word.
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), KeyKind::Issuer) {
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
        queue_input,
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
        if let Err(e) = push_export(args, root, path) {
            return fail(&e);
        }
    } else if args.flags.contains_key("archive") {
        return fail(
            "--archive files the file --export writes, so it needs one: warrantor report <id> \
             --export report.json --archive",
        );
    }
    // Everything above is printed and signed either way; what changes here is whether the command
    // claims to have described the run. It did not: the staged effects are the part a settle would
    // act on, and a report that could not read them is an incomplete answer, not a passing one.
    if let Err(reason) = &queue {
        eprintln!("warrantor: {reason}");
        eprintln!(
            "warrantor: the report above is signed and records the queue as unreadable. It does \
             NOT describe what this warrant staged."
        );
        return ExitCode::FAILURE;
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
///
/// `--issuer <hex>` pins the key that must have signed it. **Without it this command checks
/// self-consistency only**, which is a weaker statement than most readers hear: every receipt
/// carries its own public key, so a file fabricated and signed end to end by anyone at all is
/// internally consistent and passes. That matters the moment a file arrives from somewhere — an
/// evidence archive, an email, a shared drive — rather than off the disk that produced it. The flag
/// is not defaulted from the local store: verifying somebody else's evidence against your own issuer
/// key would produce a verdict from a key with nothing to do with the case.
fn cmd_verify(args: &Args) -> ExitCode {
    let Some(path) = args.positional.first() else {
        return fail(
            "usage: warrantor verify <exported-report.json | exported-stop.json> [--issuer <hex>]",
        );
    };
    // Parsed BEFORE the file is read, so a mistyped key is a refusal about the key rather than a
    // verdict about the evidence.
    let anchor = match args.flags.get("issuer") {
        None => None,
        Some(text) if text == "true" => {
            return fail(
                "--issuer needs the issuer's 64-character hex verifying key: warrantor verify \
                 <file> --issuer <hex>",
            )
        }
        Some(text) => match parse_verifying_key(text) {
            Ok(key) => Some(key),
            Err(e) => return fail(&e),
        },
    };
    let body = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return fail(&format!("read {path}: {e}")),
    };
    let declared: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return fail(&format!("{path} is not a warrantor evidence file: {e}")),
    };
    let anchor = anchor.as_ref();
    match declared.get("format").and_then(serde_json::Value::as_str) {
        Some(f) if f == report::REPORT_EXPORT_FORMAT => verify_report_export(path, &body, anchor),
        Some(f) if f == stop::STOP_EXPORT_FORMAT => verify_stop_export(path, &body, anchor),
        Some(f) if f == spend::LEDGER_EXPORT_FORMAT => verify_spend_export(path, &body, anchor),
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

fn verify_report_export(path: &str, body: &[u8], anchor: Option<&VerifyingKey>) -> ExitCode {
    let signed: report::SignedReport = match serde_json::from_slice(body) {
        Ok(s) => s,
        Err(e) => return fail(&format!("{path} is not an exported warrantor report: {e}")),
    };
    // Integrity is checked with the time-free verifier on purpose. An exported report is a record
    // of a past evaluation; it must not become unverifiable because a deadline went by, or an
    // archive would rot into a pile of files that all say "does NOT verify".
    //
    // With an anchor it is the anchored form, which is `verify_export` plus a key comparison — one
    // verifier with a stricter question, not a second verifier.
    let checked = match anchor {
        Some(key) => report::verify_export_signed_by(&signed, key),
        None => report::verify_export(&signed),
    };
    if let Err(e) = checked {
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
    println!("  anchor        {}", anchor_line(anchor));

    println!("\n── WHAT THIS DOES NOT ESTABLISH ──");
    for limitation in &signed.bundle.limitations {
        println!("  - {limitation}");
    }
    if anchor.is_none() {
        println!("  - {NO_ANCHOR_LIMITATION}");
    }
    ExitCode::SUCCESS
}

/// The sentence the no-anchor path has to say out loud.
///
/// Before `--issuer` existed this command printed `signed by <key>` and compared that key to
/// nothing, which reads as an endorsement of the key it just printed. It is not one: the key came
/// out of the same file as everything else it certifies.
const NO_ANCHOR_LIMITATION: &str =
    "No issuer anchor was pinned, so this checked SELF-CONSISTENCY ONLY: every receipt carries \
     its own public key, and a file fabricated and signed end to end by anyone at all passes this \
     check. Re-run with --issuer <hex> to bind the result to a key you obtained out of band. This \
     matters most for a file that came from somewhere -- an evidence archive, an email, a shared \
     drive -- rather than off the machine that produced it.";

/// How the anchor line reads on each path.
fn anchor_line(anchor: Option<&VerifyingKey>) -> String {
    match anchor {
        Some(key) => format!(
            "pinned — the signature is bound to {}",
            hex::encode(key.to_bytes())
        ),
        None => "NONE pinned — self-consistency only; see the limitations below".to_string(),
    }
}

/// Check an exported spend ledger.
///
/// A pass means the ledger has not changed since it was signed and its arithmetic is internally
/// consistent. It does not mean the figures are true — they are the agent's own — so the caveats
/// are printed on every pass, not only on failure.
fn verify_spend_export(path: &str, body: &[u8], anchor: Option<&VerifyingKey>) -> ExitCode {
    let signed: spend::SignedSpend = match serde_json::from_slice(body) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "{path} is not an exported warrantor spend ledger: {e}"
            ))
        }
    };
    let checked = match anchor {
        Some(key) => spend::verify_spend_signed_by(&signed, key),
        None => spend::verify_spend(&signed),
    };
    if let Err(e) = checked {
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
    println!("  anchor        {}", anchor_line(anchor));

    println!("\n── WHAT THIS DOES NOT ESTABLISH ──");
    for limitation in &signed.limitations {
        println!("  - {limitation}");
    }
    if anchor.is_none() {
        println!("  - {NO_ANCHOR_LIMITATION}");
    }
    ExitCode::SUCCESS
}

/// Check an exported stop record.
///
/// Exits non-zero when the record verifies but records a containment FAIL: a stop that could not
/// contain the run is a true record of a bad outcome, and reporting it as a clean pass would be the
/// exact failure the record exists to prevent.
fn verify_stop_export(path: &str, body: &[u8], anchor: Option<&VerifyingKey>) -> ExitCode {
    let signed: stop::SignedStop = match serde_json::from_slice(body) {
        Ok(s) => s,
        Err(e) => {
            return fail(&format!(
                "{path} is not an exported warrantor stop record: {e}"
            ))
        }
    };
    let checked = match anchor {
        Some(key) => stop::verify_stop_signed_by(&signed, key),
        None => stop::verify_stop(&signed),
    };
    if let Err(e) = checked {
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
    println!("  anchor        {}", anchor_line(anchor));
    for capability in &signed.record.conformance.report.capabilities {
        println!(
            "  {:<18}{}",
            capability.capability.label(),
            stop::verdict_word(capability.verdict)
        );
    }
    print!("{}", stop::render_limitations(&signed));
    if anchor.is_none() {
        println!("  - {NO_ANCHOR_LIMITATION}");
    }
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
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), KeyKind::Issuer) {
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
        if let Err(e) = push_export(args, root, path) {
            return fail(&e);
        }
    } else if args.flags.contains_key("archive") {
        return fail(
            "--archive files the file --export writes, so it needs one: warrantor stop <id> \
             --export stop.json --archive",
        );
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
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), KeyKind::Issuer) {
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
        if let Err(e) = push_export(args, root, path) {
            return fail(&e);
        }
    } else if args.flags.contains_key("archive") {
        return fail(
            "--archive files the file --export writes, so it needs one: warrantor spend <id> \
             --export spend.json --archive",
        );
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

// ── the guard's transport ─────────────────────────────────────────────────────────────

/// A real HTTP transport for a loopback ollama-compatible daemon.
///
/// Built exactly like [`HttpsGitHub`] and for the same reasons: the client lives in the binary so
/// the library has no socket in it, both timeouts are set so a wedged daemon cannot stall the
/// agent's tool call forever, and redirects are refused. It sends **no credential** — a loopback
/// classifier needs none, and a transport that could carry one would be a transport that could be
/// pointed somewhere worth carrying one to.
struct OllamaGuardTransport {
    agent: ureq::Agent,
    base: String,
}

impl guard::GuardTransport for OllamaGuardTransport {
    fn get(&mut self, path: &str) -> Result<String, String> {
        match self.agent.get(&format!("{}{path}", self.base)).call() {
            Ok(ok) => ok.into_string().map_err(|e| format!("read response: {e}")),
            Err(ureq::Error::Status(code, _)) => Err(format!("the guard returned HTTP {code}")),
            Err(other) => Err(format!("the guard request failed: {other}")),
        }
    }

    fn post_json(&mut self, path: &str, body: &str) -> Result<String, String> {
        let response = self
            .agent
            .post(&format!("{}{path}", self.base))
            .set("content-type", "application/json")
            .send_string(body);
        match response {
            Ok(ok) => ok.into_string().map_err(|e| format!("read response: {e}")),
            // Status only, never the body: an error body from a classifier can echo the request,
            // and the request is the agent's own tool arguments.
            Err(ureq::Error::Status(code, _)) => Err(format!("the guard returned HTTP {code}")),
            Err(other) => Err(format!("the guard request failed: {other}")),
        }
    }
}

/// Read a `--guard-*` numeric flag, or fall back rather than failing the run.
///
/// A malformed knob is reported and defaulted here, unlike `--budget`, because the fallback is not
/// an authority decision: the worst case is a guard configured differently from what was typed,
/// and the value it was actually run with is recorded in every signal's provenance, so the mistake
/// is visible in the evidence rather than silent.
fn guard_number<T: std::str::FromStr + std::fmt::Display>(
    args: &Args,
    flag: &str,
    fallback: T,
) -> T {
    match args.flags.get(flag) {
        None => fallback,
        Some(raw) => match raw.parse::<T>() {
            Ok(value) => value,
            Err(_) => {
                eprintln!(
                    "warrantor: --{flag}={raw:?} is not a number; using {fallback}. The value \
                     actually used is recorded in every guard signal's provenance."
                );
                fallback
            }
        },
    }
}

/// Build the observe-only guard, or `None` and a sentence saying no guard ran.
///
/// OFF unless `--guard` is passed. Every failure path returns `None` **and says so loudly**: a
/// guard that could not attach must never be indistinguishable from a guard that found nothing, and
/// it must never fail the run either — the run's authority comes from the warrant, not from a
/// classifier being reachable.
fn build_guard(args: &Args, warrant_id: &str, root: &Path) -> Option<Box<dyn guard::GuardSink>> {
    if !args.flags.contains_key("guard") {
        return None;
    }
    let endpoint = args
        .flags
        .get("guard-endpoint")
        .cloned()
        .unwrap_or_else(|| guard::DEFAULT_GUARD_ENDPOINT.to_string());
    let model = args
        .flags
        .get("guard-model")
        .cloned()
        .unwrap_or_else(|| guard::DEFAULT_GUARD_MODEL.to_string());
    let knobs = guard::GuardKnobs {
        seed: guard_number(args, "guard-seed", 0),
        num_ctx: guard_number(args, "guard-num-ctx", 4096),
        timeout_seconds: guard_number(args, "guard-timeout", 20),
        ..guard::GuardKnobs::default()
    };
    // Spelled so it cannot be typed by accident or reached by a tab-completion of `--guard`. The
    // measured 0.0923 adversarial false-positive rate is why: an enforcing guard denies roughly one
    // benign adversarially-phrased call in eleven, and the operator who overrides it twice stops
    // reading it. See `guard::GuardMode::Enforce`.
    let mode = if args.flags.contains_key("guard-enforce-untested-do-not-use") {
        guard::GuardMode::Enforce
    } else {
        guard::GuardMode::Observe
    };
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(knobs.timeout_seconds))
        .redirects(0)
        .build();
    let transport = OllamaGuardTransport {
        agent,
        base: endpoint.trim_end_matches('/').to_string(),
    };
    let config = guard::GuardConfig {
        warrant_id: warrant_id.to_string(),
        endpoint: endpoint.trim_end_matches('/').to_string(),
        model,
        mode,
        knobs,
        max_calls: guard_number(args, "guard-max-calls", guard::DEFAULT_MAX_CALLS),
    };
    let adapter = match guard::attach(transport, config) {
        Ok(adapter) => adapter,
        Err(e) => {
            eprintln!(
                "warrantor: the guard did NOT attach: {e}\n  \
                 NO guard ran for this session. That is not a clean bill of health -- nothing \
                 classified anything. The run continues under its warrant, which is where its \
                 authority comes from."
            );
            return None;
        }
    };
    let session = {
        use warrantor_warrant::guard::GuardSink as _;
        adapter.session_record(now())
    };
    // Written at attach, before the first tool call. A session that dies mid-run then still shows
    // exactly what was watching it, which is a different state from "no guard ran".
    if let Err(e) = guard::record_guard_session(root, &session) {
        eprintln!(
            "warrantor: the guard attached but its attach record could not be written ({e}). Its \
             signals will still be written at the end of the session."
        );
    }
    eprintln!(
        "warrantor: guard attached -- {} ({}) at {}. {}",
        session.provenance.model,
        session.provenance.model_digest,
        session.provenance.endpoint,
        match mode {
            guard::GuardMode::Observe => "observe-only: it records and never blocks.",
            guard::GuardMode::Enforce =>
                "ENFORCING: a call it calls harmful is refused before anything is staged. This \
                 mode is untested in production and denies roughly one benign adversarially- \
                 phrased call in eleven, and it bounds only calls through this endpoint -- it is \
                 not containment. Turn it off.",
        }
    );
    Some(Box::new(adapter))
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
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), KeyKind::Settle) {
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
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), KeyKind::Settle) {
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
    let at = now();
    match queue.stage(tool, arguments, at) {
        Ok(effect) => {
            // After the append. The effect is durable by now, so failing the command here would
            // report a refusal for something that happened; what is lost is the ability to detect a
            // later deletion below this point, and that is said rather than swallowed.
            if let Err(e) = store.witness_staged_chain(id, &queue, at) {
                eprintln!(
                    "warrantor: staged, but the chain witness for {id} could not be recorded \
                     ({e}). The effect is queued; a later deletion of the staged log is only \
                     detectable back to the last witness."
                );
            }
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
    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), KeyKind::Issuer) {
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
        // The session records its own chain as it stages, so a staged log deleted after the run
        // is detectable down to the last effect rather than down to the last time somebody ran a
        // CLI command.
        endpoint = endpoint.witnessed_by(store.clone());
        // Absent by default. `build_guard` returns `None` unless `--guard` was passed, and also
        // whenever attaching failed -- an absent guard produces no signals and never "all clear".
        if let Some(sink) = build_guard(args, id, root) {
            endpoint = endpoint.with_guard(sink);
        }
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
                // Beside the refusals and never mixed into them: these calls HAPPENED. The write
                // is skipped entirely when no guard was attached, so an unguarded run leaves no
                // guard log and `/v1/.../refusals` reports `configured: false`.
                if let Some(counters) = endpoint.guard_counters() {
                    let signals = endpoint.guard_signals();
                    match guard::record_guard_signals(root, id, &signals, counters, now()) {
                        Ok(_) => {}
                        // Same shape as the refusal write above: reported, never a failing exit
                        // code. The run is over and its authority never depended on this.
                        Err(e) => eprintln!(
                            "warrantor: the session's guard signals could not be written down \
                             ({e}). The counts below are the only record."
                        ),
                    }
                    // The closing sentence names the mode that was actually in force. It used to
                    // read "Nothing was blocked." unconditionally, which was a false statement to
                    // the operator on exactly the runs where it mattered -- the ones started with
                    // --guard-enforce-untested-do-not-use, where flagged calls WERE refused.
                    eprintln!(
                        "warrantor: guard -- {} classified, {} flagged, {} backend-unavailable, {} \
                         unparseable, {} skipped over budget. {}",
                        counters.classified,
                        counters.flagged,
                        counters.backend_unavailable,
                        counters.unparseable,
                        counters.skipped_over_budget,
                        match endpoint.guard_mode() {
                            Some(guard::GuardMode::Enforce) =>
                                "ENFORCING: every flagged call was refused at this endpoint before \
                                 anything was staged. That bounds calls through this endpoint only \
                                 -- it is not containment.",
                            // `None` cannot happen inside this block (the counters came from an
                            // attached guard), but reporting the shipped mode on a guess is the
                            // kind of small lie this whole surface exists to avoid.
                            Some(guard::GuardMode::Observe) => "Nothing was blocked.",
                            None => "The mode could not be read, so what was blocked is unknown.",
                        }
                    );
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

    let issuer = match load_or_create_key(&root.join("keys/issuer.key"), KeyKind::Issuer) {
        Ok(k) => k,
        Err(e) => return fail(&e),
    };
    let settle_key = match load_or_create_key(&root.join("keys/settle.key"), KeyKind::Settle) {
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
/// Where the redirect shim is written. Beside the token, in the same 0700 directory.
fn open_shim_path(root: &Path) -> PathBuf {
    root.join("serve").join("open.html")
}

/// Hand the console URL to the operator's browser **without putting the token in a command line.**
///
/// The obvious implementation — passing `http://addr/#t=<token>` straight to `start`, `open` or
/// `xdg-open` — leaks the secret twice over. An argv is world-readable on a default Linux
/// (`/proc/<pid>/cmdline`), and the browser then holds that URL in *its* argv for as long as it
/// runs. Both would undo the one thing the 0600 token file achieves, which is keeping other *users*
/// out. (It was never claimed to keep the supervised agent out; `serve.rs` is explicit about that.)
///
/// So the URL is written to a one-line redirect page inside the same 0700 directory the token
/// already lives in, and the *path* is what reaches the command line. A path is not a secret. The
/// browser reads the fragment from the page and navigates; the token never appears in any process
/// listing. The shim is removed on shutdown alongside the token file.
///
/// This runs on its own thread because the listener has not bound yet when it starts: it waits for
/// a connection to succeed rather than sleeping a guessed interval, then opens the page.
fn open_console_when_ready(addr: std::net::SocketAddr, token: String, root: &Path) {
    let shim = open_shim_path(root);
    std::thread::spawn(move || {
        // Wait for the listener. Fifty attempts at 100ms is five seconds, which is far longer than
        // a bind takes and short enough that a failed bind does not leave a thread waiting forever.
        //
        // The probe completes a whole request rather than connecting and hanging up. A bare
        // connect-then-drop is what a port scanner does, and the server correctly logs it as an
        // aborted connection -- which would put a spurious error in the operator's log on every
        // single start. It also tests the wrong thing: that something is bound, rather than that
        // the console is being served. `GET /` needs no token and returns the document.
        let probe = format!("GET / HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n\r\n");
        let mut ready = false;
        for _ in 0..50 {
            if let Ok(mut socket) =
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200))
            {
                use std::io::{Read, Write};
                let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut answer = String::new();
                if socket.write_all(probe.as_bytes()).is_ok()
                    && socket.read_to_string(&mut answer).is_ok()
                    && answer.starts_with("HTTP/1.1 200")
                {
                    ready = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !ready {
            eprintln!("warrantor: the console did not come up in time; open it yourself from the URL above.");
            return;
        }

        // `http-equiv=refresh` rather than a script, so the page works with JavaScript disabled and
        // needs no policy of its own. The fragment survives the redirect, which is the whole point.
        let url = format!("http://{addr}/#t={token}");
        let page = format!(
            "<!doctype html><meta charset=\"utf-8\">\
             <meta http-equiv=\"refresh\" content=\"0; url={url}\">\
             <title>Opening Warrantor</title>\
             <p>Opening the Warrantor console. If nothing happens, \
             <a href=\"{url}\">open it manually</a>.</p>"
        );
        if let Some(parent) = shim.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&shim, page) {
            eprintln!(
                "warrantor: could not write the console shim ({e}); open the URL above yourself."
            );
            return;
        }

        // One opener per platform, and no shell interpolation anywhere: the only argument is a path
        // this process just built.
        let opened = if cfg!(target_os = "windows") {
            // `start` is a cmd builtin, so it needs cmd. The empty string is the window title,
            // which `start` otherwise takes from the first quoted argument.
            std::process::Command::new("cmd")
                .args(["/C", "start", ""])
                .arg(&shim)
                .spawn()
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(&shim).spawn()
        } else {
            std::process::Command::new("xdg-open").arg(&shim).spawn()
        };
        if let Err(e) = opened {
            eprintln!("warrantor: could not open a browser ({e}); open the URL above yourself.");
        }
    });
}

fn cmd_serve(args: &Args, store: WarrantStore, root: &Path, open_browser: bool) -> ExitCode {
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

    // Bound before anything is printed, so every address below is the one actually bound.
    // `--port 0` asks the OS to choose, and announcing the *requested* address printed
    // `http://127.0.0.1:0` -- a URL that cannot be opened, while the server worked perfectly on a
    // port nobody had been told. Nothing caught it because every other flag makes the two equal.
    let listener = match http::bind(addr) {
        Ok(listener) => listener,
        Err(e) => return fail(&e.to_string()),
    };
    let addr = listener.local_addr().unwrap_or(addr);

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
    // The token rides in the URL *fragment*, not the query string. A fragment is never sent to a
    // server, so it cannot reach an access log, a proxy, or a Referer header on the way out. The
    // console reads it once, erases it from the address bar and from the history entry, and holds
    // it in memory for that tab only. A query string would do none of those things.
    println!("  console       http://{addr}/#t={}", token.as_str());
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

    // Started before `listen` because `listen` does not return until shutdown. The thread waits
    // for the bind rather than racing it.
    if open_browser {
        open_console_when_ready(addr, token.as_str().to_string(), root);
    }

    let api = http::StoreApi::new(
        store,
        root.to_path_buf(),
        issuer,
        settle_key,
        build_performer,
        now,
    );
    let outcome = http::serve_on(api, token, listener, &shutdown);
    // Removed whether the drain completed or not, and whether or not the loop ended in an error:
    // the token is a per-session secret and this session is over either way.
    let removed = std::fs::remove_file(&token_path);
    // The shim carries the same secret in the same directory, so it goes at the same moment and
    // under the same rule. A missing file is the expected case for `serve` without a browser.
    let _ = std::fs::remove_file(open_shim_path(root));
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

// ── the evidence archive ──────────────────────────────────────────────────────────────

/// A real HTTP transport for an evidence archive.
///
/// Built like [`HttpsGitHub`] and [`OllamaGuardTransport`] — client in the binary, both timeouts
/// set, redirects refused — with one deliberate difference: **it returns the archive's own error
/// body instead of collapsing it into a status code.** The GitHub transport hides response bodies
/// because a GitHub error can echo the request, and the request carries the developer's content.
/// The archive's refusals are the opposite: they are short sentences written about the caller's
/// request, and they are the only way an operator learns that a 401 was a clock problem
/// (`stale_request`, naming both clocks) rather than a key problem.
///
/// `redirects(0)` is load-bearing rather than tidy. A device signature covers the path; following a
/// redirect would resend a credential bound to the original path to somewhere else entirely.
struct HttpsArchive {
    agent: ureq::Agent,
    base: String,
}

/// Most this client will read back off an archive.
///
/// Twice the archive's own 4 MiB submission cap, so a legitimate artifact always fits and a
/// misbehaving or hostile server still cannot make this process grow without bound.
const MAX_ARCHIVE_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

impl ArchiveTransport for HttpsArchive {
    fn send(
        &mut self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<ArchiveAnswer, String> {
        use std::io::Read;

        let url = format!("{}{path}", self.base);
        let mut request = match method {
            "GET" => self.agent.get(&url),
            "POST" => self.agent.post(&url),
            other => {
                return Err(format!(
                    "this client speaks GET and POST; it was asked for {other}"
                ))
            }
        };
        request = request.set("user-agent", "warrantor");
        if let Some(credential) = authorization {
            request = request.set("authorization", credential);
        }
        // `send_bytes`, never `send_json`: the body is evidence read off disk and it goes out
        // exactly as it came in. A re-serialisation would change the digest, and the archive would
        // then be holding a file the operator does not have.
        let sent = if body.is_empty() {
            request.call()
        } else {
            request
                .set("content-type", "application/json")
                .send_bytes(body)
        };
        let response = match sent {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(other) => return Err(other.to_string()),
        };
        let status = response.status();
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_ARCHIVE_RESPONSE_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read the answer: {e}"))?;
        Ok(ArchiveAnswer {
            status,
            body: bytes,
        })
    }
}

fn https_archive(url: &str) -> HttpsArchive {
    HttpsArchive {
        agent: ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .redirects(0)
            .build(),
        base: url.trim_end_matches('/').to_string(),
    }
}

/// The device key and the pairing record together, or a refusal that names which half is missing.
///
/// A device key is **never created here.** One minted on demand and enrolled nowhere is not a
/// credential — it is a file that signs perfectly and every archive refuses — and the operator
/// would be reading a message about signatures when their actual problem is that they never paired.
fn archive_identity(root: &Path) -> Result<(ArchiveConfig, SigningKey), String> {
    let config = ArchiveConfig::load(root).map_err(|e| e.to_string())?;
    let path = root.join("keys/device.key");
    match load_key(&path, KeyKind::Device)? {
        // The key and the record are checked against each other *here*, before anything is signed.
        // A key that does not belong to this device id signs perfectly well and is refused at the
        // far end as a bad signature — which sends the operator hunting a crypto problem when what
        // they have is a pairing that was never finished, or a key restored from another machine.
        Some(key) => {
            config.check_key(&key, &path).map_err(|e| e.to_string())?;
            Ok((config, key))
        }
        None => Err(archive_client::ArchiveClientError::NoDeviceKey {
            path,
            url: config.url.clone(),
            device_id: config.device_id.clone(),
        }
        .to_string()),
    }
}

/// What a filing looks like to a human.
///
/// Note the heading, and note the word that is absent. A 200 from the archive means *these bytes
/// are held*, and the archive deliberately stores artifacts whose ingest check failed — so the
/// door's note is printed under a heading that says outright it is not a verdict, followed by the
/// archive's own sentence about where a real answer comes from. This command never prints
/// "verified".
fn render_filed(filed: &archive_client::Filed, url: &str) -> String {
    let mut out = String::new();
    out.push_str("\n── FILED (CUSTODY, NOT A VERDICT) ──\n");
    out.push_str(&format!("  archive        {url}\n"));
    out.push_str(&format!("  digest         {}\n", filed.digest));
    out.push_str(&format!("  kind           {}\n", filed.kind));
    out.push_str(&format!("  warrant        {}\n", filed.warrant_id));
    out.push_str(&format!("  filed by       {}\n", filed.submitted_by_device));
    out.push_str(&format!("  filed at       {}\n", filed.submitted_at));
    out.push_str(&format!(
        "  state          {}\n",
        if filed.already_held {
            "already held — the archive had these exact bytes; submission is idempotent"
        } else {
            "newly held"
        }
    ));
    out.push_str(&format!(
        "\n  the door's note (NOT a verdict): {}\n",
        filed.ingest_check
    ));
    if !filed.ingest_reason.is_empty() {
        out.push_str(&format!("    {}\n", filed.ingest_reason));
    }
    out.push_str(&format!("\n  {}\n", filed.verify_locally));
    out
}

/// `warrantor archive <enrol|push|fetch>` — the local half of the evidence archive.
///
/// Until this existed, `warrantor-archive` was a complete server with no client: nothing outside
/// that crate could produce a `Warrantor-Device` header, so the `curl` its deployment README
/// documented could not actually be typed by anybody and `submitted_by_device` had never named a
/// person. These three verbs are the whole loop — pair a device, file evidence, read it back — and
/// the reading half is authenticated too, which is why a `curl` was never going to be enough.
fn cmd_archive(args: &Args, root: &Path) -> ExitCode {
    match args.positional.first().map(String::as_str) {
        Some("enrol" | "enroll") => cmd_archive_enrol(args, root),
        Some("push") => cmd_archive_push(args, root),
        Some("fetch") => cmd_archive_fetch(args, root),
        Some(other) => fail(&format!(
            "unknown archive verb {other:?}. warrantor archive has three: enrol, push, fetch."
        )),
        None => fail(
            "usage: warrantor archive enrol --url <url> --code <code> [--replace]\n       \
             warrantor archive push <file>\n       warrantor archive fetch <sha256> --out <path>",
        ),
    }
}

fn cmd_archive_enrol(args: &Args, root: &Path) -> ExitCode {
    let Some(url) = args.flags.get("url").filter(|u| *u != "true") else {
        return fail(
            "--url is required: warrantor archive enrol --url http://127.0.0.1:8788 --code <code>",
        );
    };
    let Some(code) = args.flags.get("code").filter(|c| *c != "true") else {
        return fail(
            "--code is required. An operator mints one on the archive host with `warrantor-archive \
             enrol --label \"<this machine>\"`; it is single-use and expires in fifteen minutes.",
        );
    };
    if let Err(e) = archive_client::check_url(url) {
        return fail(&e.to_string());
    }
    let key_path = root.join("keys/device.key");
    let record_path = ArchiveConfig::path(root);

    // Enrolling over an existing pairing is refused, and the refusal is the point. Done silently it
    // mints a SECOND device at the archive while the first stays active, and overwrites the only
    // local record of the first id — which `warrantor-archive revoke --device <id>` needs. The
    // natural way to reach it is the ordinary one: a `code_not_usable`, a URL typo, and a re-run.
    // `--replace` is not a formality; it is the operator saying they have withdrawn the old device
    // or accept that they must.
    let replacing = args.flags.contains_key("replace");
    let previous = match ArchiveConfig::read_if_present(root) {
        Ok(previous) => previous,
        // An unreadable record still means a device was enrolled from this machine. Reading it as
        // "never paired" is exactly what would orphan that device.
        Err(e) => {
            if !replacing {
                return fail(
                    &archive_client::ArchiveClientError::AlreadyPaired {
                        path: record_path,
                        describes: format!("this build cannot read it — {e}"),
                    }
                    .to_string(),
                );
            }
            None
        }
    };
    if let (Some(previous), false) = (previous.as_ref(), replacing) {
        return fail(
            &archive_client::ArchiveClientError::AlreadyPaired {
                path: record_path,
                describes: format!(
                    "pairs this machine with {} as {}",
                    previous.url, previous.device_id
                ),
            }
            .to_string(),
        );
    }

    // A FRESH keypair, every enrolment — never `load_or_create_key`, which returns the key already
    // on disk. Re-using it enrols one private key under two device ids, and revocation is by id:
    // withdrawing the id an operator can name would withdraw nothing, because the same key would
    // keep signing under the other. The archive refuses the second enrolment of a key it already
    // holds, so this is the half that keeps the honest path from ever needing that refusal.
    let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let key = SigningKey::generate(&mut csprng);
    let device_public_key = hex::encode(key.verifying_key().to_bytes());

    // Nothing on disk has been touched yet, so a refusal from the archive leaves an existing
    // pairing exactly as it was.
    let mut transport = https_archive(url);
    let enrolled = match archive_client::enrol(&mut transport, url, code, &key.verifying_key()) {
        Ok(enrolled) => enrolled,
        Err(e) => return fail(&e.to_string()),
    };
    // Between here and the last write there is a device at the archive that this machine may not be
    // able to use. Every failure below says so and names it, because an enrolled device nobody can
    // name is the thing this whole command is careful about.
    let orphaned = |what: &str| {
        format!(
            "{what}\n\nThe archive HAS enrolled {}, and this machine cannot sign as it. Withdraw \
             it, or it stays active with no way to use or name it:\n  warrantor-archive revoke \
             --device {}   (on the archive host)",
            enrolled.device_id, enrolled.device_id
        )
    };
    if let Err(e) = write_device_key(&key_path, &key) {
        return fail(&orphaned(&e));
    }
    let config = ArchiveConfig {
        format: archive_client::ARCHIVE_CONFIG_FORMAT.to_string(),
        url: url.trim_end_matches('/').to_string(),
        device_id: enrolled.device_id.clone(),
        device_public_key,
        label: enrolled.label.clone(),
        enrolled_at: enrolled.enrolled_at,
    };
    let written = match config.save(root) {
        Ok(path) => path,
        Err(e) => {
            return fail(&orphaned(&format!(
                "the pairing could not be recorded, so nothing here can use it: {e}"
            )))
        }
    };
    println!("paired   {}", config.url);
    println!("device   {} ({})", enrolled.device_id, enrolled.label);
    println!("record   {}", written.display());
    println!("key      {}", key_path.display());
    if let Some(previous) = previous.as_ref() {
        println!(
            "\nREPLACED the pairing with {} as {}. That device is still ACTIVE at the archive and \
             its key is now gone from this machine. Withdraw it:\n  warrantor-archive revoke \
             --device {}   (on the archive host)",
            previous.url, previous.device_id, previous.device_id
        );
    }
    println!(
        "\nThe archive holds only the public half. Revoking this device is an operator action on \
         the archive host:\n  warrantor-archive revoke --device {}",
        enrolled.device_id
    );
    println!("\nNow: warrantor archive push <exported-evidence.json>");
    ExitCode::SUCCESS
}

fn cmd_archive_push(args: &Args, root: &Path) -> ExitCode {
    let Some(path) = args.positional.get(1) else {
        return fail("usage: warrantor archive push <file>");
    };
    let (config, key) = match archive_identity(root) {
        Ok(pair) => pair,
        Err(e) => return fail(&e),
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => return fail(&format!("read {path}: {e}")),
    };
    let mut transport = https_archive(&config.url);
    match archive_client::push(&mut transport, &config, &key, &bytes, now()) {
        Ok(filed) => {
            print!("{}", render_filed(&filed, &config.url));
            println!(
                "\nRead it back on any paired machine:  warrantor archive fetch {} --out <path>",
                filed.digest
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_archive_fetch(args: &Args, root: &Path) -> ExitCode {
    let Some(digest) = args.positional.get(1) else {
        return fail("usage: warrantor archive fetch <sha256> --out <path>");
    };
    let Some(out) = args.flags.get("out").filter(|o| *o != "true") else {
        return fail(
            "--out is required: warrantor archive fetch <sha256> --out evidence.json. The bytes are \
             written to a file rather than to stdout because the next thing to do with them is \
             `warrantor verify <file> --issuer <hex>`, which reads a path.",
        );
    };
    let (config, key) = match archive_identity(root) {
        Ok(pair) => pair,
        Err(e) => return fail(&e),
    };
    let mut transport = https_archive(&config.url);
    let bytes = match archive_client::fetch(&mut transport, &config, &key, digest, now()) {
        Ok(bytes) => bytes,
        Err(e) => return fail(&e.to_string()),
    };
    if let Err(e) = std::fs::write(out, &bytes) {
        return fail(&format!("write {out}: {e}"));
    }
    println!("fetched  {out}  ({} bytes)", bytes.len());
    println!(
        "These bytes are unverified evidence: the archive relayed them and cannot forge them, and \
         its opinion of them is not a verdict."
    );
    println!("Check them here:  warrantor verify {out} --issuer <the issuer's hex key>");
    ExitCode::SUCCESS
}

/// File an artifact that `--export` has just written, or fail the command.
///
/// One code path shared by `report`, `stop` and `spend`, reading the bytes back **off the exported
/// path** rather than re-serialising the value in memory: `write_export` uses `to_vec_pretty`, and
/// anything else here would file a digest that does not name the file on disk.
///
/// A failure is loud and the command exits non-zero. A best-effort push that only warned would let
/// a nightly pipeline report success with an empty archive behind it — the same shape as a guard
/// that was benchmarked and never invoked. What a failure never does is unwrite the local file: the
/// evidence on disk is the source of truth and stays exactly where it was written.
fn push_export(args: &Args, root: &Path, exported: &str) -> Result<(), String> {
    let Some(requested) = args.flags.get("archive") else {
        return Ok(());
    };
    let (mut config, key) = archive_identity(root)?;
    if requested != "true" {
        archive_client::check_url(requested).map_err(|e| e.to_string())?;
        config.url = requested.trim_end_matches('/').to_string();
    }
    let bytes = std::fs::read(exported).map_err(|e| format!("read back {exported}: {e}"))?;
    let mut transport = https_archive(&config.url);
    let filed =
        archive_client::push(&mut transport, &config, &key, &bytes, now()).map_err(|e| {
            format!("{exported} was written and is intact; the archive push failed: {e}")
        })?;
    print!("{}", render_filed(&filed, &config.url));
    Ok(())
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
        "archive" => cmd_archive(&args, &root),
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
        "serve" => cmd_serve(&args, store, &root, false),
        // Same server, same flags, same refusals. The only difference is that it opens the console
        // for you, which is the difference between a surface a developer can use and one a reviewer
        // can: nobody outside engineering is going to start a daemon and paste a hex token.
        "console" => cmd_serve(&args, store, &root, true),
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

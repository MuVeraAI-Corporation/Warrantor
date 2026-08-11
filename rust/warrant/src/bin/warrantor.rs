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
use warrantor_warrant::settle::{settle, void, EffectOutcome, EffectPerformer, SettleReport};
use warrantor_warrant::staging::{EffectRegistry, StagedEffect, StagingQueue};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::worktree::Worktree;
use warrantor_warrant::{
    bound_strengths, BoundStrength, SideEffectClass, Warrant, WarrantBounds, WarrantState,
};

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
    let key = SigningKey::generate(&mut rand_core_compat::OsRng);
    std::fs::write(path, key.to_bytes()).map_err(|e| format!("write {label} key: {e}"))?;
    eprintln!(
        "warrantor: created a new {label} key at {}. Protect it: anyone holding the settle key \
         can release staged effects.",
        path.display()
    );
    Ok(key)
}

/// `ed25519-dalek` v2 wants an `OsRng` from `rand_core` 0.6; the workspace has `rand` 0.8, which
/// re-exports exactly that. Aliased here so the dependency is obvious rather than mysterious.
mod rand_core_compat {
    pub use rand::rngs::OsRng;
}

// ── argument parsing ──────────────────────────────────────────────────────────────────

struct Args {
    command: String,
    positional: Vec<String>,
    flags: BTreeMap<String, String>,
}

fn parse_args() -> Option<Args> {
    let mut raw = std::env::args().skip(1);
    let command = raw.next()?;
    let mut positional = Vec::new();
    let mut flags = BTreeMap::new();
    let mut pending: Option<String> = None;
    for token in raw {
        if let Some(name) = token.strip_prefix("--") {
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
  report  <warrant-id>
  settle  <warrant-id>
  void    <warrant-id>
  stage   <warrant-id> --tool T [--target H] [--arg k=v ...]

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
        budget_cents_observed: args.flags.get("budget").and_then(|b| b.parse().ok()),
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

fn cmd_report(args: &Args, store: &WarrantStore) -> ExitCode {
    let Some(id) = args.positional.first() else {
        return fail("usage: warrantor report <warrant-id>");
    };
    let stored = match store.load(id) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    let queue = match open_queue(store, id) {
        Ok(q) => q,
        Err(e) => return fail(&e),
    };

    println!(
        "WARRANT {}  —  \"{}\"",
        stored.warrant.claims.id, stored.warrant.claims.goal
    );
    println!("state: {:?}", stored.warrant.state);

    println!("\n── AWAITING YOU ──");
    if queue.is_empty() {
        println!("  nothing staged");
    } else {
        match queue.release_order() {
            Ok(order) => {
                for effect in order {
                    println!("  {:<36}  {}", effect.handle, effect.tool);
                    for (name, value) in &effect.arguments {
                        println!("      {name}: {value}");
                    }
                }
            }
            Err(e) => println!("  release order cannot be computed: {e}"),
        }
    }

    if let (Some(repo), Some(path)) = (&stored.repo, &stored.worktree) {
        let tree = Worktree::existing(
            repo.clone(),
            path.clone(),
            stored
                .branch
                .clone()
                .unwrap_or_else(|| format!("{}{}", warrantor_warrant::worktree::BRANCH_PREFIX, id)),
            stored.base_commit.clone().unwrap_or_default(),
        );
        println!("\n── IT CHANGED ──");
        match tree.changed_files() {
            Ok(files) if files.is_empty() => println!("  no files changed"),
            Ok(files) => {
                for file in files.iter().take(20) {
                    println!("  {file}");
                }
                if files.len() > 20 {
                    println!("  … and {} more", files.len() - 20);
                }
            }
            Err(e) => println!("  (worktree unreadable: {e})"),
        }
    }

    // Distinguishing enforced from observed is the honesty that keeps a developer from relying on
    // a bound that cannot hold.
    println!("\n── BOUNDS ──");
    for (name, strength) in bound_strengths() {
        let mark = match strength {
            BoundStrength::Enforced => "enforced",
            BoundStrength::Observed => "observed",
        };
        println!("  {name:<24}{mark}");
    }

    println!("\n── EVIDENCE ──");
    println!("  {} staged effect(s)", queue.len());
    println!("  chain head {}", queue.head_digest());
    ExitCode::SUCCESS
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
        return fail("usage: warrantor settle <warrant-id>");
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
        "report" => cmd_report(&args, &store),
        "settle" => cmd_settle(&args, &store, &root),
        "void" => cmd_void(&args, &store, &root),
        "stage" => cmd_stage(&args, &store),
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

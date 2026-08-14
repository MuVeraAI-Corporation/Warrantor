//! The two MCP endpoints: what the developer's agent can do, and what a supervised agent can.
//!
//! See [`crate::mcp`] for why these are separate servers rather than one server with a permission
//! check. The short version: the agent endpoint does not publish the lifecycle tools, so there is
//! no name for a supervised agent to call and nothing to probe for.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use crate::daemon::{process_is_alive, DaemonState, Reconciliation};
use crate::mcp::{require_str, string_list, Endpoint, ToolResult, ToolSpec};
use crate::proxy::{Decision, Proxy, ToolCall};
use crate::settle::{settle, void, EffectPerformer};
use crate::staging::{EffectRegistry, StagingQueue};
use crate::stop::{OsProcessControl, StopStore};
use crate::store::{StoredWarrant, WarrantStore};
use crate::worktree::Worktree;
use crate::{SideEffectClass, Warrant, WarrantBounds, WarrantState};

fn schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

/// Read an optional whole-cents ceiling, refusing every shape that is not one.
///
/// `Value::as_u64` on its own is the trap this exists to close. It answers `None` for `"500"`, for
/// `500.0` and for `-1` alike — three shapes an LLM caller emits routinely for an integer field —
/// and `None` on this argument is not "the caller said nothing". It is a warrant with **no declared
/// ceiling**, minted silently at the exact moment the caller was declaring one. An undeclared
/// ceiling is not merely a different number: `spend::cap_declared` is false for it, so the warrant
/// is never [`crate::spend::SpendLedger::exhausted`] and nothing can refuse it on budget grounds.
///
/// So a value that does not parse is a refusal, not a default — the same decision `warrantor grant`
/// already makes for `--budget`. A string or float is accepted only where it is an exact,
/// non-negative whole count of cents; anything else is named back to the caller.
fn optional_cents(arguments: &BTreeMap<String, Value>, key: &str) -> Result<Option<u64>, String> {
    let Some(raw) = arguments.get(key) else {
        return Ok(None);
    };
    // An explicit `null` is the caller saying nothing, which already means a ceiling of zero.
    if raw.is_null() {
        return Ok(None);
    }
    let parsed = match raw {
        Value::Number(n) => n.as_u64().or_else(|| whole_cents_from_f64(n.as_f64())),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    parsed.map(Some).ok_or_else(|| {
        format!(
            "{key:?} must be a whole, non-negative number of cents -- e.g. 500 for $5.00. {raw} is \
             not one, so the warrant was NOT granted. Refusing rather than dropping it: a ceiling \
             that does not parse would leave the warrant with no declared ceiling at all, at the \
             exact moment you were declaring one."
        )
    })
}

/// A JSON float is a whole count of cents only when it is finite, non-negative, integral, and
/// small enough that an `f64` still distinguishes it from its neighbours.
///
/// `500.0` is the integer 500 written the way a model writes it, and taking it is not a guess.
/// `5.005`, `-1.0` and `1e30` are not whole cents, and each comes back as a refusal instead.
fn whole_cents_from_f64(value: Option<f64>) -> Option<u64> {
    // 2^53: above this, consecutive integers are no longer representable, so a value that large is
    // not a figure the caller can have meant exactly.
    const MAX_EXACT: f64 = 9_007_199_254_740_992.0;
    let cents = value?;
    // `is_finite` first: NaN and the infinities fail the range test too, but only by accident of
    // how comparison treats them, and a bound this load-bearing should not rest on an accident.
    if !cents.is_finite() || !(0.0..=MAX_EXACT).contains(&cents) || cents.fract() != 0.0 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(cents as u64)
}

// ── control endpoint ──────────────────────────────────────────────────────────────────

/// The developer's own endpoint: the full warrant lifecycle as MCP tools.
///
/// Registering this in your own coding agent is what turns Warrantor from a CLI you have to
/// remember into something the agent reaches natively — "grant yourself eight hours on the auth
/// bug and show me the report in the morning" becomes a thing the model can actually do.
///
/// It holds the settle key, so it must only ever be registered in an agent *you* are driving, never
/// in one running under a warrant. That is stated in the tool descriptions too, because the
/// deployment mistake is more likely than the code one.
pub struct ControlEndpoint {
    store: WarrantStore,
    root: std::path::PathBuf,
    issuer: SigningKey,
    settle_key: SigningKey,
    /// Injected so a caller owns the clock, and tests are not time-dependent.
    now: fn() -> u64,
}

impl ControlEndpoint {
    /// Build the control endpoint.
    #[must_use]
    pub fn new(
        store: WarrantStore,
        root: std::path::PathBuf,
        issuer: SigningKey,
        settle_key: SigningKey,
        now: fn() -> u64,
    ) -> Self {
        Self {
            store,
            root,
            issuer,
            settle_key,
            now,
        }
    }

    fn grant(&mut self, arguments: &BTreeMap<String, Value>) -> ToolResult {
        let goal = match require_str(arguments, "goal") {
            Ok(v) => v,
            Err(e) => return *e,
        };
        let tools: std::collections::BTreeSet<String> =
            string_list(arguments, "tools").into_iter().collect();
        if tools.is_empty() {
            return ToolResult::error(
                "\"tools\" must list at least one tool: a warrant with no tools can do nothing",
            );
        }
        // `as_u64` yields None for a JSON string ("300"), a float (300.0) and a negative number --
        // all shapes an LLM caller routinely emits. Folding those into the default silently granted
        // 8 hours to a caller who asked for 5 minutes: 96x the authority requested, with no error,
        // on a bound that is genuinely Enforced. Absent means default; present-but-unreadable means
        // refuse.
        let deadline = match arguments.get("deadline_seconds") {
            None => 8 * 3600,
            Some(value) => match value.as_u64() {
                Some(seconds) if seconds > 0 => seconds,
                _ => {
                    return ToolResult::error(format!(
                        "deadline_seconds must be a positive whole number of seconds, not {value}. \
                         Refusing rather than defaulting: defaulting here would hand you 8 hours \
                         when you asked for something shorter."
                    ))
                }
            },
        };
        // Parsed before anything is signed or created, so a bad ceiling costs the caller an error
        // message rather than a worktree and a warrant they then have to void.
        let budget_cents_observed = match optional_cents(arguments, "budget_cents") {
            Ok(cents) => cents,
            Err(message) => return ToolResult::error(message),
        };

        let now = (self.now)();
        let id = format!("wrt_{:016x}", now.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let bounds = WarrantBounds {
            tools,
            write_paths: string_list(arguments, "write_paths").into_iter().collect(),
            egress_hosts: string_list(arguments, "egress_hosts").into_iter().collect(),
            // Writes are staged unless the caller says otherwise: the safe reading of silence.
            staged_classes: [SideEffectClass::Write].into_iter().collect(),
            expires_at: now + deadline,
            // Was hardcoded `None` with no schema property, so EVERY MCP-granted warrant was
            // uncapped and the caller had no way to say otherwise. It is a declared ceiling now,
            // and absent still means none: an MCP-granted warrant without `budget_cents` can
            // record only zero-cost usage, which is the same reading the rest of this crate takes
            // of an absent limit. The bound remains observed either way -- see `crate::spend`.
            //
            // Read through `optional_cents`, never `Value::as_u64` directly: absence has to be
            // something the caller chose, not something a malformed value decayed into.
            budget_cents_observed,
            delegation_depth: arguments
                .get("delegation_depth")
                .and_then(Value::as_u64)
                .and_then(|d| u32::try_from(d).ok())
                .unwrap_or(1),
        };

        let warrant = match Warrant::grant(
            &id,
            &goal,
            "spiffe://muveraai.com/agent/mcp",
            bounds,
            now,
            &self.settle_key.verifying_key(),
            &self.issuer,
        ) {
            Ok(w) => w,
            Err(e) => return ToolResult::error(format!("grant failed: {e}")),
        };

        let repo = arguments.get("repo").and_then(Value::as_str);
        let (worktree, branch, base_commit) = match repo {
            Some(path) => match Worktree::create(path, &id) {
                Ok(tree) => (
                    Some(tree.path.clone()),
                    Some(tree.branch.clone()),
                    Some(tree.base_commit.clone()),
                ),
                Err(e) => {
                    return ToolResult::error(format!(
                        "could not create an isolated worktree in {path}: {e}. The warrant was NOT \
                         granted -- running without isolation would put the agent in your checkout."
                    ))
                }
            },
            None => (None, None, None),
        };

        let stored = StoredWarrant {
            warrant,
            worktree: worktree.clone(),
            repo: repo.map(std::path::PathBuf::from),
            branch,
            base_commit,
            // Witnessed from the moment it exists. A warrant whose witness only appeared at its
            // first staged effect would have a window in which a deleted log still read as empty.
            staged_chain: Some(crate::staging::StagedChainMark::genesis(now)),
        };
        if let Err(e) = self.store.save(&stored) {
            return ToolResult::error(format!("could not persist the warrant: {e}"));
        }

        ToolResult::ok(format!(
            "Granted {id}.\n  goal      : {goal}\n  expires   : {} (in {deadline}s)\n  worktree  : \
             {}\n\nStart the agent with:  warrantor run {id} -- <your agent command>\nThe agent \
             works in the worktree; nothing it does reaches your checkout until you settle.",
            stored.warrant.claims.bounds.expires_at,
            worktree.as_ref().map_or_else(
                || "none (no repo given; the agent is NOT isolated)".to_string(),
                |p: &std::path::PathBuf| p.display().to_string()
            ),
        ))
    }

    fn status(&mut self) -> ToolResult {
        let state = match DaemonState::open(&self.root) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("{e}")),
        };
        let found = match state.reconcile(&self.store, &process_is_alive) {
            Ok(f) => f,
            Err(e) => return ToolResult::error(format!("{e}")),
        };
        let mut lines = Vec::new();
        for (id, status) in &found {
            match status {
                Reconciliation::Supervised { pid } => {
                    lines.push(format!("running    {id}  (supervisor pid {pid})"));
                }
                // Kept distinct from Interrupted for the same reason the CLI does: an assistant
                // relaying "attention: the supervisor died" about a run that finished cleanly is
                // worse than saying nothing, because the operator acts on it.
                Reconciliation::Completed {
                    detail, expired, ..
                } => {
                    let label = if *expired { "deadline " } else { "finished " };
                    lines.push(format!("{label}  {id}\n           {detail}"));
                }
                Reconciliation::Interrupted { detail } => {
                    lines.push(format!("attention  {id}\n           {detail}"));
                }
                Reconciliation::Finished => {}
            }
        }
        if lines.is_empty() {
            return ToolResult::ok("Nothing open.");
        }
        ToolResult::ok(lines.join("\n"))
    }

    fn report(&mut self, arguments: &BTreeMap<String, Value>) -> ToolResult {
        let id = match require_str(arguments, "warrant_id") {
            Ok(v) => v,
            Err(e) => return *e,
        };
        let stored = match self.store.load(&id) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("{e}")),
        };

        // Fail-closed, exactly as the CLI does it: an unreadable stop directory means containment
        // is unknown, and an unknown must not be reported as "not contained".
        let stops = match StopStore::open(&self.root) {
            Ok(s) => s,
            Err(e) => {
                return ToolResult::error(format!(
                    "cannot read stop records, so containment is unknown: {e}"
                ))
            }
        };

        // The budget bound's ledger, read the same fail-closed way and from the same store the CLI
        // reads: a ledger that will not parse, or is signed by a key other than this store's
        // issuer, must not be shown as zero spend. Zero is an answer; "unknown" is not.
        let ledger = match crate::spend::SpendStore::open(&self.root).and_then(|ledgers| {
            ledgers.load(
                &stored.warrant.claims.bounds,
                &id,
                &stored.warrant.claims.subject,
                &self.issuer.verifying_key(),
            )
        }) {
            Ok(l) => l,
            Err(e) => return ToolResult::error(format!("cannot read the spend ledger: {e}")),
        };

        // Same bundle the CLI prints and the receipts cover. Before this there were two report
        // implementations that had already drifted apart; now there are two renderings of one.
        let queue = self.open_queue(&id).map_err(|e| e.to_string());
        let built = crate::report::build_observed(
            &stored,
            queue.as_ref().map_err(Clone::clone),
            &self.issuer.verifying_key(),
            (self.now)(),
            &stops.contained_scopes(&id),
            Some(crate::spend::section(&ledger)),
        );
        let mut out = vec![crate::report::render_mcp(built.bundle())];
        out.push(String::new());

        // Additive, exactly as on the CLI: the digest and verdict of the signed bundle. Without
        // this the MCP path would keep emitting unsigned prose while the CLI emitted evidence.
        match built.sign(&self.issuer, "issuer") {
            Ok(signed) => {
                let check = &signed.bundle.authority_check;
                out.push(format!("  evidence bundle: {}", signed.bundle_digest));
                out.push(format!(
                    "  authority: {} ({}), decided by {}",
                    if check.allowed { "allow" } else { "deny" },
                    check
                        .denied_gate
                        .clone()
                        .unwrap_or_else(|| "all nine gates passed".to_string()),
                    check.engine
                ));
                out.push(
                    "  Export the signed bundle from the CLI: warrantor report <id> --export \
                     <path>"
                        .to_string(),
                );
                out.push(String::new());
            }
            Err(e) => {
                out.push(format!("  evidence bundle: could not be signed ({e})"));
                out.push(String::new());
            }
        }

        out.push(
            "Then: warrant_settle to perform the staged effects, or warrant_void to discard \
                  the work and keep the log."
                .to_string(),
        );
        ToolResult::ok(out.join("\n"))
    }

    /// Stop a run from the developer's own agent.
    ///
    /// The same code path as `warrantor stop`, not a second implementation of it: an operator who
    /// says "stop it" to their assistant must get the identical termination, the identical held
    /// state and the identical signed record they would get by typing the command. An uncontained
    /// stop comes back as an MCP **error** so the model cannot read it as done.
    ///
    /// This tool is published on the control endpoint only. [`AgentEndpoint`] publishes nothing but
    /// the warrant's own tools, so a supervised agent has no name to call here — it can neither stop
    /// itself to dodge its deadline nor stop a sibling.
    fn stop_warrant(&mut self, arguments: &BTreeMap<String, Value>) -> ToolResult {
        let id = match require_str(arguments, "warrant_id") {
            Ok(v) => v,
            Err(e) => return *e,
        };
        let mut stored = match self.store.load(&id) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("{e}")),
        };
        let daemons = match DaemonState::open(&self.root) {
            Ok(d) => d,
            Err(e) => return ToolResult::error(format!("{e}")),
        };
        let stops = match StopStore::open(&self.root) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("{e}")),
        };

        let daemon = daemons.get(&id);
        let mut outcome = crate::stop::execute(
            &mut stored,
            daemon.as_ref(),
            &OsProcessControl,
            &self.store.staged_path(&id),
        );
        if daemon.is_some() && daemons.deregister(&id).is_ok() {
            outcome.deregistered = true;
        }
        if let Err(e) = self.store.save(&stored) {
            return ToolResult::error(format!(
                "the run was stopped but the warrant state could not be persisted: {e}"
            ));
        }

        let reason = arguments.get("reason").and_then(Value::as_str);
        let signed = match crate::stop::sign(&stored, &outcome, reason, &self.issuer, (self.now)())
        {
            Ok(s) => s,
            Err(e) => {
                return ToolResult::error(format!(
                    "the run was stopped, but the record could not be signed: {e}"
                ))
            }
        };
        if let Err(e) = stops.save(&signed) {
            return ToolResult::error(format!(
                "the run was stopped but the record was not kept: {e}"
            ));
        }

        let text = format!(
            "{}{}",
            crate::stop::render_cli(&signed),
            crate::stop::render_limitations(&signed)
        );
        if crate::stop::contained(&signed) {
            ToolResult::ok(text)
        } else {
            ToolResult::error(format!(
                "{text}\nThis stop did NOT contain the run. Treat the agent as still running until \
                 that has been confirmed some other way."
            ))
        }
    }

    fn open_queue(&self, id: &str) -> Result<StagingQueue, crate::WarrantError> {
        // Witnessed, not bare: a log that was deleted must not read back as "nothing was staged"
        // on the path that both reports and settles.
        self.store.open_queue(id, EffectRegistry::github())
    }

    fn settle_warrant(&mut self, arguments: &BTreeMap<String, Value>) -> ToolResult {
        let id = match require_str(arguments, "warrant_id") {
            Ok(v) => v,
            Err(e) => return *e,
        };
        let mut stored = match self.store.load(&id) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("{e}")),
        };
        let queue = match self.open_queue(&id) {
            Ok(q) => q,
            Err(e) => return ToolResult::error(format!("{e}")),
        };

        // No adapter is configured over MCP, so anything requiring a real external call reports
        // what is missing rather than silently doing nothing and calling it success.
        let mut performer = NoAdapter;
        let report = match settle(
            &mut stored.warrant,
            &queue,
            None,
            &self.settle_key.verifying_key(),
            &mut performer,
        ) {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("settle refused: {e}")),
        };
        if let Err(e) = self.store.save(&stored) {
            return ToolResult::error(format!("settled, but could not persist: {e}"));
        }

        let text = format!(
            "Settle of {id}: {} of {} effects released. State is now {:?}.{}",
            report.released(),
            report.effects.len(),
            stored.warrant.state,
            if report.complete {
                String::new()
            } else {
                format!(
                    "\n\nStopped at the first failure and held the rest — nothing after the \
                     boundary was attempted. Everything released so far is real. Review with \
                     warrant_report {id}."
                )
            }
        );
        if report.complete {
            ToolResult::ok(text)
        } else {
            ToolResult::error(text)
        }
    }

    fn void_warrant(&mut self, arguments: &BTreeMap<String, Value>) -> ToolResult {
        let id = match require_str(arguments, "warrant_id") {
            Ok(v) => v,
            Err(e) => return *e,
        };
        let mut stored = match self.store.load(&id) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("{e}")),
        };
        // Voiding discards the worktree too, so the branch does not linger as a half-finished
        // thing someone later mistakes for work in progress.
        let tree = stored.worktree.as_ref().map(|path| {
            Worktree::existing(
                stored.repo.clone().unwrap_or_else(|| path.clone()),
                path.clone(),
                stored.branch.clone().unwrap_or_default(),
                stored.base_commit.clone().unwrap_or_default(),
            )
        });
        if let Err(e) = void(
            &mut stored.warrant,
            tree.as_ref(),
            &self.settle_key.verifying_key(),
        ) {
            return ToolResult::error(format!("void refused: {e}"));
        }
        if let Err(e) = self.store.save(&stored) {
            return ToolResult::error(format!("voided, but could not persist: {e}"));
        }
        ToolResult::ok(format!(
            "Voided {id}. No staged effect was performed. The staged log is retained as the record \
             of what the agent intended."
        ))
    }
}

/// Reports what is missing instead of pretending an effect happened.
struct NoAdapter;

impl EffectPerformer for NoAdapter {
    fn perform(
        &mut self,
        effect: &crate::staging::StagedEffect,
        _resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        Err(format!(
            "no adapter is configured for {:?} over MCP. MCP has no credential broker, so settle \
             from the CLI where the adapter and its token live: warrantor settle <id>",
            effect.tool
        ))
    }
}

impl Endpoint for ControlEndpoint {
    fn name(&self) -> &str {
        "warrantor-control"
    }

    fn tools(&mut self) -> Vec<ToolSpec> {
        vec![
            ToolSpec {
                name: "warrant_grant".to_string(),
                description: "Grant a warrant: bounded authority for an agent to work \
                              unsupervised. Creates an isolated git worktree, so nothing the agent \
                              does reaches the main checkout until the warrant is settled."
                    .to_string(),
                input_schema: schema(
                    json!({
                        "goal": {"type": "string", "description": "What the agent is authorised to do. Reviewed later, so state it plainly."},
                        "tools": {"type": "array", "items": {"type": "string"}, "description": "Allowlisted tools. Anything not listed is refused."},
                        "write_paths": {"type": "array", "items": {"type": "string"}, "description": "Glob patterns the agent may write. Empty means none."},
                        "egress_hosts": {"type": "array", "items": {"type": "string"}, "description": "Hosts the agent may reach. Empty means no egress at all."},
                        "deadline_seconds": {"type": "integer", "description": "How long the warrant lives. Default 28800 (8h)."},
                        "repo": {"type": "string", "description": "Path to the git repo to isolate. Strongly recommended; without it the agent is not isolated."},
                        "delegation_depth": {"type": "integer", "description": "How many levels of sub-warrant may be issued. Default 1."},
                        "budget_cents": {"type": "integer", "description": "Spend ceiling in whole cents, e.g. 500 for $5.00. OBSERVED, not enforced: model API calls do not pass through Warrantor, so this is measured only from usage the agent itself reports. Absent means a ceiling of zero, not unlimited. A value that is not a whole, non-negative number of cents is REFUSED, not ignored -- the grant fails rather than quietly producing a warrant with no declared ceiling."}
                    }),
                    &["goal", "tools"],
                ),
            },
            ToolSpec {
                name: "warrant_status".to_string(),
                description: "What is running and what stopped and needs a decision. Run this \
                              first when returning to unattended work."
                    .to_string(),
                input_schema: schema(json!({}), &[]),
            },
            ToolSpec {
                name: "warrant_report".to_string(),
                description: "What an agent changed and what it staged but did not do. Read this \
                              before settling."
                    .to_string(),
                input_schema: schema(json!({"warrant_id": {"type": "string"}}), &["warrant_id"]),
            },
            ToolSpec {
                name: "warrant_stop".to_string(),
                description: "Stop a running warrant now: terminate its supervisor, hold the \
                              warrant so its staged work survives for a decision, and write a \
                              signed record of exactly what the stop contained and what it could \
                              not. Use this the moment a run should not continue. It does not \
                              discard work -- warrant_void does that."
                    .to_string(),
                input_schema: schema(
                    json!({
                        "warrant_id": {"type": "string"},
                        "reason": {"type": "string", "description": "Why the run is being stopped. Recorded verbatim in the signed stop record; left absent rather than guessed if you do not give one."}
                    }),
                    &["warrant_id"],
                ),
            },
            ToolSpec {
                name: "warrant_settle".to_string(),
                description: "Release the staged effects, in dependency order. This is the moment \
                              irreversible actions actually happen — read warrant_report first. \
                              Requires settle authority, which a supervised agent does not have."
                    .to_string(),
                input_schema: schema(json!({"warrant_id": {"type": "string"}}), &["warrant_id"]),
            },
            ToolSpec {
                name: "warrant_void".to_string(),
                description: "Discard the work. No staged effect is performed; the staged log is \
                              kept as the record of what the agent intended."
                    .to_string(),
                input_schema: schema(json!({"warrant_id": {"type": "string"}}), &["warrant_id"]),
            },
        ]
    }

    fn call(&mut self, tool: &str, arguments: &BTreeMap<String, Value>) -> ToolResult {
        match tool {
            "warrant_grant" => self.grant(arguments),
            "warrant_status" => self.status(),
            "warrant_report" => self.report(arguments),
            "warrant_stop" => self.stop_warrant(arguments),
            "warrant_settle" => self.settle_warrant(arguments),
            "warrant_void" => self.void_warrant(arguments),
            other => ToolResult::error(format!("no tool named {other:?}")),
        }
    }
}

// ── agent endpoint ────────────────────────────────────────────────────────────────────

/// The supervised agent's endpoint: the warrant's tools, policed, and nothing else.
///
/// There is no `warrant_settle` here, and no `warrant_grant`. Not denied — absent. A supervised
/// agent enumerating `tools/list` sees only what its warrant allows, which is also the clearest
/// possible signal to the model about what it is expected to work within.
pub struct AgentEndpoint {
    warrant_id: String,
    proxy: Proxy,
    queue: StagingQueue,
    /// The tool names the warrant allows, published verbatim so the model can see its own bounds.
    allowed: Vec<String>,
    /// The guard, absent unless an operator attached one at the CLI, and observe-only unless they
    /// also went out of their way — see [`crate::guard::GuardMode`].
    ///
    /// `Option`, and absent by default, because an absent guard must mean **no signals** and never
    /// "all clear". A boxed trait object rather than a generic parameter so a guard stays a runtime
    /// choice of the process that starts the session, like [`crate::proxy::ProxyMode`], and never a
    /// property of the stored warrant — a classifier knob inside signed claims would make a model's
    /// configuration part of granted authority.
    guard: Option<Box<dyn crate::guard::GuardSink>>,
    /// The store to record the staged chain into after each effect, absent in tests that drive a
    /// queue at a bare path.
    ///
    /// Absent means the session's staged effects are appended but never witnessed, so a later
    /// deletion of the log is detectable only down to whatever the last witness recorded. That is
    /// a weaker guarantee, never a false one — see [`crate::staging::StagedChainMark`].
    witness: Option<crate::store::WarrantStore>,
    now: fn() -> u64,
}

impl AgentEndpoint {
    /// Build the agent endpoint from a warrant's bounds.
    #[must_use]
    pub fn new(
        warrant_id: String,
        proxy: Proxy,
        queue: StagingQueue,
        allowed: Vec<String>,
        now: fn() -> u64,
    ) -> Self {
        Self {
            warrant_id,
            proxy,
            queue,
            allowed,
            guard: None,
            witness: None,
            now,
        }
    }

    /// Record the staged chain into `store` after every effect this session stages.
    ///
    /// A builder for the same reason as [`Self::with_guard`]: whether a session witnesses its own
    /// chain is a property of the process that started it, not of the stored warrant.
    #[must_use]
    pub fn witnessed_by(mut self, store: crate::store::WarrantStore) -> Self {
        self.witness = Some(store);
        self
    }

    /// Attach a guard to this session, in whatever mode it was built in.
    ///
    /// A builder rather than an argument to [`agent_endpoint_for`], whose signature stays as it is:
    /// it is called from the binary and from the tests, and threading a guard through it would
    /// imply the guard is something the warrant carries.
    #[must_use]
    pub fn with_guard(mut self, guard: Box<dyn crate::guard::GuardSink>) -> Self {
        self.guard = Some(guard);
        self
    }

    /// The guard signals accumulated during the session, for the end-of-run write.
    ///
    /// Empty when no guard was attached, which is the same shape as a guard that saw nothing — and
    /// the reason the log records an attach line separately, so the two can still be told apart.
    #[must_use]
    pub fn guard_signals(&self) -> Vec<crate::guard::GuardSignal> {
        self.guard.as_ref().map(|g| g.signals()).unwrap_or_default()
    }

    /// What the guard did, in counts. `None` when no guard was attached.
    #[must_use]
    pub fn guard_counters(&self) -> Option<crate::guard::GuardCounters> {
        self.guard.as_ref().map(|g| g.counters())
    }

    /// Who the guard is, or `None` when none was attached.
    #[must_use]
    pub fn guard_provenance(&self) -> Option<&crate::guard::GuardProvenance> {
        self.guard.as_ref().map(|g| g.provenance())
    }

    /// The mode the attached guard is in, or `None` when none was attached.
    ///
    /// Exposed so the end-of-session line the operator reads can name the mode that was actually in
    /// force instead of printing "Nothing was blocked." over a run in which something was.
    #[must_use]
    pub fn guard_mode(&self) -> Option<crate::guard::GuardMode> {
        self.guard.as_ref().map(|g| g.mode())
    }

    /// Classify one **permitted** call and return the denial its mode produces, if any.
    ///
    /// The only place a guard is consulted during a run, and it must be called before the call has
    /// any effect — see the comment in the `Decision::Stage` arm of [`Self::call`], and
    /// [`crate::guard::GuardObservation::enforcement_denial`]. An absent guard costs nothing here:
    /// no backend call, no signal, no latency.
    fn guard_denial(&mut self, tool: &str, arguments: &BTreeMap<String, String>) -> Option<String> {
        // Read before the mutable borrow of `self.guard`: `self.now` is a field, and borrowck is
        // right to refuse both at once.
        let at = (self.now)();
        let guard = self.guard.as_mut()?;
        guard.observe(tool, arguments, at).enforcement_denial()
    }

    /// Denials recorded during the session, for the morning report.
    #[must_use]
    pub fn authority_requests(&self) -> Vec<&crate::proxy::AuthorityRequest> {
        self.proxy.authority_requests()
    }

    /// Egress denials with their destination and reason.
    ///
    /// Surfaced separately from [`Self::authority_requests`] because the destination is the part a
    /// developer acts on, and the bound name alone does not carry it.
    #[must_use]
    pub fn egress_refusals(&self) -> Vec<&crate::egress::EgressRefusal> {
        self.proxy.egress_refusals()
    }
}

impl Endpoint for AgentEndpoint {
    fn name(&self) -> &str {
        "warrantor-agent"
    }

    fn tools(&mut self) -> Vec<ToolSpec> {
        self.allowed
            .iter()
            .map(|name| ToolSpec {
                name: name.clone(),
                description: format!(
                    "{name}, permitted by warrant {}. Write actions are staged rather than \
                     performed: you will receive a handle, and the real action happens only if a \
                     human settles the warrant.",
                    self.warrant_id
                ),
                input_schema: json!({"type": "object", "additionalProperties": true}),
            })
            .collect()
    }

    fn call(&mut self, tool: &str, arguments: &BTreeMap<String, Value>) -> ToolResult {
        // Arguments arrive as arbitrary JSON; the policy engine works in strings, so stringify
        // scalars and keep the JSON form for anything structured rather than dropping it.
        let flattened: BTreeMap<String, String> = arguments
            .iter()
            .map(|(k, v)| {
                let s = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                (k.clone(), s)
            })
            .collect();

        let call = ToolCall {
            tool: tool.to_string(),
            arguments: flattened,
            // Anything the registry knows how to stage is a write; the proxy decides from there.
            side_effect: if EffectRegistry::github().get(tool).is_some() {
                SideEffectClass::Write
            } else {
                SideEffectClass::Read
            },
        };

        // The warrant decides first, and its decision is never reconsidered below: no arm of the
        // guard can turn a denial into an allow, because a denial returns without ever reaching it.
        match self.proxy.decide(&call) {
            // A bound refused this, so the call did NOT happen -- and an unhappened call is not
            // something to classify. Handing its arguments to the classifier would put a signal in
            // `<root>/guard/` for a call the refusal log already records as refused, double-counting
            // one event across two logs whose whole distinction is that a refusal did not happen and
            // a signal's call did. It would also ship the refused arguments to another process and
            // spend a slot of the per-session call cap that coverage of the calls which DO proceed
            // depends on. So: refused calls are not observed at all.
            Decision::Deny { reason, bound } => {
                ToolResult::error(format!("refused by the warrant's {bound} bound: {reason}"))
            }
            Decision::Stage { .. } => {
                // BEFORE `apply`, and this ordering is the whole enforcement path. `apply` ->
                // `StagingQueue::stage` hash-chains the effect and `sync_all`s it to
                // `<root>/staged/<id>.jsonl`; an `Enforce` denial returned after that told the agent
                // it was refused, told the operator's log it was refused, and left the effect queued
                // to fire the moment a human settled the warrant. A denial that arrives after the
                // effect is durable is theatre. Under `Observe` -- the default and the shipped mode
                // -- `guard_denial` is `None` for every outcome, so this line changes nothing and
                // the result below is byte-identical to an unguarded run.
                if let Some(denial) = self.guard_denial(tool, &call.arguments) {
                    return ToolResult::error(denial);
                }
                let at = (self.now)();
                match self.proxy.apply(&call, &mut self.queue, at) {
                    Ok(effect) => {
                        // AFTER the append, never before. The effect is already durable at this
                        // point, so a failure here costs future detection, not the effect — and
                        // returning an error would tell the agent its call was refused when it was
                        // staged. It is said out loud on stderr instead of swallowed.
                        if let Some(store) = &self.witness {
                            if let Err(e) =
                                store.witness_staged_chain(&self.warrant_id, &self.queue, at)
                            {
                                eprintln!(
                                    "warrantor: staged {} but could not record the chain witness \
                                     for {}: {e}. The effect is queued; a later deletion of the \
                                     staged log is only detectable back to the last witness.",
                                    effect.handle, self.warrant_id
                                );
                            }
                        }
                        ToolResult::ok(format!(
                            "Staged as {}. This has NOT happened yet — it will be performed only \
                             if a human settles warrant {}. Use this handle wherever you would use \
                             the real result; it will be resolved to the real identifier at settle \
                             time.",
                            effect.handle, self.warrant_id
                        ))
                    }
                    Err(e) => ToolResult::error(format!("could not stage: {e}")),
                }
            }
            // A forwarded call needs an upstream MCP server to forward to. Until that is wired,
            // saying so is the only honest answer -- returning success would be the exact
            // success-shaped-mock failure this codebase already fixed once.
            //
            // No guard call here either, and for the same reason as the `Deny` arm: nothing is
            // forwarded, so nothing happened, so there is nothing to record a signal about. Whoever
            // wires an upstream owes this arm the `Stage` arm's shape -- `guard_denial` first, then
            // the call -- and `GuardObservation::enforcement_denial` says so at the definition.
            Decision::Forward => ToolResult::error(format!(
                "{tool} is permitted by the warrant, but no upstream MCP server is configured to \
                 forward it to. Start the agent endpoint with --upstream <command> so calls have \
                 somewhere to go."
            )),
        }
    }
}

/// Build an agent endpoint from a stored warrant.
///
/// # Errors
/// [`crate::WarrantError`] if the warrant is not open or its staging queue cannot be opened.
pub fn agent_endpoint_for(
    stored: &StoredWarrant,
    staged_path: std::path::PathBuf,
    mode: crate::proxy::ProxyMode,
    now: fn() -> u64,
) -> Result<AgentEndpoint, crate::WarrantError> {
    if !matches!(stored.warrant.state, WarrantState::Open) {
        return Err(crate::WarrantError::Encode(format!(
            "warrant {} is {:?}, not Open; there is nothing to police",
            stored.warrant.claims.id, stored.warrant.state
        )));
    }
    let id = stored.warrant.claims.id.clone();
    let bounds = stored.warrant.claims.bounds.clone();
    let allowed: Vec<String> = bounds.tools.iter().cloned().collect();
    // Checked against the witness the warrant carries, so a session cannot start on a log that has
    // been truncated or removed and then append fresh effects on top of the gap.
    let queue = StagingQueue::open_witnessed(
        staged_path,
        &id,
        EffectRegistry::github(),
        stored.staged_chain.as_ref(),
    )?;
    let proxy = Proxy::new(bounds, mode, EffectRegistry::github());
    Ok(AgentEndpoint::new(id, proxy, queue, allowed, now))
}

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
        let deadline = arguments
            .get("deadline_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(8 * 3600);

        let now = (self.now)();
        let id = format!("wrt_{:016x}", now.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let bounds = WarrantBounds {
            tools,
            write_paths: string_list(arguments, "write_paths").into_iter().collect(),
            egress_hosts: string_list(arguments, "egress_hosts").into_iter().collect(),
            // Writes are staged unless the caller says otherwise: the safe reading of silence.
            staged_classes: [SideEffectClass::Write].into_iter().collect(),
            expires_at: now + deadline,
            budget_cents_observed: None,
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
        let mut out = vec![
            format!("Warrant {id} — {:?}", stored.warrant.state),
            format!("  goal: {}", stored.warrant.claims.goal),
        ];

        if let Some(path) = &stored.worktree {
            let tree = Worktree::existing(
                stored.repo.clone().unwrap_or_else(|| path.clone()),
                path.clone(),
                stored.branch.clone().unwrap_or_default(),
                stored.base_commit.clone().unwrap_or_default(),
            );
            match tree.changed_files() {
                Ok(files) if files.is_empty() => out.push("  changed files: none".to_string()),
                Ok(files) => {
                    out.push(format!("  changed files ({}):", files.len()));
                    for f in files.iter().take(50) {
                        out.push(format!("    {f}"));
                    }
                }
                Err(e) => out.push(format!("  changed files: could not read ({e})")),
            }
        }

        match self.open_queue(&id) {
            Ok(queue) => match queue.release_order() {
                Ok(effects) if effects.is_empty() => {
                    out.push("  staged effects: none".to_string());
                }
                Ok(effects) => {
                    out.push(format!(
                        "  staged effects ({}) — NOT yet performed, in release order:",
                        effects.len()
                    ));
                    for e in effects {
                        out.push(format!("    {}  {}", e.handle, e.tool));
                    }
                }
                Err(e) => out.push(format!("  staged effects: {e}")),
            },
            Err(e) => out.push(format!("  staged effects: {e}")),
        }
        out.push(String::new());
        out.push(
            "Then: warrant_settle to perform the staged effects, or warrant_void to discard \
                  the work and keep the log."
                .to_string(),
        );
        ToolResult::ok(out.join("\n"))
    }

    fn open_queue(&self, id: &str) -> Result<StagingQueue, crate::WarrantError> {
        StagingQueue::open(self.store.staged_path(id), id, EffectRegistry::github())
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
                        "delegation_depth": {"type": "integer", "description": "How many levels of sub-warrant may be issued. Default 1."}
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
            now,
        }
    }

    /// Denials recorded during the session, for the morning report.
    #[must_use]
    pub fn authority_requests(&self) -> Vec<&crate::proxy::AuthorityRequest> {
        self.proxy.authority_requests()
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

        match self.proxy.decide(&call) {
            Decision::Deny { reason, bound } => {
                ToolResult::error(format!("refused by the warrant's {bound} bound: {reason}"))
            }
            Decision::Stage { .. } => {
                match self.proxy.apply(&call, &mut self.queue, (self.now)()) {
                    Ok(effect) => ToolResult::ok(format!(
                        "Staged as {}. This has NOT happened yet — it will be performed only if a \
                     human settles warrant {}. Use this handle wherever you would use the real \
                     result; it will be resolved to the real identifier at settle time.",
                        effect.handle, self.warrant_id
                    )),
                    Err(e) => ToolResult::error(format!("could not stage: {e}")),
                }
            }
            // A forwarded call needs an upstream MCP server to forward to. Until that is wired,
            // saying so is the only honest answer -- returning success would be the exact
            // success-shaped-mock failure this codebase already fixed once.
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
    let queue = StagingQueue::open(staged_path, &id, EffectRegistry::github())?;
    let proxy = Proxy::new(bounds, mode, EffectRegistry::github());
    Ok(AgentEndpoint::new(id, proxy, queue, allowed, now))
}

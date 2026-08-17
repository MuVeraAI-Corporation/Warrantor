//! The other half of the proxy: a client for the MCP servers a policed call is forwarded *to*.
//!
//! # Why this file had to exist before any harness integration could
//!
//! [`crate::proxy`] has decided `Forward` since it was written, and until now
//! [`crate::mcp_endpoints::AgentEndpoint`] answered that decision with an error telling the
//! operator to "start the agent endpoint with `--upstream <command>`" — a flag that did not exist
//! anywhere in the binary. The consequence was not cosmetic. It meant that of everything an agent
//! could ask a warranted session to do, exactly four calls worked (the GitHub effects the staging
//! registry knows how to queue) and every other permitted call came back as a failure whose
//! remedy could not be performed. A proxy that cannot forward is not a proxy; it is a deny-list
//! with a staging queue bolted to it.
//!
//! That is why this is the first thing built rather than another harness config generator. Wiring
//! Claude Code, Codex or Cursor at `warrantor mcp --agent <id>` before this existed would have
//! pointed a real agent at an endpoint that fails every call it permits — the
//! [[wire before widen]] mistake, made a fourth time, on the surface where a user meets the
//! product.
//!
//! # What this is
//!
//! A synchronous MCP client speaking JSON-RPC 2.0 over a child process's stdio, plus
//! [`UpstreamSet`], which owns several of them and knows which tool belongs to which. It is
//! deliberately the same transport shape as [`crate::mcp`] — one message per line — because the
//! server half of this repository already proved that framing against real clients.
//!
//! **No async runtime.** `rust/warrant` carries seven external dependencies and no tokio, and that
//! posture is a security property rather than a preference: the verifier and the policy engine are
//! the smallest auditable thing they can be. A per-call deadline is bought with a reader thread and
//! [`std::sync::mpsc::Receiver::recv_timeout`] instead, which needs nothing outside `std`.
//!
//! # Namespacing, and why the published name is not the upstream's name
//!
//! Two MCP servers may both publish `search`. A warrant's tool allowlist is a set of strings, so if
//! both were published unqualified the allowlist could not say *which* `search` it meant, and a
//! grant intended for a read-only documentation server would silently authorise a different
//! server's tool of the same name. Every upstream is therefore given a name at the command line and
//! its tools are published as `<name>.<tool>`. That is the string the warrant is granted against,
//! the string the refusal log records, and the string the agent calls; the bare `<tool>` is what
//! goes over the wire to that server and nowhere else.
//!
//! It also happens to match the shape the effect registry already used (`github.create_pr`), so a
//! grant written before this file existed reads the same afterwards.
//!
//! # The one upstream this refuses to attach
//!
//! An MCP server that publishes warrant *lifecycle* tools — `settle`, `void`, `grant`, `stage` —
//! is refused at attach time, loudly, before a single call is forwarded. The obvious instance is
//! Warrantor's own control endpoint (`warrantor mcp` with no `--agent`), and an operator wiring
//! their agent to "the warrantor MCP server" without noticing which endpoint they picked is a
//! plausible mistake rather than a contrived one. The consequence would be total: the supervised
//! agent could settle its own warrant, which is the single authority
//! [`crate::mcp_endpoints`] is shaped to withhold, and which [`crate::CapabilityToken`] has no
//! field to express.
//!
//! The check is on the *published tool names*, not on the command, so it catches any server that
//! offers those verbs — including one that is not ours.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use serde_json::{json, Value};

use crate::mcp::{ToolResult, ToolSpec, PROTOCOL_VERSION};

/// How long to wait for one upstream reply before giving up, when nothing else is said.
///
/// Thirty seconds is long enough for a real tool (a network fetch, a repository search) and short
/// enough that a hung server does not silently become an agent that appears to be thinking. The
/// timeout is per call, not per session.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The lifecycle verbs no upstream may publish.
///
/// Matched against **every** segment of a published tool name, split on the four characters tool
/// names are conventionally composed with. The first version of this check split on `.` alone and
/// took the last segment — and the very first thing it was pointed at, Warrantor's own control
/// endpoint, publishes `warrant_settle`. It passed. A check that misses the one server it was
/// written for is worse than none, because it is believed.
///
/// This is a **heuristic**, and it is deliberately biased toward refusing: a false positive costs
/// an operator one flag, and a false negative hands a supervised agent the authority to release
/// its own staged work. [`UpstreamSet::start_allowing_lifecycle_tools`] is the flag.
const LIFECYCLE_VERBS: [&str; 4] = ["grant", "settle", "void", "stage"];

/// Whether a lifecycle-publishing server may be attached anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePolicy {
    /// Refuse. The default, and the only value anything but an explicit opt-in flag produces.
    Refuse,
    /// Attach regardless. Reachable only from a command-line flag whose name says what it does.
    Allow,
}

/// Whether a published tool name looks like a warrant lifecycle verb.
fn is_lifecycle_tool(name: &str) -> bool {
    name.split(['.', '_', '-', '/'])
        .any(|segment| LIFECYCLE_VERBS.contains(&segment))
}

/// What went wrong talking to an upstream.
#[derive(Debug)]
pub enum UpstreamError {
    /// The child process could not be started at all.
    Spawn {
        /// The program name as given.
        program: String,
        /// The OS error.
        detail: String,
    },
    /// The server did not answer within the deadline.
    Timeout {
        /// Which server.
        name: String,
        /// The deadline that elapsed.
        after: Duration,
    },
    /// The server closed its output, or died.
    Closed {
        /// Which server.
        name: String,
    },
    /// The server answered, but not with something this client can read.
    Protocol {
        /// Which server.
        name: String,
        /// What was wrong.
        detail: String,
    },
    /// The server answered with a JSON-RPC error.
    Rpc {
        /// Which server.
        name: String,
        /// The error code.
        code: i64,
        /// The error message.
        message: String,
    },
    /// The server publishes warrant lifecycle tools and was refused.
    LifecycleTools {
        /// Which server.
        name: String,
        /// The offending tool names, so the operator can see what was found.
        tools: Vec<String>,
    },
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn { program, detail } => write!(
                f,
                "could not start the upstream MCP server {program:?}: {detail}"
            ),
            Self::Timeout { name, after } => write!(
                f,
                "upstream {name:?} did not answer within {}s",
                after.as_secs()
            ),
            Self::Closed { name } => {
                write!(f, "upstream {name:?} closed its output; the server is gone")
            }
            Self::Protocol { name, detail } => {
                write!(f, "upstream {name:?} answered unreadably: {detail}")
            }
            Self::Rpc {
                name,
                code,
                message,
            } => write!(f, "upstream {name:?} refused: {message} (code {code})"),
            Self::LifecycleTools { name, tools } => write!(
                f,
                "upstream {name:?} publishes warrant lifecycle tools ({}) and will not be \
                 attached. A supervised agent that can call these holds the one authority this \
                 endpoint exists to withhold: it could release its own staged work. If you meant \
                 to point at Warrantor's own MCP server, note there are two endpoints -- the \
                 control endpoint (`warrantor mcp`, lifecycle tools, for YOUR agent) and the agent \
                 endpoint (`warrantor mcp --agent <id>`, no lifecycle tools, for the SUPERVISED \
                 agent). This is the former.",
                tools.join(", ")
            ),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// How to start one upstream server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    /// The name its tools are published under. Becomes the `<name>.` prefix.
    pub name: String,
    /// The program to run.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
}

impl UpstreamSpec {
    /// Parse a `--upstream` value: `name=program arg arg`.
    ///
    /// Splitting on whitespace rather than accepting a shell string is deliberate. A shell string
    /// would mean this process decides how quoting works, and quoting rules that differ between
    /// the shell an operator tested in and the parser that actually runs the command is how a
    /// command ends up being something other than what was read. An argument containing a space
    /// is expressed by repeating the flag's `--upstream-arg` form rather than by quoting here.
    ///
    /// # Errors
    /// A sentence naming what was wrong with the value.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((name, command)) = raw.split_once('=') else {
            return Err(format!(
                "--upstream takes name=command, e.g. --upstream 'files=npx -y \
                 @modelcontextprotocol/server-filesystem .'; got {raw:?}"
            ));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("--upstream {raw:?} has an empty name"));
        }
        // The name becomes a prefix in a tool identifier the warrant is granted against, and a
        // name containing a dot would make `a.b.c` ambiguous about where the server name ends.
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "upstream name {name:?} must be letters, digits, '-' or '_': it becomes the \
                 prefix of every tool name the warrant is granted against, and a dot in it would \
                 make that name ambiguous"
            ));
        }
        let mut parts = command.split_whitespace().map(str::to_string);
        let Some(program) = parts.next() else {
            return Err(format!("--upstream {raw:?} names no command to run"));
        };
        Ok(Self {
            name: name.to_string(),
            program,
            args: parts.collect(),
        })
    }
}

/// One connected upstream MCP server.
pub struct Upstream {
    name: String,
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<Option<String>>,
    next_id: u64,
    tools: Vec<ToolSpec>,
    timeout: Duration,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("name", &self.name)
            .field("tools", &self.tools.len())
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// Start a server, handshake, and read its tool list.
    ///
    /// Everything that can fail is done here rather than lazily on first call, so an operator
    /// learns their wiring is wrong at the moment they start the session and not in the middle of
    /// an agent's run — the point at which a failure is most expensive and least legible.
    ///
    /// # Errors
    /// [`UpstreamError`] for a server that will not start, will not handshake, will not list its
    /// tools, or publishes lifecycle tools.
    pub fn start(spec: &UpstreamSpec, timeout: Duration) -> Result<Self, UpstreamError> {
        Self::start_with(spec, timeout, LifecyclePolicy::Refuse)
    }

    /// Start a server under an explicit lifecycle policy.
    ///
    /// # Errors
    /// As [`Self::start`], except that [`LifecyclePolicy::Allow`] skips the lifecycle refusal.
    pub fn start_with(
        spec: &UpstreamSpec,
        timeout: Duration,
        policy: LifecyclePolicy,
    ) -> Result<Self, UpstreamError> {
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited on purpose. An MCP server's stderr is where it explains why it is about to
            // be useless -- a missing token, an unresolvable path -- and swallowing it would turn
            // every such case into this client's generic timeout.
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| UpstreamError::Spawn {
                program: spec.program.clone(),
                detail: e.to_string(),
            })?;

        let stdin = child.stdin.take().ok_or_else(|| UpstreamError::Spawn {
            program: spec.program.clone(),
            detail: "no stdin pipe".to_string(),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| UpstreamError::Spawn {
            program: spec.program.clone(),
            detail: "no stdout pipe".to_string(),
        })?;

        // A reader thread, because a blocking read cannot be given a deadline and a server that
        // stops answering must not stop the session. `None` is pushed once when the stream ends,
        // which is what distinguishes "gone" from "slow" at the receiving end.
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        if tx.send(Some(l)).is_err() {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(None);
        });

        let mut upstream = Self {
            name: spec.name.clone(),
            child,
            stdin,
            lines,
            next_id: 1,
            tools: Vec::new(),
            timeout,
        };

        upstream.handshake()?;
        upstream.tools = upstream.list_tools()?;
        if policy == LifecyclePolicy::Refuse {
            upstream.refuse_lifecycle_tools()?;
        }
        Ok(upstream)
    }

    /// The name this server's tools are published under.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The tools it published, with the names and schemas it gave them.
    #[must_use]
    pub fn tools(&self) -> &[ToolSpec] {
        &self.tools
    }

    fn handshake(&mut self) -> Result<(), UpstreamError> {
        let result = self.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "warrantor-proxy", "version": env!("CARGO_PKG_VERSION") },
            }),
        )?;
        // The version the server answers with is recorded, not enforced. MCP's own guidance is
        // that a client decides whether to proceed; refusing a server that speaks a different
        // revision would break wiring that works, and this client uses only the three methods
        // every revision has carried.
        let _ = result;
        // A notification, so no id and no reply. Servers that gate `tools/list` on it exist.
        self.notify("notifications/initialized", json!({}))
    }

    fn list_tools(&mut self) -> Result<Vec<ToolSpec>, UpstreamError> {
        let result = self.request("tools/list", json!({}))?;
        let Some(items) = result.get("tools").and_then(Value::as_array) else {
            return Err(UpstreamError::Protocol {
                name: self.name.clone(),
                detail: "tools/list did not return a \"tools\" array".to_string(),
            });
        };
        let mut tools = Vec::with_capacity(items.len());
        for item in items {
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                return Err(UpstreamError::Protocol {
                    name: self.name.clone(),
                    detail: "a tool in tools/list has no name".to_string(),
                });
            };
            tools.push(ToolSpec {
                name: name.to_string(),
                description: item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                // Kept verbatim. The schema is what the model reasons about when it composes a
                // call, and a schema this proxy rewrote would make the agent's calls wrong in a
                // way the upstream would reject and the agent could not diagnose.
                input_schema: item
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object", "additionalProperties": true})),
            });
        }
        Ok(tools)
    }

    fn refuse_lifecycle_tools(&self) -> Result<(), UpstreamError> {
        let offending: Vec<String> = self
            .tools
            .iter()
            .filter(|t| is_lifecycle_tool(&t.name))
            .map(|t| t.name.clone())
            .collect();
        if offending.is_empty() {
            return Ok(());
        }
        Err(UpstreamError::LifecycleTools {
            name: self.name.clone(),
            tools: offending,
        })
    }

    /// Call one of this server's tools by its **unprefixed** name.
    ///
    /// # Errors
    /// [`UpstreamError`] for transport, timeout and protocol failures. A *tool* failure is not one
    /// of these: MCP carries it inside the result with `isError: true`, and it is returned as a
    /// [`ToolResult`] so the model can read and adapt to it, exactly as it would from a direct
    /// connection.
    pub fn call(
        &mut self,
        tool: &str,
        arguments: &BTreeMap<String, Value>,
    ) -> Result<ToolResult, UpstreamError> {
        let args: serde_json::Map<String, Value> = arguments.clone().into_iter().collect();
        let result = self.request(
            "tools/call",
            json!({ "name": tool, "arguments": Value::Object(args) }),
        )?;
        Ok(read_tool_result(&result))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, UpstreamError> {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.stdin, "{body}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| UpstreamError::Protocol {
                name: self.name.clone(),
                detail: format!("could not write {method}: {e}"),
            })?;
        self.await_reply(id)
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), UpstreamError> {
        let body = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        writeln!(self.stdin, "{body}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| UpstreamError::Protocol {
                name: self.name.clone(),
                detail: format!("could not write {method}: {e}"),
            })
    }

    /// Read until the reply with this id arrives, the deadline passes, or the server goes.
    ///
    /// Messages that are not this reply are discarded rather than treated as a fault: a server may
    /// legitimately interleave notifications (progress, logging) with replies, and a client that
    /// fell over on the first one would work against toy servers and fail against real ones.
    ///
    /// The deadline is on the *whole wait*, not on each line, so a server emitting a notification
    /// every second cannot hold a call open forever.
    fn await_reply(&mut self, id: u64) -> Result<Value, UpstreamError> {
        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(UpstreamError::Timeout {
                    name: self.name.clone(),
                    after: self.timeout,
                });
            }
            let line = match self.lines.recv_timeout(remaining) {
                Ok(Some(line)) => line,
                Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(UpstreamError::Closed {
                        name: self.name.clone(),
                    })
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(UpstreamError::Timeout {
                        name: self.name.clone(),
                        after: self.timeout,
                    })
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                // Not fatal on its own: some servers print a banner to stdout before speaking
                // JSON-RPC. It is skipped, and a server that only ever prints banners still fails
                // -- on the deadline, with a message naming itself.
                continue;
            };
            let Some(answered) = message.get("id").and_then(Value::as_u64) else {
                continue;
            };
            if answered != id {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(UpstreamError::Rpc {
                    name: self.name.clone(),
                    code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("no message")
                        .to_string(),
                });
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

impl Drop for Upstream {
    /// Stop the server when the session ends.
    ///
    /// Closing stdin first is the polite half — a well-behaved MCP server exits on EOF — and the
    /// kill is the half that does not depend on the server being well behaved. Leaving a spawned
    /// server running after the warrant's session is over would leave a process holding whatever
    /// credentials it was started with, outliving the authority that justified starting it.
    fn drop(&mut self) {
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read an MCP `tools/call` result into the shape the endpoint hands back to the agent.
///
/// Content parts that are not text are named rather than dropped: a model that receives an empty
/// string where an image was returned will conclude the tool did nothing, and retry.
fn read_tool_result(result: &Value) -> ToolResult {
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = match result.get("content").and_then(Value::as_array) {
        Some(parts) => {
            let rendered: Vec<String> = parts
                .iter()
                .map(|part| match part.get("type").and_then(Value::as_str) {
                    Some("text") => part
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    Some(other) => format!("[{other} content, not rendered as text]"),
                    None => "[content part with no type]".to_string(),
                })
                .collect();
            rendered.join("\n")
        }
        // A result with no `content` at all is still a result. Structured-only replies exist, and
        // showing the model the JSON is better than showing it nothing.
        None => result.to_string(),
    };
    ToolResult { text, is_error }
}

/// Several upstreams, and the routing table from a published tool name to one of them.
#[derive(Debug, Default)]
pub struct UpstreamSet {
    servers: Vec<Upstream>,
    /// Published name (`<server>.<tool>`) → (server index, unprefixed tool name).
    routes: BTreeMap<String, (usize, String)>,
}

impl UpstreamSet {
    /// Start every spec, in order, and build the routing table.
    ///
    /// The first failure stops the whole set. Starting an agent against a partially-attached set
    /// would give it a session where some permitted tools work and others report a transport
    /// failure, and an agent cannot tell that apart from a tool that is broken today — so it
    /// retries, and the run burns its deadline against a wiring mistake.
    ///
    /// # Errors
    /// The first [`UpstreamError`], with every already-started server stopped on the way out.
    pub fn start(specs: &[UpstreamSpec], timeout: Duration) -> Result<Self, UpstreamError> {
        Self::start_with(specs, timeout, LifecyclePolicy::Refuse)
    }

    /// Start every spec, attaching even servers that publish lifecycle verbs.
    ///
    /// Named at length on purpose. It is reachable from one command-line flag, and an operator who
    /// types that flag has said, in the clearest terms the interface can offer, that they accept a
    /// supervised agent being able to call tools whose names look like `settle`.
    ///
    /// # Errors
    /// As [`Self::start`], minus the lifecycle refusal.
    pub fn start_allowing_lifecycle_tools(
        specs: &[UpstreamSpec],
        timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        Self::start_with(specs, timeout, LifecyclePolicy::Allow)
    }

    fn start_with(
        specs: &[UpstreamSpec],
        timeout: Duration,
        policy: LifecyclePolicy,
    ) -> Result<Self, UpstreamError> {
        let mut set = Self::default();
        for spec in specs {
            let upstream = Upstream::start_with(spec, timeout, policy)?;
            let index = set.servers.len();
            for tool in upstream.tools() {
                set.routes.insert(
                    format!("{}.{}", upstream.name(), tool.name),
                    (index, tool.name.clone()),
                );
            }
            set.servers.push(upstream);
        }
        Ok(set)
    }

    /// Whether any server is attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// How many servers are attached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Every tool, under its published `<server>.<tool>` name.
    #[must_use]
    pub fn published_tools(&self) -> Vec<ToolSpec> {
        let mut all = Vec::new();
        for server in &self.servers {
            for tool in server.tools() {
                all.push(ToolSpec {
                    name: format!("{}.{}", server.name(), tool.name),
                    description: tool.description.clone(),
                    input_schema: tool.input_schema.clone(),
                });
            }
        }
        all
    }

    /// Whether a published name routes anywhere.
    #[must_use]
    pub fn has(&self, published: &str) -> bool {
        self.routes.contains_key(published)
    }

    /// Forward one call by its published name.
    ///
    /// # Errors
    /// [`UpstreamError`] from the server, or a [`UpstreamError::Protocol`] naming the unroutable
    /// tool. The unroutable case is a real one rather than an assertion: a warrant may allow a
    /// tool no attached server publishes, and the agent must be told *that* rather than told the
    /// call failed.
    pub fn call(
        &mut self,
        published: &str,
        arguments: &BTreeMap<String, Value>,
    ) -> Result<ToolResult, UpstreamError> {
        let Some((index, tool)) = self.routes.get(published).cloned() else {
            return Err(UpstreamError::Protocol {
                name: published.to_string(),
                detail: format!(
                    "no attached upstream publishes {published:?}. Attached: {}",
                    self.describe_attached()
                ),
            });
        };
        self.servers[index].call(&tool, arguments)
    }

    /// A one-line account of what is attached, for refusals and for the session banner.
    #[must_use]
    pub fn describe_attached(&self) -> String {
        if self.servers.is_empty() {
            return "nothing".to_string();
        }
        self.servers
            .iter()
            .map(|s| format!("{} ({} tools)", s.name(), s.tools().len()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spec_needs_a_name_and_a_command() {
        assert!(UpstreamSpec::parse("npx server").is_err());
        assert!(UpstreamSpec::parse("=npx").is_err());
        assert!(UpstreamSpec::parse("files=").is_err());
    }

    #[test]
    fn a_name_with_a_dot_is_refused_because_it_would_make_tool_names_ambiguous() {
        let error = UpstreamSpec::parse("a.b=npx server").unwrap_err();
        assert!(error.contains("ambiguous"), "{error}");
    }

    #[test]
    fn a_spec_splits_program_from_arguments() {
        let spec = UpstreamSpec::parse("files=npx -y @modelcontextprotocol/server-filesystem .")
            .expect("parses");
        assert_eq!(spec.name, "files");
        assert_eq!(spec.program, "npx");
        assert_eq!(
            spec.args,
            vec!["-y", "@modelcontextprotocol/server-filesystem", "."]
        );
    }

    #[test]
    fn a_text_result_is_rendered_and_an_error_flag_survives() {
        let result = read_tool_result(&json!({
            "content": [{"type": "text", "text": "hello"}],
            "isError": true,
        }));
        assert_eq!(result.text, "hello");
        assert!(result.is_error);
    }

    #[test]
    fn non_text_content_is_named_rather_than_dropped() {
        // A model handed "" where an image was returned concludes the tool did nothing and
        // retries, which is worse than being told the shape it got.
        let result = read_tool_result(&json!({
            "content": [{"type": "image", "data": "..."}],
        }));
        assert!(result.text.contains("image content"), "{}", result.text);
        assert!(!result.is_error);
    }

    #[test]
    fn a_result_with_no_content_is_shown_rather_than_blanked() {
        let result = read_tool_result(&json!({"structuredContent": {"rows": 2}}));
        assert!(result.text.contains("rows"), "{}", result.text);
    }

    #[test]
    fn lifecycle_verbs_are_matched_on_every_segment_not_just_the_last_dotted_one() {
        // `warrant_settle` is what this repository's own control endpoint publishes, and the first
        // version of this check — last segment, dot-separated only — let it straight through. A
        // check that misses the one server it was written for is worse than none.
        for name in [
            "settle",
            "warrant_settle",
            "warrant.settle",
            "a.b.void",
            "grant",
            "warrant-void",
            "warrant/stage",
        ] {
            assert!(is_lifecycle_tool(name), "{name} should be caught");
        }
        // The bias is toward refusing, but not to the point of catching anything containing the
        // letters: a segment must be the whole verb.
        for name in [
            "search",
            "read_file",
            "settlement_report",
            "avoid",
            "staged_list",
        ] {
            assert!(!is_lifecycle_tool(name), "{name} should pass");
        }
    }

    #[test]
    fn a_missing_program_is_a_spawn_error_naming_the_program() {
        let spec = UpstreamSpec::parse("x=definitely-not-a-real-program-9f3a").expect("parses");
        let error = Upstream::start(&spec, Duration::from_millis(200)).expect_err("cannot start");
        let rendered = error.to_string();
        assert!(
            rendered.contains("definitely-not-a-real-program-9f3a"),
            "{rendered}"
        );
        assert!(rendered.contains("could not start"), "{rendered}");
    }

    #[test]
    fn an_empty_set_routes_nothing_and_says_so() {
        let mut set = UpstreamSet::default();
        assert!(set.is_empty());
        assert_eq!(set.describe_attached(), "nothing");
        let error = set
            .call("files.read", &BTreeMap::new())
            .expect_err("nothing is attached");
        assert!(error.to_string().contains("files.read"), "{error}");
    }
}

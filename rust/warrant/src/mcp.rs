//! MCP transport — JSON-RPC 2.0 over stdio, and the two endpoints Warrantor speaks it on.
//!
//! [`crate::proxy`] holds the policy: what is forwarded, staged, or refused. Until now nothing
//! spoke a protocol to it, which meant the warrant's tool allowlist was enforced only where the
//! harness happened to see a call. This module is what makes it a boundary.
//!
//! # Two endpoints, and why they are not the same server
//!
//! The single most dangerous thing this file could do is expose `settle` to the wrong caller. The
//! whole design rests on the agent holding act-scoped authority with no way to release its own
//! staged effects — that is why [`crate::CapabilityToken`] has no settle field to set. An MCP tool
//! named `warrant_settle`, reachable by a supervised agent, would hand back exactly the authority
//! the type system was shaped to withhold.
//!
//! So there are two endpoints:
//!
//! | Endpoint | Who connects | Tools |
//! |----------|--------------|-------|
//! | [`Endpoint::Control`] | the developer's own agent | `grant`, `status`, `report`, `settle`, `void`, `stage` |
//! | [`Endpoint::Agent`] | an agent running under a warrant | the upstream's tools, policed; nothing else |
//!
//! The agent endpoint does not *deny* the lifecycle tools. It does not have them. They are absent
//! from `tools/list`, so there is no name to call and nothing to probe for. Refusing a call the
//! agent can see is a policy decision that can be misconfigured; not publishing the tool is a
//! structural one that cannot.
//!
//! # Framing
//!
//! MCP's stdio transport is newline-delimited JSON-RPC 2.0: one message per line, no Content-Length
//! headers. Embedded newlines are escaped by JSON itself, so a line is always exactly one message.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The MCP revision this server implements.
///
/// Sent back in `initialize`. A client asking for something else still gets this, which is the
/// documented behaviour: the server states what it speaks and the client decides whether to go on.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// One JSON-RPC request.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    /// Always `"2.0"`; carried so a malformed value can be reported rather than assumed.
    #[serde(default)]
    pub jsonrpc: String,
    /// Absent for notifications, which take no reply.
    #[serde(default)]
    pub id: Option<Value>,
    /// Method name.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: Option<Value>,
}

/// A JSON-RPC error payload.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    /// JSON-RPC error code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
}

/// Standard JSON-RPC codes, plus the ones MCP leans on.
pub mod codes {
    /// The request was not valid JSON.
    pub const PARSE_ERROR: i32 = -32700;
    /// The request was JSON but not a valid request object.
    pub const INVALID_REQUEST: i32 = -32600;
    /// No such method.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// The method exists but the parameters are wrong.
    pub const INVALID_PARAMS: i32 = -32602;
    /// Anything else that went wrong on our side.
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// A tool as advertised in `tools/list`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ToolSpec {
    /// Tool name, as the agent will call it.
    pub name: String,
    /// What it does, in the terms the model will reason about.
    pub description: String,
    /// JSON Schema for the arguments.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// What a tool call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    /// Text handed back to the model.
    pub text: String,
    /// Whether this represents a failure. MCP carries tool failures in the *result* with
    /// `isError: true` rather than as JSON-RPC errors, so the model can read and adapt to them
    /// instead of the client treating them as transport faults.
    pub is_error: bool,
}

impl ToolResult {
    /// A successful result.
    #[must_use]
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }

    /// A failure the model should read and adapt to.
    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "content": [{ "type": "text", "text": self.text }],
            "isError": self.is_error,
        })
    }
}

/// What a server exposes and how it answers calls.
pub trait Endpoint {
    /// The server's advertised name.
    fn name(&self) -> &str;
    /// Tools this endpoint publishes. What is not here cannot be called.
    fn tools(&mut self) -> Vec<ToolSpec>;
    /// Handle one tool call.
    fn call(&mut self, tool: &str, arguments: &BTreeMap<String, Value>) -> ToolResult;
}

/// Serve one endpoint over a reader/writer pair until the input closes.
///
/// Returns the number of requests handled, which is the only thing a caller can usefully assert
/// about a loop whose real output went to the writer.
///
/// # Errors
/// Only I/O failures on the writer. A malformed *request* is answered with a JSON-RPC error and the
/// loop continues: one bad message from a client must not take down a session that is supervising a
/// running agent.
pub fn serve<E: Endpoint, R: BufRead, W: Write>(
    endpoint: &mut E,
    input: R,
    output: &mut W,
) -> std::io::Result<usize> {
    let mut handled = 0;
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        handled += 1;

        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_error(
                    output,
                    None,
                    codes::PARSE_ERROR,
                    &format!("invalid JSON: {e}"),
                )?;
                continue;
            }
        };

        // A notification has no id and takes no reply. `notifications/initialized` is the common
        // one; answering it would violate JSON-RPC.
        let Some(id) = request.id.clone() else {
            continue;
        };

        if request.jsonrpc != "2.0" {
            write_error(
                output,
                Some(id),
                codes::INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            )?;
            continue;
        }

        match request.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": endpoint.name(), "version": env!("CARGO_PKG_VERSION") },
                });
                write_result(output, id, result)?;
            }
            "ping" => write_result(output, id, json!({}))?,
            "tools/list" => {
                let tools = endpoint.tools();
                write_result(output, id, json!({ "tools": tools }))?;
            }
            "tools/call" => {
                let params = request.params.unwrap_or(Value::Null);
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    write_error(
                        output,
                        Some(id),
                        codes::INVALID_PARAMS,
                        "tools/call requires \"name\"",
                    )?;
                    continue;
                };
                let arguments = params
                    .get("arguments")
                    .and_then(Value::as_object)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default();
                let result = endpoint.call(name, &arguments);
                write_result(output, id, result.to_value())?;
            }
            other => {
                write_error(
                    output,
                    Some(id),
                    codes::METHOD_NOT_FOUND,
                    &format!("no method {other:?}"),
                )?;
            }
        }
    }
    Ok(handled)
}

fn write_result<W: Write>(output: &mut W, id: Value, result: Value) -> std::io::Result<()> {
    let body = json!({ "jsonrpc": "2.0", "id": id, "result": result });
    writeln!(output, "{body}")?;
    output.flush()
}

fn write_error<W: Write>(
    output: &mut W,
    id: Option<Value>,
    code: i32,
    message: &str,
) -> std::io::Result<()> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": { "code": code, "message": message },
    });
    writeln!(output, "{body}")?;
    output.flush()
}

/// Read a string argument, or return the error the model should see.
///
/// # Errors
/// A [`ToolResult`] naming the missing argument, so the model can correct the call rather than
/// guess at a generic failure.
pub fn require_str(
    arguments: &BTreeMap<String, Value>,
    key: &str,
) -> Result<String, Box<ToolResult>> {
    match arguments.get(key).and_then(Value::as_str) {
        Some(v) if !v.is_empty() => Ok(v.to_string()),
        _ => Err(Box::new(ToolResult::error(format!(
            "{key:?} is required and must be a non-empty string"
        )))),
    }
}

/// Read a string-array argument as a set, defaulting to empty.
///
/// Empty is the safe default everywhere in this codebase: an absent bound means *none*, never
/// *unlimited*.
#[must_use]
pub fn string_list(arguments: &BTreeMap<String, Value>, key: &str) -> Vec<String> {
    arguments
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

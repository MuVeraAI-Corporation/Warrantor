//! A read API over the warrant store, plus the three acts that require a human.
//!
//! Until now a warrant store was JSON files under `~/.warrantor` on one machine, readable only by
//! the CLI standing in front of it. Multi-user oversight needs a service: a second person, a
//! desktop application, a browser client. This is that service, and it is deliberately the smallest
//! thing that could be one.
//!
//! # What it serves, and what it refuses to serve
//!
//! Read routes cover the store. **Exactly three routes mutate**: `settle`, `void` and `stop` — the
//! three acts that require a human, and the three an agent must never reach. There is no `grant`
//! over HTTP. Grant mints authority and holds the issuer key, and the whole design rests on
//! authority being minted by a human at a terminal or by the control MCP endpoint they drive. The
//! moment `grant` appears here, warrant-minting authority lives in a network-reachable process.
//!
//! Every answer is produced by calling the function the CLI calls. [`crate::report::build_observed`]
//! builds the bundle, [`crate::settle::settle`] releases the effects, [`crate::stop::execute`] +
//! [`crate::stop::sign`] + [`crate::stop::StopStore::save`] performs a stop in that order. Nothing
//! here re-derives an answer, for the reason [`crate::mcp_endpoints`] already states about stop: an
//! operator who clicks "stop" in a console must get the identical termination, the identical held
//! state and the identical signed record they would get by typing the command.
//!
//! # Answering `daemon.rs`: why this is a port when that file argues for a socket
//!
//! [`crate::daemon`] carries a block titled "Why the socket is a socket and not a port", and it is
//! right: *a TCP port on localhost is reachable by every process on the machine, including the
//! agent, and an agent that can talk to the authorization endpoint directly is an agent that can ask
//! for a different answer.* This module does the thing that block argues against, so it owes the
//! argument rather than a silence.
//!
//! Three separate mechanisms, none of which is claimed to be another:
//!
//! * **The loopback bind keeps other hosts out.** Nothing more. It is not a permission check.
//! * **The pre-routing bearer token keeps other *users* out.** It is minted per process, written
//!   owner-only where the platform supports it, and checked *before any route is resolved*, so an
//!   unauthenticated caller cannot even enumerate warrant ids by status code.
//!
//!   It does **not** keep the supervised agent out, and an earlier version of this comment claimed
//!   it did. There are no read bounds in this system — `read_paths` does not exist, and
//!   `write_paths` is `Observed` — so an agent's reads are unconstrained, and owner-only
//!   permissions do nothing against a process running as the same user. An agent can read the
//!   token file and call this API. Under a same-UID model that is not fully fixable: a process
//!   that can read a file can usually also ptrace the process holding the secret, so there is no
//!   filesystem or in-memory secret that excludes it.
//!
//!   What answers `daemon.rs` is therefore **not** the token. It is that this server holds no
//!   settle key unless the operator passed `--allow-settle`, so possession of the token yields a
//!   viewer rather than a release button. `daemon.rs` achieves the same end more cleanly: the
//!   agent's capability token is act-scoped and carries no settle authority at all, so there is
//!   nothing there to steal. This bearer token is a single unscoped value, and scoping it the same
//!   way is the right next fix.
//! * **Neither is TLS.** There is none. The token protects *access*, not *bytes on the wire*, and
//!   the non-loopback warning is written so it cannot be misread as saying otherwise.
//!
//! The daemon's Unix socket remains the better transport and is not replaced. It is not the
//! transport a browser client can speak, and a browser client is the point of this work.
//!
//! # Framing
//!
//! HTTP/1.1, one request per connection, `Connection: close` on every response — including errors.
//! The body length is `Content-Length` or nothing: **any `Transfer-Encoding` header at all is a
//! 400**. That deletes the request-smuggling class instead of defending against it, and it costs
//! nothing, because the consumer is one console polling at human speed. No keep-alive means no idle
//! state machine, no pipelining ambiguity and no timeout table.
//!
//! Path segments are **validated, never decoded**: `%` is not in the accepted character set, so
//! there is no percent-decoding step and therefore no double-decoding bug. A warrant id is
//! `wrt_` followed by 1–64 of `[A-Za-z0-9_-]`, checked before the store is touched.
//!
//! # The verification envelope
//!
//! Every response carries a server-computed verdict:
//!
//! ```json
//! { "verified": true,
//!   "verification": { "integrity": "ok", "liveness": "live", "checked_at": 1786000000, … },
//!   "data": { … } }
//! ```
//!
//! `integrity` and `liveness` are **separate three-valued fields** and are never collapsed. That is
//! the same split `warrantor verify` already makes, for the same reason: an exported report is a
//! record of a past evaluation and must not become unverifiable because a deadline went by. And
//! `unknown` (the check could not run) is a different claim from `failed` (it ran and the signature
//! is wrong) — the distinction [`crate::mcp_endpoints`] already enforces for containment.
//!
//! No cryptography happens above the Rust line, ever. A client renders `verified`; it never derives
//! it. That invariant is what lets a browser or Electron renderer be a *viewer* rather than a second
//! implementation of the verifier — which would be a second implementation that can disagree.
//!
//! A record that fails verification still returns **200 with `verified: false`**. That is not
//! fail-open: the reader is a human oversight console, and a tampered report is the single most
//! important thing to put in front of a human. Hiding it behind a 500 is what would be dishonest.
//! The three *mutating* routes are the opposite — they refuse outright on any non-`ok` integrity.
//!
//! # Deliberately not implemented
//!
//! Keep-alive, chunked encoding, TLS, CORS (no `Access-Control-Allow-Origin` header at all — one
//! would let any page in the user's browser reach a loopback API that holds settle authority),
//! cookies, compression, HTTP/2, `Range`, multipart, streaming, pagination cursors, and any async
//! runtime. `tokio`/`hyper`/`axum` are named because they are the reflex: this crate is
//! tokio-free with about seven external dependencies, and pulling one in would make it
//! unpublishable in its current form for a server whose peak load is a human pressing refresh.
//!
//! # Hazards this module inherits and does not pretend away
//!
//! * **`panic = "abort"`.** The workspace release profile aborts on panic, so a thread-per-
//!   connection server cannot isolate a panicking handler. "Never panics" is therefore a hard
//!   requirement here, not a nicety: inputs are validated before any call, no handler indexes,
//!   unwraps or expects, and a poisoned mutex is recovered rather than re-panicked.
//! * **Slow handlers.** `report` shells out to git twice with no timeout; `stop` sleeps up to five
//!   seconds polling for quiescence; `settle` can make one network call per staged effect. These are
//!   correct for a CLI verb and they are slow here too. The connection cap, not a timeout, is what
//!   keeps a slow handler from becoming a denial of service.
//! * **No store-level locking.** [`crate::store::WarrantStore::save`] writes to a deterministic temp
//!   path and renames, and nothing anywhere takes a lock. Two concurrent writers race. This module's
//!   answer is a single mutex over the whole API, so every request is serialised against every other
//!   request *in this process* — it cannot serialise against a CLI invocation in another, and it
//!   does not claim to.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::daemon::{process_is_alive, DaemonState, Reconciliation};
use crate::egress::EgressRefusal;
use crate::proxy::AuthorityRequest;
use crate::report::{self, SignedReport};
use crate::settle::{settle, void, EffectPerformer};
use crate::spend::{self, SpendError, SpendStore};
use crate::staging::{EffectRegistry, StagedEffect, StagingQueue};
use crate::stop::{self, OsProcessControl, StopError, StopStore};
use crate::store::{StoredWarrant, WarrantStore};
use crate::{bound_strengths, WarrantError, WarrantState};

// ── status codes ──────────────────────────────────────────────────────────────────────

/// The HTTP statuses this server emits, named so no integer literal appears at a call site.
///
/// Mirrors the shape of [`crate::mcp::codes`] for the same reason: a bare `409` at a call site is a
/// number, and a reader has to reconstruct the intent from the surrounding code.
pub mod status {
    /// The request was answered.
    pub const OK: u16 = 200;
    /// The request was malformed: framing, method, target shape, query or JSON body.
    pub const BAD_REQUEST: u16 = 400;
    /// No bearer token, or one that did not match.
    pub const UNAUTHORIZED: u16 = 401;
    /// The act was refused on authority grounds — a key that is not the settle authority, or a
    /// serving process that was started without release authority at all.
    pub const FORBIDDEN: u16 = 403;
    /// No such route, or no such warrant.
    pub const NOT_FOUND: u16 = 404;
    /// A known route reached with the wrong method. Always carries `Allow`.
    pub const METHOD_NOT_ALLOWED: u16 = 405;
    /// The act was refused because the warrant is not in a state that permits it, or because it was
    /// performed and did not complete.
    pub const CONFLICT: u16 = 409;
    /// The request body is larger than [`MAX_BODY_BYTES`].
    pub const PAYLOAD_TOO_LARGE: u16 = 413;
    /// The request line is longer than [`MAX_REQUEST_LINE`].
    pub const URI_TOO_LONG: u16 = 414;
    /// A POST arrived without `content-type: application/json`.
    pub const UNSUPPORTED_MEDIA_TYPE: u16 = 415;
    /// Too many header bytes or too many header lines.
    pub const HEADERS_TOO_LARGE: u16 = 431;
    /// Something went wrong on this side. The body says so and nothing else.
    pub const INTERNAL: u16 = 500;
    /// The connection cap was reached.
    pub const UNAVAILABLE: u16 = 503;
    /// The request named an HTTP version this server does not speak.
    pub const VERSION_NOT_SUPPORTED: u16 = 505;
}

/// The reason phrase for a status. Cosmetic — clients read the code.
fn reason_phrase(code: u16) -> &'static str {
    match code {
        status::OK => "OK",
        status::BAD_REQUEST => "Bad Request",
        status::UNAUTHORIZED => "Unauthorized",
        status::FORBIDDEN => "Forbidden",
        status::NOT_FOUND => "Not Found",
        status::METHOD_NOT_ALLOWED => "Method Not Allowed",
        status::CONFLICT => "Conflict",
        status::PAYLOAD_TOO_LARGE => "Payload Too Large",
        status::URI_TOO_LONG => "URI Too Long",
        status::UNSUPPORTED_MEDIA_TYPE => "Unsupported Media Type",
        status::HEADERS_TOO_LARGE => "Request Header Fields Too Large",
        status::UNAVAILABLE => "Service Unavailable",
        status::VERSION_NOT_SUPPORTED => "HTTP Version Not Supported",
        _ => "Internal Server Error",
    }
}

// ── limits ────────────────────────────────────────────────────────────────────────────

/// Longest request line accepted, in bytes. Beyond it, [`status::URI_TOO_LONG`].
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
/// Largest total header block accepted, in bytes.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Most header lines accepted.
pub const MAX_HEADERS: usize = 64;
/// Largest request body accepted, in bytes. Every POST body this API takes is a handful of fields.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Longest warrant id accepted after the `wrt_` prefix.
pub const MAX_ID_BODY: usize = 64;

/// The four caps [`parse_request_with`] enforces, gathered so a second server can reuse the parser
/// with different numbers instead of writing a second parser.
///
/// Only the numbers differ between callers. The *behaviour* — refuse every `Transfer-Encoding`,
/// validate path segments and never decode them, cap every line read, refuse a duplicate
/// `Content-Length` — is the part worth not rewriting, and it is exactly the part a second
/// implementation gets wrong. `warrantor-archive` faces a network rather than a loopback socket and
/// needs a much larger body cap than 64 KiB, because an exported report bundle with a long
/// changed-files list will exceed it; that is a constant, not a reason for another parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longest request line, in bytes.
    pub request_line: usize,
    /// Largest total header block, in bytes.
    pub header_bytes: usize,
    /// Most header lines.
    pub headers: usize,
    /// Largest request body, in bytes.
    pub body_bytes: usize,
}

impl Limits {
    /// What [`parse_request`] has always enforced, and what this server still uses.
    pub const DEFAULT: Self = Self {
        request_line: MAX_REQUEST_LINE,
        header_bytes: MAX_HEADER_BYTES,
        headers: MAX_HEADERS,
        body_bytes: MAX_BODY_BYTES,
    };
}
/// Connections served at once before [`status::UNAVAILABLE`].
///
/// A hard cap rather than a queue: a hung client must not be able to exhaust the process, and a
/// console that has opened 64 simultaneous connections is not a console.
pub const MAX_CONNECTIONS: usize = 64;
/// Socket read and write timeout. Applies to one syscall, not to a whole handler — a `stop` that
/// takes five seconds inside the handler is unaffected.
pub const SOCKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Default port. Loopback only unless a bind address is given explicitly.
pub const DEFAULT_PORT: u16 = 8787;
/// Wire format of a persisted refusal record.
pub const REFUSAL_RECORD_FORMAT: &str = "warrantor.refusal-record/1";

// ── errors ────────────────────────────────────────────────────────────────────────────

/// Everything that can go wrong starting or running the server.
///
/// Deliberately small and deliberately never rendered to a client: every variant describes this
/// machine, and the wire never learns about this machine.
#[derive(Debug, Error)]
pub enum ServeError {
    /// A key could not be read, or does not exist.
    #[error("{0}")]
    Key(String),
    /// The session token could not be minted or written.
    #[error("{0}")]
    Token(String),
    /// The listener could not bind.
    #[error("cannot bind {addr}: {detail}")]
    Bind {
        /// The address that was refused.
        addr: SocketAddr,
        /// Why, from the OS.
        detail: String,
    },
    /// A refusal log could not be read or written.
    #[error("{0}")]
    Refusals(String),
}

// ── the request, as parsed ────────────────────────────────────────────────────────────

/// One parsed HTTP request: everything the router is allowed to see.
///
/// Constructed only by [`parse_request`]. Nothing downstream re-parses a raw byte, which is what
/// makes "the path never reaches the filesystem un-validated" a structural claim rather than a
/// discipline applied at a dozen call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Uppercased method, e.g. `GET`.
    pub method: String,
    /// Path segments, already validated against the accepted character set.
    pub segments: Vec<String>,
    /// Query parameters. Keys and values are validated, never decoded.
    pub query: BTreeMap<String, String>,
    /// The `authorization` header value, verbatim.
    pub authorization: Option<String>,
    /// The body, empty when none was sent.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Build a request directly, for tests and for callers that already have the parts.
    ///
    /// Does **not** validate: [`parse_request`] is the validating constructor. A caller assembling
    /// one by hand is asserting it has done the same checks.
    #[must_use]
    pub fn new(method: &str, segments: &[&str], query: BTreeMap<String, String>) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            segments: segments.iter().map(|s| (*s).to_string()).collect(),
            query,
            authorization: None,
            body: Vec::new(),
        }
    }

    /// The same, with a bearer token attached.
    #[must_use]
    pub fn with_bearer(mut self, token: &str) -> Self {
        self.authorization = Some(format!("Bearer {token}"));
        self
    }

    /// The same, with a JSON body attached.
    #[must_use]
    pub fn with_body(mut self, body: &Value) -> Self {
        self.body = body.to_string().into_bytes();
        self
    }
}

/// Read one request off a reader.
///
/// The only function in this module that looks at a raw byte. Split out from [`serve_conn`] so
/// truncated heads, oversized lines, a present `Transfer-Encoding` and a `Content-Length` mismatch
/// are all unit-testable without building a response or opening a socket.
///
/// # Errors
/// The [`Response`] that should be written back. A parse failure is answered, not swallowed: a
/// server that accepts a connection and never replies hangs its peer forever.
pub fn parse_request<R: BufRead>(input: &mut R) -> Result<HttpRequest, Response> {
    parse_request_with(input, &Limits::DEFAULT)
}

/// [`parse_request`], with the caps supplied rather than taken from this module's constants.
///
/// Exists so `warrantor-archive` — a second HTTP surface, on a network rather than on loopback —
/// gets this parser instead of its own. A second parser is a second place a `Transfer-Encoding`
/// header, a percent-encoded path segment or an unbounded line read can be got wrong, and the two
/// would then disagree about what a well-formed request is while both claiming to be hardened.
///
/// # Errors
/// As [`parse_request`].
pub fn parse_request_with<R: BufRead>(
    input: &mut R,
    limits: &Limits,
) -> Result<HttpRequest, Response> {
    let line = read_capped_line(input, limits.request_line).map_err(|e| match e {
        LineError::TooLong => refuse(
            status::URI_TOO_LONG,
            "uri_too_long",
            "the request line is longer than this server accepts",
        ),
        LineError::Eof => refuse(
            status::BAD_REQUEST,
            "empty_request",
            "the connection closed before a request line arrived",
        ),
        LineError::Encoding | LineError::Io => refuse(
            status::BAD_REQUEST,
            "malformed_request_line",
            "the request line could not be read as text",
        ),
    })?;

    let mut parts = line.trim_end().split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(refuse(
            status::BAD_REQUEST,
            "malformed_request_line",
            "a request line is METHOD TARGET HTTP/1.1",
        ));
    };
    if parts.next().is_some() {
        return Err(refuse(
            status::BAD_REQUEST,
            "malformed_request_line",
            "a request line is METHOD TARGET HTTP/1.1",
        ));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(refuse(
            status::VERSION_NOT_SUPPORTED,
            "unsupported_version",
            "this server speaks HTTP/1.1",
        ));
    }

    // Headers. Counted and measured before anything is stored, so a client cannot make this
    // process allocate by sending header lines.
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut header_bytes = 0usize;
    let mut header_count = 0usize;
    let mut content_length: Option<usize> = None;
    loop {
        let raw = read_capped_line(input, limits.header_bytes).map_err(|e| match e {
            LineError::TooLong => refuse(
                status::HEADERS_TOO_LARGE,
                "headers_too_large",
                "a header line is longer than this server accepts",
            ),
            LineError::Eof => refuse(
                status::BAD_REQUEST,
                "truncated_headers",
                "the connection closed inside the header block",
            ),
            LineError::Encoding | LineError::Io => refuse(
                status::BAD_REQUEST,
                "malformed_header",
                "a header line could not be read as text",
            ),
        })?;
        let trimmed = raw.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        header_bytes = header_bytes.saturating_add(raw.len());
        header_count = header_count.saturating_add(1);
        if header_bytes > limits.header_bytes || header_count > limits.headers {
            return Err(refuse(
                status::HEADERS_TOO_LARGE,
                "headers_too_large",
                "this request carries more header data than the server accepts",
            ));
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(refuse(
                status::BAD_REQUEST,
                "malformed_header",
                "a header line is name: value",
            ));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();

        // Content-Length only, never chunked. Refusing every Transfer-Encoding, rather than
        // rejecting the ones known to smuggle, is what removes the class.
        if name == "transfer-encoding" {
            return Err(refuse(
                status::BAD_REQUEST,
                "transfer_encoding_refused",
                "this server reads Content-Length bodies only; send no Transfer-Encoding header",
            ));
        }
        if name == "content-length" {
            if content_length.is_some() {
                return Err(refuse(
                    status::BAD_REQUEST,
                    "duplicate_content_length",
                    "two Content-Length headers is ambiguous, so it is refused",
                ));
            }
            let Ok(parsed) = value.parse::<usize>() else {
                return Err(refuse(
                    status::BAD_REQUEST,
                    "malformed_content_length",
                    "Content-Length must be a whole number of bytes",
                ));
            };
            if parsed > limits.body_bytes {
                return Err(refuse(
                    status::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    "the request body is larger than this server accepts",
                ));
            }
            content_length = Some(parsed);
        }
        headers.insert(name, value);
    }

    let method = method.to_ascii_uppercase();
    let (path, raw_query) = target.split_once('?').map_or((target, ""), |(p, q)| (p, q));
    let segments = parse_segments(path)?;
    let query = parse_query(raw_query)?;

    let mut body = Vec::new();
    if let Some(length) = content_length {
        if length > 0 {
            // The content type is checked before the body is read, so an oversized body under the
            // wrong type is still refused for the reason the caller can act on.
            let content_type = headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or_default();
            if !is_json_content_type(content_type) {
                return Err(refuse(
                    status::UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_media_type",
                    "request bodies must be application/json",
                ));
            }
            body = vec![0u8; length];
            if input.read_exact(&mut body).is_err() {
                return Err(refuse(
                    status::BAD_REQUEST,
                    "truncated_body",
                    "the connection closed before Content-Length bytes arrived",
                ));
            }
        }
    } else if method == "POST" {
        // A POST with no body is legal here — `void` takes none — but a POST that *declares* no
        // length and then writes bytes would leave them unread on a connection we are about to
        // close, which is exactly the ambiguity `Connection: close` exists to remove.
        body = Vec::new();
    }

    Ok(HttpRequest {
        method,
        segments,
        query,
        authorization: headers.get("authorization").cloned(),
        body,
    })
}

/// `application/json`, with or without parameters.
fn is_json_content_type(value: &str) -> bool {
    let base = value.split(';').next().unwrap_or("").trim();
    base.eq_ignore_ascii_case("application/json")
}

/// What went wrong reading one line.
enum LineError {
    /// The line exceeded the cap without a newline.
    TooLong,
    /// The stream ended before a newline.
    Eof,
    /// The bytes were not UTF-8.
    Encoding,
    /// The underlying reader failed.
    Io,
}

/// Read one `\n`-terminated line, refusing rather than allocating past `limit`.
///
/// `BufRead::read_line` is unbounded, which on a socket means a client can make this process
/// allocate without limit by never sending a newline. `take(limit)` is what bounds it; a full buffer
/// with no newline is the signal that the line was too long rather than merely the last one.
fn read_capped_line<R: BufRead>(input: &mut R, limit: usize) -> Result<String, LineError> {
    let mut line = String::new();
    let read = input
        .by_ref()
        .take(limit as u64)
        .read_line(&mut line)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                LineError::Encoding
            } else {
                LineError::Io
            }
        })?;
    if read == 0 {
        return Err(LineError::Eof);
    }
    if !line.ends_with('\n') {
        return Err(if read >= limit {
            LineError::TooLong
        } else {
            LineError::Eof
        });
    }
    Ok(line)
}

/// Characters accepted inside a path segment or a query key or value.
///
/// `%` is **not** here, so there is no percent-decoding step in this server and therefore no
/// double-decoding bug, no over-long UTF-8 trick and no `%2e%2e` traversal. A caller that needs a
/// character outside this set is refused and told so; nothing in this API's vocabulary needs one.
fn is_target_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')
}

fn parse_segments(path: &str) -> Result<Vec<String>, Response> {
    if !path.starts_with('/') {
        return Err(refuse(
            status::BAD_REQUEST,
            "malformed_target",
            "the request target must be an absolute path",
        ));
    }
    let mut out = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        if !segment.chars().all(is_target_char) {
            return Err(refuse(
                status::BAD_REQUEST,
                "malformed_target",
                "path segments accept only letters, digits and _-.: — percent-encoding is not read",
            ));
        }
        // `.` and `..` cannot reach the filesystem from here — ids are validated separately and
        // routes are matched against literals — but a target containing them is a request for
        // something this API does not have, and saying so beats matching it against nothing.
        if segment == "." || segment == ".." {
            return Err(refuse(
                status::BAD_REQUEST,
                "malformed_target",
                "relative path segments are not accepted",
            ));
        }
        out.push(segment.to_string());
    }
    Ok(out)
}

fn parse_query(raw: &str) -> Result<BTreeMap<String, String>, Response> {
    let mut out = BTreeMap::new();
    if raw.is_empty() {
        return Ok(out);
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            return Err(refuse(
                status::BAD_REQUEST,
                "malformed_query",
                "each query parameter must be key=value",
            ));
        };
        if key.is_empty() || !key.chars().all(is_target_char) || !value.chars().all(is_target_char)
        {
            return Err(refuse(
                status::BAD_REQUEST,
                "malformed_query",
                "query keys and values accept only letters, digits and _-.: — percent-encoding is \
                 not read",
            ));
        }
        out.insert(key.to_string(), value.to_string());
    }
    Ok(out)
}

/// Is this a warrant id this store could hold?
///
/// Validated, not sanitised. A sanitiser turns a hostile string into a different string and then
/// uses it; this refuses the request before the store is touched, so no path is ever built from
/// unvalidated input.
#[must_use]
pub fn is_warrant_id(value: &str) -> bool {
    let Some(body) = value.strip_prefix("wrt_") else {
        return false;
    };
    !body.is_empty()
        && body.len() <= MAX_ID_BODY
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// ── responses ─────────────────────────────────────────────────────────────────────────

/// One response, ready to write.
///
/// There are exactly three constructors — [`Response::json`], [`Response::error`] and
/// [`Response::asset`] — and every route exits through one of them. Single-response-per-request
/// framing and the presence of the verification envelope are therefore structural properties of
/// this type rather than a discipline applied at thirty call sites — the same reason
/// [`crate::mcp`] has exactly two write paths.
///
/// [`Response::asset`] is the one that carries no verification envelope, and it is the only
/// constructor whose body a route did not compute: it serves a fixed byte string compiled into
/// this binary. That is what keeps the exception narrow. An asset makes no claim about a warrant,
/// so there is no verdict for it to carry and none is invented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// The JSON body. Empty and unused when [`Response::asset`] built this.
    pub body: Value,
    headers: Vec<(&'static str, &'static str)>,
    /// A pre-encoded body and its content type, when this is a static asset.
    ///
    /// `'static` on both halves is deliberate: the only thing that can become an asset is
    /// something already in the binary, so no caller-supplied bytes and no filesystem read can
    /// reach this field. The console cannot be made to serve a file off the disk.
    asset: Option<(&'static str, &'static [u8])>,
}

impl Response {
    /// A successful answer: the verification envelope wrapped around `data`.
    #[must_use]
    pub fn json(status: u16, verification: &Verification, data: Value) -> Self {
        Self {
            status,
            body: json!({
                "verified": verification.verified(),
                "verification": verification,
                "data": data,
            }),
            headers: Vec::new(),
            asset: None,
        }
    }

    /// A static asset: bytes already in this binary, with the content type to send them as.
    ///
    /// Carries no verification envelope, because it makes no claim that could be verified — see
    /// the note on [`Response`]. The hardening headers a document needs are attached by
    /// [`console_asset`], not here, so this constructor stays a dumb byte carrier.
    #[must_use]
    pub fn asset(status: u16, content_type: &'static str, bytes: &'static [u8]) -> Self {
        Self {
            status,
            body: Value::Null,
            headers: Vec::new(),
            asset: Some((content_type, bytes)),
        }
    }

    /// A refusal: a stable machine code, a sentence phrased about the caller, and a verdict.
    ///
    /// The verdict is present even here, so a client never has to branch on whether the field
    /// exists. When nothing was read there is nothing to vouch for, and the envelope says exactly
    /// that rather than defaulting to a cheerful `verified: true`.
    #[must_use]
    pub fn error(status: u16, code: &str, message: &str, verification: &Verification) -> Self {
        Self {
            status,
            asset: None,
            body: json!({
                "error": { "code": code, "message": message },
                "verified": verification.verified(),
                "verification": verification,
            }),
            headers: Vec::new(),
        }
    }

    /// Attach an outcome to a refusal — the settle that ran and did not complete, the stop that ran
    /// and did not contain.
    ///
    /// Those two are refusals *with a result*: the act happened, so the record must reach the
    /// operator, and the status must still stop a client reading it as done.
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        if let Some(object) = self.body.as_object_mut() {
            if let Some(error) = object.get_mut("error").and_then(Value::as_object_mut) {
                error.insert("details".to_string(), details);
            }
        }
        self
    }

    /// Add a header. Static values only: nothing a caller supplied can reach a header, so header
    /// injection is impossible by construction rather than by escaping.
    #[must_use]
    pub fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Fill in `checked_at` on a refusal that was built before a clock was in scope.
    ///
    /// The framing and routing layers refuse requests before any [`Api`] is reached, so their
    /// verdicts are stamped `0` at construction. Leaving it there would put a 1970 timestamp on the
    /// one field whose whole job is to say *when this was decided*. Only a zero is replaced, so a
    /// verdict a route actually computed is never overwritten by a later, coarser clock read.
    #[must_use]
    pub fn stamped(mut self, now: u64) -> Self {
        if let Some(verification) = self
            .body
            .get_mut("verification")
            .and_then(Value::as_object_mut)
        {
            if verification.get("checked_at").and_then(Value::as_u64) == Some(0) {
                verification.insert("checked_at".to_string(), json!(now));
            }
        }
        self
    }
}

/// Build a refusal with the "nothing was checked" verdict. The common case.
fn refuse(status: u16, code: &str, message: &str) -> Response {
    Response::error(status, code, message, &Verification::not_attempted(0))
}

/// Write one response. The only place bytes leave this module.
///
/// # Errors
/// I/O failures on the writer only. There is no path by which a response fails to *serialise*: the
/// body is a [`Value`] the two constructors built.
pub fn write_response<W: Write>(out: &mut W, response: &Response) -> std::io::Result<()> {
    // An asset is already bytes; everything else is serialised JSON. The framing below is
    // identical either way, so a static document cannot accidentally acquire different
    // connection semantics from an API answer.
    let (content_type, body) = match response.asset {
        Some((content_type, bytes)) => (content_type, bytes.to_vec()),
        None => (
            "application/json",
            serde_json::to_vec(&response.body).unwrap_or_else(|_| {
                // Unreachable with a body built by the constructors, and handled anyway: this
                // process aborts on panic, so "cannot happen" is not a licence to unwrap.
                br#"{"error":{"code":"internal","message":"the response could not be encoded"}}"#
                    .to_vec()
            }),
        ),
    };
    write!(
        out,
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason_phrase(response.status)
    )?;
    write!(out, "content-type: {content_type}\r\n")?;
    write!(out, "content-length: {}\r\n", body.len())?;
    out.write_all(b"connection: close\r\n")?;
    out.write_all(b"cache-control: no-store\r\n")?;
    out.write_all(b"x-content-type-options: nosniff\r\n")?;
    for (name, value) in &response.headers {
        write!(out, "{name}: {value}\r\n")?;
    }
    out.write_all(b"\r\n")?;
    out.write_all(&body)?;
    out.flush()
}

// ── the verification envelope ─────────────────────────────────────────────────────────

/// Did the signatures over this record still check out?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    /// Checked, and nothing has changed since signing.
    Ok,
    /// Checked, and it does not hold. The record is served anyway, marked.
    Failed,
    /// Not checked. A different claim from [`Integrity::Failed`], and never rendered as one.
    Unknown,
}

/// Does the authority the record describes still hold *now*?
///
/// Separate from [`Integrity`] and never folded into it. An archived report whose warrant lapsed is
/// intact and stale; collapsing the two makes it look tampered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    /// The deadline has not passed.
    Live,
    /// The deadline passed. The signatures are unaffected.
    Expired,
    /// Not determined.
    Unknown,
}

/// The server's verdict about whatever it just served.
///
/// Computed here, always, from the same functions `warrantor verify` calls. A client renders it and
/// never derives it: no key and no signature check ever crosses the Rust line, which is what keeps
/// a renderer a viewer rather than a second verifier that can disagree with this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verification {
    /// Signature and digest state.
    pub integrity: Integrity,
    /// Deadline state.
    pub liveness: Liveness,
    /// When this verdict was taken, epoch seconds.
    pub checked_at: u64,
    /// The digest the verdict covers, when there is one.
    pub digest: Option<String>,
    /// Hex verifying key that signed it, when integrity is [`Integrity::Ok`].
    ///
    /// Absent on a failure, deliberately: reporting the key a broken record *claims* would let a
    /// forged file put a trusted-looking key in front of a reader.
    pub signed_by: Option<String>,
    /// A stable word for the failure or the reason nothing was checked.
    pub code: Option<&'static str>,
    /// What the verdict means, in the terms a human reviewing a run needs.
    pub reason: String,
}

impl Verification {
    /// True only when integrity is [`Integrity::Ok`].
    ///
    /// Liveness deliberately does not enter into it: an expired report is a true record of a past
    /// decision, and marking it unverified would teach a reader to distrust their own archive.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.integrity == Integrity::Ok
    }

    /// The verdict for a response that read no record.
    #[must_use]
    pub fn not_attempted(checked_at: u64) -> Self {
        Self {
            integrity: Integrity::Unknown,
            liveness: Liveness::Unknown,
            checked_at,
            digest: None,
            signed_by: None,
            code: Some("not_attempted"),
            reason: "nothing was verified: the request was refused before any record was read."
                .to_string(),
        }
    }

    /// The verdict for data that exists but that nothing signs.
    #[must_use]
    pub fn unsigned(checked_at: u64, reason: &str) -> Self {
        Self {
            integrity: Integrity::Unknown,
            liveness: Liveness::Unknown,
            checked_at,
            digest: None,
            signed_by: None,
            code: Some("unsigned_record"),
            reason: reason.to_string(),
        }
    }
}

// ── the API surface ───────────────────────────────────────────────────────────────────

/// Which warrants a listing should include.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilter {
    /// Only this lifecycle state.
    pub state: Option<WarrantState>,
    /// Only warrants issued at or after this epoch second.
    pub since: Option<u64>,
}

/// Which slice of time a summary should answer about.
///
/// `since` is inclusive and `until` is exclusive, both in epoch seconds. `None` on a side means
/// unbounded, so the default is the all-time aggregate this route always answered.
///
/// It exists because the route used to accept `?since=` and ignore it: `request.query` was read at
/// exactly one place, inside [`list_filter`], reached only from `Target::List`. A caller asking for
/// one month got a 200 carrying every refusal ever recorded, and a console rendering that under a
/// month heading would be the `?status=open silently returning every warrant` defect with a nicer
/// font. A window the API cannot apply must not be a window the API accepts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SummaryWindow {
    /// At or after this epoch second.
    pub since: Option<u64>,
    /// Strictly before this epoch second.
    pub until: Option<u64>,
}

impl SummaryWindow {
    /// Whether a record stamped `at` falls inside this window.
    ///
    /// Delegates to [`crate::guard::window_holds`] rather than restating the half-open rule, because
    /// the guard log windows itself with the same rule and two copies of an inclusive/exclusive
    /// boundary is the shape that drifts by one on the next edit — putting a refusal and its own
    /// session's guard signals in different months.
    #[must_use]
    pub fn holds(&self, at: u64) -> bool {
        crate::guard::window_holds(at, self.since, self.until)
    }
}

/// What every windowed answer has to carry about the timestamps it was filtered on.
///
/// Stated by the server rather than composed by the client, for the same reason the guard note is:
/// the caveat is a fact about how the records were written, and a renderer inventing its own
/// wording for it will eventually invent a weaker one. It is not "these totals are approximate" —
/// the error is not noise.
///
/// It names each half separately because the two halves of this payload are filtered on different
/// things, and a single sentence covering both was **false about one of them**. Refusals are
/// stamped once per session, at the end, so filtering a refusal on its own `at` is filtering it on
/// its session. Guard records are not: an attach record is written at the start of the session,
/// each signal at the moment of its call, and the counters at the end, so the guard half is
/// filtered by SESSION — see [`crate::guard::GuardLog::within`] — and only records written before
/// sessions carried an id still fall back to their own clock.
const WINDOW_CAVEAT: &str =
    "This window is applied per record type, on the clock each record actually carries, and the two \
     halves of this answer do not carry the same one. REFUSALS: every refusal a session recorded is \
     stamped with one moment, the time that SESSION ENDED, so a session straddling the boundary \
     contributes all of its refusals to the side it ended on -- systematically attributed, not \
     merely imprecise. GUARD: its three record types are written on three different clocks -- the \
     attach record when the session STARTED, each signal at the moment of the CALL it describes (a \
     repeat keeping the first sighting's time), the counters when the session ENDED -- so the guard \
     half is windowed by SESSION and a session is held or dropped whole, on the last moment it \
     wrote anything. Guard records written before sessions carried an id cannot be grouped and are \
     each windowed on their own clock, which can split one such session across the boundary; \
     `guard.unattributed_records` counts exactly those. `unreadable_lines` is counted over the \
     WHOLE log and is not windowed at all: a line that did not parse has no timestamp to compare.";

/// Everything the HTTP layer is allowed to ask for.
///
/// A trait for the same reason [`crate::mcp::Endpoint`] is one: it keeps [`route`] and
/// [`serve_conn`] free of any warrant knowledge, so a transport bug cannot hide behind a policy stub
/// and a policy bug cannot hide behind a transport test. The real implementation is [`StoreApi`].
pub trait Api {
    /// The clock, injected so a caller owns it and tests are not time-dependent.
    fn now(&self) -> u64;
    /// Version, store location and process identity.
    fn health(&mut self) -> Response;
    /// Every warrant, newest first, filtered.
    fn list_warrants(&mut self, filter: &ListFilter) -> Response;
    /// One warrant: claims, bounds, bound strengths, containment.
    fn warrant(&mut self, id: &str) -> Response;
    /// The report bundle, with its verdict.
    fn report(&mut self, id: &str) -> Response;
    /// Staged effects in release order.
    fn effects(&mut self, id: &str) -> Response;
    /// Refusals recorded for this warrant.
    fn refusals(&mut self, id: &str) -> Response;
    /// The signed, exportable evidence bundle.
    fn evidence(&mut self, id: &str) -> Response;
    /// Release the staged effects. Requires settle authority.
    fn settle(&mut self, id: &str, commit: Option<&str>) -> Response;
    /// Discard the work. Requires settle authority.
    fn void(&mut self, id: &str) -> Response;
    /// End the run now and write a signed stop record.
    fn stop(&mut self, id: &str, reason: Option<&str>) -> Response;
    /// Refusals aggregated across every warrant, over one window — the tuning signal.
    fn summary_refusals(&mut self, window: &SummaryWindow) -> Response;
    /// The morning digest.
    fn summary_daily(&mut self) -> Response;
}

/// The routes, and the single method each accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Health,
    List,
    Warrant(String),
    Report(String),
    Effects(String),
    Refusals(String),
    Evidence(String),
    Settle(String),
    Void(String),
    Stop(String),
    SummaryRefusals,
    SummaryDaily,
}

/// Resolve a target, refusing a bad id before the store is reachable.
fn resolve(segments: &[String]) -> Result<(Target, &'static str), Response> {
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    let bad_id = || {
        refuse(
            status::BAD_REQUEST,
            "malformed_warrant_id",
            "a warrant id is wrt_ followed by up to 64 letters, digits, underscores or hyphens",
        )
    };
    match parts.as_slice() {
        ["v1", "health"] => Ok((Target::Health, "GET")),
        ["v1", "warrants"] => Ok((Target::List, "GET")),
        ["v1", "summary", "refusals"] => Ok((Target::SummaryRefusals, "GET")),
        ["v1", "summary", "daily"] => Ok((Target::SummaryDaily, "GET")),
        ["v1", "warrants", id] => {
            if !is_warrant_id(id) {
                return Err(bad_id());
            }
            Ok((Target::Warrant((*id).to_string()), "GET"))
        }
        ["v1", "warrants", id, leaf] => {
            if !is_warrant_id(id) {
                return Err(bad_id());
            }
            let id = (*id).to_string();
            match *leaf {
                "report" => Ok((Target::Report(id), "GET")),
                "effects" => Ok((Target::Effects(id), "GET")),
                "refusals" => Ok((Target::Refusals(id), "GET")),
                "evidence" => Ok((Target::Evidence(id), "GET")),
                "settle" => Ok((Target::Settle(id), "POST")),
                "void" => Ok((Target::Void(id), "POST")),
                "stop" => Ok((Target::Stop(id), "POST")),
                _ => Err(not_found_route()),
            }
        }
        _ => Err(not_found_route()),
    }
}

fn not_found_route() -> Response {
    refuse(
        status::NOT_FOUND,
        "no_such_route",
        "this server serves /v1/health, /v1/warrants, /v1/warrants/{id}[/report|effects|refusals|\
         evidence|settle|void|stop] and /v1/summary/{refusals|daily}",
    )
}

/// The JSON object a POST body carries, or the refusal it earns.
fn body_object(request: &HttpRequest) -> Result<serde_json::Map<String, Value>, Response> {
    if request.body.is_empty() {
        return Ok(serde_json::Map::new());
    }
    let value: Value = serde_json::from_slice(&request.body).map_err(|_| {
        refuse(
            status::BAD_REQUEST,
            "malformed_body",
            "the request body must be a JSON object",
        )
    })?;
    match value {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(serde_json::Map::new()),
        _ => Err(refuse(
            status::BAD_REQUEST,
            "malformed_body",
            "the request body must be a JSON object",
        )),
    }
}

/// An optional non-empty string field, refusing every other shape.
///
/// Absent is fine and means absent. Present-but-not-a-string is a refusal, never a silent default —
/// the reading [`crate::mcp_endpoints`] already applies to every bound it parses.
fn optional_text(
    body: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<String>, Response> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(refuse(
            status::BAD_REQUEST,
            "malformed_field",
            "that field must be a string when it is present at all",
        )),
    }
}

/// Dispatch a parsed, already-authenticated request.
///
/// Pure dispatch: everything it can answer on its own is a refusal about the request's shape, and
/// everything else is handed to the [`Api`]. Tests drive this directly, with no socket.
pub fn route<A: Api>(api: &mut A, request: &HttpRequest) -> Response {
    let now = api.now();
    dispatch(api, request).stamped(now)
}

fn dispatch<A: Api>(api: &mut A, request: &HttpRequest) -> Response {
    let (target, allowed) = match resolve(&request.segments) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if request.method != allowed {
        // `Allow` is a static string per route, so no caller-supplied text reaches a header.
        let allow: &'static str = if allowed == "GET" { "GET" } else { "POST" };
        return refuse(
            status::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "that route accepts a different method; see the Allow header",
        )
        .with_header("Allow", allow);
    }

    // Query handling is per route, and every route has one. Two routes parse a query; the rest
    // refuse one. The middle option -- accept and ignore -- is what shipped, and it is the only one
    // that can answer 200 to a question it did not ask: `/v1/summary/refusals?since=X` returned the
    // all-time aggregate under whatever heading the caller had in mind. A filter that cannot run
    // must not report success.
    if !matches!(target, Target::List | Target::SummaryRefusals) {
        if let Err(response) = no_query(request) {
            return response;
        }
    }

    match target {
        Target::Health => api.health(),
        Target::List => match list_filter(request) {
            Ok(filter) => api.list_warrants(&filter),
            Err(response) => response,
        },
        Target::Warrant(id) => api.warrant(&id),
        Target::Report(id) => api.report(&id),
        Target::Effects(id) => api.effects(&id),
        Target::Refusals(id) => api.refusals(&id),
        Target::Evidence(id) => api.evidence(&id),
        Target::SummaryRefusals => match summary_window(request) {
            Ok(window) => api.summary_refusals(&window),
            Err(response) => response,
        },
        Target::SummaryDaily => api.summary_daily(),
        Target::Settle(id) => {
            match body_object(request).and_then(|b| optional_text(&b, "commit")) {
                Ok(commit) => api.settle(&id, commit.as_deref()),
                Err(response) => response,
            }
        }
        Target::Void(id) => match body_object(request) {
            Ok(_) => api.void(&id),
            Err(response) => response,
        },
        Target::Stop(id) => match body_object(request).and_then(|b| optional_text(&b, "reason")) {
            Ok(reason) => api.stop(&id, reason.as_deref()),
            Err(response) => response,
        },
    }
}

/// Parse `?state=` and `?since=`, refusing anything else.
///
/// An unknown query key is a refusal rather than an ignored word. `?status=open` silently returning
/// every warrant is the shape of the `--budget 5x` bug: the caller believed they had filtered, and
/// had not, at the exact moment they were thinking about the filter.
fn list_filter(request: &HttpRequest) -> Result<ListFilter, Response> {
    let mut filter = ListFilter::default();
    for (key, value) in &request.query {
        match key.as_str() {
            "state" => {
                filter.state = Some(match value.as_str() {
                    "open" => WarrantState::Open,
                    "held" => WarrantState::Held,
                    "settled" => WarrantState::Settled,
                    "void" => WarrantState::Void,
                    _ => {
                        return Err(refuse(
                            status::BAD_REQUEST,
                            "malformed_query",
                            "state must be one of open, held, settled, void",
                        ))
                    }
                });
            }
            "since" => {
                let Ok(parsed) = value.parse::<u64>() else {
                    return Err(refuse(
                        status::BAD_REQUEST,
                        "malformed_query",
                        "since must be a whole number of seconds since the Unix epoch",
                    ));
                };
                filter.since = Some(parsed);
            }
            _ => {
                return Err(refuse(
                    status::BAD_REQUEST,
                    "malformed_query",
                    "this route accepts only state and since; an unrecognised filter is refused \
                     rather than ignored",
                ))
            }
        }
    }
    Ok(filter)
}

/// Refuse a query string on a route that has no filters.
///
/// The other half of [`list_filter`]'s argument, applied to the ten routes that had no parser at
/// all. `GET /v1/warrants/{id}?state=settled` used to answer 200 with the warrant, which reads as
/// though the parameter meant something. It never did. This makes it a 400 instead — a behaviour
/// change to `/v1`, and the right one: the alternative is a surface where whether a filter is
/// honoured depends on which route the caller happened to hit.
fn no_query(request: &HttpRequest) -> Result<(), Response> {
    if request.query.is_empty() {
        return Ok(());
    }
    Err(refuse(
        status::BAD_REQUEST,
        "malformed_query",
        "this route takes no query parameters; an unrecognised filter is refused rather than \
         ignored, because a caller who believed they had filtered and had not is the failure this \
         surface exists to prevent",
    ))
}

/// Parse `?since=` and `?until=` for the summary route, refusing anything else.
///
/// Both are whole seconds since the Unix epoch. An inverted or empty window is refused rather than
/// answered: `since=B&until=A` would return an empty aggregate, which is shaped exactly like a
/// quiet month and is not one.
fn summary_window(request: &HttpRequest) -> Result<SummaryWindow, Response> {
    let mut window = SummaryWindow::default();
    for (key, value) in &request.query {
        let field =
            match key.as_str() {
                "since" => &mut window.since,
                "until" => &mut window.until,
                _ => return Err(refuse(
                    status::BAD_REQUEST,
                    "malformed_query",
                    "this route accepts only since and until; an unrecognised filter is refused \
                     rather than ignored",
                )),
            };
        let Ok(parsed) = value.parse::<u64>() else {
            return Err(refuse(
                status::BAD_REQUEST,
                "malformed_query",
                "since and until must each be a whole number of seconds since the Unix epoch",
            ));
        };
        *field = Some(parsed);
    }
    if let (Some(start), Some(end)) = (window.since, window.until) {
        if start >= end {
            return Err(refuse(
                status::BAD_REQUEST,
                "malformed_query",
                "until must be strictly after since: an empty window answers nothing while looking \
                 exactly like a window in which nothing happened",
            ));
        }
    }
    Ok(window)
}

// ── authentication ────────────────────────────────────────────────────────────────────

/// A per-process bearer token.
///
/// Minted at startup, never persisted beyond the run, and checked **before any route is resolved**.
/// That ordering is the property: a caller with no token gets the same 401 for a warrant that exists
/// and one that does not, so the API cannot be used to enumerate ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    value: String,
}

impl SessionToken {
    /// Mint 32 bytes from the system CSPRNG.
    ///
    /// # Errors
    /// [`ServeError::Token`] if the operating system will not supply randomness. Refusing to start
    /// is the only safe response: a server that fell back to a weaker source would have a token
    /// shaped like a secret and not be one.
    pub fn mint() -> Result<Self, ServeError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| ServeError::Token(format!("the system CSPRNG refused: {e}")))?;
        Ok(Self {
            value: hex::encode(bytes),
        })
    }

    /// Adopt an existing token value, for tests and for a caller that minted its own.
    #[must_use]
    pub fn from_value(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// The token as it appears after `Bearer `.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Does a presented value match?
    ///
    /// The comparison folds every byte with no early return, so a caller cannot learn the token one
    /// character at a time from response timing. The length check *is* an early return, and that is
    /// deliberate and harmless: the length is a fixed public constant documented in this file, so
    /// leaking it leaks something the attacker read here.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        let expected = self.value.as_bytes();
        let got = presented.as_bytes();
        if expected.len() != got.len() {
            return false;
        }
        let mut difference: u8 = 0;
        for (a, b) in expected.iter().zip(got.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }

    /// Write the token where a local client can read it, owner-only where the platform allows.
    ///
    /// Returns the path so a caller can name it. On Unix the directory is `0o700` and the file
    /// `0o600`. **On Windows `std` offers no equivalent**, so the file is protected by inherited
    /// directory ACLs only — the caller is expected to say so out loud rather than let a reader
    /// assume parity. Nothing here relies on the file: the token is also printed to stderr, so the
    /// file is a convenience.
    ///
    /// # Errors
    /// [`ServeError::Token`] if the directory or file cannot be created.
    pub fn write_to(&self, root: &Path) -> Result<PathBuf, ServeError> {
        let path = default_token_path(root);
        let dir = path
            .parent()
            .ok_or_else(|| ServeError::Token("the store root has no parent".to_string()))?
            .to_path_buf();
        std::fs::create_dir_all(&dir)
            .map_err(|e| ServeError::Token(format!("create the token directory: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&dir, mode)
                .map_err(|e| ServeError::Token(format!("restrict the token directory: {e}")))?;
        }
        self.write_secret(&path)?;
        Ok(path)
    }

    /// Write the token to a path the operator named with `--token-file`.
    ///
    /// The difference from [`write_to`](Self::write_to) is what it will *not* do. It does not create
    /// the containing directory and it does not change that directory's mode: a caller who names a
    /// path has already decided where the secret lives, and a server that silently mkdir'd a tree —
    /// or quietly narrowed the permissions of a directory holding other people's files — would be
    /// making that decision for them. A missing directory is a refusal, before the socket is bound,
    /// while the operator is still reading the terminal.
    ///
    /// The file itself is still `0o600` on Unix. That is the one permission that is unambiguously
    /// about this file, so it is not up for negotiation.
    ///
    /// # Errors
    /// [`ServeError::Token`] if the containing directory does not exist, or the file cannot be
    /// created or written.
    pub fn write_to_file(&self, path: &Path) -> Result<(), ServeError> {
        if let Some(parent) = path.parent() {
            // `Path::new("token").parent()` is `Some("")` — an empty parent means the current
            // directory, which exists by construction, so it is not checked.
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                return Err(ServeError::Token(format!(
                    "the directory holding {} does not exist. This will not create it: a session \
                     token is a secret, and the directory it lives in is a decision you make, not \
                     one a server makes on the way to binding a socket.",
                    path.display()
                )));
            }
        }
        self.write_secret(path)
    }

    /// The one place bytes of the token reach the filesystem.
    fn write_secret(&self, path: &Path) -> Result<(), ServeError> {
        // Truncate through a fresh handle so a previous run's longer token cannot survive as a
        // tail on disk.
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
        };
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path);
        let mut file =
            file.map_err(|e| ServeError::Token(format!("create the token file: {e}")))?;
        // No trailing newline: `$(cat ~/.warrantor/serve/token)` is the way this gets used, and a
        // newline that survives into an `Authorization` header is a 401 nobody can explain.
        file.write_all(self.value.as_bytes())
            .and_then(|()| file.flush())
            .map_err(|e| ServeError::Token(format!("write the token file: {e}")))?;
        Ok(())
    }
}

/// Where the token goes when the operator does not say.
///
/// Under the store root, so it lives and dies with the store it unlocks, and inside its own
/// directory so Unix can put a `0o700` in front of the `0o600` — two independent things that have
/// to be wrong before another local user reads it.
#[must_use]
pub fn default_token_path(root: &Path) -> PathBuf {
    root.join("serve").join("token")
}

/// Extract the bearer value from an `Authorization` header.
fn bearer_of(header: &str) -> Option<&str> {
    let (scheme, value) = header.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !value.trim().is_empty() {
        Some(value.trim())
    } else {
        None
    }
}

// ── the console, served same-origin ───────────────────────────────────────────────────

/// `index.html`, compiled in.
const CONSOLE_HTML: &str = include_str!("console/index.html");
/// `console.css`, compiled in.
const CONSOLE_CSS: &str = include_str!("console/console.css");
/// `console.js`, compiled in.
const CONSOLE_JS: &str = include_str!("console/console.js");

/// The content security policy the console document is served under.
///
/// `connect-src 'self'` is the load-bearing directive. The console holds a token to an API that
/// can hold settle authority, so the question that matters is not whether a script can run but
/// where it could send what it read. Restricting connections to this origin means a script that
/// somehow executed here has nowhere to send the token: no beacon, no image ping, no websocket.
/// `default-src 'none'` makes every other fetch category deny-by-default rather than
/// allow-by-omission — the same rule this product applies to bounds, where an absent limit means
/// none and never unlimited.
///
/// `frame-ancestors 'none'` is the other half of the CORS decision recorded at the top of this
/// module. Refusing cross-origin *reads* would be undone if a hostile page could frame the console
/// and drive it as the user, so framing is refused too.
const CONSOLE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                           connect-src 'self'; img-src 'self' data:; base-uri 'none'; \
                           form-action 'none'; frame-ancestors 'none'";

/// Serve a console asset, or `None` when the path is not one.
///
/// # Why this runs before authentication
///
/// A browser cannot put an `Authorization` header on the navigation that loads a page, so a
/// token-gated document could never be opened by the client it exists for. Serving it
/// unauthenticated is safe for one specific reason, and only that reason: these three responses
/// are fixed byte strings compiled into the binary. They contain no warrant, no id, no store path
/// and no token, and they are byte-identical whether or not this machine has ever granted a
/// warrant. An unauthenticated caller learns exactly one thing — that something is listening —
/// which the TCP handshake already told them.
///
/// The property that matters is therefore untouched: `/v1` still answers 401 before [`resolve`]
/// runs, so an unauthenticated caller still cannot tell a real warrant id from an invented one.
/// This function returns `None` for every `/v1` path, and the router below is unreachable from it.
fn console_asset(request: &HttpRequest) -> Option<Response> {
    let parts: Vec<&str> = request.segments.iter().map(String::as_str).collect();
    let (content_type, bytes) = match parts.as_slice() {
        [] | ["index.html"] => ("text/html; charset=utf-8", CONSOLE_HTML.as_bytes()),
        ["console.css"] => ("text/css; charset=utf-8", CONSOLE_CSS.as_bytes()),
        ["console.js"] => ("text/javascript; charset=utf-8", CONSOLE_JS.as_bytes()),
        _ => return None,
    };

    // A document is a GET. Anything else is a mistake worth naming rather than a body to ignore.
    if request.method != "GET" {
        return Some(
            refuse(
                status::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "the console is served over GET",
            )
            .with_header("Allow", "GET"),
        );
    }

    Some(
        Response::asset(status::OK, content_type, bytes)
            .with_header("content-security-policy", CONSOLE_CSP)
            .with_header("x-frame-options", "DENY")
            .with_header("referrer-policy", "no-referrer"),
    )
}

/// Authenticate, then dispatch.
///
/// The order is the point. A 401 is answered before [`resolve`] runs, so an unauthenticated caller
/// cannot tell a real warrant id from an invented one, a real route from a typo, or a settle route
/// from a read route. The body names nothing: it does not say which header was wrong, whether the
/// token was close, or that this store holds anything at all — the notary's rule, that a denial
/// which explains itself describes the shape of the boundary.
pub fn handle<A: Api>(api: &mut A, token: &SessionToken, request: &HttpRequest) -> Response {
    // The console document, stylesheet and script are served before the token check. See
    // [`console_asset`] for why that does not weaken the line above: it answers only for paths
    // that carry no store data, and returns `None` for every `/v1` path.
    if let Some(response) = console_asset(request) {
        return response;
    }

    let presented = request.authorization.as_deref().and_then(bearer_of);
    let authenticated = presented.is_some_and(|value| token.matches(value));
    if !authenticated {
        return Response::error(
            status::UNAUTHORIZED,
            "unauthorized",
            "this request carried no usable bearer token",
            &Verification::not_attempted(api.now()),
        )
        .with_header("WWW-Authenticate", "Bearer");
    }
    route(api, request)
}

/// Read one request, answer it, and stop.
///
/// Generic over the reader and writer, so the whole parse → authenticate → route → write path is
/// driven in tests by a `Cursor` and a `Vec<u8>` with no socket anywhere — the same shape
/// [`crate::mcp::serve`] uses, and the reason its test file opens zero sockets.
///
/// # Errors
/// I/O failures on the writer only. A malformed *request* is answered with a JSON error, because a
/// server that accepts a connection and never replies hangs its peer forever.
pub fn serve_conn<A: Api, R: BufRead, W: Write>(
    api: &mut A,
    token: &SessionToken,
    input: &mut R,
    output: &mut W,
) -> std::io::Result<()> {
    let response = match parse_request(input) {
        Ok(request) => handle(api, token, &request),
        // A framing refusal is built before any clock is in scope, so it is stamped here.
        Err(response) => response.stamped(api.now()),
    };
    write_response(output, &response)
}

// ── refusal records ───────────────────────────────────────────────────────────────────

/// Which bound refused, coarsely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// A tool the warrant does not permit, or a class refused even in observe mode.
    Tool,
    /// A destination the warrant does not permit.
    Egress,
}

/// One durable refusal, as the API can read it back.
///
/// # Why this file has to exist
///
/// [`crate::proxy::AuthorityRequest`] and [`crate::egress::EgressRefusal`] live only inside a live
/// [`crate::proxy::Proxy`], for the lifetime of one MCP session, and are printed to stderr when that
/// session ends. Nothing wrote them down. So `/v1/warrants/{id}/refusals` could not have been built
/// by calling an existing function — the *types* existed and the *data* did not.
///
/// The sink is deliberately the narrowest thing that fixes that: append-only JSONL under
/// `<root>/refusals/<id>.jsonl`, written once at the end of a session by the process that held the
/// proxy, read by this API and by nothing else. One writer per session and appends only, so it does
/// not become a second writer racing the warrant store.
///
/// It is **not** hash-chained, and it is not signed. A staging queue is chained because a staged
/// effect that silently vanished would be work the developer was promised and did not get; a missing
/// refusal costs a tuning signal. Claiming a chain here would be claiming a guarantee to match a
/// neighbour's shape rather than because anything needs it — and the reader says so on every
/// response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalRecord {
    /// Wire format; see [`REFUSAL_RECORD_FORMAT`].
    pub format: String,
    /// The warrant the refusal happened under.
    pub warrant_id: String,
    /// When the session that recorded it ended, epoch seconds.
    pub at: u64,
    /// Tool bound or egress bound.
    pub kind: RefusalKind,
    /// The tool whose call was refused.
    pub tool: String,
    /// The bound that refused it, verbatim from the proxy.
    pub bound: String,
    /// The destination, for an egress refusal.
    pub destination: Option<String>,
    /// The argument the destination was named in.
    pub argument: Option<String>,
    /// The broker's coarse reason word, for an egress refusal.
    pub reason: Option<String>,
    /// How many times this exact refusal happened in that session.
    pub count: u32,
}

/// What a refusal log holds, and how much of it did not parse.
///
/// The unreadable count is carried rather than dropped. [`crate::store::WarrantStore::list`]
/// silently skips a corrupt warrant file, which is right for a CLI listing and wrong for an API: a
/// count that is quietly lower than what is on disk is an answer with no signal that it is short.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefusalLog {
    /// The records that parsed.
    pub records: Vec<RefusalRecord>,
    /// Lines that did not.
    pub unreadable_lines: usize,
}

/// Append a finished session's refusals to the durable log.
///
/// Called by the process that held the proxy, once, as its session ends. The proxy books an egress
/// denial **twice** — one [`AuthorityRequest`] under the `egress_hosts` bound and one
/// [`EgressRefusal`] carrying the destination — so the `egress_hosts` authority requests are
/// dropped here and the egress records kept: the destination is the part an operator acts on, and
/// counting both would double every egress number in the summary.
///
/// # Errors
/// [`ServeError::Refusals`] if the log cannot be created or appended to.
pub fn record_refusals(
    root: &Path,
    warrant_id: &str,
    tool_refusals: &[&AuthorityRequest],
    egress_refusals: &[&EgressRefusal],
    at: u64,
) -> Result<usize, ServeError> {
    let mut records: Vec<RefusalRecord> = Vec::new();
    for request in tool_refusals {
        if request.bound == "egress_hosts" {
            continue;
        }
        records.push(RefusalRecord {
            format: REFUSAL_RECORD_FORMAT.to_string(),
            warrant_id: warrant_id.to_string(),
            at,
            kind: RefusalKind::Tool,
            tool: request.tool.clone(),
            bound: request.bound.clone(),
            destination: None,
            argument: None,
            reason: None,
            count: request.count,
        });
    }
    for refusal in egress_refusals {
        records.push(RefusalRecord {
            format: REFUSAL_RECORD_FORMAT.to_string(),
            warrant_id: warrant_id.to_string(),
            at,
            kind: RefusalKind::Egress,
            tool: refusal.tool.clone(),
            bound: "egress_hosts".to_string(),
            destination: Some(refusal.destination.clone()),
            argument: Some(refusal.argument.clone()),
            reason: Some(crate::egress::reason_word(refusal.reason.clone()).to_string()),
            count: refusal.count,
        });
    }
    if records.is_empty() {
        return Ok(0);
    }

    let dir = root.join("refusals");
    std::fs::create_dir_all(&dir)
        .map_err(|e| ServeError::Refusals(format!("create the refusal directory: {e}")))?;
    let path = dir.join(format!("{warrant_id}.jsonl"));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| ServeError::Refusals(format!("open the refusal log: {e}")))?;
    let mut body = String::new();
    for record in &records {
        let line = serde_json::to_string(record)
            .map_err(|e| ServeError::Refusals(format!("encode a refusal record: {e}")))?;
        body.push_str(&line);
        body.push('\n');
    }
    file.write_all(body.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|e| ServeError::Refusals(format!("append to the refusal log: {e}")))?;
    Ok(records.len())
}

fn read_refusal_file(path: &Path, log: &mut RefusalLog) {
    let Ok(body) = std::fs::read_to_string(path) else {
        // An unreadable file is one unreadable line's worth of signal, not a reason to refuse the
        // whole listing: the same reading `WarrantStore::list` takes, with the count kept.
        log.unreadable_lines = log.unreadable_lines.saturating_add(1);
        return;
    };
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RefusalRecord>(line) {
            Ok(record) => log.records.push(record),
            Err(_) => log.unreadable_lines = log.unreadable_lines.saturating_add(1),
        }
    }
}

/// Read one warrant's refusal log.
#[must_use]
pub fn read_refusals(root: &Path, warrant_id: &str) -> RefusalLog {
    let mut log = RefusalLog::default();
    let path = root.join("refusals").join(format!("{warrant_id}.jsonl"));
    if path.exists() {
        read_refusal_file(&path, &mut log);
    }
    log
}

/// Read every warrant's refusal log.
#[must_use]
pub fn read_all_refusals(root: &Path) -> RefusalLog {
    let mut log = RefusalLog::default();
    let Ok(entries) = std::fs::read_dir(root.join("refusals")) else {
        return log;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            read_refusal_file(&path, &mut log);
        }
    }
    log
}

/// Occurrences at or above which a refusal is "repeated" rather than a one-off.
///
/// A threshold, not a truth. It is named and public so the number is arguable rather than buried in
/// a comparison.
pub const REPEATED_OCCURRENCES: u64 = 5;
/// Distinct warrants at or above which a refusal has spread beyond one run.
pub const SPREAD_WARRANTS: usize = 2;

/// What a group of refusals is probably telling you.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalSignal {
    /// The same wall, repeatedly, in more than one run.
    BoundsProbablyWrong,
    /// The same wall repeatedly, but only in one run.
    RepeatedInOneRun,
    /// Once or twice, in one run.
    Isolated,
}

/// One tool or destination, aggregated across every warrant.
///
/// This is the refusal-review habit expressed as an API. The raw per-warrant list answers "what did
/// this run hit"; only the aggregate answers the question that changes what an operator *does* —
/// whether the bound is wrong or the agent is. Twenty refusals of one destination across four
/// warrants is a bound that was scoped wrong. One refusal of `rm` is the interesting one, and it is
/// the one a per-run view buries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusalGroup {
    /// Tool bound or egress bound.
    pub kind: RefusalKind,
    /// The tool name, or the destination for an egress refusal.
    pub subject: String,
    /// Total refusals across every warrant.
    pub occurrences: u64,
    /// How many distinct warrants hit it.
    pub warrants: usize,
    /// Which ones, so an operator can go and read a run.
    pub warrant_ids: Vec<String>,
    /// The bounds that did the refusing.
    pub bounds: Vec<String>,
    /// The heuristic verdict.
    pub signal: RefusalSignal,
    /// The verdict as a sentence, in the terms the operator acts on.
    pub guidance: String,
}

/// Group refusals by tool and by destination, across warrants, and read the signal.
///
/// Sorted loudest first, then by name, so the ordering is total and a client renders a stable list.
#[must_use]
pub fn aggregate_refusals(records: &[RefusalRecord]) -> Vec<RefusalGroup> {
    struct Bucket {
        occurrences: u64,
        warrants: BTreeSet<String>,
        bounds: BTreeSet<String>,
    }
    let mut buckets: BTreeMap<(RefusalKind, String), Bucket> = BTreeMap::new();
    for record in records {
        let subject = match record.kind {
            RefusalKind::Tool => record.tool.clone(),
            RefusalKind::Egress => record
                .destination
                .clone()
                .unwrap_or_else(|| "(unresolved destination)".to_string()),
        };
        let bucket = buckets
            .entry((record.kind, subject))
            .or_insert_with(|| Bucket {
                occurrences: 0,
                warrants: BTreeSet::new(),
                bounds: BTreeSet::new(),
            });
        bucket.occurrences = bucket.occurrences.saturating_add(u64::from(record.count));
        bucket.warrants.insert(record.warrant_id.clone());
        bucket.bounds.insert(record.bound.clone());
    }

    let mut out: Vec<RefusalGroup> = buckets
        .into_iter()
        .map(|((kind, subject), bucket)| {
            let warrants = bucket.warrants.len();
            let occurrences = bucket.occurrences;
            let noun = match kind {
                RefusalKind::Tool => "was refused",
                RefusalKind::Egress => "was refused as a destination",
            };
            let (signal, guidance) =
                if occurrences >= REPEATED_OCCURRENCES && warrants >= SPREAD_WARRANTS {
                    (
                        RefusalSignal::BoundsProbablyWrong,
                        format!(
                        "{subject} {noun} {occurrences} times across {warrants} warrants. The same \
                         wall in more than one run is usually a bound that is wrong rather than an \
                         agent that is wrong: widen it deliberately in the next grant, or decide \
                         that the refusal is the point and stop granting work that needs it."
                    ),
                    )
                } else if occurrences >= REPEATED_OCCURRENCES {
                    (
                        RefusalSignal::RepeatedInOneRun,
                        format!(
                        "{subject} {noun} {occurrences} times under a single warrant. Either that \
                         run needed it and the bound was too narrow, or the agent looped against a \
                         wall it should have adapted to. Read that run before widening anything."
                    ),
                    )
                } else {
                    (
                        RefusalSignal::Isolated,
                        format!(
                        "{subject} {noun} {occurrences} time(s), under {warrants} warrant(s). Look \
                         at that one. A single refusal is the interesting case, not the noisy one: \
                         it is where an agent tried something it was not granted."
                    ),
                    )
                };
            RefusalGroup {
                kind,
                subject,
                occurrences,
                warrants,
                warrant_ids: bucket.warrants.into_iter().collect(),
                bounds: bucket.bounds.into_iter().collect(),
                signal,
                guidance,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then(a.subject.cmp(&b.subject))
    });
    out
}

// ── keys ──────────────────────────────────────────────────────────────────────────────

/// Load a signing key, refusing to create one.
///
/// `warrantor`'s own `load_or_create_key` mints a key on first use with default file permissions,
/// which is right for a CLI a developer just installed and wrong for a server: a fresh box would
/// silently acquire an issuer identity, world-readable on Unix, and start signing evidence with it.
/// A server loads or refuses.
///
/// A permissive mode is a warning to stderr rather than a refusal. Refusing would lock out every
/// existing install created by the CLI, which is a real cost for a hardening this server cannot
/// retroactively apply.
///
/// # Errors
/// [`ServeError::Key`] when the key is absent or not 32 bytes.
pub fn load_key(path: &Path, label: &str) -> Result<SigningKey, ServeError> {
    let body = std::fs::read(path).map_err(|_| {
        ServeError::Key(format!(
            "no {label} key was found. `warrantor serve` loads keys and never creates them: a \
             server that minted an identity on first use would sign evidence with a key nobody \
             chose. Run a `warrantor` command that creates it first."
        ))
    })?;
    let bytes: [u8; 32] = body
        .as_slice()
        .try_into()
        .map_err(|_| ServeError::Key(format!("the {label} key is not 32 bytes")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                eprintln!(
                    "warrantor: the {label} key is readable by more than its owner. Anyone who can \
                     read it can sign as this identity: chmod 600 it."
                );
            }
        }
    }
    Ok(SigningKey::from_bytes(&bytes))
}

/// Refuses every staged effect, naming what is missing.
///
/// The default performer for a settle over HTTP. Warrantor has no credential broker, so a server
/// with no adapter configured must refuse rather than report a success it did not achieve — the
/// success-shaped-mock failure this codebase has already fixed once.
struct NoAdapter;

impl EffectPerformer for NoAdapter {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        _resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        Err(format!(
            "no adapter is configured for {:?} on this server. Settle from the CLI, where the \
             adapter and its credentials live: warrantor settle <id>",
            effect.tool
        ))
    }
}

/// The performer a server uses when its caller configured none.
#[must_use]
pub fn no_adapter() -> Box<dyn EffectPerformer> {
    Box::new(NoAdapter)
}

// ── the store-backed API ──────────────────────────────────────────────────────────────

/// The real API: every answer computed by calling the function the CLI calls.
///
/// # Which keys it holds, and why that is a choice rather than a default
///
/// The issuer key is always loaded: report, stop and spend all need it, and none of them releases
/// anything. The **settle key is optional**, because loading it puts release authority in a
/// network-reachable process. With it absent, `settle` and `void` refuse with a named code and
/// every read route and `stop` still work. The [`crate::mcp_endpoints::ControlEndpoint`] precedent
/// is to hold it and warn loudly, and a server that could never settle would not be the oversight
/// console this is for — so the CLI verb loads it by default and says so at startup. The point is
/// that it is a sentence an operator reads, not a fact they discover.
pub struct StoreApi {
    store: WarrantStore,
    root: PathBuf,
    issuer: SigningKey,
    settle_key: Option<SigningKey>,
    performer: fn() -> Box<dyn EffectPerformer>,
    now: fn() -> u64,
}

impl StoreApi {
    /// Build the API over a store root.
    ///
    /// `performer` is injected rather than constructed here so the GitHub adapter and its
    /// credentials stay in the binary that owns them, and so a test can settle against a stub
    /// without a network.
    #[must_use]
    pub fn new(
        store: WarrantStore,
        root: PathBuf,
        issuer: SigningKey,
        settle_key: Option<SigningKey>,
        performer: fn() -> Box<dyn EffectPerformer>,
        now: fn() -> u64,
    ) -> Self {
        Self {
            store,
            root,
            issuer,
            settle_key,
            performer,
            now,
        }
    }

    fn issuer_key(&self) -> VerifyingKey {
        self.issuer.verifying_key()
    }

    /// Load a warrant, or the refusal a caller should see.
    ///
    /// [`WarrantError::Invalid`] from the store means "no such warrant" and its wording is reused
    /// verbatim rather than replaced with a second vocabulary. Every other variant is a fault on
    /// this side and becomes a fixed sentence: [`WarrantError::Encode`] is the one variant in that
    /// enum that carries I/O detail, and I/O detail is where a host path would come from.
    fn load(&self, id: &str) -> Result<StoredWarrant, Response> {
        self.store.load(id).map_err(|e| match e {
            WarrantError::Invalid(_) => refuse(
                status::NOT_FOUND,
                "no_such_warrant",
                &format!("no warrant {id} in this store"),
            ),
            other => self.internal("load a warrant", &other),
        })
    }

    /// A fault on this side: a stable code and a fixed sentence on the wire, the real detail on
    /// stderr where the operator running the server can see it and a client cannot.
    fn internal(&self, context: &str, detail: &dyn std::fmt::Display) -> Response {
        eprintln!("warrantor serve: {context}: {detail}");
        Response::error(
            status::INTERNAL,
            "internal",
            "this request could not be completed. The server operator has the detail; it is not \
             sent here, because it would describe this machine.",
            &Verification::not_attempted((self.now)()),
        )
    }

    /// The stop store, read fail-closed.
    ///
    /// A stop directory that will not open means containment is **unknown**, and an unknown is
    /// refused rather than rendered as "not contained" — the reading `warrantor report`,
    /// `warrantor egress` and the MCP control endpoint all already take.
    fn stops(&self) -> Result<StopStore, Response> {
        StopStore::open(&self.root).map_err(|e| {
            eprintln!("warrantor serve: open the stop records: {e}");
            Response::error(
                status::INTERNAL,
                "containment_unknown",
                "the stop records could not be read, so it is unknown whether this warrant has \
                 been stopped. This request is refused rather than answered without that.",
                &Verification::not_attempted((self.now)()),
            )
        })
    }

    /// The verdict over a warrant record itself: is its signature genuine against the trust anchor
    /// on disk, and has its deadline passed?
    ///
    /// Verified at `t = 0` on purpose, exactly as [`crate::report::build_observed`] does: expiry is
    /// a separate question with a separate answer, and folding it into the signature check makes an
    /// ordinary lapse look like tampering.
    fn warrant_verdict(&self, stored: &StoredWarrant, now: u64) -> Verification {
        let anchor = self.issuer_key();
        let genuine = stored.warrant.verify(&anchor, 0).is_ok();
        let live = stored.warrant.claims.bounds.expires_at > now;
        Verification {
            integrity: if genuine {
                Integrity::Ok
            } else {
                Integrity::Failed
            },
            liveness: if live {
                Liveness::Live
            } else {
                Liveness::Expired
            },
            checked_at: now,
            digest: None,
            signed_by: if genuine {
                Some(hex::encode(anchor.to_bytes()))
            } else {
                None
            },
            code: if genuine {
                None
            } else {
                Some("signature_invalid")
            },
            reason: if genuine {
                "the warrant's signature verifies against this store's issuer key. That establishes \
                 that these bounds are the ones that were granted; it does not establish that the \
                 issuer should be trusted, which has to come from somewhere else."
                    .to_string()
            } else {
                "the warrant's signature does NOT verify against this store's issuer key. Treat \
                 every bound below as unattested: the record was signed by a different key, or it \
                 has been altered since."
                    .to_string()
            },
        }
    }

    /// The whole signed report for one warrant, built exactly as `warrantor report` builds it.
    fn signed_report(&self, id: &str) -> Result<SignedReport, Response> {
        let stored = self.load(id)?;
        let now = (self.now)();

        // Same registry as every other caller, or handle types would differ. Witnessed against the
        // chain the warrant record carries, so a log that was removed reaches the `Unavailable`
        // path below -- and from there `queue_available: false` and a notary denial -- rather than
        // being reported as an empty queue.
        let queue = StagingQueue::open_witnessed(
            self.store.staged_path(id),
            id,
            EffectRegistry::github(),
            stored.staged_chain.as_ref(),
        );
        let queue_input: Result<&StagingQueue, String> = match &queue {
            Ok(q) => Ok(q),
            Err(e) => Err(safe_warrant_message(e)),
        };

        let stops = self.stops()?;
        let contained = stops.contained_scopes(id);

        // The budget bound's ledger, read fail-closed: unreadable is an error, never a zero. A
        // report that silently showed no spend because the ledger would not parse would be worse
        // than one that showed nothing, because it would look like an answer.
        let ledger = SpendStore::open(&self.root)
            .and_then(|ledgers| {
                ledgers.load(
                    &stored.warrant.claims.bounds,
                    id,
                    &stored.warrant.claims.subject,
                    &self.issuer_key(),
                )
            })
            .map_err(|e| {
                eprintln!("warrantor serve: read the spend ledger for {id}: {e}");
                Response::error(
                    status::INTERNAL,
                    spend_error_code(&e),
                    "the spend ledger for this warrant could not be read, so the budget bound's \
                     observed figure is unknown. This request is refused rather than reporting a \
                     zero that would look like an answer.",
                    &Verification::not_attempted(now),
                )
            })?;

        let built = report::build_observed(
            &stored,
            queue_input,
            &self.issuer_key(),
            now,
            &contained,
            Some(spend::section(&ledger)),
        );
        built
            .sign(&self.issuer, "issuer")
            .map_err(|e| self.internal("sign a report bundle", &e))
    }

    /// The verdict over a signed report: the exact two questions `warrantor verify` asks.
    fn report_verdict(&self, signed: &SignedReport, now: u64) -> Verification {
        let integrity_error = report::verify_export(signed).err();
        let integrity = if integrity_error.is_none() {
            Integrity::Ok
        } else {
            Integrity::Failed
        };
        let (liveness, liveness_note) = if integrity == Integrity::Ok {
            match report::verify_export_at(signed, now) {
                Ok(()) => (Liveness::Live, "The warrant's deadline has not passed."),
                Err(report::ReportError::Expired { .. }) => (
                    Liveness::Expired,
                    "The warrant's deadline HAS passed. The signatures are unaffected: this is a \
                     true record of a past decision, not a statement about authority the subject \
                     still holds.",
                ),
                Err(_) => (
                    Liveness::Unknown,
                    "The deadline check did not agree with the integrity check, so liveness is \
                     reported as unknown rather than folded into a cheerful answer.",
                ),
            }
        } else {
            (
                Liveness::Unknown,
                "Liveness was not determined: a record whose integrity does not hold cannot be \
                 asked whether it is still current.",
            )
        };
        Verification {
            integrity,
            liveness,
            checked_at: now,
            digest: Some(signed.bundle_digest.clone()),
            signed_by: if integrity == Integrity::Ok {
                Some(signed.evidence_receipt.signature.public_key.clone())
            } else {
                None
            },
            code: integrity_error.as_ref().map(report_error_code),
            reason: if integrity == Integrity::Ok {
                format!(
                    "The bundle hashes to the digest both receipts commit to, both Ed25519 \
                     signatures verify, the authority intersection recomputes, and every binding \
                     between receipt and bundle holds. {liveness_note} Verifying a signature proves \
                     who signed and that nothing changed since; it does not establish that the \
                     signer should be trusted."
                )
            } else {
                format!(
                    "This bundle does NOT verify. It is served anyway and marked, because a \
                     tampered report is the single most important thing to put in front of a \
                     human. {liveness_note}"
                )
            },
        }
    }

    /// Refuse a mutating request whose warrant does not verify.
    ///
    /// The reads fail *open and marked*; the three acts fail *closed*. Releasing effects under
    /// bounds whose signature does not check out would be performing an irreversible act on the
    /// authority of a record that is not attested.
    fn require_intact(&self, stored: &StoredWarrant, now: u64) -> Result<(), Response> {
        let verdict = self.warrant_verdict(stored, now);
        if verdict.integrity == Integrity::Ok {
            return Ok(());
        }
        Err(Response::error(
            status::FORBIDDEN,
            "integrity_failed",
            "this warrant's signature does not verify against this store's issuer key, so no act \
             is performed under it. Reads still answer, marked; the three acts that change \
             something do not.",
            &verdict,
        ))
    }

    /// The settle key, or the refusal that names why there is none.
    fn settle_authority(&self) -> Result<&SigningKey, Response> {
        self.settle_key.as_ref().ok_or_else(|| {
            Response::error(
                status::FORBIDDEN,
                "settle_authority_absent",
                "this server was started without release authority, so it cannot settle or void. \
                 Settle from the CLI, or restart the server with the settle key loaded.",
                &Verification::not_attempted((self.now)()),
            )
        })
    }

    /// Warrants the store holds but could not parse.
    ///
    /// `WarrantStore::list` drops them silently, which is correct for a CLI listing — one corrupt
    /// file must not hide every other warrant — and incomplete for an API, where a count that is
    /// quietly short is an answer with no signal that it is short.
    fn unreadable_records(&self, listed: usize) -> usize {
        let Ok(entries) = std::fs::read_dir(self.root.join("warrants")) else {
            return 0;
        };
        let on_disk = entries
            .flatten()
            .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("json"))
            .count();
        on_disk.saturating_sub(listed)
    }

    fn summary_of(&self, stored: &StoredWarrant, now: u64) -> Value {
        let verdict = self.warrant_verdict(stored, now);
        let claims = &stored.warrant.claims;
        json!({
            "id": claims.id,
            "goal": claims.goal,
            "subject": claims.subject,
            "parent": claims.parent,
            "state": stored.warrant.state,
            "issued_at": claims.issued_at,
            "expires_at": claims.bounds.expires_at,
            "tools": claims.bounds.tools,
            // Whether a worktree exists, not where it is. A listing has no use for an absolute
            // host path, and every field that does not need to carry one does not.
            "has_worktree": stored.worktree.is_some(),
            "branch": stored.branch,
            "verified": verdict.verified(),
            "verification": verdict,
        })
    }
}

/// A word for a report verification failure, for a client to switch on.
fn report_error_code(error: &report::ReportError) -> &'static str {
    match error {
        report::ReportError::Encode(_) => "encode",
        report::ReportError::Format { .. } => "unknown_format",
        report::ReportError::Digest { .. } => "digest_mismatch",
        report::ReportError::Notary(_) => "notary_receipt",
        report::ReportError::Evidence(_) => "evidence_receipt",
        report::ReportError::Binding(_) => "receipt_binding",
        report::ReportError::Mode(_) => "enforcement_mode",
        report::ReportError::Predicate(_) => "predicate_invariant",
        report::ReportError::Expired { .. } => "expired",
    }
}

/// A word for a spend-ledger failure. The variant name only: `SpendError::Encode` wraps I/O, and
/// I/O text is where a host path would come from.
fn spend_error_code(error: &SpendError) -> &'static str {
    match error {
        SpendError::Encode(_) => "spend_unreadable",
        SpendError::Format { .. } => "spend_unknown_format",
        SpendError::Digest { .. } => "spend_digest_mismatch",
        SpendError::Receipt(_) => "spend_receipt_invalid",
        SpendError::Binding(_) => "spend_binding_invalid",
        SpendError::Backends(_) => "spend_no_price_table",
    }
}

/// A word for a stop failure, for the same reason.
fn stop_error_code(error: &StopError) -> &'static str {
    match error {
        StopError::Encode(_) => "stop_unwritable",
        StopError::Format { .. } => "stop_unknown_format",
        StopError::Conformance(_) => "stop_conformance_refused",
        StopError::Digest { .. } => "stop_digest_mismatch",
        StopError::Signature(_) => "stop_signature_invalid",
        StopError::Binding(_) => "stop_binding_invalid",
        StopError::OverClaim(_) => "stop_over_claim",
    }
}

/// A [`WarrantError`] rendered for a caller.
///
/// [`WarrantError::Encode`] is the one variant that wraps I/O, so it is the one variant whose text
/// never crosses the wire. Every other variant is a statement about the caller's own warrant, and
/// its wording is deliberate and explanatory — part of the honesty doctrine — so it is forwarded
/// intact rather than flattened into a generic sentence.
fn safe_warrant_message(error: &WarrantError) -> String {
    match error {
        WarrantError::Encode(_) => {
            "a file backing this warrant could not be read or written on the server".to_string()
        }
        other => other.to_string(),
    }
}

/// The status a [`WarrantError`] earns.
fn warrant_error_status(error: &WarrantError) -> (u16, &'static str) {
    match error {
        WarrantError::WrongState { .. } => (status::CONFLICT, "wrong_state"),
        WarrantError::NotSettleAuthority => (status::FORBIDDEN, "not_settle_authority"),
        WarrantError::Expired { .. } => (status::CONFLICT, "expired"),
        WarrantError::SignatureInvalid => (status::FORBIDDEN, "signature_invalid"),
        WarrantError::AuthorityExpanded(_) => (status::CONFLICT, "authority_expanded"),
        WarrantError::UnknownFormat(_) => (status::CONFLICT, "unknown_format"),
        WarrantError::Invalid(_) => (status::CONFLICT, "invalid"),
        WarrantError::Encode(_) => (status::INTERNAL, "internal"),
    }
}

impl Api for StoreApi {
    fn now(&self) -> u64 {
        (self.now)()
    }

    fn health(&mut self) -> Response {
        let now = (self.now)();
        // The store root is named here on purpose: "am I pointed at the right store" is the whole
        // question this route answers, and the caller already holds a token to a server that reads
        // that directory. It appears in no other response and in no error body.
        let data = json!({
            "service": "warrantor-serve",
            "version": env!("CARGO_PKG_VERSION"),
            "store_root": self.root.display().to_string(),
            "server_pid": std::process::id(),
            "now": now,
            "release_authority": self.settle_key.is_some(),
            // Warrantor stores supervisor pids, never agent pids: the supervisor is the process it
            // started and can prove it started. Per-warrant supervisor pids are in /v1/summary/daily.
            "agent_pid": Value::Null,
            "agent_pid_note": "Warrantor never records an agent's pid. It records the SUPERVISOR it \
                               started, which is the process whose lifetime the agent's is linked \
                               to; see /v1/summary/daily.",
        });
        Response::json(
            status::OK,
            &Verification::unsigned(
                now,
                "this route reports on the server, not on a warrant, and nothing signs it.",
            ),
            data,
        )
    }

    fn list_warrants(&mut self, filter: &ListFilter) -> Response {
        let now = (self.now)();
        let warrants = match self.store.list() {
            Ok(w) => w,
            Err(e) => return self.internal("list the store", &e),
        };
        let unreadable = self.unreadable_records(warrants.len());

        let mut worst = None;
        let mut items = Vec::new();
        for stored in &warrants {
            if let Some(state) = filter.state {
                if stored.warrant.state != state {
                    continue;
                }
            }
            if let Some(since) = filter.since {
                if stored.warrant.claims.issued_at < since {
                    continue;
                }
            }
            let verdict = self.warrant_verdict(stored, now);
            worst = Some(match (worst, verdict.integrity) {
                (Some(Integrity::Failed), _) | (_, Integrity::Failed) => Integrity::Failed,
                (_, other) => other,
            });
            items.push(self.summary_of(stored, now));
        }

        let integrity = worst.unwrap_or(Integrity::Unknown);
        let reason = match integrity {
            Integrity::Ok if unreadable == 0 => {
                "every warrant listed verifies against this store's issuer key.".to_string()
            }
            Integrity::Ok => format!(
                "every warrant listed verifies against this store's issuer key, and {unreadable} \
                 file(s) in the store could not be parsed at all and are therefore absent from \
                 this list. The count is reported rather than silently swallowed."
            ),
            Integrity::Failed => "at least one warrant in this list does NOT verify against this \
                                  store's issuer key. Each entry carries its own verdict."
                .to_string(),
            Integrity::Unknown => "no warrant matched, so nothing was verified.".to_string(),
        };
        Response::json(
            status::OK,
            &Verification {
                integrity,
                liveness: Liveness::Unknown,
                checked_at: now,
                digest: None,
                signed_by: None,
                code: if integrity == Integrity::Failed {
                    Some("signature_invalid")
                } else {
                    None
                },
                reason,
            },
            json!({
                "count": items.len(),
                "unreadable_records": unreadable,
                "warrants": items,
            }),
        )
    }

    fn warrant(&mut self, id: &str) -> Response {
        let stored = match self.load(id) {
            Ok(s) => s,
            Err(response) => return response,
        };
        let stops = match self.stops() {
            Ok(s) => s,
            Err(response) => return response,
        };
        let now = (self.now)();
        let claims = &stored.warrant.claims;
        let strengths: Vec<Value> = bound_strengths()
            .into_iter()
            .map(|(name, strength)| json!({ "name": name, "strength": strength }))
            .collect();
        let data = json!({
            "id": claims.id,
            "goal": claims.goal,
            "subject": claims.subject,
            "parent": claims.parent,
            "state": stored.warrant.state,
            "issued_at": claims.issued_at,
            "bounds": claims.bounds,
            "bound_strengths": strengths,
            "stopped": stops.is_stopped(id),
            "has_worktree": stored.worktree.is_some(),
            "branch": stored.branch,
            "base_commit": stored.base_commit,
            "note": "write_paths and budget_cents_observed are OBSERVED, not enforced. Nothing \
                     refuses a write outside the declared paths at the moment it happens, and \
                     nothing sees a model API call at all.",
        });
        Response::json(status::OK, &self.warrant_verdict(&stored, now), data)
    }

    fn report(&mut self, id: &str) -> Response {
        let signed = match self.signed_report(id) {
            Ok(s) => s,
            Err(response) => return response,
        };
        let now = (self.now)();
        let verdict = self.report_verdict(&signed, now);
        Response::json(status::OK, &verdict, json!({ "bundle": signed.bundle }))
    }

    fn evidence(&mut self, id: &str) -> Response {
        let signed = match self.signed_report(id) {
            Ok(s) => s,
            Err(response) => return response,
        };
        let now = (self.now)();
        let verdict = self.report_verdict(&signed, now);
        // The whole export, byte-identical to what `warrantor report --export` writes, so a third
        // party can re-verify it offline on a machine with no access to this one. That is the point
        // of the route, and it is why the bundle is not trimmed here: a redacted bundle would no
        // longer hash to the digest the receipts commit to, and an evidence file that cannot be
        // re-verified is not evidence.
        Response::json(
            status::OK,
            &verdict,
            json!({
                "export": signed,
                "note": "This is the exportable evidence file. It carries the host paths the report \
                         bundle records, because removing them would change the bytes the \
                         signatures cover and the file would no longer verify anywhere.",
            }),
        )
    }

    fn effects(&mut self, id: &str) -> Response {
        // A projection of the report, not a second reading of the queue. It costs the report's git
        // calls; what it buys is that the staged section here can never disagree with the staged
        // section a signed bundle records, which is what a second implementation would eventually
        // do.
        let signed = match self.signed_report(id) {
            Ok(s) => s,
            Err(response) => return response,
        };
        let now = (self.now)();
        let verdict = self.report_verdict(&signed, now);
        let bundle = &signed.bundle;
        Response::json(
            status::OK,
            &verdict,
            json!({
                "warrant_id": bundle.warrant_id,
                // `None` means the queue could not be read, never that it was empty. Rendering an
                // unknown count as zero is the fail-open answer and is indistinguishable from a
                // genuinely empty queue.
                "count": bundle.staged_count,
                "chain_head": bundle.chain_head,
                "staged": bundle.staged,
                "note": "Staged effects have NOT happened. Each is performed only if a human \
                         settles this warrant, and then in the order listed: every prefix of that \
                         order is a coherent state.",
            }),
        )
    }

    fn refusals(&mut self, id: &str) -> Response {
        let now = (self.now)();
        // A refusal log for a warrant this store does not hold would be an answer about nothing.
        if let Err(response) = self.load(id) {
            return response;
        }
        let log = read_refusals(&self.root, id);
        let groups = aggregate_refusals(&log.records);
        let guard_log = crate::guard::read_guard_log(&self.root, id);
        Response::json(
            status::OK,
            &Verification::unsigned(now, REFUSAL_PROVENANCE),
            json!({
                "warrant_id": id,
                "records": log.records,
                "grouped": groups,
                "unreadable_lines": log.unreadable_lines,
                "note": REFUSAL_PROVENANCE,
                // A sibling, never merged into the arrays above. A refusal means a bound said no and
                // the call did NOT happen; a guard signal means the warrant PERMITTED the call and a
                // model disliked it. Folding guard counts into
                // `records`/`grouped`/`total_occurrences` would make the console report N refusals
                // for N calls the warrant allowed, and would put `aggregate_refusals`' "widen the
                // bound" guidance behind a classifier score.
                "guard": guard_object(&guard_log, GuardScope::Warrant),
            }),
        )
    }

    fn summary_refusals(&mut self, window: &SummaryWindow) -> Response {
        let now = (self.now)();
        let log = read_all_refusals(&self.root);
        // Filtered before aggregation, never after: `aggregate_refusals` reads
        // `REPEATED_OCCURRENCES` and `SPREAD_WARRANTS` off the set it is given, so a group's
        // `signal` has to be the verdict for THIS window. Aggregating all time and then dropping
        // rows would label a bound "probably wrong" on evidence the reader is not being shown.
        let records: Vec<RefusalRecord> = log
            .records
            .iter()
            .filter(|record| window.holds(record.at))
            .cloned()
            .collect();
        let groups = aggregate_refusals(&records);
        let total: u64 = groups.iter().map(|g| g.occurrences).sum();
        let wrong_bounds = groups
            .iter()
            .filter(|g| g.signal == RefusalSignal::BoundsProbablyWrong)
            .count();
        // The same window on the same axis, for the same reason. `configured()` and
        // `blocking_posture()` are then read off the WINDOWED log, so a month in which no guard
        // attached says so even when one attached in another month.
        let guard_log =
            crate::guard::read_all_guard_logs(&self.root).within(window.since, window.until);
        Response::json(
            status::OK,
            &Verification::unsigned(now, REFUSAL_PROVENANCE),
            json!({
                "total_occurrences": total,
                "groups": groups,
                "bounds_probably_wrong": wrong_bounds,
                "thresholds": {
                    "repeated_occurrences": REPEATED_OCCURRENCES,
                    "spread_warrants": SPREAD_WARRANTS,
                },
                // The window this answer is actually about, echoed back resolved. A client that
                // rendered the window it ASKED for would keep printing "August" over an answer the
                // server had not filtered -- which is precisely what this route did before.
                "window": {
                    "since": window.since,
                    "until": window.until,
                    "records_in_window": records.len(),
                    "records_all_time": log.records.len(),
                    "caveat": WINDOW_CAVEAT,
                },
                // All-time, and it cannot be otherwise: an unparseable line has no timestamp. The
                // caveat above names it so this number is never read as a fact about the window.
                "unreadable_lines": log.unreadable_lines,
                "note": REFUSAL_PROVENANCE,
                // Additive and adjacent: `total_occurrences` and `bounds_probably_wrong` above are
                // computed from refusals alone and no guard signal may move either.
                "guard": guard_object(&guard_log, GuardScope::Store),
            }),
        )
    }

    fn summary_daily(&mut self) -> Response {
        let now = (self.now)();
        let warrants = match self.store.list() {
            Ok(w) => w,
            Err(e) => return self.internal("list the store", &e),
        };
        let unreadable = self.unreadable_records(warrants.len());

        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut needs_decision = Vec::new();
        let mut expiring = Vec::new();
        for stored in &warrants {
            let word = match stored.warrant.state {
                WarrantState::Open => "open",
                WarrantState::Held => "held",
                WarrantState::Settled => "settled",
                WarrantState::Void => "void",
            };
            *counts.entry(word).or_insert(0) += 1;
            if matches!(
                stored.warrant.state,
                WarrantState::Open | WarrantState::Held
            ) {
                needs_decision.push(self.summary_of(stored, now));
                let expires = stored.warrant.claims.bounds.expires_at;
                if expires > now && expires.saturating_sub(now) <= 3600 {
                    expiring.push(json!({
                        "id": stored.warrant.claims.id,
                        "expires_at": expires,
                        "seconds_left": expires.saturating_sub(now),
                    }));
                }
            }
        }

        // Reconciliation is a side effect and is meant to be: the answer to "what happened
        // overnight" and the cleanup of dead supervisor records are the same operation, exactly as
        // `warrantor status` performs it. It costs one process probe per Open warrant.
        let mut running = Vec::new();
        let mut finished = Vec::new();
        let mut attention = Vec::new();
        match DaemonState::open(&self.root) {
            Ok(daemons) => match daemons.reconcile(&self.store, &process_is_alive) {
                Ok(found) => {
                    for (id, state) in &found {
                        match state {
                            Reconciliation::Supervised { pid } => {
                                running.push(json!({ "id": id, "supervisor_pid": pid }));
                            }
                            Reconciliation::Completed {
                                detail,
                                expired,
                                exit_code,
                            } => finished.push(json!({
                                "id": id,
                                "detail": detail,
                                "expired": expired,
                                "exit_code": exit_code,
                            })),
                            Reconciliation::Interrupted { detail } => {
                                attention.push(json!({ "id": id, "detail": detail }));
                            }
                            Reconciliation::Finished => {}
                        }
                    }
                }
                Err(e) => return self.internal("reconcile daemons", &e),
            },
            Err(e) => return self.internal("open the daemon state", &e),
        }

        let refusal_log = read_all_refusals(&self.root);
        let mut refusal_groups = aggregate_refusals(&refusal_log.records);
        refusal_groups.truncate(5);

        Response::json(
            status::OK,
            &Verification::unsigned(
                now,
                "this digest is assembled from records that each carry their own verdict; the \
                 digest itself is not a signed artifact. Read a warrant's /report for one that is.",
            ),
            json!({
                "generated_at": now,
                "counts": counts,
                "unreadable_records": unreadable,
                "needs_decision": needs_decision,
                "expiring_within_the_hour": expiring,
                "runs": {
                    "running": running,
                    "finished": finished,
                    "attention": attention,
                },
                "top_refusals": refusal_groups,
                "note": "`needs_decision` is every Open or Held warrant: those are the ones whose \
                         staged work nobody has settled or voided yet.",
            }),
        )
    }

    fn settle(&mut self, id: &str, commit: Option<&str>) -> Response {
        let settle_key = match self.settle_authority() {
            Ok(k) => k.clone(),
            Err(response) => return response,
        };
        let mut stored = match self.load(id) {
            Ok(s) => s,
            Err(response) => return response,
        };
        let now = (self.now)();
        if let Err(response) = self.require_intact(&stored, now) {
            return response;
        }
        // Witnessed: settling against a log that has lost records would release whatever survived
        // and call it the whole queue.
        let queue = match StagingQueue::open_witnessed(
            self.store.staged_path(id),
            id,
            EffectRegistry::github(),
            stored.staged_chain.as_ref(),
        ) {
            Ok(q) => q,
            Err(e) => {
                let (code, word) = warrant_error_status(&e);
                return Response::error(
                    code,
                    word,
                    &format!(
                        "the staged-effect queue could not be opened, so nothing was settled: {}",
                        safe_warrant_message(&e)
                    ),
                    &Verification::not_attempted(now),
                );
            }
        };

        let tree = crate::worktree::of_stored(&stored);
        let mut committed = Value::Null;
        if let Some(message) = commit {
            let Some(tree) = tree.as_ref() else {
                return Response::error(
                    status::CONFLICT,
                    "no_worktree",
                    "a commit was asked for and this warrant has no worktree",
                    &Verification::not_attempted(now),
                );
            };
            let message = if message.trim().is_empty() {
                format!("warrant {id}: {}", stored.warrant.claims.goal)
            } else {
                message.to_string()
            };
            match tree.commit_all(&message, &stored.warrant.claims.bounds.write_paths) {
                Ok(count) => committed = json!(count),
                Err(e) => {
                    let (code, word) = warrant_error_status(&e);
                    return Response::error(
                        code,
                        word,
                        &safe_warrant_message(&e),
                        &Verification::not_attempted(now),
                    );
                }
            }
        }

        let mut performer = (self.performer)();
        let report = match settle(
            &mut stored.warrant,
            &queue,
            tree.as_ref(),
            &settle_key.verifying_key(),
            performer.as_mut(),
        ) {
            Ok(r) => r,
            Err(e) => {
                let (code, word) = warrant_error_status(&e);
                return Response::error(
                    code,
                    word,
                    &safe_warrant_message(&e),
                    &Verification::not_attempted(now),
                );
            }
        };
        // Settle mutates in memory; persisting is the caller's job on every surface, and skipping
        // it here would release real effects against a warrant that still reads as Open.
        if let Err(e) = self.store.save(&stored) {
            return self.internal("persist a settled warrant", &e);
        }

        let verdict = self.warrant_verdict(&stored, now);
        let data = json!({
            "warrant_id": id,
            "state": stored.warrant.state,
            "committed_paths": committed,
            "released": report.released(),
            "effects": report.effects,
            "complete": report.complete,
            "worktree_merged": report.worktree_merged,
            "boundary": report.boundary,
        });
        if report.complete {
            Response::json(status::OK, &verdict, data)
        } else {
            // A partial settle really happened, so the record has to reach the operator — and the
            // status has to stop a client reading it as done. Everything before the boundary is
            // real; nothing after it was attempted.
            Response::error(
                status::CONFLICT,
                "settle_incomplete",
                "the settle stopped at the first failure and held the rest. Everything released \
                 before the boundary is real; nothing after it was attempted.",
                &verdict,
            )
            .with_details(data)
        }
    }

    fn void(&mut self, id: &str) -> Response {
        let settle_key = match self.settle_authority() {
            Ok(k) => k.clone(),
            Err(response) => return response,
        };
        let mut stored = match self.load(id) {
            Ok(s) => s,
            Err(response) => return response,
        };
        let now = (self.now)();
        if let Err(response) = self.require_intact(&stored, now) {
            return response;
        }
        let tree = crate::worktree::of_stored(&stored);
        if let Err(e) = void(
            &mut stored.warrant,
            tree.as_ref(),
            &settle_key.verifying_key(),
        ) {
            let (code, word) = warrant_error_status(&e);
            return Response::error(
                code,
                word,
                &safe_warrant_message(&e),
                &Verification::not_attempted(now),
            );
        }
        if let Err(e) = self.store.save(&stored) {
            return self.internal("persist a voided warrant", &e);
        }
        let verdict = self.warrant_verdict(&stored, now);
        Response::json(
            status::OK,
            &verdict,
            json!({
                "warrant_id": id,
                "state": stored.warrant.state,
                "note": "No staged effect was performed. The staged log is retained as the record \
                         of what the agent intended -- that is how you learn the warrant was \
                         scoped wrongly, or that the agent tried something it should not have.",
            }),
        )
    }

    fn stop(&mut self, id: &str, reason: Option<&str>) -> Response {
        let mut stored = match self.load(id) {
            Ok(s) => s,
            Err(response) => return response,
        };
        let now = (self.now)();
        if let Err(response) = self.require_intact(&stored, now) {
            return response;
        }
        let daemons = match DaemonState::open(&self.root) {
            Ok(d) => d,
            Err(e) => return self.internal("open the daemon state", &e),
        };
        let stops = match self.stops() {
            Ok(s) => s,
            Err(response) => return response,
        };

        // The same four steps, in the same order, as `warrantor stop` and the MCP control
        // endpoint. A third order would produce records that disagree with the other two.
        let daemon = daemons.get(id);
        let mut outcome = stop::execute(
            &mut stored,
            daemon.as_ref(),
            &OsProcessControl,
            &self.store.staged_path(id),
        );
        if daemon.is_some() && daemons.deregister(id).is_ok() {
            outcome.deregistered = true;
        }
        // Persist the held state before signing, so a crash between the two leaves a warrant that
        // is held with no record rather than a record of a hold that did not happen.
        if let Err(e) = self.store.save(&stored) {
            return self.internal("persist a stopped warrant", &e);
        }
        let signed = match stop::sign(&stored, &outcome, reason, &self.issuer, now) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warrantor serve: sign a stop record for {id}: {e}");
                return Response::error(
                    status::INTERNAL,
                    stop_error_code(&e),
                    "the run was stopped, but the record could not be signed. The stop is real; \
                     the evidence for it is missing.",
                    &Verification::not_attempted(now),
                );
            }
        };
        if let Err(e) = stops.save(&signed) {
            eprintln!("warrantor serve: keep a stop record for {id}: {e}");
            return Response::error(
                status::INTERNAL,
                stop_error_code(&e),
                "the run was stopped, but the record was not kept.",
                &Verification::not_attempted(now),
            );
        }

        let verified = stop::verify_stop(&signed).is_ok();
        let verdict = Verification {
            integrity: if verified {
                Integrity::Ok
            } else {
                Integrity::Failed
            },
            liveness: Liveness::Unknown,
            checked_at: now,
            digest: Some(signed.record_digest.clone()),
            signed_by: if verified {
                Some(signed.signature_public_key.clone())
            } else {
                None
            },
            code: if verified {
                None
            } else {
                Some("stop_record_invalid")
            },
            reason: if verified {
                "the stop record verifies: both signatures hold and the record does not over-claim. \
                 Liveness is not a question a stop record answers."
                    .to_string()
            } else {
                "the stop record was written and does NOT verify. Treat it as unattested."
                    .to_string()
            },
        };

        let contained = stop::contained(&signed);
        let data = json!({
            "warrant_id": id,
            "state": stored.warrant.state,
            "contained": contained,
            "record": signed,
            "limitations": stop::render_limitations(&signed),
        });
        if contained {
            Response::json(status::OK, &verdict, data)
        } else {
            Response::error(
                status::CONFLICT,
                "stop_not_contained",
                "this stop did NOT contain the run -- see the failing capability in the record. \
                 Treat the agent as still running until you have confirmed otherwise yourself.",
                &verdict,
            )
            .with_details(data)
        }
    }
}

/// The sentence every guard answer carries about what a model's opinion is and is not.
///
/// Longer than [`REFUSAL_PROVENANCE`] because it has more to disclaim. A refusal is a fact about a
/// bound; a guard signal is a model's opinion, and both directions of it mislead if read as a
/// verdict. The measured numbers are in the sentence rather than in a doc nobody opens: at 0.8152
/// adversarial recall an empty list is not a clean run, and at a false-positive rate that
/// quadruples under adversarial phrasing a full list is not a list of incidents.
const GUARD_PROVENANCE: &str =
    "Guard signals are a MODEL's opinion about calls the warrant PERMITTED, recorded beside a run; \
     a call a bound refused is never classified, so it never appears here. Measured recall under \
     adversarial phrasing is 0.8152 and the false-positive rate quadruples under it (0.0224 -> \
     0.0923), so an empty list is NOT a clean bill of health and a full one is NOT a list of \
     incidents. Integrity remains an Ed25519 question with a three-valued answer, and no classifier \
     score enters it: the `verification` object on this response is computed without reading any of \
     this.";

/// What a `guard` object is answering about: one warrant's log, or every log in the store.
///
/// An enum rather than the `grouped` bool it replaces, because the bool was doing two jobs and got
/// one of them wrong: it selected the rendering *and* was silently assumed to select the scope of
/// the "nothing was attached" sentence, so the per-warrant route answered a question about one file
/// with a claim about the whole store.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardScope {
    /// One warrant's log, rendered as individual signals.
    Warrant,
    /// Every warrant's log, rendered as aggregated groups.
    Store,
}

/// The `guard` sibling object on the two refusal routes.
///
/// A function rather than two inline `json!` blocks so the disclaiming sentence and the
/// `configured: false` case cannot drift between the per-warrant and the summary route. `configured`
/// is false when no attach record exists **in what was read**, and the note says what that means,
/// because "no guard signals" and "no guard ran" render identically otherwise — the exact failure
/// `ml/README.md` names about a dead backend reading as perfect safety, one level up.
///
/// The note is composed, never constant. Two facts vary and both of them mislead if assumed: the
/// scope the absence covers, and the **mode** the sessions actually ran in. A stored sentence saying
/// the guard "blocked nothing and cannot" is false for a log whose sessions ran in
/// [`crate::guard::GuardMode::Enforce`], and it is the console's copy of that sentence an operator
/// reads.
fn guard_object(log: &crate::guard::GuardLog, scope: GuardScope) -> Value {
    let configured = log.configured();
    let note = if configured {
        // Three states, never two. `enforcing()` is `any(..)`, and this route's log covers EVERY
        // warrant in the store, so a two-way branch let one enforce session anywhere assert that
        // harmful calls "did not happen" -- over a scope that also held observe-mode signals whose
        // calls proceeded. A sentence here may only describe what is true of the WHOLE scope.
        let mode_clause = match log.blocking_posture() {
            crate::guard::BlockingPosture::Enforced => {
                " Every session here ran with enforcement ON: calls the guard called harmful were \
                 REFUSED at the MCP endpoint before any effect was staged, so those calls did not \
                 happen. That bound reaches only calls passing through the endpoint -- it is not \
                 containment."
            }
            crate::guard::BlockingPosture::Mixed => {
                " Sessions here ran in BOTH modes, so no single sentence covers them: a call \
                 flagged in an enforce session was refused at the MCP endpoint and did not happen, \
                 while a call flagged in an observe session PROCEEDED and was only recorded. Read \
                 each signal's own mode before concluding anything about a particular call. Where \
                 enforcement did apply it reaches only calls passing through the endpoint -- it is \
                 not containment."
            }
            crate::guard::BlockingPosture::ObserveOnly => {
                " Every session here ran observe-only: the guard blocked nothing."
            }
        };
        format!("{GUARD_PROVENANCE}{mode_clause}")
    } else if !log.signals.is_empty() || !log.summaries.is_empty() {
        // An attach record is written before the run and the signals after it, so this state is
        // reachable: the attach write failed and the session's own signals landed anyway. Saying
        // "nothing classified anything" over a list of classifications would be a plainly false
        // sentence sitting next to its own counter-evidence.
        // One `format!` argument and no line continuations: the previous spelling broke the string
        // across source lines without `\`, so the note an operator read carried fourteen literal
        // spaces mid-sentence ("what was watching              cannot be named").
        format!(
            "{GUARD_PROVENANCE} No attach record was found for these signals, so what was watching \
             cannot be named from this log alone -- read the per-signal provenance. Whether \
             anything was blocked is read from the signals' own mode."
        )
    } else {
        match scope {
            // Said about one file, so it claims only about that file. The old wording made a
            // store-wide claim from a single warrant's log, and it was false whenever any other
            // warrant in the same store was guarded -- on the one sentence whose job is to
            // separate "no findings" from "no coverage".
            GuardScope::Warrant => "No guard was attached to any run of THIS warrant, so nothing \
                                    classified anything here. This is an absence of observation, \
                                    NOT an absence of findings: read it as no coverage. It says \
                                    nothing about other warrants in this store -- /v1/summary/refusals \
                                    answers that."
                .to_string(),
            GuardScope::Store => "No guard was attached to any run in this store, so nothing \
                                  classified anything. This is an absence of observation, NOT an \
                                  absence of findings: read it as no coverage."
                .to_string(),
        }
    };
    // Three values on the wire, plus `null` for "nothing was read here at all". `enforcing` stays
    // for the callers that already read it, but it is not enough on its own and never was: it is
    // `any(..)`, so a client branching on it renders `Mixed` as `Enforced` and tells an operator
    // that calls which actually proceeded did not happen. Without this field the only alternative
    // open to a renderer is string-matching the English in `note`.
    let posture = if log.sessions.is_empty() && log.signals.is_empty() {
        None
    } else {
        Some(log.blocking_posture().word())
    };
    let mut object = json!({
        "configured": configured,
        "enforcing": log.enforcing(),
        "blocking_posture": posture,
        "sessions": log.sessions,
        "counters": log.summaries,
        // What was NOT looked at, which is the only honest live answer to "what did we miss".
        // There is no live answer to "what did it look at and get wrong": nothing in this product
        // labels live traffic, and multiplying a benchmark miss rate by these counts would put a
        // number with no measurement behind it on the surface that least tolerates one.
        "coverage": log.coverage(),
        "unreadable_lines": log.unreadable_lines,
        // How many of the records above were written before sessions carried an id, so could not be
        // windowed as part of a session and fell back to their own clock. Nonzero is the one case
        // in which `window.caveat`'s "held or dropped whole" does not hold, and a reader is owed
        // that rather than left to assume the better rule applied to all of it.
        "unattributed_records": log.unattributed_records(),
        "note": note,
    });
    let grouped = scope == GuardScope::Store;
    let detail = if grouped {
        json!(crate::guard::aggregate_guard_signals(&log.signals))
    } else {
        json!(log.signals)
    };
    if let Some(map) = object.as_object_mut() {
        map.insert(
            if grouped { "groups" } else { "signals" }.to_string(),
            detail,
        );
    }
    object
}

/// The sentence every refusal answer carries about where its data came from.
const REFUSAL_PROVENANCE: &str =
    "Refusal records are a local observation log written when a supervised MCP session ends. \
     Nothing signs them and nothing chains them, so this says what the log contains and not that \
     the log is complete: an agent that never traversed the Warrantor proxy left no record here, \
     and the refusals it did not hit are not evidence that it did not try.";

// ── the socket ────────────────────────────────────────────────────────────────────────

/// The warning a non-loopback bind must print, or `None` for a loopback one.
///
/// A function rather than a `println!` in the binary so the wording is testable and cannot quietly
/// lose a clause. It names what became reachable, and it says plainly that the token is not TLS: a
/// warning that implied the bearer token protected bytes on the wire would be worse than none.
#[must_use]
pub fn bind_warning(addr: SocketAddr, root: &Path, release_authority: bool) -> Option<String> {
    if addr.ip().is_loopback() {
        return None;
    }
    Some(format!(
        "warrantor: WARNING -- binding {addr}, which is NOT loopback.\n  \
         Every warrant, report, staged effect and stop record under {} is now readable by anything \
         that can reach that address and holds the session token.\n  \
         {}\n  \
         There is no TLS here. The token controls ACCESS, not confidentiality: the token itself and \
         every byte of every response cross the network in the clear, so anyone who can watch the \
         traffic can take the token and use it. Put a reverse proxy in front of this if it must \
         leave the machine.",
        root.display(),
        if release_authority {
            "settle, void and stop are reachable too: a token holder can release staged effects, \
             discard work, and terminate a running agent."
        } else {
            "stop is reachable too: a token holder can terminate a running agent. This server was \
             started without release authority, so settle and void refuse."
        }
    ))
}

// ── stopping ──────────────────────────────────────────────────────────────────────────

/// How often the accept loop wakes to ask whether it has been told to stop.
///
/// The cost of this interval is one wakeup per tenth of a second on an idle server; the benefit is
/// that Ctrl-C is answered within it. Both numbers are the right ones for a service whose busiest
/// client is a person refreshing a console.
pub const SHUTDOWN_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// How long a stopping server waits for the requests already in flight.
///
/// Bounded rather than unbounded on purpose. `/stop` can legitimately sleep for seconds polling for
/// quiescence, and a settle is mid-commit; those deserve to finish. A client that has wedged its
/// own connection does not deserve to hold the terminal forever, and after this the server says how
/// many were still running rather than pretending it drained.
pub const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The one process-global bit, set by an OS handler and read by the accept loop.
///
/// A `static` because a `static` is all an OS handler can reach: `signal(2)` and
/// `SetConsoleCtrlHandler` both take a bare function pointer with nowhere to put a captured `Arc`.
/// Storing to an `AtomicBool` is the whole of what the handler does, and that is what makes it
/// legal: it is async-signal-safe, which almost nothing else is. Every decision about *how* to stop
/// is made afterwards, on the accept loop, in ordinary code.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// A request that the server stop accepting new connections.
///
/// Cloneable and cheap; every clone watches the same bit, plus the process-wide interrupt. Held by
/// the caller rather than owned by [`listen`] so a test — or an embedder with its own console — can
/// stop a server without raising a signal at itself.
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}

impl Shutdown {
    /// A shutdown that has not been asked for.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the server to stop after the request it is answering.
    pub fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Has a stop been asked for, by this handle or by Ctrl-C?
    #[must_use]
    pub fn stopping(&self) -> bool {
        self.flag.load(Ordering::SeqCst) || INTERRUPTED.load(Ordering::SeqCst)
    }
}

/// Install an interrupt handler so Ctrl-C trips [`Shutdown::stopping`].
///
/// Returns `false` when this platform has no handler this module knows how to install. That is a
/// return value rather than a silent no-op because the caller has to be able to say so: a server
/// that claims Ctrl-C will shut it down cleanly, on a platform where Ctrl-C will instead kill it
/// mid-settle and leave a token file naming a token that no longer opens anything, has told the
/// operator something untrue about what happens to their work.
///
/// Installing twice is harmless — the second install replaces the first with the same handler.
pub fn install_interrupt_handler() -> bool {
    interrupt::install()
}

#[cfg(unix)]
// The crate denies unsafe globally, and this is the third exception, of the same kind as the two in
// `supervise`: a signal disposition is a kernel object, not something safe Rust can express. The
// module's whole surface is one libc call and a handler that does one atomic store.
#[allow(unsafe_code)]
mod interrupt {
    use std::sync::atomic::Ordering;

    /// `SIGINT` and `SIGTERM`. Both numbers are fixed at 2 and 15 across every Unix platform Rust's
    /// `std` supports, which is why they can be written here instead of read from a C header.
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    /// `SIG_ERR` is `(void (*)(int)) -1`.
    const SIG_ERR: usize = usize::MAX;

    extern "C" {
        /// `signal(2)`, declared rather than depended on.
        ///
        /// One extern declaration of one function whose signature has not changed since the 1980s
        /// is a smaller thing to audit than a new crate in the dependency graph, and this crate's
        /// short dependency list is a promise to the people who vendor it.
        fn signal(signum: i32, handler: usize) -> usize;
    }

    extern "C" fn on_signal(_signum: i32) {
        super::INTERRUPTED.store(true, Ordering::SeqCst);
    }

    pub fn install() -> bool {
        let handler = on_signal as extern "C" fn(i32) as usize;
        // SAFETY: `handler` is a real `extern "C" fn(c_int)`, which is exactly what `signal(2)`
        // expects, and it does one async-signal-safe thing: an atomic store.
        let previous_int = unsafe { signal(SIGINT, handler) };
        // SAFETY: as above.
        let previous_term = unsafe { signal(SIGTERM, handler) };
        previous_int != SIG_ERR && previous_term != SIG_ERR
    }
}

#[cfg(windows)]
// Same exception, same justification: the console control handler is registered with the OS, and
// there is no safe Rust that registers it. Declared against kernel32 directly, as `supervise` does
// for job objects, rather than adding a Windows crate for one call.
#[allow(unsafe_code)]
mod interrupt {
    use std::sync::atomic::Ordering;

    const CTRL_C_EVENT: u32 = 0;
    const CTRL_BREAK_EVENT: u32 = 1;
    const HANDLED: i32 = 1;
    const NOT_HANDLED: i32 = 0;

    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    /// Windows runs this on a thread of its own. Returning `HANDLED` is what stops the default
    /// handler from terminating the process, which is the whole point: the accept loop is left
    /// alive long enough to finish what it is holding.
    ///
    /// Close, logoff and shutdown events are deliberately *not* claimed. Windows gives a handler a
    /// few seconds for those and then ends the process regardless, so claiming them would buy a
    /// drain that may not complete while suppressing the OS's own handling of a real shutdown.
    unsafe extern "system" fn on_ctrl(event: u32) -> i32 {
        if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT {
            super::INTERRUPTED.store(true, Ordering::SeqCst);
            HANDLED
        } else {
            NOT_HANDLED
        }
    }

    pub fn install() -> bool {
        // SAFETY: a valid handler pointer with the signature the API documents, added rather than
        // removed. The handler stores to an atomic and returns.
        unsafe { SetConsoleCtrlHandler(Some(on_ctrl), HANDLED) != 0 }
    }
}

#[cfg(not(any(unix, windows)))]
mod interrupt {
    pub fn install() -> bool {
        false
    }
}

/// How a stopping server left the requests that were already running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drain {
    /// Every in-flight request finished. Nothing was cut off.
    Complete,
    /// [`DRAIN_TIMEOUT`] ran out with this many connections still being served. Reported rather
    /// than swallowed: an operator who stopped a server mid-settle needs to know that is what
    /// happened before they read the store.
    Incomplete(usize),
}

/// Wait for in-flight connections, bounded.
fn drain(live: &Arc<AtomicUsize>) -> Drain {
    let deadline = std::time::Instant::now() + DRAIN_TIMEOUT;
    loop {
        let outstanding = live.load(Ordering::SeqCst);
        if outstanding == 0 {
            return Drain::Complete;
        }
        if std::time::Instant::now() >= deadline {
            return Drain::Incomplete(outstanding);
        }
        std::thread::sleep(SHUTDOWN_POLL);
    }
}

/// Bind and serve until `shutdown` is tripped.
///
/// The only socket-aware function in this module, and deliberately the smallest one: everything it
/// does that could be wrong about *policy* has already been decided in [`serve_conn`], which tests
/// drive with a `Cursor`.
///
/// One mutex over the whole API, held for the duration of each request. That is not a performance
/// compromise at human polling rates, and it buys something real: two concurrent settles on one
/// warrant become impossible by construction, in a store that has no locking of its own. It cannot
/// serialise against a `warrantor` command running in another process, and nothing here claims it
/// can.
///
/// Stopping is a poll rather than a blocking `accept`. The listener is non-blocking and the loop
/// wakes every [`SHUTDOWN_POLL`], so a Ctrl-C that arrives while nothing is connecting is still
/// answered — a blocking `accept` would sit there until the next client happened along, which on a
/// server watching an idle agent could be all night.
///
/// # Errors
/// [`ServeError::Bind`] if the address cannot be bound. An error on one *connection* is logged and
/// dropped: one bad client must not take down a service that is watching a running agent.
pub fn listen<A: Api + Send + 'static>(
    api: A,
    token: SessionToken,
    addr: SocketAddr,
    shutdown: &Shutdown,
) -> Result<Drain, ServeError> {
    serve_on(api, token, bind(addr)?, shutdown)
}

/// Bind the listener, separately from serving on it.
///
/// Split out so a caller can learn the address it actually got **before** it prints one. With
/// `--port 0` the operator asks the OS for a free port, and a caller that announced the requested
/// address would print `http://127.0.0.1:0` — a URL that is not merely unhelpful but unusable, and
/// which nothing would catch, because the server then works perfectly on a port nobody was told.
///
/// Read the real address back with [`TcpListener::local_addr`].
///
/// # Errors
/// [`ServeError::Bind`] if the address cannot be bound, or if the listener will not go
/// non-blocking.
pub fn bind(addr: SocketAddr) -> Result<TcpListener, ServeError> {
    let listener = TcpListener::bind(addr).map_err(|e| ServeError::Bind {
        addr,
        detail: e.to_string(),
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|e| ServeError::Bind {
            addr,
            detail: format!("the listener would not go non-blocking, so Ctrl-C could not be answered promptly: {e}"),
        })?;
    Ok(listener)
}

/// Serve on a listener that is already bound. See [`listen`], which is this plus [`bind`].
///
/// # Errors
/// As [`listen`].
pub fn serve_on<A: Api + Send + 'static>(
    api: A,
    token: SessionToken,
    listener: TcpListener,
    shutdown: &Shutdown,
) -> Result<Drain, ServeError> {
    let api = Arc::new(Mutex::new(api));
    let token = Arc::new(token);
    let live = Arc::new(AtomicUsize::new(0));

    while !shutdown.stopping() {
        let stream = match listener.accept() {
            Ok((stream, _peer)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(SHUTDOWN_POLL);
                continue;
            }
            // A failed accept — the descriptor table is full, the peer vanished between the
            // connect and the accept — is one lost connection, not a reason to stop watching a
            // running agent. The sleep is what keeps a persistent failure from becoming a spin.
            Err(_) => {
                std::thread::sleep(SHUTDOWN_POLL);
                continue;
            }
        };
        // An accepted socket inherits the listener's non-blocking mode on Windows and on the BSDs,
        // and does not on Linux. Every handler below is written against blocking reads with a
        // timeout, so the mode is set explicitly rather than left to the platform.
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));

        if live.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            let mut stream = stream;
            // `try_lock` rather than `lock`: this branch is reached precisely when every other
            // thread is busy, and blocking the accept loop to read a clock would make a saturated
            // server stop answering instead of answering "saturated". An unavailable clock leaves
            // the verdict's `checked_at` at zero, which the verdict already says nothing was
            // checked at.
            let stamped_at = api.try_lock().map(|guard| guard.now()).unwrap_or(0);
            let _ = write_response(
                &mut stream,
                &refuse(
                    status::UNAVAILABLE,
                    "too_many_connections",
                    "this server is serving as many connections as it accepts at once",
                )
                .stamped(stamped_at),
            );
            continue;
        }
        let Ok(read_half) = stream.try_clone() else {
            continue;
        };

        live.fetch_add(1, Ordering::SeqCst);
        let slot = Slot {
            live: Arc::clone(&live),
        };
        let api = Arc::clone(&api);
        let token = Arc::clone(&token);
        let spawned = std::thread::Builder::new()
            .name("warrantor-serve".to_string())
            .spawn(move || {
                // Decremented by `Drop`, so an early return or an unwind cannot leak a slot and
                // walk the server down to a permanent 503.
                let _slot = slot;
                let mut input = std::io::BufReader::new(read_half);
                let mut output = stream;

                // Read outside the lock, decide inside it, write outside it. A slow client can
                // stall its own read and its own write, and neither one holds the store while it
                // does: the lock covers exactly the window where the store is being touched. That
                // is the whole reason this uses `parse_request` + `handle` rather than
                // `serve_conn`, which is the same three steps fused for tests.
                let response = match parse_request(&mut input) {
                    Ok(request) => {
                        let mut guard = lock_or_recover(&api);
                        handle(&mut *guard, &token, &request)
                    }
                    Err(response) => {
                        let now = lock_or_recover(&api).now();
                        response.stamped(now)
                    }
                };
                if let Err(e) = write_response(&mut output, &response) {
                    eprintln!("warrantor serve: connection: {e}");
                }
            });
        if let Err(e) = spawned {
            // Deliberately NOT decrementing here. `slot` was moved into the closure, and a failed
            // `spawn` drops that closure — so `Slot::drop` has already released this slot. The
            // manual `fetch_sub` that used to sit here was a second decrement on the same slot,
            // and `AtomicUsize` wraps: one failed spawn took the counter to `usize::MAX` and the
            // server answered 503 forever after, having never served the request that broke it.
            //
            // The lesson generalises past this line: once a guard owns the release, every other
            // path must let the guard do it.
            eprintln!("warrantor serve: could not spawn a worker: {e}");
        }
    }
    // The listener is dropped here, before the drain: nothing new is accepted while the requests
    // already inside are finishing.
    drop(listener);
    Ok(drain(&live))
}

/// One connection's place in the cap, released on drop.
struct Slot {
    live: Arc<AtomicUsize>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Take the API lock, recovering from poison rather than re-panicking.
///
/// With `panic = "abort"` a poisoned lock cannot arise in release, because the first panic takes
/// the process. In a debug build it can, and unwrapping would turn one failed request into a panic
/// in every thread that followed it.
fn lock_or_recover<A: Api>(api: &Arc<Mutex<A>>) -> std::sync::MutexGuard<'_, A> {
    match api.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

//! L4-27 — the governed HTTP call.
//!
//! Outbound HTTP for the long tail nobody writes an adapter for. Three properties, in order of
//! how much they matter:
//!
//! 1. **The agent never names a destination.** The tool takes a `capability`, an enum over the
//!    warrant's egress catalog; there is no `url`, `host` or `endpoint` parameter and the
//!    schema is closed. An uncataloged destination is not refused, it is unexpressible. A raw
//!    address smuggled into the `capability` field is refused by the proxy at call time.
//! 2. **The payload declares a data class**, and the catalog entry carries the highest class
//!    it may carry. Absent means `public`.
//! 3. **The response never re-enters an agent context.** The adapter runs at settle, when the
//!    agent is gone; it keeps the status, a digest and a byte count, never the body.
//!
//! Where this holds: the proxy chokepoint and the settling process. `bound_strengths()` still
//! says `egress_hosts` is `Mediated`, and nothing here changes that.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use warrantor_egress as broker;

use crate::egress::EgressBroker;
use crate::mcp::ToolSpec;

/// The tool name the agent calls.
pub const TOOL: &str = "http.call";
/// Format of each timing record the adapter emits.
pub const HTTP_CALL_FORMAT: &str = "warrantor.http-call/1";
/// The argument naming the destination capability.
pub const ARG_CAPABILITY: &str = "capability";
/// The argument naming the HTTP method.
pub const ARG_METHOD: &str = "method";
/// The argument naming the path under the capability's destination.
pub const ARG_PATH: &str = "path";
/// The optional argument carrying the request body.
pub const ARG_BODY: &str = "body";
/// The argument declaring the payload's data class.
pub const ARG_DATA_CLASS: &str = "data_class";

/// Methods a capability may permit. `CONNECT`, `OPTIONS` and `TRACE` are not expressible.
pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// Payload data classes, ordered: a request may carry at most the entry's ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Anything that may already be seen by anyone.
    Public,
    /// Internal to the tenant; not for publication.
    Internal,
    /// Business-sensitive material.
    Confidential,
    /// The class whose leak is the incident.
    Restricted,
}

impl DataClass {
    /// The lower-case words the schema publishes, in order.
    pub const WORDS: &'static [&'static str] =
        &["public", "internal", "confidential", "restricted"];

    /// Parse the lower-case word. Anything else is not a class.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }

    /// The ceiling an entry declares. `None` reads as `Public`: absent means the least.
    ///
    /// # Errors
    /// A sentence when the entry names a class this build does not know — a catalog written by
    /// a newer build must refuse here rather than be read as one of the known classes.
    pub fn ceiling_of(entry: &broker::CatalogEntry) -> Result<Self, String> {
        match entry.max_data_class.as_deref() {
            None => Ok(Self::Public),
            Some(word) => Self::parse(word).ok_or_else(|| {
                format!(
                    "the catalog entry for {} declares max_data_class {word:?}, which is not a \
                     data class; refusing rather than guessing",
                    entry.logical_endpoint
                )
            }),
        }
    }
}

/// What the adapter hands the transport. `url` is built by the adapter from the catalog entry;
/// the agent contributed only `method`, `path` and `body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Built from the pinned address and the path; never from anything the agent named.
    pub url: String,
    /// One of [`METHODS`].
    pub method: String,
    /// Present only on methods that carry one.
    pub body: Option<String>,
    /// The bearer token for this endpoint, held by the settling process. Never logged.
    pub bearer: Option<String>,
}

/// What came back, before the adapter digests it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body, digested by the adapter and then dropped; never returned to any agent.
    pub body: Vec<u8>,
}

/// A minimal transport, injected so the adapter is testable without a network — the same shape
/// and the same reason as [`crate::adapters::github::GitHubTransport`].
pub trait HttpTransport {
    /// Send one request. Errors are human-readable; the settle engine stops on the first.
    fn send(&mut self, request: &HttpRequest) -> Result<HttpResponse, String>;
}

/// One performed call, for the receipt graph (L7-09). Carries digests, never bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCallRecord {
    /// Always [`HTTP_CALL_FORMAT`].
    pub format: String,
    /// The staged handle this call performed.
    pub handle: String,
    /// The capability the agent named.
    pub capability: String,
    /// The logical endpoint the capability resolved to.
    pub logical_endpoint: String,
    /// The method.
    pub method: String,
    /// The path under the destination.
    pub path: String,
    /// The declared payload class.
    pub data_class: DataClass,
    /// The catalog digest the decision was made against.
    pub catalog_digest: String,
    /// Digest over method, path and body: what was sent, without the bytes.
    pub request_digest: String,
    /// The response status.
    pub status: u16,
    /// Digest of the response body; the body itself is dropped.
    pub response_digest: String,
    /// Length of the response body.
    pub response_bytes: u64,
    /// Clock in milliseconds, before the send.
    pub started_at_ms: u64,
    /// Clock in milliseconds, after the send.
    pub finished_at_ms: u64,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// The tool as the agent sees it. Closed schema; the only destination vocabulary is the
/// capability enum, taken from the broker the proxy will decide against.
#[must_use]
pub fn tool_spec(broker: &EgressBroker) -> ToolSpec {
    ToolSpec {
        name: TOOL.to_string(),
        description: "Make one outbound HTTP request to a destination this warrant grants as a \
                      capability. There is no URL parameter: choose a capability, a method, a \
                      path under that destination, and declare the payload's data class. The \
                      request is staged and performed only if a human settles the warrant; you \
                      receive a handle, never the response body."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": [ARG_CAPABILITY, ARG_METHOD, ARG_PATH, ARG_DATA_CLASS],
            "properties": {
                ARG_CAPABILITY: { "type": "string", "enum": broker.capabilities() },
                ARG_METHOD: { "type": "string", "enum": METHODS },
                ARG_PATH: { "type": "string", "pattern": "^/" },
                ARG_BODY: { "type": "string" },
                ARG_DATA_CLASS: { "type": "string", "enum": DataClass::WORDS },
            }
        }),
    }
}

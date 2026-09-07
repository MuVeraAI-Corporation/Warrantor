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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use warrantor_egress as broker;

use crate::egress::{EgressBroker, EGRESS_CAPABILITY_PREFIX};
use crate::mcp::ToolSpec;
use crate::settle::EffectPerformer;
use crate::staging::StagedEffect;

/// The proxy's check for this tool: decide the named capability through the broker.
///
/// Returns the refusal to record, or `None` for any other tool and for a permitted capability.
/// A missing `capability` argument is a raw (empty) destination and is refused, never skipped —
/// the same fail-closed reading [`crate::egress::destinations_of`] gives an unresolvable
/// destination argument.
#[must_use]
pub fn capability_refusal(
    call: &crate::proxy::ToolCall,
    broker: &EgressBroker,
) -> Option<crate::egress::EgressRefusal> {
    if call.tool != TOOL {
        return None;
    }
    let named = call
        .arguments
        .get(ARG_CAPABILITY)
        .cloned()
        .unwrap_or_default();
    match broker.decide_capability(&named) {
        broker::EgressVerdict::Allow { .. } => None,
        broker::EgressVerdict::Deny { reason } => Some(crate::egress::EgressRefusal {
            tool: TOOL.to_string(),
            argument: ARG_CAPABILITY.to_string(),
            destination: named
                .strip_prefix(EGRESS_CAPABILITY_PREFIX)
                .unwrap_or(&named)
                .to_string(),
            capability: named,
            reason,
            count: 1,
        }),
    }
}

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

/// Refuse a path that could move the request off the cataloged destination.
///
/// # Errors
/// The reason, in terms the operator can act on.
pub fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("path {path:?} must start with '/'"));
    }
    if path.starts_with("//") {
        return Err(format!(
            "path {path:?} is protocol-relative and would name a host"
        ));
    }
    if path.contains("://") || path.contains('@') {
        return Err(format!(
            "path {path:?} carries a scheme or credentials; the destination is the capability's"
        ));
    }
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "path {path:?} contains whitespace or a control character"
        ));
    }
    Ok(())
}

/// Performs governed HTTP calls against the catalog the proxy decided against.
pub struct HttpAdapter<T: HttpTransport> {
    transport: T,
    catalog: broker::DestinationCatalog,
    bearers: BTreeMap<String, String>,
    clock: Box<dyn FnMut() -> u64>,
    records: Vec<HttpCallRecord>,
}

impl<T: HttpTransport> HttpAdapter<T> {
    /// Build an adapter over `catalog`. `clock` returns milliseconds and is called twice per call.
    #[must_use]
    pub fn new(
        transport: T,
        catalog: broker::DestinationCatalog,
        clock: Box<dyn FnMut() -> u64>,
    ) -> Self {
        Self {
            transport,
            catalog,
            bearers: BTreeMap::new(),
            clock,
            records: Vec::new(),
        }
    }

    /// Hold a bearer token for one logical endpoint. The agent never sees it: this runs at settle.
    #[must_use]
    pub fn with_bearer(mut self, logical_endpoint: &str, token: &str) -> Self {
        self.bearers
            .insert(logical_endpoint.to_string(), token.to_string());
        self
    }

    /// Every call performed, in order, for the receipt graph.
    #[must_use]
    pub fn records(&self) -> &[HttpCallRecord] {
        &self.records
    }

    /// The transport, so a test can read what was sent.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn argument<'a>(effect: &'a StagedEffect, name: &str) -> Result<&'a str, String> {
        effect
            .arguments
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("{TOOL} requires {name}"))
    }

    fn perform_call(&mut self, effect: &StagedEffect) -> Result<String, String> {
        let capability = Self::argument(effect, ARG_CAPABILITY)?.to_string();
        let method = Self::argument(effect, ARG_METHOD)?.to_string();
        let path = Self::argument(effect, ARG_PATH)?.to_string();
        let class_word = Self::argument(effect, ARG_DATA_CLASS)?;
        let data_class = DataClass::parse(class_word).ok_or_else(|| {
            format!(
                "{class_word:?} is not a data class; one of {DATA_CLASSES:?}",
                DATA_CLASSES = DataClass::WORDS
            )
        })?;
        let body = effect.arguments.get(ARG_BODY).cloned();

        if !METHODS.contains(&method.as_str()) {
            return Err(format!(
                "{method:?} is not a method this adapter can express; one of {METHODS:?}"
            ));
        }
        if matches!(method.as_str(), "GET" | "HEAD") && body.is_some() {
            return Err(format!("{method} carries no body"));
        }
        validate_path(&path)?;

        // Decide again, here, against the catalog: the settle process trusts the proxy's
        // decision no more than the proxy trusted the agent's.
        let logical_endpoint = capability
            .strip_prefix(EGRESS_CAPABILITY_PREFIX)
            .filter(|e| !e.is_empty())
            .ok_or_else(|| format!("{capability:?} is not a capability"))?
            .to_string();
        let request = broker::EgressRequest {
            capability: capability.clone(),
            logical_endpoint: logical_endpoint.clone(),
            chain_capabilities: vec![capability.clone()],
            enforcement_mode: "advisory".to_string(),
            is_discovery: false,
            has_approval: false,
        };
        let (pinned, catalog_digest) = match broker::decide(&request, Some(&self.catalog)) {
            broker::EgressVerdict::Allow {
                pinned_addresses,
                catalog_digest,
                ..
            } => (pinned_addresses, catalog_digest),
            broker::EgressVerdict::Deny { reason } => {
                return Err(format!(
                    "egress to {logical_endpoint} is refused at settle: {}",
                    crate::egress::reason_phrase(reason)
                ))
            }
        };
        let entry = self
            .catalog
            .find(&logical_endpoint)
            .ok_or_else(|| format!("{logical_endpoint} left the catalog"))?
            .clone();
        if !entry.permitted_methods.iter().any(|m| m == &method) {
            return Err(format!(
                "the capability for {logical_endpoint} permits {:?}, not {method}; a bare \
                 --egress host permits GET only and a write needs a declared capability",
                entry.permitted_methods
            ));
        }
        let ceiling = DataClass::ceiling_of(&entry)?;
        if data_class > ceiling {
            return Err(format!(
                "the payload is declared {class_word} and the capability for {logical_endpoint} \
                 carries at most {:?}",
                DataClass::WORDS[ceiling as usize]
            ));
        }
        let [address] = pinned.as_slice() else {
            return Err(format!(
                "the capability for {logical_endpoint} pins {} addresses; this adapter sends to \
                 exactly one and does not choose",
                pinned.len()
            ));
        };

        let http_request = HttpRequest {
            url: format!("https://{address}{path}"),
            method: method.clone(),
            body: body.clone(),
            bearer: self.bearers.get(&logical_endpoint).cloned(),
        };
        let request_digest =
            sha256_hex(format!("{method} {path}\n{}", body.unwrap_or_default()).as_bytes());
        let started_at_ms = (self.clock)();
        let response = self.transport.send(&http_request)?;
        let finished_at_ms = (self.clock)();
        let response_digest = sha256_hex(&response.body);
        let real_id = format!("http {} {response_digest}", response.status);
        self.records.push(HttpCallRecord {
            format: HTTP_CALL_FORMAT.to_string(),
            handle: effect.handle.clone(),
            capability,
            logical_endpoint,
            method,
            path,
            data_class,
            catalog_digest,
            request_digest,
            status: response.status,
            response_digest,
            response_bytes: response.body.len() as u64,
            started_at_ms,
            finished_at_ms,
        });
        Ok(real_id)
    }
}

impl<T: HttpTransport> EffectPerformer for HttpAdapter<T> {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        _resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        if effect.tool != TOOL {
            return Err(format!(
                "the HTTP adapter does not implement {}",
                effect.tool
            ));
        }
        self.perform_call(effect)
    }
}

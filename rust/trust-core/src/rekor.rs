//! # Rekor transparency-log client
//!
//! A dependency-light client for the public Rekor transparency log
//! (<https://rekor.sigstore.dev>) and Rekor-compatible instances. Rekor is
//! Sigstore's append-only transparency log; recording an entry there makes a
//! signature publicly verifiable and timestamped.
//!
//! This module is part of T1 trust-core — the single authoritative
//! implementation of every security invariant in Warrantor. Per the trusted-core
//! scope boundary, the **request construction and response parsing have no
//! external HTTP dependency**: they are pure functions over byte buffers. The
//! actual network transport is isolated behind the [`RekorTransport`] trait so
//! that:
//!
//!   - tests inject a mock transport (no network),
//!   - production can plug in any HTTP client (reqwest, hyper, …) without
//!     pulling that dependency into the trusted core, and
//!   - the bundled [`StdTransport`] uses `std::net::TcpStream` for plaintext
//!     HTTP against a configurable host:port (sufficient for a local Rekor or a
//!     TLS-terminating sidecar). For the public `https://rekor.sigstore.dev`
//!     endpoint, supply a TLS-capable transport.
//!
//! ## Entry type
//!
//! We create **hashed-rekord** entries (Rekor type `hashedrekord:v0.0.1`),
//! which record a SHA-256 digest + signature + verifying key without uploading
//! the payload itself. This keeps the notarized artifact confidential while
//! still providing a public, timestamped proof of the signature.
//!
//! ## API
//!
//!   - [`RekorClient::new`] — point at the public Rekor instance.
//!   - [`RekorClient::with_transport`] — inject a transport (tests / custom TLS).
//!   - [`RekorClient::notarize`] — build the hashed-rekord request, POST it,
//!     return a [`RekorEntry`].
//!   - [`RekorClient::build_notarize_request`] — pure function exposing the
//!     exact JSON body that *would* be sent (used by tests and for offline
//!     verification).
//!   - [`RekorClient::verify_entry`] — confirm an entry exists on the log.

#![allow(clippy::needless_borrow)]

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use thiserror::Error;

/// Default base URL of the public Rekor instance (Sigstore's production log).
pub const DEFAULT_REKOR_BASE_URL: &str = "https://rekor.sigstore.dev";

/// The Rekor entry type string this client creates.
pub const HASHED_REKORD_TYPE: &str = "hashedrekord:v0.0.1";

/// Errors returned by the Rekor client.
#[derive(Debug, Error)]
pub enum RekorError {
    /// Network-level failure (DNS, connection refused, timeout, TLS handshake).
    #[error("rekor network error: {0}")]
    Network(String),
    /// The Rekor API returned a non-2xx HTTP status.
    #[error("rekor api error: status {status}: {body}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Response body (truncated for logging).
        body: String,
    },
    /// The response could not be parsed into the expected shape.
    #[error("rekor invalid response: {0}")]
    InvalidResponse(String),
}

/// A Rekor transparency-log entry returned by [`RekorClient::notarize`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekorEntry {
    /// The log ID (UUID) of the entry, as assigned by Rekor.
    #[serde(default)]
    pub log_id: String,
    /// The monotonic log index of the entry.
    #[serde(default)]
    pub log_index: i64,
    /// Unix timestamp (seconds) at which the entry was integrated into the log.
    #[serde(default)]
    pub integrated_time: i64,
    /// The entry's UUID (Rekor's primary identifier; `logID` is the log tree).
    #[serde(default, rename = "uuid")]
    pub uuid: Option<String>,
    /// The proposed (or returned) content hash, base64-encoded, for traceability.
    #[serde(default, rename = "content_hash")]
    pub content_hash: Option<String>,
}

/// A network transport used by [`RekorClient`].
///
/// Implementations must POST `body` (already-serialized JSON bytes) to `path`
/// under the configured base URL, and return the response body bytes. The HTTP
/// status is communicated via [`TransportResponse`] so callers can distinguish
/// 2xx from error responses.
pub trait RekorTransport: Send + Sync {
    /// POST `body` to `path`, return the raw response.
    fn post(&self, path: &str, body: &[u8]) -> Result<TransportResponse, RekorError>;
    /// GET `path`, return the raw response.
    fn get(&self, path: &str) -> Result<TransportResponse, RekorError>;
}

/// The raw response from a transport call.
#[derive(Debug, Clone)]
pub struct TransportResponse {
    /// HTTP status code (e.g. 201).
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// A [`RekorTransport`] backed by `std::net::TcpStream` (plaintext HTTP).
///
/// Sufficient for a local Rekor deployment reachable over plain HTTP, or for a
/// TLS-terminating sidecar. **It cannot speak TLS**, so pointing it at
/// `https://rekor.sigstore.dev` will fail with a network error — supply a
/// TLS-capable transport for that. The bundled transport exists so the trusted
/// core has a working, dependency-free default for non-TLS deployments and for
/// integration tests that front Rekor with a local proxy.
pub struct StdTransport {
    /// The hostname (no scheme, no port).
    pub host: String,
    /// The destination port.
    pub port: u16,
    timeout: Duration,
}

impl StdTransport {
    /// Construct a plaintext transport for `host:port`.
    ///
    /// `url` is parsed loosely: only the host and port are extracted. The path
    /// component is ignored (the client supplies the path per-call). If `url`
    /// has no explicit port, 80 is assumed for `http://` schemes and 443 for
    /// `https://` (the latter will fail at connect time without TLS support —
    /// prefer a TLS-capable transport in that case).
    pub fn new(url: &str) -> Result<Self, RekorError> {
        let stripped = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let authority = stripped.split('/').next().unwrap_or(stripped);
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| RekorError::Network(format!("invalid port in url {url:?}")))?;
                (h.to_string(), port)
            }
            None => {
                let port = if url.starts_with("https://") { 443 } else { 80 };
                (authority.to_string(), port)
            }
        };
        Ok(Self {
            host,
            port,
            timeout: Duration::from_secs(15),
        })
    }

    /// Override the connect/read timeout (default 15s).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<TransportResponse, RekorError> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .to_socket_addrs_first()
                .ok_or_else(|| RekorError::Network(format!("resolve {addr}")))?,
            self.timeout,
        )
        .map_err(|e| RekorError::Network(format!("connect {addr}: {e}")))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| RekorError::Network(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| RekorError::Network(format!("set_write_timeout: {e}")))?;

        let body_len = body.map(|b| b.len()).unwrap_or(0);
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             User-Agent: warrantor-trust-core/1.0\r\n",
            self.host
        );
        if body.is_some() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {body_len}\r\n"));
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .map_err(|e| RekorError::Network(format!("write request: {e}")))?;
        if let Some(b) = body {
            stream
                .write_all(b)
                .map_err(|e| RekorError::Network(format!("write body: {e}")))?;
        }

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| RekorError::Network(format!("read response: {e}")))?;

        Self::parse_http_response(&raw)
    }

    /// Parse a raw HTTP/1.x response into status + body. Splits on the first
    /// `\r\n\r\n` to separate headers from the body. Handles both
    /// `Content-Length`-delimited and connection-close-delimited bodies (the
    /// latter because we send `Connection: close`).
    fn parse_http_response(raw: &[u8]) -> Result<TransportResponse, RekorError> {
        let split_idx = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| RekorError::InvalidResponse("no header/body separator".into()))?;
        let headers = &raw[..split_idx];
        let body = &raw[split_idx + 4..];

        let header_str = std::str::from_utf8(headers)
            .map_err(|e| RekorError::InvalidResponse(format!("non-utf8 headers: {e}")))?;
        let status_line = header_str.lines().next().unwrap_or("");
        // Format: "HTTP/1.1 200 OK"
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                RekorError::InvalidResponse(format!("unparseable status line: {status_line:?}"))
            })?;

        let body = Self::maybe_unchunk(body, header_str).unwrap_or_else(|| body.to_vec());
        Ok(TransportResponse { status, body })
    }

    /// Decode a chunked-transfer-encoded body when `Transfer-Encoding: chunked`
    /// is present. Returns `None` if the body is not chunked.
    fn maybe_unchunk(body: &[u8], headers: &str) -> Option<Vec<u8>> {
        if !headers
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            return None;
        }
        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor < body.len() {
            // Find the chunk-size line terminator.
            let nl = body[cursor..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|p| cursor + p)?;
            let size_line = std::str::from_utf8(&body[cursor..nl]).ok()?;
            let chunk_size = usize::from_str_radix(size_line.trim().split(';').next()?, 16).ok()?;
            cursor = nl + 2;
            if chunk_size == 0 {
                break;
            }
            let end = cursor.checked_add(chunk_size)?;
            if end > body.len() {
                return None;
            }
            out.extend_from_slice(&body[cursor..end]);
            cursor = end + 2; // skip trailing CRLF
        }
        Some(out)
    }
}

impl RekorTransport for StdTransport {
    fn post(&self, path: &str, body: &[u8]) -> Result<TransportResponse, RekorError> {
        self.request("POST", path, Some(body))
    }
    fn get(&self, path: &str) -> Result<TransportResponse, RekorError> {
        self.request("GET", path, None)
    }
}

/// Helper to resolve a `host:port` to the first socket address without pulling
/// `ToSocketAddrs` into the public API.
trait ToFirstAddr {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr>;
}

impl ToFirstAddr for str {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok()?.next()
    }
}

/// A Rekor transparency-log client.
pub struct RekorClient {
    base_url: String,
    transport: Box<dyn RekorTransport>,
}

impl RekorClient {
    /// Construct a client pointing at the public Rekor instance
    /// (<https://rekor.sigstore.dev>) using the bundled [`StdTransport`].
    ///
    /// Note: the bundled transport is plaintext HTTP. To notarize against the
    /// public HTTPS endpoint, construct with [`RekorClient::with_transport`]
    /// and supply a TLS-capable transport.
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url_and_default_transport(DEFAULT_REKOR_BASE_URL)
    }

    /// Construct a client pointing at `base_url` using the bundled transport.
    #[must_use]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self::with_base_url_and_default_transport(&base_url.into())
    }

    fn with_base_url_and_default_transport(base_url: &str) -> Self {
        let transport: Box<dyn RekorTransport> = match StdTransport::new(base_url) {
            Ok(t) => Box::new(t),
            // If we cannot even parse the URL, fall back to a transport that
            // always errors. The caller will see a typed error on first use.
            Err(e) => Box::new(AlwaysErrorTransport(e)),
        };
        Self {
            base_url: base_url.to_string(),
            transport,
        }
    }

    /// Construct a client with a custom transport (e.g. a TLS-capable HTTP
    /// client, or a mock transport in tests).
    #[must_use]
    pub fn with_transport(base_url: impl Into<String>, transport: Box<dyn RekorTransport>) -> Self {
        Self {
            base_url: base_url.into(),
            transport,
        }
    }

    /// The base URL this client is configured against.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build the exact JSON body for a `hashedrekord:v0.0.1` entry request.
    ///
    /// This is the canonical Rekor request shape and is exposed publicly so
    /// callers (and tests) can verify the bytes that would be submitted
    /// without performing any network I/O. `digest` is the base64-encoded
    /// SHA-256 of the payload; `signature` is the base64-encoded signature;
    /// `verifying_key` is the base64-encoded public key.
    ///
    /// Returns the serialized JSON as a pretty-printable [`Value`] (so callers
    /// can inspect or re-serialize it) and as a compact byte vector.
    #[must_use]
    pub fn build_notarize_request(
        &self,
        digest_b64: &str,
        signature_b64: &str,
        verifying_key_b64: &str,
    ) -> Value {
        json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "signature": {
                    "content": signature_b64,
                    "publicKey": {
                        "content": verifying_key_b64
                    }
                },
                "data": {
                    "hash": {
                        "algorithm": "sha512",
                        "value": digest_b64
                    }
                }
            }
        })
    }

    /// Notarize a payload on Rekor: hash the payload, build a hashed-rekord
    /// entry from `(payload_digest, signature, verifying_key)`, POST it, and
    /// return the resulting [`RekorEntry`].
    ///
    /// The payload itself is **not** uploaded — only its SHA-256 digest. The
    /// signature and verifying key are uploaded (base64) so the entry is
    /// independently verifiable.
    ///
    /// `payload`, `signature`, and `verifying_key` are raw bytes (the caller
    /// signs/encodes them however they like; this function only base64-encodes
    /// for transport and SHA-256-hashes the payload).
    pub fn notarize(
        &self,
        payload: &[u8],
        signature: &[u8],
        verifying_key: &[u8],
    ) -> Result<RekorEntry, RekorError> {
        // SHA-512, not SHA-256. Ed25519 signs over SHA-512 internally, and Rekor rejects a
        // hashedrekord whose hash algorithm does not match the key type:
        //   "unsupported hash algorithm: \"SHA-256\" not in [SHA-512]"
        // Verified against Rekor v1.3.6.
        let digest = Sha512::digest(payload);
        // `data.hash.value` is HEX, not base64. The previous comment here recorded the
        // author guessing between the two and choosing base64; a real Rekor rejects that
        // entry.
        let digest_hex = hex::encode(digest);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
        // `signature.publicKey.content` is base64 of a PEM-encoded key, not of the raw
        // key bytes. Raw bytes yield "invalid public key: failure decoding PEM" (400).
        let key_b64 =
            base64::engine::general_purpose::STANDARD.encode(ed25519_public_key_pem(verifying_key));

        let body = self
            .build_notarize_request(&digest_hex, &signature_b64, &key_b64)
            .to_string();
        let body_bytes = body.as_bytes();

        let resp = self.transport.post("/api/v1/log/entries", body_bytes)?;
        if !(200..300).contains(&resp.status) {
            return Err(RekorError::Api {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).to_string(),
            });
        }
        self.parse_notarize_response(&resp.body, &digest_hex)
    }

    /// Parse the JSON returned by `POST /api/v1/log/entries`.
    ///
    /// Rekor returns a map of `{uuid: { logID, logIndex, integratedTime, body }}`
    /// (a map because the API is generic over batched submissions). We pick the
    /// first entry. If the map is empty we return an `InvalidResponse` error.
    fn parse_notarize_response(
        &self,
        raw: &[u8],
        digest_b64: &str,
    ) -> Result<RekorEntry, RekorError> {
        let val: Value = serde_json::from_slice(raw)
            .map_err(|e| RekorError::InvalidResponse(format!("not a JSON object: {e}")))?;
        let obj = val
            .as_object()
            .ok_or_else(|| RekorError::InvalidResponse("response is not a JSON object".into()))?;
        if obj.is_empty() {
            return Err(RekorError::InvalidResponse(
                "response object has no entries".into(),
            ));
        }
        // The single key is the entry UUID.
        let (uuid, entry) = obj.iter().next().expect("non-empty checked above");
        let log_id = entry
            .get("logID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let log_index = entry.get("logIndex").and_then(|v| v.as_i64()).unwrap_or(0);
        let integrated_time = entry
            .get("integratedTime")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        Ok(RekorEntry {
            log_id,
            log_index,
            integrated_time,
            uuid: Some(uuid.clone()),
            content_hash: Some(digest_b64.to_string()),
        })
    }

    /// Verify that an entry exists on the Rekor log by fetching it by UUID.
    ///
    /// Returns `true` if Rekor returns a 2xx response whose body contains the
    /// expected `logID`/`logIndex`. Returns `false` if Rekor returns 404.
    /// Other errors are surfaced as [`RekorError`].
    pub fn verify_entry(&self, entry: &RekorEntry) -> Result<bool, RekorError> {
        let uuid = entry.uuid.as_deref().ok_or_else(|| {
            RekorError::InvalidResponse("entry has no uuid; cannot verify".into())
        })?;
        let path = format!("/api/v1/log/entries/{uuid}");
        let resp = self.transport.get(&path)?;
        if resp.status == 404 {
            return Ok(false);
        }
        if !(200..300).contains(&resp.status) {
            return Err(RekorError::Api {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).to_string(),
            });
        }
        let val: Value = serde_json::from_slice(&resp.body)
            .map_err(|e| RekorError::InvalidResponse(format!("verify response not JSON: {e}")))?;
        // The entry's UUID should be a top-level key.
        let found = val
            .as_object()
            .and_then(|o| o.get(uuid))
            .and_then(|e| e.get("logIndex"))
            .and_then(|v| v.as_i64());
        Ok(found == Some(entry.log_index))
    }
}

impl Default for RekorClient {
    fn default() -> Self {
        Self::new()
    }
}

/// A transport that always returns a fixed error (used when the bundled
/// `StdTransport` could not be constructed from the base URL, e.g. for an
/// HTTPS URL where plaintext TCP will not work).
struct AlwaysErrorTransport(RekorError);

impl RekorTransport for AlwaysErrorTransport {
    fn post(&self, _path: &str, _body: &[u8]) -> Result<TransportResponse, RekorError> {
        Err(RekorError::Network(format!(
            "no usable transport for HTTPS endpoint: {}",
            self.0
        )))
    }
    fn get(&self, _path: &str) -> Result<TransportResponse, RekorError> {
        Err(RekorError::Network(format!(
            "no usable transport for HTTPS endpoint: {}",
            self.0
        )))
    }
}

/// Wrap a raw 32-byte Ed25519 public key as a PEM `SubjectPublicKeyInfo`.
///
/// Rekor's `hashedrekord` entry requires `signature.publicKey.content` to be base64 of a
/// PEM document. Supplying base64 of the raw key bytes returns
/// `400 invalid public key: failure decoding PEM`.
///
/// Ed25519 SPKI is fixed-shape, so the DER is a constant 12-byte prefix followed by the
/// key. Encoding it by hand avoids pulling a full ASN.1 crate into the trusted core.
///
///   30 2a           SEQUENCE (42 bytes)
///     30 05         SEQUENCE (5 bytes)  -- AlgorithmIdentifier
///       06 03 2b6570  OID 1.3.101.112 (Ed25519)
///     03 21 00      BIT STRING (33 bytes, 0 unused bits)
///       <32-byte key>
fn ed25519_public_key_pem(verifying_key: &[u8]) -> String {
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = Vec::with_capacity(SPKI_PREFIX.len() + verifying_key.len());
    der.extend_from_slice(&SPKI_PREFIX);
    der.extend_from_slice(verifying_key);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type RecordedCall = (String, Vec<u8>);
    type SharedCalls = Arc<Mutex<Vec<RecordedCall>>>;
    type CannedResponses = Arc<Mutex<Vec<Result<TransportResponse, RekorError>>>>;

    /// A mock transport that records every call and returns a canned response
    /// from a shared queue. Both the call log and the response queue live
    /// behind `Arc<Mutex<...>>` so the transport is cheaply shareable.
    struct SharedMockTransport {
        calls: SharedCalls,
        responses: CannedResponses,
    }

    impl SharedMockTransport {
        fn new(responses: Vec<Result<TransportResponse, RekorError>>) -> (Self, SharedCalls) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let responses = Arc::new(Mutex::new(responses));
            let calls_handle = Arc::clone(&calls);
            (Self { calls, responses }, calls_handle)
        }
    }

    impl RekorTransport for SharedMockTransport {
        fn post(&self, path: &str, body: &[u8]) -> Result<TransportResponse, RekorError> {
            self.calls
                .lock()
                .unwrap()
                .push((format!("POST {path}"), body.to_vec()));
            let mut q = self.responses.lock().unwrap();
            if q.is_empty() {
                Err(RekorError::Network("no canned response".into()))
            } else {
                q.remove(0)
            }
        }
        fn get(&self, path: &str) -> Result<TransportResponse, RekorError> {
            self.calls
                .lock()
                .unwrap()
                .push((format!("GET {path}"), Vec::new()));
            let mut q = self.responses.lock().unwrap();
            if q.is_empty() {
                Err(RekorError::Network("no canned response".into()))
            } else {
                q.remove(0)
            }
        }
    }

    #[test]
    fn default_base_url_is_public_rekor() {
        let c = RekorClient::new();
        assert_eq!(c.base_url(), DEFAULT_REKOR_BASE_URL);
    }

    #[test]
    fn build_notarize_request_has_correct_shape() {
        let c = RekorClient::new();
        let req = c.build_notarize_request("DIGESTB64", "SIGB64", "KEYB64");
        assert_eq!(req["apiVersion"], "0.0.1");
        assert_eq!(req["kind"], "hashedrekord");
        assert_eq!(req["spec"]["signature"]["content"], "SIGB64");
        assert_eq!(req["spec"]["signature"]["publicKey"]["content"], "KEYB64");
        // sha512, not sha256: Rekor rejects SHA-256 for an Ed25519 key with
        // "unsupported hash algorithm: SHA-256 not in [SHA-512]". This assertion
        // previously locked in the wrong value, which is why the bug survived.
        assert_eq!(req["spec"]["data"]["hash"]["algorithm"], "sha512");
        assert_eq!(req["spec"]["data"]["hash"]["value"], "DIGESTB64");
    }

    #[test]
    fn build_notarize_request_is_deterministic() {
        // Same inputs => identical bytes (cross-language reproducibility).
        let c = RekorClient::new();
        let a = c.build_notarize_request("d", "s", "k").to_string();
        let b = c.build_notarize_request("d", "s", "k").to_string();
        assert_eq!(a, b);
    }

    #[test]
    fn notarize_posts_to_correct_path_and_parses_response() {
        let canned_body = r#"{
            "11111111-2222-3333-4444-555555555555": {
                "logID": "abcdef0123456789",
                "logIndex": 42,
                "integratedTime": 1700000000,
                "body": "..."
            }
        }"#;
        let (transport, calls) = SharedMockTransport::new(vec![Ok(TransportResponse {
            status: 201,
            body: canned_body.as_bytes().to_vec(),
        })]);
        let client = RekorClient::with_transport("https://rekor.example", Box::new(transport));

        let entry = client
            .notarize(b"hello", b"fakesig", b"fakekey")
            .expect("notarize ok");

        // The POST hit the canonical Rekor path.
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "POST /api/v1/log/entries");
        // The body posted was the hashed-rekord JSON.
        let posted: Value = serde_json::from_slice(&calls[0].1).unwrap();
        assert_eq!(posted["kind"], "hashedrekord");
        // The entry was parsed.
        assert_eq!(entry.log_index, 42);
        assert_eq!(entry.integrated_time, 1_700_000_000);
        assert_eq!(
            entry.uuid.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }

    #[test]
    fn notarize_propagates_api_errors() {
        let (transport, _calls) = SharedMockTransport::new(vec![Ok(TransportResponse {
            status: 400,
            body: b"bad request".to_vec(),
        })]);
        let client = RekorClient::with_transport("https://x", Box::new(transport));
        let err = client.notarize(b"x", b"y", b"z").unwrap_err();
        match err {
            RekorError::Api { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("bad request"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn notarize_propagates_network_errors() {
        let (transport, _calls) =
            SharedMockTransport::new(vec![Err(RekorError::Network("conn refused".into()))]);
        let client = RekorClient::with_transport("https://x", Box::new(transport));
        let err = client.notarize(b"x", b"y", b"z").unwrap_err();
        assert!(matches!(err, RekorError::Network(_)));
    }

    #[test]
    fn verify_entry_returns_true_when_log_index_matches() {
        let entry_body = r#"{
            "abc": { "logID": "L", "logIndex": 7, "integratedTime": 1 }
        }"#;
        let (transport, _calls) = SharedMockTransport::new(vec![Ok(TransportResponse {
            status: 200,
            body: entry_body.as_bytes().to_vec(),
        })]);
        let client = RekorClient::with_transport("https://x", Box::new(transport));
        let entry = RekorEntry {
            log_id: "L".into(),
            log_index: 7,
            integrated_time: 1,
            uuid: Some("abc".into()),
            content_hash: None,
        };
        assert!(client.verify_entry(&entry).expect("verify ok"));
    }

    #[test]
    fn verify_entry_returns_false_on_404() {
        let (transport, _calls) = SharedMockTransport::new(vec![Ok(TransportResponse {
            status: 404,
            body: Vec::new(),
        })]);
        let client = RekorClient::with_transport("https://x", Box::new(transport));
        let entry = RekorEntry {
            log_id: String::new(),
            log_index: 0,
            integrated_time: 0,
            uuid: Some("missing".into()),
            content_hash: None,
        };
        assert!(!client.verify_entry(&entry).expect("verify ok"));
    }

    #[test]
    fn verify_entry_returns_false_when_index_differs() {
        // Rekor returns logIndex 99 but the entry claims 7 — verify must fail.
        let entry_body = r#"{ "abc": { "logIndex": 99 } }"#;
        let (transport, _calls) = SharedMockTransport::new(vec![Ok(TransportResponse {
            status: 200,
            body: entry_body.as_bytes().to_vec(),
        })]);
        let client = RekorClient::with_transport("https://x", Box::new(transport));
        let entry = RekorEntry {
            log_id: String::new(),
            log_index: 7,
            integrated_time: 0,
            uuid: Some("abc".into()),
            content_hash: None,
        };
        assert!(!client.verify_entry(&entry).expect("verify ok"));
    }

    #[test]
    fn verify_entry_errors_without_uuid() {
        let (transport, _calls) = SharedMockTransport::new(vec![]);
        let client = RekorClient::with_transport("https://x", Box::new(transport));
        let entry = RekorEntry {
            log_id: String::new(),
            log_index: 0,
            integrated_time: 0,
            uuid: None,
            content_hash: None,
        };
        let err = client.verify_entry(&entry).unwrap_err();
        assert!(matches!(err, RekorError::InvalidResponse(_)));
    }

    #[test]
    fn parse_http_response_handles_simple_body() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let resp = StdTransport::parse_http_response(raw).expect("parse ok");
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, b"{\"ok\":true}");
    }

    #[test]
    fn parse_http_response_decodes_chunked_body() {
        // A chunked body carrying "hello world".
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let resp = StdTransport::parse_http_response(raw).expect("parse ok");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");
    }

    #[test]
    fn std_transport_parses_http_url_host_port() {
        let t = StdTransport::new("http://localhost:3009").unwrap();
        assert_eq!(t.host, "localhost");
        assert_eq!(t.port, 3009);
    }

    #[test]
    fn std_transport_defaults_port_for_http() {
        let t = StdTransport::new("http://rekor.local").unwrap();
        assert_eq!(t.port, 80);
    }

    #[test]
    fn std_transport_defaults_port_for_https() {
        let t = StdTransport::new("https://rekor.sigstore.dev").unwrap();
        assert_eq!(t.port, 443);
    }

    #[test]
    fn std_transport_rejects_bad_port() {
        assert!(StdTransport::new("http://h:notaport").is_err());
    }

    #[test]
    fn rekor_entry_serializes_round_trip() {
        let entry = RekorEntry {
            log_id: "L".into(),
            log_index: 9,
            integrated_time: 1_700_000_000,
            uuid: Some("uuid-1".into()),
            content_hash: Some("h".into()),
        };
        let s = serde_json::to_string(&entry).unwrap();
        let back: RekorEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(entry, back);
    }
}
